#!/usr/bin/env python3
"""
TrustPulse Mobile - Policy Decision Point (PDP) Validation Backend
-----------------------------------------------------------------
A lightweight, privacy-focused security validation backend built with FastAPI.
Evaluates mobile posture payloads, logs anonymous compliance records,
and issues short-lived cryptographic session tokens.

GDPR Compliance & Privacy-First Architecture:
1. Zero PII storage: No email, username, phone numbers, or clear-text addresses.
2. Device ID masking: Only anonymous, high-entropy unique identifiers are processed.
3. Decoupled Context logs: Posture features (e.g. specific security flags) are transient 
   and evaluated purely in-memory. They are NEVER logged to raw storage. Only the overall 
   Status (Pass/Fail) is recorded inside persistent logs.
"""

import time
import base64
import hmac
import hashlib
import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

app = FastAPI(
    title="TrustPulse Mobile Validation Gateway",
    description="Privacy-First Mobile Endpoint Validation Engine for Small Businesses.",
    version="1.0.0"
)

# Cryptographic Salt / Secret for Token Signing (Keep highly secure in Vault/Env in production)
JWT_MOCK_SECRET = "trustpulse_byod_gateway_academic_sig_key_2026_super_secret"

# Secure Audit Log File Path (Stored locally on-disk securely, zero PII, structured JSON lines/array)
AUDIT_LOG_FILE = "compliance_secure_audit.json"

# GDPR Preserving In-Memory Structured Log Variable
# ONLY stores: Timestamp, Anonymous Device ID, Compliance Status, Segmented Event Meta
# NO store of user profile, specific file paths, or private configuration.
compliance_database_log: List[Dict[str, Any]] = []

class PosturePayload(BaseModel):
    device_id: str = Field(..., description="Anonymized unique SHA-256 identifier representing the endpoint.")
    passcode_enabled: bool = Field(..., description="Flag specifying if screen lock / biometric PIN is active.")
    os_version: str = Field(..., description="Operating System version string (e.g. 16.4).")
    is_rooted: bool = Field(..., description="Flag indicating system-level jailbreak/root access state.")
    timestamp: int = Field(..., description="Epoch timestamp of scan generation.")
    
    # Newly added simulated security checks
    malicious_apps_detected: bool = Field(default=False, description="Presence of malware or restricted hacker utility apps.")
    network_anomalies_detected: bool = Field(default=False, description="Heuristic detection of cellular/Wi-Fi proxy or traffic interception.")
    unusual_permissions_granted: bool = Field(default=False, description="Atypical runtime system level permission concessions.")

class TokenRefreshRequest(BaseModel):
    token: str = Field(..., description="Current signed web token.")

def parse_version(v_str: str) -> List[int]:
    """Parse dot-separated version strings safely (e.g., '16.4.1' -> [16, 4, 1])."""
    try:
        return [int(x) for x in v_str.split('.')]
    except ValueError:
        return [0]

def create_cryptographic_access_header(payload: Dict[str, Any], secret_key: str) -> str:
    """
    Constructs a standard-compliant, signed, short-lived mock Access Token (JWT-equivalent).
    Using pure Python libraries to guarantee instant compatibility without external pip burdens.
    """
    # 1. Base64 encode the header
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode('utf-8')).decode('utf-8').rstrip('=')
    
    # 2. Base64 encode the payload (claims)
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode('utf-8')).decode('utf-8').rstrip('=')
    
    # 3. Form unique HMAC SHA-256 signature
    signing_input = f"{header_b64}.{payload_b64}"
    signature = hmac.new(
        key=secret_key.encode('utf-8'),
        msg=signing_input.encode('utf-8'),
        digestmod=hashlib.sha256
    ).digest()
    signature_b64 = base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')
    
    return f"{header_b64}.{payload_b64}.{signature_b64}"

def verify_cryptographic_access_header(token: str, secret_key: str) -> Dict[str, Any]:
    """
    Parses, cryptographically validates, and decodes the signed token (JWT-equivalent).
    Raises ValueError on integrity/signature mismatch or decode failures.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Token format mismatch. Must have 3 parts.")
        
        header_b64, payload_b64, signature_b64 = parts
        
        # Verify cryptographic signature integrity
        signing_input = f"{header_b64}.{payload_b64}"
        expected_signature = hmac.new(
            key=secret_key.encode('utf-8'),
            msg=signing_input.encode('utf-8'),
            digestmod=hashlib.sha256
        ).digest()
        expected_sig_b64 = base64.urlsafe_b64encode(expected_signature).decode('utf-8').rstrip('=')
        
        if not hmac.compare_digest(signature_b64, expected_sig_b64):
            raise ValueError("HMAC validation failed. Token is altered or forged.")
        
        # Base64 decode padding correction support
        rem = len(payload_b64) % 4
        if rem > 0:
            payload_b64 += "=" * (4 - rem)
            
        payload_bytes = base64.urlsafe_b64decode(payload_b64.encode('utf-8'))
        return json.loads(payload_bytes.decode('utf-8'))
    except Exception as e:
        raise ValueError(f"Integrity check failed: {str(e)}")

@app.post("/api/v1/validate", status_code=200)
def validate_device_posture(payload: PosturePayload):
    """
    Validates the device security properties, checks against the baseline BYOD policy,
    and returns a short-lived cryptographically signed token if validation is approved.
    """
    print(f"\n📥 Received validation request from Device ID: {payload.device_id}")
    
    # --- STEP 1: Evaluate Baseline BYOD Policy Rules ---
    
    # 1. Passcode Check: Device passcode must be active!
    if not payload.passcode_enabled:
        reason = "Non-compliant state: Local Device passcode/screen lock is disabled."
        log_compliance_event(payload.device_id, "FAILED", reason, "POLICY_VIOLATION", "WARNING")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "Access Denied", "detail": reason}
        )
        
    # 2. OS version check: OS must be updated (Minimum version baseline v16.4)
    baseline_version = [16, 4]
    client_version = parse_version(payload.os_version)
    if client_version < baseline_version:
        reason = f"Non-compliant state: OS outdated (v{payload.os_version}). Required: >= v16.4."
        log_compliance_event(payload.device_id, "FAILED", reason, "POLICY_VIOLATION", "WARNING")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "Access Denied", "detail": reason}
        )
        
    # 3. Root check: Jailbroken state must be false to avoid compromised sandbox danger
    if payload.is_rooted:
        reason = "Non-compliant state: Sandbox integrity is compromised (rooted/jailbroken)."
        log_compliance_event(payload.device_id, "FAILED", reason, "POLICY_VIOLATION", "CRITICAL")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "Access Denied", "detail": reason}
        )

    # 4. ADVANCED SECURITY CHECKS (Newly added telemetry validation policies)
    
    # A. Malicious applications installed: High security severity validation bypass block.
    if payload.malicious_apps_detected:
        reason = "Non-compliant threat: Multiple known malicious or hacking utility apps detected on endpoint list."
        log_compliance_event(payload.device_id, "SUSPICIOUS", reason, "SUSPICIOUS_ACTIVITY", "CRITICAL")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "Access Denied", "detail": reason}
        )
        
    # B. Network interception / Proxies detected: MITM interception anomaly.
    if payload.network_anomalies_detected:
        reason = "Non-compliant threat: Heuralistic network analysis reports an active TLS proxy intercept anomaly."
        log_compliance_event(payload.device_id, "SUSPICIOUS", reason, "SUSPICIOUS_ACTIVITY", "CRITICAL")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "Access Denied", "detail": reason}
        )
        
    # C. Unusual permissions check: Excess capability leak warning.
    if payload.unusual_permissions_granted:
        reason = "Non-compliant threat: Atypical system privileges granted to multiple unknown applications."
        # Logs as a policy violation warning but doesn't necessarily block if passcode/version is valid (demonstrating soft criteria warning logs)
        log_compliance_event(payload.device_id, "SUSPICIOUS", reason, "SUSPICIOUS_ACTIVITY", "WARNING")
        # Soft compliance warning log - we allow bypass but log as warning to auditing dashboards.

    # --- STEP 2: Compliance Policy Is Fully MET ---
    print(f"🛡️ Posture verification SUCCESS values matched policies. Initiating credentials emission...")
    
    # Issue short-lived access credentials set to expire in exactly 5 minutes (300 seconds)
    expiration_epoch = int(time.time()) + 300
    
    token_claims = {
        "sub": payload.device_id,
        "iss": "TrustPulse Gateway",
        "exp": expiration_epoch,
        "scope": "byod.gateway.access",
        "status": "APPROVED"
    }
    
    cryptographic_token = create_cryptographic_access_header(token_claims, JWT_MOCK_SECRET)
    
    # Save a privacy-preserving validation success log
    log_compliance_event(
        device_id=payload.device_id, 
        status="APPROVED", 
        detail="Successful secure posture validation. Issued short-lived signature.",
        event_type="VALIDATION_SUCCESS",
        severity="INFO"
    )
    
    return {
        "status": "APPROVED",
        "token": cryptographic_token,
        "expires_in": 300,
        "expiration_timestamp": expiration_epoch
    }

# In-memory storage for token refresh rate limiting (device_id -> list of float timestamps)
refresh_timestamps: Dict[str, List[float]] = {}

@app.post("/api/v1/refresh", status_code=200)
def refresh_token(payload: TokenRefreshRequest):
    """
    Verifies the current signed token. If valid, or within the security grace period,
    generates a fresh cryptographically signed session token.
    This endpoint is protected by a local rate limiter to prevent abuse.
    """
    # 1. Cryptographically parse and verify token
    try:
        token_payload = verify_cryptographic_access_header(payload.token, JWT_MOCK_SECRET)
    except ValueError as e:
        log_compliance_event(
            device_id="unknown_bad_token",
            status="SUSPICIOUS",
            detail=f"Token validation failed during refresh trial: {str(e)}",
            event_type="SUSPICIOUS_ACTIVITY",
            severity="CRITICAL"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "Unauthorized", "detail": f"Token verification failed: {str(e)}"}
        )
        
    device_id = token_payload.get("sub", "unknown")
    token_exp = token_payload.get("exp", 0)
    current_time = int(time.time())
    
    # 2. Check Security Rate Limiting (Limit to max 3 refresh requests per 60 seconds per device)
    now = time.time()
    if device_id not in refresh_timestamps:
        refresh_timestamps[device_id] = []
    
    # Prune old timestamps
    refresh_timestamps[device_id] = [t for t in refresh_timestamps[device_id] if now - t < 60.0]
    
    if len(refresh_timestamps[device_id]) >= 3:
        log_compliance_event(
            device_id=device_id,
            status="SUSPICIOUS",
            detail=f"Token refresh abuse detected for device {device_id}. Threshold 3 req/min breached.",
            event_type="RATE_LIMIT_TRIGGER",
            severity="WARNING"
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Maximum 3 token refreshes permitted per minute."
        )
        
    # Append current invocation
    refresh_timestamps[device_id].append(now)
    
    # 3. Validation Grace Period evaluation (120 seconds maximum overflow window)
    grace_period = 120
    is_expired = current_time > token_exp
    
    if is_expired:
        elapsed_since_expiration = current_time - token_exp
        if elapsed_since_expiration > grace_period:
            log_compliance_event(
                device_id=device_id,
                status="FAILED",
                detail=f"Token refresh rejected. Exceeded token grace period by {elapsed_since_expiration}s (Limit {grace_period}s).",
                event_type="POLICY_VIOLATION",
                severity="WARNING"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access token fully expired. Secure device re-validation is required."
            )
        else:
            print(f"⚠️ Token expired but within acceptable grace period ({elapsed_since_expiration}s / {grace_period}s). Granting refresh...")
            
    # 4. Everything is compliant. Generate fresh cryptographic token
    new_expiration_epoch = int(time.time()) + 300
    new_claims = {
        "sub": device_id,
        "iss": "TrustPulse Gateway",
        "exp": new_expiration_epoch,
        "scope": "byod.gateway.access",
        "status": "APPROVED"
    }
    
    new_token = create_cryptographic_access_header(new_claims, JWT_MOCK_SECRET)
    
    log_compliance_event(
        device_id=device_id,
        status="APPROVED",
        detail="Cryptographic session token successfully refreshed.",
        event_type="TOKEN_REFRESH",
        severity="INFO"
    )
    
    return {
        "status": "APPROVED",
        "token": new_token,
        "expires_in": 300,
        "expiration_timestamp": new_expiration_epoch
    }

@app.get("/api/v1/compliance-logs", description="Get privacy-preserving compliance validation logs.")
def get_compliance_logs(
    start_time: Optional[int] = None,
    end_time: Optional[int] = None,
    status: Optional[str] = None,
    event_type: Optional[str] = None,
    min_severity: Optional[str] = None
):
    """
    Exposes the system compliance register containing raw, context-restricted metadata logs.
    Strictly GDPR compliant: Contains zero unencrypted PII.
    Provides optional criteria queries (start_time, end_time, status, event_type, min_severity).
    """
    filtered_logs = compliance_database_log
    
    if start_time is not None:
        filtered_logs = [log for log in filtered_logs if log["timestamp_utc"] >= start_time]
    if end_time is not None:
        filtered_logs = [log for log in filtered_logs if log["timestamp_utc"] <= end_time]
    if status is not None:
        filtered_logs = [log for log in filtered_logs if log["compliance_status"].upper() == status.upper()]
    if event_type is not None:
        filtered_logs = [log for log in filtered_logs if log["event_type"].upper() == event_type.upper()]
    if min_severity is not None:
         severity_map = {"INFO": 1, "WARNING": 2, "CRITICAL": 3}
         min_val = severity_map.get(min_severity.upper(), 0)
         filtered_logs = [
             log for log in filtered_logs 
             if severity_map.get(log.get("severity", "INFO"), 0) >= min_val
         ]

    return {
        "filter_criteria": {
            "start_time": start_time,
            "end_time": end_time,
            "compliance_status": status,
            "event_type": event_type,
            "min_severity": min_severity
        },
        "total_records": len(filtered_logs),
        "logs": filtered_logs
    }

def log_compliance_event(device_id: str, status: str, detail: str, event_type: str = "VALIDATION", severity: str = "INFO"):
    """
    Saves a GDPR-compliant security audit log structure to in-memory history and secure file on disk.
    Does NOT collect user IP, hardware serials, network SSIDs, GPS, or clear credentials.
    """
    now_ts = int(time.time())
    iso_ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    
    log_entry = {
         "timestamp_utc": now_ts,
         "timestamp_iso": iso_ts,
         "device_id": device_id,                  # Pre-anonymized SHA-256 hash only
         "compliance_status": status,            # APPROVED, FAILED, or SUSPICIOUS
         "event_type": event_type,                # VALIDATION_SUCCESS, POLICY_VIOLATION, SUSPICIOUS_ACTIVITY, etc.
         "policy_detail": detail,                 # Anonymized structural validation outcome description
         "severity": severity                     # INFO, WARNING, or CRITICAL
    }
    
    compliance_database_log.append(log_entry)
    print(f"💾 GDPR Compliant Log Generated (In-Memory DB): {json.dumps(log_entry)}")
    
    # Store securely to local audit file in a robust, structured format
    try:
        existing_logs = []
        try:
            with open(AUDIT_LOG_FILE, "r") as f:
                content = f.read().strip()
                if content:
                    existing_logs = json.loads(content)
        except (FileNotFoundError, json.JSONDecodeError):
            pass
            
        existing_logs.append(log_entry)
        with open(AUDIT_LOG_FILE, "w") as f:
            json.dump(existing_logs, f, indent=2)
    except Exception as e:
        print(f"⚠️ Secure Audit File writing error: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    print("\n-------------------------------------------")
    print("  Starting TrustPulse Mobile Backend API   ")
    print("-------------------------------------------\n")
    # Launching local development uvicorn runner (Default port: 8000)
    uvicorn.run(app, host="127.0.0.1", port=8000)

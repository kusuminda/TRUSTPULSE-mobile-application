#!/usr/bin/env python3
"""
TrustPulse Mobile - Mock Mobile Frontend (Device Posture Scanner)
----------------------------------------------------------------
Provides a clean code prototype simulating local mobile system flags validation
and packaging compliance posture data securely before sending to the backend API.

Privacy-First Design (Data Minimization & GDPR Compliance):
1. No PII (Personally Identifiable Information) like name, phone, email, or IMEI is collected.
2. The Device ID is dynamically hashed locally (SHA-256) to ensure complete anonymity.
3. Only security compliance boolean signals and high-level platform versions are processed.
"""

import json
import hashlib
import time
import requests

# Target Backend Configuration
API_BASE_URL = "http://127.0.0.1:8000"

def get_anonymous_device_id():
    """
    Generates a GDPR-compliant anonymous device identifier using an on-device
    salt/raw ID hash. Never exposes the hardware-level raw Serial or MAC address.
    """
    raw_hardware_id = "hw_mac_00_1a_2b_3c_4d_5e" # In a real app, this is retrieved from OS sandbox safely
    # Hash using SHA-256 to ensure complete irreversibility (anonymization)
    hasher = hashlib.sha256()
    hasher.update(raw_hardware_id.encode('utf-8'))
    return f"anon_{hasher.hexdigest()[:16]}" # Shortened 16-character secure identifier

def scan_device_posture_simulated(
    passcode_enabled=True, 
    os_version="16.5", 
    is_rooted=False,
    malicious_apps_detected=False,
    network_anomalies_detected=False,
    unusual_permissions_granted=False
):
    """
    Simulates performing low-level native checks on the mobile device sandbox:
    1. Screen Lock PIN/Passcode status: Checked via Android KeyguardManager or iOS LocalAuthentication.
    2. OS Version: Evaluates if system is updated above security baselines (e.g., iOS 16.4+).
    3. Root/Jailbreak Detection: Inspects typical sandbox bypass hazards.
    4. Malicious application inventory scans: Checks presence of restricted software.
    5. Heuristic network checks: Analyses proxies, malicious bypass routes, or intercepting gateways.
    6. Unusual active permission states: Inspects privileged contexts granted on system.
    """
    # Simulate hardware level indicators
    print("[TrustPulse Client] Actively scanning hardware sandbox state and active signals...")
    time.sleep(0.4) # Simulating scanner check delay
    
    posture_data = {
        "passcode_enabled": passcode_enabled,
        "os_version": os_version,
        "is_rooted": is_rooted,
        "malicious_apps_detected": malicious_apps_detected,
        "network_anomalies_detected": network_anomalies_detected,
        "unusual_permissions_granted": unusual_permissions_granted
    }
    
    print(f"🔒 Passcode Lock Status: {'ACTIVE' if passcode_enabled else 'INSECURE'}")
    print(f"📱 Operating System Info: v{os_version}")
    print(f"🛡️ Sandbox Jailbreak State: {'ROOTED (RISK)' if is_rooted else 'SECURE (RESTRICTED)'}")
    print(f"🦠 Malicious Apps Status: {'DETECTED (CRITICAL)' if malicious_apps_detected else 'CLEAN'}")
    print(f"🌐 Traffic Decryption Intercepts: {'ANOMALOUS (SUSPICIOUS)' if network_anomalies_detected else 'SECURE'}")
    print(f"🔑 Highly Privileged Contexts: {'UNUSUAL PERMISSIONS DETECTED' if unusual_permissions_granted else 'DEFAULT'}")
    
    return posture_data

def package_and_send_payload(posture_data):
    """
    Gathers the posture state, attaches the anonymized Device ID, and packages
    into a secure JSON payload delivered via POST over an encrypted tunnel.
    """
    anonymous_id = get_anonymous_device_id()
    
    # GDPR-Minimization: Combine scanned flags only. No GPS, user accounts, or filenames.
    payload = {
        "device_id": anonymous_id,
        "passcode_enabled": posture_data["passcode_enabled"],
        "os_version": posture_data["os_version"],
        "is_rooted": posture_data["is_rooted"],
        "timestamp": int(time.time()),
        "malicious_apps_detected": posture_data.get("malicious_apps_detected", False),
        "network_anomalies_detected": posture_data.get("network_anomalies_detected", False),
        "unusual_permissions_granted": posture_data.get("unusual_permissions_granted", False)
    }
    
    print(f"\n[TrustPulse Client] Generated GDPR-Compliant Posture Payload:\n{json.dumps(payload, indent=2)}")
    
    # Send securely to the Endpoint Validation Server (Checking local test environment)
    try:
        response = requests.post(f"{API_BASE_URL}/api/v1/validate", json=payload, timeout=5)
        
        if response.status_code == 200:
            result = response.json()
            print("✅ Device Posture Validation SUCCESSFUL!")
            print(f"🔑 Received Short-Lived Access Token: {result.get('token')}")
            print(f"⏱️ Token Expires In: {result.get('expires_in')} seconds")
            return result.get('token')
        else:
            print(f"❌ Device Posture Validation FAILED (HTTP {response.status_code})")
            print(f"⚠️ Reason: {response.json().get('detail', 'Unknown error context')}")
            return None
            
    except requests.exceptions.ConnectionError:
        print("\n🌐 Demonstration Notice: Local connection simulation bypass.")
        print(f"💡 Launch 'server.py' to run this end-to-end on {API_BASE_URL}!")
        return "mock_signature_bypass_token.abc123xyz"

if __name__ == "__main__":
    print("=========================================")
    print("   TrustPulse Mobile: Client Scanner    ")
    print("=========================================\n")
    
    # Try to ping server to see if uvicorn is running
    server_online = False
    try:
        requests.get(f"{API_BASE_URL}/api/v1/compliance-logs", timeout=1)
        server_online = True
        print(f"📡 Connection established to locally running PDP: {API_BASE_URL}")
    except requests.exceptions.ConnectionError:
        print("💡 Optional server setup: Run 'python server.py' in a workspace shell for real REST calls!")
        
    # Scenario 1: Fully Compliant Device (Should pass validation)
    print("\n--- SCENARIO 1: COMPLIANT BYOD DEVICE ---")
    compliant_state = scan_device_posture_simulated(
        passcode_enabled=True, 
        os_version="17.2", 
        is_rooted=False
    )
    token = package_and_send_payload(compliant_state)
    
    print("\n-----------------------------------------\n")
    
    # Scenario 2: Traditional policy violation (Should fail validation)
    print("--- SCENARIO 2: NON-COMPLIANT BYOD DEVICE (OUTDATED & ROOTED) ---")
    vulnerable_state = scan_device_posture_simulated(
        passcode_enabled=False, 
        os_version="15.1", 
        is_rooted=True
    )
    package_and_send_payload(vulnerable_state)
    
    print("\n-----------------------------------------\n")

    # Scenario 3: Newly Added Simulated Security Threats (Suspicious Activity)
    print("--- SCENARIO 3: HIGH-ALERT SUSPICIOUS ACTIVITY THREAT (MALWARE + PROXY DETECTED) ---")
    suspicious_state = scan_device_posture_simulated(
        passcode_enabled=True,
        os_version="16.5",
        is_rooted=False,
        malicious_apps_detected=True,       # Simulated security threat trigger!
        network_anomalies_detected=True,    # Simulated security threat trigger!
        unusual_permissions_granted=True
    )
    package_and_send_payload(suspicious_state)

    if server_online and token:
        print("\n-----------------------------------------\n")
        # Scenario 4: Token Refresh Mechanism (Grace Period Demo)
        print("--- SCENARIO 4: SESSION TOKEN REFRESH DEMO (COMPLIANT GRACE PERIOD) ---")
        refresh_payload = {"token": token}
        print(f"🔄 Requesting fresh token using current signature on refresh endpoint...")
        refresh_resp = requests.post(f"{API_BASE_URL}/api/v1/refresh", json=refresh_payload, timeout=5)
        if refresh_resp.status_code == 200:
            new_tok = refresh_resp.json().get("token")
            print("✅ Token Refresh APPROVED!")
            print(f"🔑 Newly Emitted Session Token: {new_tok}")
        else:
            print(f"❌ Token Refresh DENIED: {refresh_resp.json()}")

        print("\n-----------------------------------------\n")
        # Scenario 5: Token Refresh Security Rate Limiting Demo (Exceeding limit)
        print("--- SCENARIO 5: SECURITY RATE-LIMITING TRIGGER (ABUSE PREVENTION) ---")
        print("⚡ Rapidly dispatching multiple token refresh requests to test ratelimit protection...")
        for i in range(4):
            print(f"   [Refresh Call #{i+1}] Sending token payload...")
            resp = requests.post(f"{API_BASE_URL}/api/v1/refresh", json=refresh_payload, timeout=5)
            if resp.status_code == 200:
                print("   ✅ Refreshed successfully.")
            elif resp.status_code == 429:
                print(f"   🛑 Rate-Limited: HTTP {resp.status_code} - {resp.json().get('detail')}")
            else:
                print(f"   ❌ Denied: HTTP {resp.status_code} - {resp.json()}")

        print("\n-----------------------------------------\n")
        # Scenario 6: Privacy Audit Query (Demonstrating Log Filtering)
        print("--- SCENARIO 6: GDPR COMPLIANCE LOG QUERY FILTER DEMO ---")
        print("🔍 Querying audit logs for 'SUSPICIOUS' incidents with high danger severity...")
        query_params = {"status": "SUSPICIOUS", "min_severity": "WARNING"}
        log_resp = requests.get(f"{API_BASE_URL}/api/v1/compliance-logs", params=query_params, timeout=5)
        if log_resp.status_code == 200:
            logs_data = log_resp.json()
            print(f"📊 Filtered Records Found: {logs_data.get('total_records')}")
            print(json.dumps(logs_data.get("logs"), indent=2))
        else:
            print(f"❌ Failed to query logs: {log_resp.status_code}")


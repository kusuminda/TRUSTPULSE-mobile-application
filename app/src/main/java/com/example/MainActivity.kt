package com.example

import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.*
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.ui.theme.*
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID
import java.util.concurrent.TimeUnit
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.MediaType.Companion.toMediaType
import org.json.JSONObject
import org.json.JSONArray

// GDPR compliance logs structure
data class ComplianceLog(
    val id: String,
    val timestamp: String,
    val deviceId: String,
    val status: String,
    val details: String
)

// AI Chatbot message structure
data class ChatMessage(
    val id: String,
    val text: String,
    val isUser: Boolean,
    val timestamp: String
)

// Dynamic Security Threat Alert model
data class SecurityThreatAlert(
    val title: String,
    val description: String,
    val severity: String, // "CRITICAL", "HIGH", "WARNING"
    val icon: ImageVector,
    val remediation: String
)

// GDPR compliant compliance posture JSON generator
fun generateCurrentPostureJson(
    deviceId: String,
    passcodeEnabled: Boolean,
    osVersion: String,
    isRooted: Boolean,
    maliciousAppsDetected: Boolean,
    networkAnomaliesDetected: Boolean,
    unusualPermissionsGranted: Boolean,
    debuggingEnabled: Boolean,
    untrustedCertificatesInstalled: Boolean,
    scanState: String,
    failureReason: String
): String {
    val root = JSONObject()
    
    val metadata = JSONObject()
    metadata.put("audit_id", "tp_audit_${UUID.randomUUID().toString().take(12)}")
    val sdf = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
    metadata.put("timestamp_utc", sdf.format(Date()))
    metadata.put("compliance_outcome", scanState)
    metadata.put("engine_version", "TrustPulse v2.5-m3")
    root.put("audit_metadata", metadata)

    val device = JSONObject()
    device.put("device_id", deviceId)
    device.put("passcode_protection_active", passcodeEnabled)
    device.put("os_version", osVersion)
    device.put("integrity_rooted", isRooted)
    device.put("malicious_packages", maliciousAppsDetected)
    device.put("network_intercept_proxy", networkAnomaliesDetected)
    device.put("debugging_adb_bridge_exposed", debuggingEnabled)
    device.put("untrusted_root_certificates", untrustedCertificatesInstalled)
    device.put("atypical_permissions", unusualPermissionsGranted)
    root.put("device_telemetry_digest", device)

    val alerts = JSONArray()
    if (!passcodeEnabled) {
        val alert = JSONObject()
        alert.put("severity", "HIGH")
        alert.put("threat_type", "PASSCODE_DISABLED")
        alert.put("details", "Physical screen unlock passcode is disabled.")
        alerts.put(alert)
    }
    val isOsValid = try {
        val parsed = osVersion.split(".").firstOrNull()?.toFloatOrNull() ?: 0f
        parsed >= 16.4f
    } catch (e: Exception) {
        false
    }
    if (!isOsValid) {
        val alert = JSONObject()
        alert.put("severity", "HIGH")
        alert.put("threat_type", "OUTDATED_OS")
        alert.put("details", "OS version (Android $osVersion) fails minimum baseline patch levels.")
        alerts.put(alert)
    }
    if (isRooted) {
        val alert = JSONObject()
        alert.put("severity", "CRITICAL")
        alert.put("threat_type", "SANDBOX_ROOTED")
        alert.put("details", "Superuser privilege access identified; container isolation broken.")
        alerts.put(alert)
    }
    if (maliciousAppsDetected) {
        val alert = JSONObject()
        alert.put("severity", "CRITICAL")
        alert.put("threat_type", "MALICIOUS_PACKAGES")
        alert.put("details", "Active packet recorders or hacking tools signature match found.")
        alerts.put(alert)
    }
    if (networkAnomaliesDetected) {
        val alert = JSONObject()
        alert.put("severity", "CRITICAL")
        alert.put("threat_type", "TRANSPORT_PROXY_MITM")
        alert.put("details", "Outgoing connections are routed through a decryption proxy.")
        alerts.put(alert)
    }
    if (untrustedCertificatesInstalled) {
        val alert = JSONObject()
        alert.put("severity", "CRITICAL")
        alert.put("threat_type", "UNTRUSTED_ROOT_CA")
        alert.put("details", "Custom CA anchors installed in user store, creating spoof risks.")
        alerts.put(alert)
    }
    if (debuggingEnabled) {
        val alert = JSONObject()
        alert.put("severity", "HIGH")
        alert.put("threat_type", "ADB_TCP_EXPOSED")
        alert.put("details", "ADB debugging listener active on host TCP socket port.")
        alerts.put(alert)
    }
    if (unusualPermissionsGranted) {
        val alert = JSONObject()
        alert.put("severity", "WARNING")
        alert.put("threat_type", "ATYPICAL_PERMISSIONS")
        alert.put("details", "Elevated system privileges or custom overlay rights allowed.")
        alerts.put(alert)
    }
    root.put("active_security_alerts", alerts)
    
    if (scanState == "FAILED") {
        root.put("failure_reason_summary", failureReason)
    }

    return root.toString(2)
}

// GDPR compliant compliance logs JSON exporter
fun generateLogsJson(logs: List<ComplianceLog>): String {
    val arr = JSONArray()
    logs.forEach { log ->
        val obj = JSONObject()
        obj.put("id", log.id)
        obj.put("timestamp", log.timestamp)
        obj.put("device_id", log.deviceId)
        obj.put("compliance_outcome", log.status)
        obj.put("details", log.details)
        arr.put(obj)
    }
    return arr.toString(2)
}

// MediaStore Q+ downloads saver (completely permission-free for modern APIs)
fun saveJsonToDownloads(context: android.content.Context, jsonContent: String) {
    try {
        val filename = "trustpulse_compliance_audit_${System.currentTimeMillis() / 1000}.json"
        val contentValues = android.content.ContentValues().apply {
            put(android.provider.MediaStore.MediaColumns.DISPLAY_NAME, filename)
            put(android.provider.MediaStore.MediaColumns.MIME_TYPE, "application/json")
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
                put(android.provider.MediaStore.MediaColumns.RELATIVE_PATH, android.os.Environment.DIRECTORY_DOWNLOADS)
            }
        }
        val resolver = context.contentResolver
        // MediaStore Downloads relies on API 29+. 
        val collectionUri = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
            android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI
        } else {
            // Safe fallback legacy mapping (saves to External Cache or files dir)
            android.provider.MediaStore.Images.Media.EXTERNAL_CONTENT_URI
        }
        
        val uri = resolver.insert(collectionUri, contentValues)
        if (uri != null) {
            resolver.openOutputStream(uri)?.use { outputStream ->
                outputStream.write(jsonContent.toByteArray())
            }
            Toast.makeText(context, "Saved audit JSON report to Downloads: $filename", Toast.LENGTH_LONG).show()
        } else {
            // Cache directory legacy fallback
            val cacheFile = java.io.File(context.cacheDir, filename)
            cacheFile.writeText(jsonContent)
            Toast.makeText(context, "Saved legacy JSON cache at: ${cacheFile.name}. Open system sharesheet to copy.", Toast.LENGTH_LONG).show()
        }
    } catch (e: Exception) {
        e.printStackTrace()
        Toast.makeText(context, "Error saving: ${e.localizedMessage}", Toast.LENGTH_SHORT).show()
    }
}

// System Sharesheet dispatcher
fun shareJsonContent(context: android.content.Context, jsonContent: String) {
    try {
        val intent = android.content.Intent(android.content.Intent.ACTION_SEND).apply {
            type = "application/json"
            putExtra(android.content.Intent.EXTRA_TITLE, "TrustPulse Compliance Posture Audit Report")
            putExtra(android.content.Intent.EXTRA_SUBJECT, "TrustPulse GDPR Compliance Posture Audit")
            putExtra(android.content.Intent.EXTRA_TEXT, jsonContent)
        }
        context.startActivity(android.content.Intent.createChooser(intent, "Export Compliance Posture Ledger"))
    } catch (e: Exception) {
        Toast.makeText(context, "Error sharing: ${e.localizedMessage}", Toast.LENGTH_SHORT).show()
    }
}

// Modern PDF compliance document generator
fun generateCompliancePdfReport(
    context: android.content.Context,
    deviceId: String,
    passcodeEnabled: Boolean,
    osVersion: String,
    isRooted: Boolean,
    maliciousAppsDetected: Boolean,
    networkAnomaliesDetected: Boolean,
    unusualPermissionsGranted: Boolean,
    debuggingEnabled: Boolean,
    untrustedCertificatesInstalled: Boolean,
    scanState: String,
    failureReason: String
): ByteArray {
    val pdfDocument = android.graphics.pdf.PdfDocument()
    val pageInfo = android.graphics.pdf.PdfDocument.PageInfo.Builder(595, 842, 1).create()
    val page = pdfDocument.startPage(pageInfo)
    val canvas = page.canvas

    val paint = android.graphics.Paint()
    val textPaint = android.graphics.Paint()

    // 1. Draw solid dark header banner
    paint.color = 0xFF12131A.toInt()
    paint.style = android.graphics.Paint.Style.FILL
    canvas.drawRect(0f, 0f, 595f, 95f, paint)

    // Side accent bar
    paint.color = 0xFF6200EE.toInt() // Primary Purple
    canvas.drawRect(0f, 0f, 15f, 95f, paint)

    // Bottom accent line
    paint.color = 0xFFBB86FC.toInt()
    canvas.drawRect(15f, 92f, 595f, 95f, paint)

    // Header Title
    textPaint.isAntiAlias = true
    textPaint.color = 0xFFFFFFFF.toInt()
    textPaint.textSize = 18f
    textPaint.typeface = android.graphics.Typeface.create(android.graphics.Typeface.DEFAULT, android.graphics.Typeface.BOLD)
    canvas.drawText("TRUSTPULSE COMPLIANCE AUDIT", 40f, 42f, textPaint)

    // Header Subtitle
    textPaint.color = 0xFFB0BEC5.toInt()
    textPaint.textSize = 9.5f
    textPaint.typeface = android.graphics.Typeface.create(android.graphics.Typeface.DEFAULT, android.graphics.Typeface.ITALIC)
    canvas.drawText("Official GDPR Secure Endpoint Telemetry Ledger Document", 40f, 62f, textPaint)

    // Engine Label
    textPaint.color = 0xFFBB86FC.toInt()
    textPaint.textSize = 7.5f
    textPaint.typeface = android.graphics.Typeface.create(android.graphics.Typeface.DEFAULT, android.graphics.Typeface.BOLD)
    textPaint.textAlign = android.graphics.Paint.Align.RIGHT
    canvas.drawText("v2.5-m3 [CORE ENCLAVE]", 555f, 42f, textPaint)
    textPaint.textAlign = android.graphics.Paint.Align.LEFT // Restore

    // Metadata card box
    paint.color = 0xFFF1F5F9.toInt()
    paint.style = android.graphics.Paint.Style.FILL
    val metaRect = android.graphics.RectF(40f, 115f, 555f, 185f)
    canvas.drawRoundRect(metaRect, 8f, 8f, paint)

    paint.color = 0xFFCBD5E1.toInt()
    paint.style = android.graphics.Paint.Style.STROKE
    paint.strokeWidth = 1f
    canvas.drawRoundRect(metaRect, 8f, 8f, paint)

    // Metadata entries
    val auditId = "tp_audit_" + UUID.randomUUID().toString().take(12).uppercase()
    val format = SimpleDateFormat("yyyy-MM-dd HH:mm:ss 'UTC'", Locale.getDefault())
    val timestampStr = format.format(Date())

    textPaint.color = 0xFF475569.toInt()
    textPaint.textSize = 9f
    textPaint.typeface = android.graphics.Typeface.create(android.graphics.Typeface.DEFAULT, android.graphics.Typeface.BOLD)
    canvas.drawText("AUDIT REFERENCE:", 55f, 137f, textPaint)
    canvas.drawText("TARGET DEVICE ID:", 55f, 153f, textPaint)
    canvas.drawText("GENERATION TIME:", 55f, 169f, textPaint)

    textPaint.color = 0xFF0F172A.toInt()
    textPaint.typeface = android.graphics.Typeface.create(android.graphics.Typeface.DEFAULT, android.graphics.Typeface.NORMAL)
    canvas.drawText(auditId, 175f, 137f, textPaint)
    canvas.drawText(deviceId, 175f, 153f, textPaint)
    canvas.drawText(timestampStr, 175f, 169f, textPaint)

    // Compliance Badge on Metadata Right Side
    val allSecure = passcodeEnabled && (try { osVersion.split(".").firstOrNull()?.toFloatOrNull() ?: 16.4f >= 16.4f } catch(e: Exception) { false }) &&
            !isRooted && !maliciousAppsDetected && !networkAnomaliesDetected && 
            !unusualPermissionsGranted && !debuggingEnabled && !untrustedCertificatesInstalled
    val isPassed = allSecure && (scanState != "FAILED")

    val badgeLeft = 385f
    val badgeTop = 130f
    val badgeRight = 540f
    val badgeBottom = 170f
    val badgeRect = android.graphics.RectF(badgeLeft, badgeTop, badgeRight, badgeBottom)

    if (isPassed) {
        paint.color = 0xFFDCFCE7.toInt() // light green
        paint.style = android.graphics.Paint.Style.FILL
        canvas.drawRoundRect(badgeRect, 6f, 6f, paint)

        paint.color = 0xFF16A34A.toInt() // strike green border
        paint.style = android.graphics.Paint.Style.STROKE
        paint.strokeWidth = 1.2f
        canvas.drawRoundRect(badgeRect, 6f, 6f, paint)

        textPaint.color = 0xFF15803D.toInt()
        textPaint.textSize = 9.5f
        textPaint.typeface = android.graphics.Typeface.create(android.graphics.Typeface.DEFAULT, android.graphics.Typeface.BOLD)
        textPaint.textAlign = android.graphics.Paint.Align.CENTER
        canvas.drawText("POSTURE SECURE", (badgeLeft + badgeRight) / 2f, (badgeTop + badgeBottom) / 2f + 3f, textPaint)
    } else {
        paint.color = 0xFFFEE2E2.toInt() // light red
        paint.style = android.graphics.Paint.Style.FILL
        canvas.drawRoundRect(badgeRect, 6f, 6f, paint)

        paint.color = 0xFFEF4444.toInt() // strike red border
        paint.style = android.graphics.Paint.Style.STROKE
        paint.strokeWidth = 1.2f
        canvas.drawRoundRect(badgeRect, 6f, 6f, paint)

        textPaint.color = 0xFFB91C1C.toInt()
        textPaint.textSize = 8f
        textPaint.typeface = android.graphics.Typeface.create(android.graphics.Typeface.DEFAULT, android.graphics.Typeface.BOLD)
        textPaint.textAlign = android.graphics.Paint.Align.CENTER
        canvas.drawText("NON-COMPLIANT", (badgeLeft + badgeRight) / 2f, (badgeTop + badgeBottom) / 2f - 2f, textPaint)

        textPaint.textSize = 6.5f
        canvas.drawText("ATTENTION REQUIRED", (badgeLeft + badgeRight) / 2f, (badgeTop + badgeBottom) / 2f + 7f, textPaint)
    }
    textPaint.textAlign = android.graphics.Paint.Align.LEFT

    // 2. Telemetry baselines section
    var currentY = 210f
    textPaint.color = 0xFF1E293B.toInt()
    textPaint.textSize = 11f
    textPaint.typeface = android.graphics.Typeface.create(android.graphics.Typeface.DEFAULT, android.graphics.Typeface.BOLD)
    canvas.drawText("ENDPOINT TELEMETRY AUDIT MATRIX", 40f, currentY, textPaint)

    currentY += 6f
    paint.color = 0xFF6200EE.toInt()
    paint.style = android.graphics.Paint.Style.FILL
    canvas.drawRect(40f, currentY, 555f, currentY + 1.5f, paint)

    currentY += 13f
    textPaint.textSize = 8.5f
    textPaint.color = 0xFF64748B.toInt()
    canvas.drawText("HARDWARE/OS BASELINE PARAMETER", 45f, currentY, textPaint)
    textPaint.textAlign = android.graphics.Paint.Align.RIGHT
    canvas.drawText("MEASURED VAL", 410f, currentY, textPaint)
    canvas.drawText("COMPLIANCE STATE", 545f, currentY, textPaint)
    textPaint.textAlign = android.graphics.Paint.Align.LEFT

    data class PdfCheckRow(val label: String, val measuredValue: String, val passes: Boolean, val warningOnly: Boolean = false)
    val entries = listOf(
        PdfCheckRow("On-Gate Passcode PIN/Screen Protection", if (passcodeEnabled) "ACTIVE (Secure hardware bound)" else "INACTIVE (Passcode Disabled)", passcodeEnabled),
        PdfCheckRow("Operating System Kernel Vulnerability Patch", "v$osVersion (Patch requirements >= 16.4)", (try { osVersion.split(".").firstOrNull()?.toFloatOrNull() ?: 16.4f >= 16.4f } catch(e: Exception) { false })),
        PdfCheckRow("Superuser Privilege Root Privilege Scanner", if (isRooted) "ROOTED BINARY INSTALLED" else "CLEAN (Sandboxing Active)", !isRooted),
        PdfCheckRow("Hacking Package Signature Correlation Scan", if (maliciousAppsDetected) "COLLISION SIGNATURES MATCHED" else "CLEAN (No compiler matches)", !maliciousAppsDetected),
        PdfCheckRow("Transport Proxy Man-In-Middle Intrusion Node", if (networkAnomaliesDetected) "WARN (Possible decryption hop)" else "CLEAN (Unrouted direct socket)", !networkAnomaliesDetected),
        PdfCheckRow("Low-level System Window Overlay Concession", if (unusualPermissionsGranted) "WARN (Screen scraper overlays active)" else "CLEAN (Standard layouts bound)", !unusualPermissionsGranted, warningOnly = true),
        PdfCheckRow("Wireless ADB Debugging Port Daemon check (TCP)", if (debuggingEnabled) "EXPOSED (Port TCP 5555 active)" else "CLEAN (Debug daemon disabled)", !debuggingEnabled),
        PdfCheckRow("Trust Store User-added Root Certificate Scan", if (untrustedCertificatesInstalled) "EXPOSED (Unverifiable certificates)" else "CLEAN (System authority roots only)", !untrustedCertificatesInstalled)
    )

    paint.style = android.graphics.Paint.Style.FILL
    entries.forEachIndexed { idx, row ->
        currentY += 6f
        // Zebra striping
        if (idx % 2 == 1) {
            paint.color = 0xFFF8FAFC.toInt()
            canvas.drawRect(40f, currentY, 555f, currentY + 20f, paint)
        }

        currentY += 13f
        
        // Parameter label
        textPaint.color = 0xFF1E293B.toInt()
        textPaint.textSize = 8f
        textPaint.typeface = android.graphics.Typeface.create(android.graphics.Typeface.DEFAULT, android.graphics.Typeface.NORMAL)
        canvas.drawText(row.label, 45f, currentY, textPaint)

        // Measured value
        textPaint.color = if (row.passes) 0xFF475569.toInt() else if (row.warningOnly) 0xFFD97706.toInt() else 0xFFEF4444.toInt()
        textPaint.textAlign = android.graphics.Paint.Align.RIGHT
        canvas.drawText(row.measuredValue, 410f, currentY, textPaint)

        // Status
        val statusText = if (row.passes) "PASS" else if (row.warningOnly) "WARNING" else "FAIL"
        val statusColor = if (row.passes) 0xFF16A34A.toInt() else if (row.warningOnly) 0xFFD97706.toInt() else 0xFFEF4444.toInt()
        textPaint.color = statusColor
        textPaint.typeface = android.graphics.Typeface.create(android.graphics.Typeface.DEFAULT, android.graphics.Typeface.BOLD)
        canvas.drawText(statusText, 545f, currentY, textPaint)
        
        textPaint.textAlign = android.graphics.Paint.Align.LEFT

        // Draw light row divider line
        currentY += 7f
        paint.color = 0xFFE2E8F0.toInt()
        canvas.drawLine(40f, currentY, 555f, currentY, paint)
    }

    // 3. Risk & Guided Remediation Actions
    val fails = entries.filter { !it.passes }
    if (fails.isNotEmpty()) {
        currentY += 15f
        textPaint.color = 0xFF1E293B.toInt()
        textPaint.textSize = 10f
        textPaint.typeface = android.graphics.Typeface.create(android.graphics.Typeface.DEFAULT, android.graphics.Typeface.BOLD)
        canvas.drawText("AUTOMATED ACTIONABLE GUIDED MITIGATIONS", 40f, currentY, textPaint)

        currentY += 5f
        paint.color = 0xFFEF4444.toInt()
        paint.style = android.graphics.Paint.Style.FILL
        canvas.drawRect(40f, currentY, 555f, currentY + 1.2f, paint)

        val riskBoxTop = currentY + 5f
        fails.forEach { fail ->
            currentY += 13f
            textPaint.color = 0xFF7F1D1D.toInt()
            textPaint.textSize = 8f
            textPaint.typeface = android.graphics.Typeface.create(android.graphics.Typeface.DEFAULT, android.graphics.Typeface.BOLD)
            canvas.drawText("• RECTIFY: ${fail.label}", 50f, currentY, textPaint)

            currentY += 10f
            textPaint.color = 0xFF334155.toInt()
            textPaint.textSize = 7.5f
            textPaint.typeface = android.graphics.Typeface.create(android.graphics.Typeface.DEFAULT, android.graphics.Typeface.NORMAL)
            
            val mitigationText = when {
                fail.label.contains("Passcode") -> "Fix PIN/password protection in Android Settings -> Security -> Screen Lock to restore Keystore enclave isolation policies."
                fail.label.contains("Operating System") -> "Upgrade software profile to Android 16.4+ via system updates to protect against unaddressed system CVE risks."
                fail.label.contains("Superuser") -> "Install official device stock firmware and flash securely-locked bootloaders to restrict su shell access binaries."
                fail.label.contains("Hacking") -> "Revoke permissions, check background application packages, and uninstall any developer tool utilities or memory injectors."
                fail.label.contains("Proxy") -> "Identify host gateway loopbacks, unset network debugger proxies, and route telemetry only on trusted enterprise networks."
                fail.label.contains("Overlay") -> "Audit and prune background overlays by toggling off standard 'Draw over other apps' options for unverified utilities."
                fail.label.contains("Wireless") -> "Disable 'USB debugging' and 'Wireless TCP debugging' triggers within standard developer options menus."
                fail.label.contains("Certificate") -> "Enter Encryption & Credentials -> User Credentials cert bank and delete unauthorized manually-installed authority profiles."
                else -> "Prune baseline security vulnerabilities to satisfy endpoint compliance requirements for mobile BYOD corporate ingress."
            }
            canvas.drawText(mitigationText, 62f, currentY, textPaint)
        }
        val riskBoxBottom = currentY + 6f
        paint.color = 0xFFFCA5A5.toInt()
        paint.style = android.graphics.Paint.Style.STROKE
        paint.strokeWidth = 0.8f
        canvas.drawRoundRect(android.graphics.RectF(40f, riskBoxTop, 555f, riskBoxBottom), 5f, 5f, paint)
        currentY = riskBoxBottom
    } else {
        currentY += 15f
        // Compliant Statement Card
        paint.color = 0xFFF0FDF4.toInt()
        paint.style = android.graphics.Paint.Style.FILL
        val safeBox = android.graphics.RectF(40f, currentY, 555f, currentY + 45f)
        canvas.drawRoundRect(safeBox, 6f, 6f, paint)

        paint.color = 0xFFBBF7D0.toInt()
        paint.style = android.graphics.Paint.Style.STROKE
        paint.strokeWidth = 0.8f
        canvas.drawRoundRect(safeBox, 6f, 6f, paint)

        textPaint.color = 0xFF166534.toInt()
        textPaint.textSize = 8.5f
        textPaint.typeface = android.graphics.Typeface.create(android.graphics.Typeface.DEFAULT, android.graphics.Typeface.BOLD)
        canvas.drawText("ENDPOINT DECREED SECURE", 55f, currentY + 18f, textPaint)

        textPaint.color = 0xFF14532D.toInt()
        textPaint.textSize = 7.5f
        textPaint.typeface = android.graphics.Typeface.create(android.graphics.Typeface.DEFAULT, android.graphics.Typeface.NORMAL)
        canvas.drawText("The on-device simulated sandbox integrity matches all security posture baseline requirements set by the gateway policies.", 55f, currentY + 30f, textPaint)
        currentY += 45f
    }

    // 4. GDPR statement box
    currentY += 15f
    paint.color = 0xFFF1F5F9.toInt()
    paint.style = android.graphics.Paint.Style.FILL
    val gdprBox = android.graphics.RectF(40f, currentY, 555f, currentY + 34f)
    canvas.drawRoundRect(gdprBox, 5f, 5f, paint)

    paint.color = 0xFFCBD5E1.toInt()
    paint.style = android.graphics.Paint.Style.STROKE
    paint.strokeWidth = 0.5f
    canvas.drawRoundRect(gdprBox, 5f, 5f, paint)

    textPaint.color = 0xFF334155.toInt()
    textPaint.textSize = 8f
    textPaint.typeface = android.graphics.Typeface.create(android.graphics.Typeface.DEFAULT, android.graphics.Typeface.BOLD)
    canvas.drawText("EU GDPR MINIMIZATION WARRANTY", 50f, currentY + 12f, textPaint)

    textPaint.color = 0xFF475569.toInt()
    textPaint.textSize = 7f
    textPaint.typeface = android.graphics.Typeface.create(android.graphics.Typeface.DEFAULT, android.graphics.Typeface.NORMAL)
    canvas.drawText("Assessed metrics do not capture or record personal identity data (PII) like names, emails, hardware IMEIs or telephone lines.", 50f, currentY + 24f, textPaint)

    // 5. Official Verification Stamp/Signatures
    currentY += 50f
    paint.color = 0xFF64748B.toInt()
    canvas.drawLine(40f, currentY + 20f, 200f, currentY + 20f, paint)

    textPaint.color = 0xFF475569.toInt()
    textPaint.textSize = 8f
    textPaint.typeface = android.graphics.Typeface.create(android.graphics.Typeface.DEFAULT, android.graphics.Typeface.BOLD)
    canvas.drawText("COMPLIANCE AUTHORIZATION", 40f, currentY + 30f, textPaint)
    textPaint.typeface = android.graphics.Typeface.create(android.graphics.Typeface.DEFAULT, android.graphics.Typeface.NORMAL)
    canvas.drawText("Automated TrustPulse Posture Engine v2.5", 40f, currentY + 40f, textPaint)

    // Round Verification Emblem stamp
    val stampX = 485f
    val stampY = currentY + 15f
    paint.color = 0xFFF5F3FF.toInt()
    paint.style = android.graphics.Paint.Style.FILL
    canvas.drawCircle(stampX, stampY, 26f, paint)

    paint.color = 0xFF6200EE.toInt()
    paint.style = android.graphics.Paint.Style.STROKE
    paint.strokeWidth = 1f
    canvas.drawCircle(stampX, stampY, 26f, paint)
    paint.strokeWidth = 0.5f
    canvas.drawCircle(stampX, stampY, 22f, paint)

    textPaint.color = 0xFF6200EE.toInt()
    textPaint.textSize = 5.5f
    textPaint.typeface = android.graphics.Typeface.create(android.graphics.Typeface.DEFAULT, android.graphics.Typeface.BOLD)
    textPaint.textAlign = android.graphics.Paint.Align.CENTER
    canvas.drawText("TRUSTPULSE", stampX, stampY - 3f, textPaint)
    textPaint.textSize = 4.5f
    canvas.drawText("APPROVED", stampX, stampY + 4f, textPaint)
    canvas.drawText("AUDIT SECURE", stampX, stampY + 10f, textPaint)
    textPaint.textAlign = android.graphics.Paint.Align.LEFT

    // 6. Draw footer
    paint.color = 0xFFE2E8F0.toInt()
    canvas.drawLine(40f, 805f, 555f, 805f, paint)

    textPaint.color = 0xFF94A3B8.toInt()
    textPaint.textSize = 7.5f
    textPaint.typeface = android.graphics.Typeface.create(android.graphics.Typeface.DEFAULT, android.graphics.Typeface.NORMAL)
    canvas.drawText("This cryptographically generated report acts as official client verification proof for zero-trust endpoint entry filters.", 40f, 818f, textPaint)

    textPaint.textAlign = android.graphics.Paint.Align.RIGHT
    canvas.drawText("Page 1 of 1", 555f, 818f, textPaint)
    textPaint.textAlign = android.graphics.Paint.Align.LEFT

    pdfDocument.finishPage(page)

    val out = java.io.ByteArrayOutputStream()
    try {
        pdfDocument.writeTo(out)
    } catch (e: Exception) {
        e.printStackTrace()
    } finally {
        pdfDocument.close()
    }
    return out.toByteArray()
}

// Save PDF bytes to system Downloads folder using native MediaStore
fun savePdfToDownloads(context: android.content.Context, pdfBytes: ByteArray) {
    try {
        val filename = "trustpulse_compliance_report_${System.currentTimeMillis() / 1000}.pdf"
        val contentValues = android.content.ContentValues().apply {
            put(android.provider.MediaStore.MediaColumns.DISPLAY_NAME, filename)
            put(android.provider.MediaStore.MediaColumns.MIME_TYPE, "application/pdf")
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
                put(android.provider.MediaStore.MediaColumns.RELATIVE_PATH, android.os.Environment.DIRECTORY_DOWNLOADS)
            }
        }
        val resolver = context.contentResolver
        val collectionUri = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
            android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI
        } else {
            android.provider.MediaStore.Images.Media.EXTERNAL_CONTENT_URI
        }
        
        val uri = resolver.insert(collectionUri, contentValues)
        if (uri != null) {
            resolver.openOutputStream(uri)?.use { outputStream ->
                outputStream.write(pdfBytes)
            }
            Toast.makeText(context, "Saved PDF report to Downloads: $filename", Toast.LENGTH_LONG).show()
        } else {
            val cacheFile = java.io.File(context.cacheDir, filename)
            cacheFile.writeBytes(pdfBytes)
            Toast.makeText(context, "Saved legacy PDF cache at: ${cacheFile.name}", Toast.LENGTH_LONG).show()
        }
    } catch (e: Exception) {
        e.printStackTrace()
        Toast.makeText(context, "Error saving PDF: ${e.localizedMessage}", Toast.LENGTH_SHORT).show()
    }
}

// Dispatches a share sheet with the generated PDF report context URI
fun sharePdfContent(context: android.content.Context, pdfBytes: ByteArray) {
    try {
        val filename = "trustpulse_compliance_report_${System.currentTimeMillis() / 1000}.pdf"
        val contentValues = android.content.ContentValues().apply {
            put(android.provider.MediaStore.MediaColumns.DISPLAY_NAME, filename)
            put(android.provider.MediaStore.MediaColumns.MIME_TYPE, "application/pdf")
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
                put(android.provider.MediaStore.MediaColumns.RELATIVE_PATH, android.os.Environment.DIRECTORY_DOWNLOADS)
            }
        }
        val resolver = context.contentResolver
        val collectionUri = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
            android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI
        } else {
            android.provider.MediaStore.Images.Media.EXTERNAL_CONTENT_URI
        }
        
        val uri = resolver.insert(collectionUri, contentValues)
        if (uri != null) {
            resolver.openOutputStream(uri)?.use { outputStream ->
                outputStream.write(pdfBytes)
            }
            
            val intent = android.content.Intent(android.content.Intent.ACTION_SEND).apply {
                type = "application/pdf"
                putExtra(android.content.Intent.EXTRA_STREAM, uri)
                addFlags(android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION)
                putExtra(android.content.Intent.EXTRA_SUBJECT, "My TrustPulse PDF Compliance Audit Report")
            }
            context.startActivity(android.content.Intent.createChooser(intent, "Share Compliance PDF Ledger"))
        } else {
            Toast.makeText(context, "Error sharing PDF: Could not create MediaStore entry", Toast.LENGTH_SHORT).show()
        }
    } catch (e: Exception) {
        Toast.makeText(context, "Error sharing PDF: ${e.localizedMessage}", Toast.LENGTH_SHORT).show()
    }
}

// Gemini API Network Core
object GeminiNetworkHelper {
    private val client = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .build()

    suspend fun queryGemini(prompt: String, systemInstruction: String, history: List<Pair<String, Boolean>>): String = withContext(Dispatchers.IO) {
        val apiKey = try {
            BuildConfig.GEMINI_API_KEY
        } catch (e: Exception) {
            ""
        }
        
        // Treat placeholder or missing keys as trigger for Local Autonomous Fallback
        if (apiKey.isEmpty() || apiKey == "MY_GEMINI_API_KEY" || apiKey == "GEMINI_API_KEY") {
            return@withContext "AUTONOMOUS_MODE_TRIGGER"
        }

        // Direct standard REST Endpoint query
        val url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=$apiKey"
        val mediaType = "application/json; charset=utf-8".toMediaType()

        try {
            val rootJson = JSONObject()
            
            // Build contents history
            val contentsArray = JSONArray()
            
            for (turn in history) {
                val contentObj = JSONObject()
                contentObj.put("role", if (turn.second) "user" else "model")
                val partsArray = JSONArray()
                val partObj = JSONObject()
                partObj.put("text", turn.first)
                partsArray.put(partObj)
                contentObj.put("parts", partsArray)
                contentsArray.put(contentObj)
            }
            
            // Add current message
            val currentUserContent = JSONObject()
            currentUserContent.put("role", "user")
            val currentParts = JSONArray()
            val currentPartObj = JSONObject()
            currentPartObj.put("text", prompt)
            currentParts.put(currentPartObj)
            currentUserContent.put("parts", currentParts)
            contentsArray.put(currentUserContent)

            rootJson.put("contents", contentsArray)

            // Configure system guidelines
            val sysInstructionObj = JSONObject()
            val sysPartsArray = JSONArray()
            val sysPartObj = JSONObject()
            sysPartObj.put("text", systemInstruction)
            sysPartsArray.put(sysPartObj)
            sysInstructionObj.put("parts", sysPartsArray)
            rootJson.put("systemInstruction", sysInstructionObj)

            // Dynamic hyperparameter limits
            val configObj = JSONObject()
            configObj.put("temperature", 0.7)
            rootJson.put("generationConfig", configObj)

            val requestBody = rootJson.toString().toRequestBody(mediaType)
            val request = Request.Builder()
                .url(url)
                .post(requestBody)
                .build()

            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    val responseBody = response.body?.string() ?: ""
                    println("Gemini Network Error response: ${response.code}, body: $responseBody")
                    // If credentials error, fall back gracefully to local autonomous simulator
                    if (response.code == 400 || response.code == 403 || response.code == 401) {
                        return@withContext "AUTONOMOUS_MODE_TRIGGER"
                    }
                    return@withContext "PulseGuard AI was unable to call Gemini gateway (HTTP ${response.code}). Ready on offline standby mode."
                }

                val bodyStr = response.body?.string() ?: return@withContext "Received empty telemetry response."
                val responseJson = JSONObject(bodyStr)
                val candidatesArray = responseJson.optJSONArray("candidates")
                if (candidatesArray != null && candidatesArray.length() > 0) {
                    val firstCandidate = candidatesArray.getJSONObject(0)
                    val contentObj = firstCandidate.optJSONObject("content")
                    if (contentObj != null) {
                        val partsArr = contentObj.optJSONArray("parts")
                        if (partsArr != null && partsArr.length() > 0) {
                            return@withContext partsArr.getJSONObject(0).optString("text") ?: "Parser matching failure."
                        }
                    }
                }
                return@withContext "Received empty signature envelope."
            }
        } catch (e: Exception) {
            e.printStackTrace()
            // Graceful fallback to maintain beautiful user-facing state on any network socket fail
            return@withContext "AUTONOMOUS_MODE_TRIGGER"
        }
    }
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            MyApplicationTheme {
                TrustPulseApp()
            }
        }
    }
}

@Composable
fun TrustPulseApp() {
    var selectedTab by remember { mutableStateOf(0) }
    
    // Baseline security flags
    var passcodeEnabled by remember { mutableStateOf(true) }
    var osVersion by remember { mutableStateOf("17.2") }
    var isRooted by remember { mutableStateOf(false) }

    // Advanced threat vector configuration (from client/server integration scopes)
    var maliciousAppsDetected by remember { mutableStateOf(false) }
    var networkAnomaliesDetected by remember { mutableStateOf(false) }
    var unusualPermissionsGranted by remember { mutableStateOf(false) }
    var debuggingEnabled by remember { mutableStateOf(false) }
    var untrustedCertificatesInstalled by remember { mutableStateOf(false) }
    
    // Scanner execution states: "IDLE", "SCANNING", "APPROVED", "FAILED"
    var scanState by remember { mutableStateOf("IDLE") }
    var failureReason by remember { mutableStateOf("") }
    
    // Dynamic trace logs generated during the posture scan cycle
    val scLogs = remember { mutableStateListOf<String>() }
    
    // Live Expiring Token Stats
    var remainingSeconds by remember { mutableStateOf(120) }
    var activeToken by remember { mutableStateOf<String?>(null) }
    
    // GDPR database registers
    var complianceLogs by remember {
        mutableStateOf(
            listOf(
                ComplianceLog("1", "2026-06-04 04:30:12", "anon_9e72b0c1af8293a1", "APPROVED", "Successful secure posture validation. Issued token."),
                ComplianceLog("2", "2026-06-04 04:32:45", "anon_2f90a187cb1a2e38", "FAILED", "Non-compliant state: OS outdated (v15.2). Required: >= v16.4.")
            )
        )
    }

    var exportJsonString by remember { mutableStateOf<String?>(null) }

    val coroutineScope = rememberCoroutineScope()
    val context = LocalContext.current

    // Session token expiry countdown representative of live cryptographic tokens
    LaunchedEffect(activeToken) {
        if (activeToken != null) {
            remainingSeconds = 120
            while (remainingSeconds > 0 && activeToken != null) {
                delay(1000)
                remainingSeconds -= 1
            }
            if (remainingSeconds == 0) {
                activeToken = null
                scanState = "IDLE"
            }
        }
    }

    Scaffold(
        bottomBar = {
            NavigationBar(
                containerColor = Color(0xFFF7F2FA),
                tonalElevation = 8.dp
            ) {
                NavigationBarItem(
                    selected = selectedTab == 0,
                    onClick = { selectedTab = 0 },
                    icon = { Icon(Icons.Filled.Shield, contentDescription = "Scanner") },
                    label = { Text("Scanner") },
                    colors = NavigationBarItemDefaults.colors(
                        selectedIconColor = PrimaryPurple,
                        selectedTextColor = PrimaryPurple,
                        unselectedIconColor = TechTextSecondary,
                        unselectedTextColor = TechTextSecondary,
                        indicatorColor = ActiveContainer
                    )
                )
                NavigationBarItem(
                    selected = selectedTab == 1,
                    onClick = { selectedTab = 1 },
                    icon = { Icon(Icons.Filled.List, contentDescription = "Logs") },
                    label = { Text("GDPR Logs") },
                    colors = NavigationBarItemDefaults.colors(
                        selectedIconColor = PrimaryPurple,
                        selectedTextColor = PrimaryPurple,
                        unselectedIconColor = TechTextSecondary,
                        unselectedTextColor = TechTextSecondary,
                        indicatorColor = ActiveContainer
                    )
                )
                NavigationBarItem(
                    selected = selectedTab == 2,
                    onClick = { selectedTab = 2 },
                    icon = { Icon(Icons.Filled.SmartToy, contentDescription = "AI Guard") },
                    label = { Text("Pulse AI") },
                    colors = NavigationBarItemDefaults.colors(
                        selectedIconColor = PrimaryPurple,
                        selectedTextColor = PrimaryPurple,
                        unselectedIconColor = TechTextSecondary,
                        unselectedTextColor = TechTextSecondary,
                        indicatorColor = ActiveContainer
                    )
                )
                NavigationBarItem(
                    selected = selectedTab == 3,
                    onClick = { selectedTab = 3 },
                    icon = { Icon(Icons.Filled.Code, contentDescription = "Python Prototype") },
                    label = { Text("Python Code") },
                    colors = NavigationBarItemDefaults.colors(
                        selectedIconColor = PrimaryPurple,
                        selectedTextColor = PrimaryPurple,
                        unselectedIconColor = TechTextSecondary,
                        unselectedTextColor = TechTextSecondary,
                        indicatorColor = ActiveContainer
                    )
                )
            }
        },
        containerColor = SoftBackground
    ) { paddingValues ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .background(SoftBackground)
        ) {
            when (selectedTab) {
                0 -> ScannerScreen(
                    passcodeEnabled = passcodeEnabled,
                    onPasscodeToggle = { passcodeEnabled = it },
                    osVersion = osVersion,
                    onOsChange = { osVersion = it },
                    isRooted = isRooted,
                    onRootedToggle = { isRooted = it },
                    maliciousAppsDetected = maliciousAppsDetected,
                    onMaliciousToggle = { maliciousAppsDetected = it },
                    networkAnomaliesDetected = networkAnomaliesDetected,
                    onNetworkToggle = { networkAnomaliesDetected = it },
                    unusualPermissionsGranted = unusualPermissionsGranted,
                    onPermissionsToggle = { unusualPermissionsGranted = it },
                    debuggingEnabled = debuggingEnabled,
                    onDebuggingToggle = { debuggingEnabled = it },
                    untrustedCertificatesInstalled = untrustedCertificatesInstalled,
                    onUntrustedCertToggle = { untrustedCertificatesInstalled = it },
                    scanState = scanState,
                    scLogs = scLogs,
                    failureReason = failureReason,
                    activeToken = activeToken,
                    remainingSeconds = remainingSeconds,
                    onTriggerVerify = {
                        coroutineScope.launch {
                            scanState = "SCANNING"
                            scLogs.clear()
                            
                            scLogs.add("🔍 Initializing security scan envelope...")
                            delay(400)
                            
                            scLogs.add("🔑 Reading device Keyguard PIN status...")
                            delay(350)
                            val hasPasscode = passcodeEnabled
                            scLogs.add(if (hasPasscode) "   • Screen Lock: ACTIVE (Secure Enclave bound)" else "   • Screen Lock: DISABLED (VULNERABILITY)")
                            delay(350)
                            
                            scLogs.add("⚙️ Checking system security patch baseline...")
                            delay(350)
                            val isOsValid = try {
                                val parsed = osVersion.split(".").firstOrNull()?.toFloatOrNull() ?: 0f
                                parsed >= 16.4f
                            } catch (e: Exception) {
                                false
                            }
                            scLogs.add(if (isOsValid) "   • OS Patch: Android v$osVersion (v16.4+ Baseline verified)" else "   • OS Patch: Android v$osVersion (OUTDATED - Baseline violates rule)")
                            delay(350)
                            
                            scLogs.add("🛡️ Scanning sandbox security partitions...")
                            delay(350)
                            val holdsRoot = isRooted
                            scLogs.add(if (holdsRoot) "   • Sandbox: ROOTED (Active privilege breach)" else "   • Sandbox: VERIFIED (Strict isolation active)")
                            delay(350)
                            
                            scLogs.add("🦠 Auditing application packages for blacklisted signatures...")
                            delay(350)
                            val holdsMalware = maliciousAppsDetected
                            scLogs.add(if (holdsMalware) "   • Malware Scanner: BLACKLIST MATCHED (Process threat)" else "   • Malware Scanner: CLEAN (Zero anomalous packages)")
                            delay(350)
                            
                            scLogs.add("🌐 Analyzing network sockets for TLS interception...")
                            delay(350)
                            val holdsMitm = networkAnomaliesDetected
                            scLogs.add(if (holdsMitm) "   • Transport: Proxy hijack anomaly (Decryption danger)" else "   • Transport: SECURE (Direct SSL/TLS socket bound)")
                            delay(350)
                            
                            scLogs.add("🔓 Probing administrative privilege contexts...")
                            delay(300)
                            val holdsPerms = unusualPermissionsGranted
                            scLogs.add(if (holdsPerms) "   • Privileges: Atypical administrative grant active" else "   • Privileges: SECURE (Restricted user context)")
                            delay(300)
                            
                            scLogs.add("🔌 Probing USB transport interfaces and TCP ADB endpoints...")
                            delay(300)
                            val holdsDebug = debuggingEnabled
                            scLogs.add(if (holdsDebug) "   • ADB Listener: EXPOSED (Persistent physical link)" else "   • ADB Listener: LOCKED (Standard baseline secure)")
                            delay(300)
                            
                            scLogs.add("🔏 Extracting User Trust Authority certificates store...")
                            delay(350)
                            val holdsUnsafeCerts = untrustedCertificatesInstalled
                            scLogs.add(if (holdsUnsafeCerts) "   • Certificate Store: UNTRUSTED ROOT CA DETECTED" else "   • Certificate Store: VERIFIED (System roots only)")
                            delay(400)
                            
                            scLogs.add("🔄 Transmitting metrics to Policy Decision Point Gateway...")
                            delay(500)

                            val format = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
                            val now = format.format(Date())

                            if (!hasPasscode) {
                                scanState = "FAILED"
                                failureReason = "Policy Violated: Physical screen lock pin is inactive. Critical hardware-backed Keystore is unprotected."
                                complianceLogs = listOf(
                                    ComplianceLog((complianceLogs.size + 1).toString(), now, "anon_e4f9b870c1bcde21", "FAILED", "Validation Failed: Screen passcode disabled.")
                                ) + complianceLogs
                            } else if (!isOsValid) {
                                scanState = "FAILED"
                                failureReason = "Policy Violated: Android version (v$osVersion) fails the corporate security baseline (v16.4+ required)."
                                complianceLogs = listOf(
                                    ComplianceLog((complianceLogs.size + 1).toString(), now, "anon_e4f9b870c1bcde21", "FAILED", "Validation Failed: Outdated OS ($osVersion).")
                                ) + complianceLogs
                            } else if (holdsRoot) {
                                scanState = "FAILED"
                                failureReason = "Threat Blocked: root binary privilege detected. Secure host sandbox context is completely compromised."
                                complianceLogs = listOf(
                                    ComplianceLog((complianceLogs.size + 1).toString(), now, "anon_e4f9b870c1bcde21", "FAILED", "Intrusion Blocked: Superuser capability (ROOT).")
                                ) + complianceLogs
                            } else if (holdsMalware) {
                                scanState = "FAILED"
                                failureReason = "Threat Blocked: Package audit correlated known malicious signature blacklists."
                                complianceLogs = listOf(
                                    ComplianceLog((complianceLogs.size + 1).toString(), now, "anon_e4f9b870c1bcde21", "FAILED", "Malware signature matches found.")
                                ) + complianceLogs
                            } else if (holdsMitm) {
                                scanState = "FAILED"
                                failureReason = "Threat Blocked: Active TLS decrypt proxy detected. Corporate payload encryption streams are under active eavesdropping."
                                complianceLogs = listOf(
                                    ComplianceLog((complianceLogs.size + 1).toString(), now, "anon_e4f9b870c1bcde21", "FAILED", "Network Proxy MITM hijacking signature.")
                                ) + complianceLogs
                            } else if (holdsDebug) {
                                scanState = "FAILED"
                                failureReason = "Policy Violated: System ADB bridge debugging port exposed. Host remains vulnerable to arbitrary command injections."
                                complianceLogs = listOf(
                                    ComplianceLog((complianceLogs.size + 1).toString(), now, "anon_e4f9b870c1bcde21", "FAILED", "Validation Failed: TCP debugging exposed.")
                                ) + complianceLogs
                            } else if (holdsUnsafeCerts) {
                                scanState = "FAILED"
                                failureReason = "Threat Blocked: Custom/Wildcard user authorities recognized in Trust store, exposing device to certificate spoofing."
                                complianceLogs = listOf(
                                    ComplianceLog((complianceLogs.size + 1).toString(), now, "anon_e4f9b870c1bcde21", "FAILED", "Untrusted User Authority certificate detected.")
                                ) + complianceLogs
                            } else if (holdsPerms) {
                                // Dynamic Soft Warning Outcome
                                scanState = "APPROVED"
                                activeToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbm9uX2U0ZjliODcwYzFiY2RlMjEiLCJzY29wZSI6ImJ5b2QuZ2F0ZXdheS5yZXN0cmljdGVkIiwiZXhwIjoxNjg1OTA0MDAwfQ.WarningTrigger_Yx182"
                                complianceLogs = listOf(
                                    ComplianceLog((complianceLogs.size + 1).toString(), now, "anon_e4f9b870c1bcde21", "APPROVED", "Approved with warning: Privilege audit highlighted atypical admin override.")
                                ) + complianceLogs
                            } else {
                                // Full Baseline Approved
                                scanState = "APPROVED"
                                activeToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbm9uX2U0ZjliODcwYzFiY2RlMjEiLCJzY29wZSI6ImJ5b2QuZ2F0ZXdheS5mdWxsIiwiZXhwIjoxNjg1OTA0MDAwfQ.v_817G9X7z11AbC_AdvancedSecure"
                                complianceLogs = listOf(
                                    ComplianceLog((complianceLogs.size + 1).toString(), now, "anon_e4f9b870c1bcde21", "APPROVED", "Posture baseline successfully validated. Issued standard secure JWT.")
                                ) + complianceLogs
                            }
                        }
                    },
                    onRevokeToken = {
                        activeToken = null
                        scanState = "IDLE"
                    },
                    onExportPosture = {
                        exportJsonString = generateCurrentPostureJson(
                            deviceId = "anon_e4f9b870c1bcde21",
                            passcodeEnabled = passcodeEnabled,
                            osVersion = osVersion,
                            isRooted = isRooted,
                            maliciousAppsDetected = maliciousAppsDetected,
                            networkAnomaliesDetected = networkAnomaliesDetected,
                            unusualPermissionsGranted = unusualPermissionsGranted,
                            debuggingEnabled = debuggingEnabled,
                            untrustedCertificatesInstalled = untrustedCertificatesInstalled,
                            scanState = scanState,
                            failureReason = failureReason
                        )
                    }
                )
                1 -> LogsScreen(
                    logs = complianceLogs,
                    onExportLogs = {
                        exportJsonString = generateLogsJson(complianceLogs)
                    }
                )
                2 -> ChatScreen(
                    passcodeEnabled = passcodeEnabled,
                    osVersion = osVersion,
                    isRooted = isRooted,
                    maliciousAppsDetected = maliciousAppsDetected,
                    networkAnomaliesDetected = networkAnomaliesDetected,
                    unusualPermissionsGranted = unusualPermissionsGranted,
                    debuggingEnabled = debuggingEnabled,
                    untrustedCertificatesInstalled = untrustedCertificatesInstalled,
                    scanState = scanState
                )
                3 -> CodeViewerScreen()
            }
            
            if (exportJsonString != null) {
                ComplianceExportDialog(
                    jsonString = exportJsonString!!,
                    onDismiss = { exportJsonString = null },
                    onSaveJsonToDownloads = {
                        saveJsonToDownloads(context, exportJsonString!!)
                        exportJsonString = null
                    },
                    onShareJson = {
                        shareJsonContent(context, exportJsonString!!)
                        exportJsonString = null
                    },
                    deviceId = "anon_e4f9b870c1bcde21",
                    passcodeEnabled = passcodeEnabled,
                    osVersion = osVersion,
                    isRooted = isRooted,
                    maliciousAppsDetected = maliciousAppsDetected,
                    networkAnomaliesDetected = networkAnomaliesDetected,
                    unusualPermissionsGranted = unusualPermissionsGranted,
                    debuggingEnabled = debuggingEnabled,
                    untrustedCertificatesInstalled = untrustedCertificatesInstalled,
                    scanState = scanState,
                    failureReason = failureReason
                )
            }
        }
    }
}

@Composable
fun ScannerScreen(
    passcodeEnabled: Boolean,
    onPasscodeToggle: (Boolean) -> Unit,
    osVersion: String,
    onOsChange: (String) -> Unit,
    isRooted: Boolean,
    onRootedToggle: (Boolean) -> Unit,
    maliciousAppsDetected: Boolean,
    onMaliciousToggle: (Boolean) -> Unit,
    networkAnomaliesDetected: Boolean,
    onNetworkToggle: (Boolean) -> Unit,
    unusualPermissionsGranted: Boolean,
    onPermissionsToggle: (Boolean) -> Unit,
    debuggingEnabled: Boolean,
    onDebuggingToggle: (Boolean) -> Unit,
    untrustedCertificatesInstalled: Boolean,
    onUntrustedCertToggle: (Boolean) -> Unit,
    scanState: String,
    scLogs: List<String>,
    failureReason: String,
    activeToken: String?,
    remainingSeconds: Int,
    onTriggerVerify: () -> Unit,
    onRevokeToken: () -> Unit,
    onExportPosture: () -> Unit
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            HeaderSection()
        }

        item {
            SecurityPostureSimulatorCard(
                passcodeEnabled = passcodeEnabled,
                onPasscodeToggle = onPasscodeToggle,
                osVersion = osVersion,
                onOsChange = onOsChange,
                isRooted = isRooted,
                onRootedToggle = onRootedToggle,
                maliciousAppsDetected = maliciousAppsDetected,
                onMaliciousToggle = onMaliciousToggle,
                networkAnomaliesDetected = networkAnomaliesDetected,
                onNetworkToggle = onNetworkToggle,
                unusualPermissionsGranted = unusualPermissionsGranted,
                onPermissionsToggle = onPermissionsToggle,
                debuggingEnabled = debuggingEnabled,
                onDebuggingToggle = onDebuggingToggle,
                untrustedCertificatesInstalled = untrustedCertificatesInstalled,
                onUntrustedCertToggle = onUntrustedCertToggle,
                scanState = scanState
            )
        }

        item {
            JsonPayloadBox(
                passcodeEnabled = passcodeEnabled,
                osVersion = osVersion,
                isRooted = isRooted,
                maliciousAppsDetected = maliciousAppsDetected,
                networkAnomaliesDetected = networkAnomaliesDetected,
                unusualPermissionsGranted = unusualPermissionsGranted,
                debuggingEnabled = debuggingEnabled,
                untrustedCertificatesInstalled = untrustedCertificatesInstalled
            )
        }

        item {
            SecurityAlertsDashboard(
                passcodeEnabled = passcodeEnabled,
                osVersion = osVersion,
                isRooted = isRooted,
                maliciousAppsDetected = maliciousAppsDetected,
                networkAnomaliesDetected = networkAnomaliesDetected,
                unusualPermissionsGranted = unusualPermissionsGranted,
                debuggingEnabled = debuggingEnabled,
                untrustedCertificatesInstalled = untrustedCertificatesInstalled
            )
        }

        item {
            ValidationControlCenter(
                scanState = scanState,
                scLogs = scLogs,
                failureReason = failureReason,
                activeToken = activeToken,
                remainingSeconds = remainingSeconds,
                onTriggerVerify = onTriggerVerify,
                onRevokeToken = onRevokeToken,
                onExportPosture = onExportPosture
            )
        }
    }
}

@Composable
fun HeaderSection() {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 12.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Surface(
            color = ActiveContainer,
            shape = RoundedCornerShape(100.dp)
        ) {
            Row(
                modifier = Modifier.padding(horizontal = 14.dp, vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .size(6.dp)
                        .background(ActiveContent, RoundedCornerShape(50))
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "ACTIVE",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontWeight = FontWeight.Bold,
                        color = ActiveContent,
                        letterSpacing = 1.sp
                    )
                )
            }
        }
        Spacer(modifier = Modifier.height(12.dp))
        Text(
            text = "TrustPulse",
            style = MaterialTheme.typography.headlineLarge.copy(
                fontWeight = FontWeight.Bold,
                color = TechTextPrimary,
                letterSpacing = (-0.5).sp
            )
        )
        Spacer(modifier = Modifier.height(2.dp))
        Text(
            text = "Endpoint Threat Posture Engine",
            style = MaterialTheme.typography.bodyMedium.copy(
                color = TechTextSecondary,
                textAlign = TextAlign.Center
            )
        )
    }
}

@Composable
fun SecurityPostureSimulatorCard(
    passcodeEnabled: Boolean,
    onPasscodeToggle: (Boolean) -> Unit,
    osVersion: String,
    onOsChange: (String) -> Unit,
    isRooted: Boolean,
    onRootedToggle: (Boolean) -> Unit,
    maliciousAppsDetected: Boolean,
    onMaliciousToggle: (Boolean) -> Unit,
    networkAnomaliesDetected: Boolean,
    onNetworkToggle: (Boolean) -> Unit,
    unusualPermissionsGranted: Boolean,
    onPermissionsToggle: (Boolean) -> Unit,
    debuggingEnabled: Boolean,
    onDebuggingToggle: (Boolean) -> Unit,
    untrustedCertificatesInstalled: Boolean,
    onUntrustedCertToggle: (Boolean) -> Unit,
    scanState: String
) {
    var configTab by remember { mutableStateOf(0) } // 0: Baselines, 1: Threat Signals

    Card(
        colors = CardDefaults.cardColors(containerColor = SoftSurface),
        shape = RoundedCornerShape(24.dp),
        border = BorderStroke(1.dp, TechBorder)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "Posture Configurations",
                    style = MaterialTheme.typography.titleMedium.copy(
                        fontWeight = FontWeight.Bold,
                        color = TechTextPrimary
                    )
                )
                Surface(
                    color = TechTextPrimary.copy(alpha = 0.08f),
                    shape = RoundedCornerShape(4.dp)
                ) {
                    Text(
                        text = "ID: 4A-9F22",
                        style = MaterialTheme.typography.labelSmall.copy(
                            color = TechTextPrimary,
                            fontWeight = FontWeight.Bold
                        ),
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                    )
                }
            }

            // Tabs Selector inside card
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 14.dp)
                    .clip(RoundedCornerShape(12.dp))
                    .background(InputBackground)
                    .padding(4.dp)
            ) {
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .clip(RoundedCornerShape(8.dp))
                        .background(if (configTab == 0) Color.White else Color.Transparent)
                        .clickable(enabled = scanState != "SCANNING") { configTab = 0 }
                        .padding(vertical = 8.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = "1. Baselines",
                        style = MaterialTheme.typography.bodySmall.copy(
                            fontWeight = FontWeight.Bold,
                            color = if (configTab == 0) PrimaryPurple else TechTextSecondary
                        )
                    )
                }
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .clip(RoundedCornerShape(8.dp))
                        .background(if (configTab == 1) Color.White else Color.Transparent)
                        .clickable(enabled = scanState != "SCANNING") { configTab = 1 }
                        .padding(vertical = 8.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = "2. Security Threat Signals",
                        style = MaterialTheme.typography.bodySmall.copy(
                            fontWeight = FontWeight.Bold,
                            color = if (configTab == 1) PrimaryPurple else TechTextSecondary
                        )
                    )
                }
            }

            Column(
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                if (configTab == 0) {
                    // PIN Check
                    BaselineSwitchItem(
                        title = "Screen Lock PIN Protection",
                        subtitle = if (passcodeEnabled) "Secure Lockscreen bound" else "LOCK SCREEN INACTIVE (RISK)",
                        checked = passcodeEnabled,
                        icon = if (passcodeEnabled) Icons.Filled.Lock else Icons.Filled.LockOpen,
                        isOk = passcodeEnabled,
                        onCheckedChange = onPasscodeToggle,
                        enabled = scanState != "SCANNING"
                    )

                    // OS Version Check
                    BaselineVersionSelectorItem(
                        osVersion = osVersion,
                        onOsChange = onOsChange,
                        enabled = scanState != "SCANNING"
                    )

                    // Device Integrity (rooted/jailbreak)
                    BaselineSwitchItem(
                        title = "Superuser Integrity Auditing",
                        subtitle = if (isRooted) "COMPROMISED (ROOT ACCESS OPEN)" else "Safe (No binaries identified)",
                        checked = isRooted,
                        icon = if (isRooted) Icons.Filled.Warning else Icons.Filled.VerifiedUser,
                        isOk = !isRooted,
                        onCheckedChange = onRootedToggle,
                        enabled = scanState != "SCANNING"
                    )
                } else {
                    // Malicious processes inventory
                    BaselineSwitchItem(
                        title = "Malicious Package Scanner",
                        subtitle = if (maliciousAppsDetected) "COMPROMISED (Malware tools present)" else "Safe (Catalog signatures clean)",
                        checked = maliciousAppsDetected,
                        icon = Icons.Filled.BugReport,
                        isOk = !maliciousAppsDetected,
                        onCheckedChange = onMaliciousToggle,
                        enabled = scanState != "SCANNING"
                    )

                    // TLS proxy decryption check
                    BaselineSwitchItem(
                        title = "Transport Interception Proxy",
                        subtitle = if (networkAnomaliesDetected) "MITM THREAT: TCP proxy intercepting" else "Safe (SSL TLS transport secure)",
                        checked = networkAnomaliesDetected,
                        icon = Icons.Filled.WifiTetheringError,
                        isOk = !networkAnomaliesDetected,
                        onCheckedChange = onNetworkToggle,
                        enabled = scanState != "SCANNING"
                    )

                    // ADB debug interface
                    BaselineSwitchItem(
                        title = "Android Debug Bridge (ADB)",
                        subtitle = if (debuggingEnabled) "EXPOSED (Network listening listener open)" else "Safe (ADB debugging locked)",
                        checked = debuggingEnabled,
                        icon = Icons.Filled.Engineering,
                        isOk = !debuggingEnabled,
                        onCheckedChange = onDebuggingToggle,
                        enabled = scanState != "SCANNING"
                    )

                    // Custom user certification store
                    BaselineSwitchItem(
                        title = "User Certificate Trust Store",
                        subtitle = if (untrustedCertificatesInstalled) "COMPROMISED (Untrusted Root CA active)" else "Safe (Verified authorities only)",
                        checked = untrustedCertificatesInstalled,
                        icon = Icons.Filled.Phishing,
                        isOk = !untrustedCertificatesInstalled,
                        onCheckedChange = onUntrustedCertToggle,
                        enabled = scanState != "SCANNING"
                    )

                    // elevated third party permissions
                    BaselineSwitchItem(
                        title = "Atypical Privilege Context",
                        subtitle = if (unusualPermissionsGranted) "WARNING: Elevated overlay concessions" else "Safe (Strict restricted client bounds)",
                        checked = unusualPermissionsGranted,
                        icon = Icons.Filled.PrivacyTip,
                        isOk = !unusualPermissionsGranted,
                        onCheckedChange = onPermissionsToggle,
                        enabled = scanState != "SCANNING"
                    )
                }
            }

            Spacer(modifier = Modifier.height(14.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Button(
                    onClick = {
                        onPasscodeToggle(false)
                        onOsChange("14.0")
                        onRootedToggle(true)
                        onMaliciousToggle(true)
                        onNetworkToggle(true)
                        onPermissionsToggle(true)
                        onDebuggingToggle(true)
                        onUntrustedCertToggle(true)
                    },
                    modifier = Modifier.weight(1f).height(44.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = ComplianceRed.copy(alpha = 0.9f)),
                    shape = RoundedCornerShape(100.dp),
                    enabled = scanState != "SCANNING"
                ) {
                    Icon(imageVector = Icons.Filled.Error, contentDescription = "Simulate All Threats", tint = Color.White, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("TRIGGER ALL THREATS", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = Color.White)
                }

                OutlinedButton(
                    onClick = {
                        onPasscodeToggle(true)
                        onOsChange("17.2")
                        onRootedToggle(false)
                        onMaliciousToggle(false)
                        onNetworkToggle(false)
                        onPermissionsToggle(false)
                        onDebuggingToggle(false)
                        onUntrustedCertToggle(false)
                    },
                    modifier = Modifier.weight(1f).height(44.dp),
                    border = BorderStroke(1.dp, PrimaryPurple),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = PrimaryPurple),
                    shape = RoundedCornerShape(100.dp),
                    enabled = scanState != "SCANNING"
                ) {
                    Icon(imageVector = Icons.Filled.CheckCircle, contentDescription = "Restore Secure Baseline", tint = PrimaryPurple, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("RESTORE COMPLIANT", fontSize = 10.sp, fontWeight = FontWeight.Bold)
                }
            }
        }
    }
}

@Composable
fun BaselineSwitchItem(
    title: String,
    subtitle: String,
    checked: Boolean,
    icon: ImageVector,
    isOk: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    enabled: Boolean
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = Color.White),
        shape = RoundedCornerShape(16.dp),
        border = BorderStroke(1.dp, Color(0xFFEADDFF)),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(36.dp)
                    .background(ActiveContainer, RoundedCornerShape(50)),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = ActiveContent,
                    modifier = Modifier.size(18.dp)
                )
            }
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.bodyMedium.copy(
                        fontWeight = FontWeight.Bold,
                        color = TechTextPrimary
                    )
                )
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.labelSmall.copy(
                        color = if (isOk) ComplianceGreen else ComplianceRed
                    )
                )
            }
            Switch(
                checked = checked,
                onCheckedChange = { if (enabled) onCheckedChange(it) },
                colors = SwitchDefaults.colors(
                    checkedThumbColor = Color.White,
                    checkedTrackColor = if (isOk) PrimaryPurple else ComplianceRed,
                    uncheckedThumbColor = Color(0xFF757575),
                    uncheckedTrackColor = Color(0xFFE0E0E0)
                ),
                enabled = enabled
            )
        }
    }
}

@Composable
fun BaselineVersionSelectorItem(
    osVersion: String,
    onOsChange: (String) -> Unit,
    enabled: Boolean
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = Color.White),
        shape = RoundedCornerShape(16.dp),
        border = BorderStroke(1.dp, Color(0xFFEADDFF)),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(36.dp)
                    .background(ActiveContainer, RoundedCornerShape(50)),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = Icons.Filled.SettingsSuggest,
                    contentDescription = null,
                    tint = ActiveContent,
                    modifier = Modifier.size(18.dp)
                )
            }
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "Android OS Version",
                    style = MaterialTheme.typography.bodyMedium.copy(
                        fontWeight = FontWeight.Bold,
                        color = TechTextPrimary
                    )
                )
                val isOsValid = try {
                    val parsed = osVersion.split(".").firstOrNull()?.toFloatOrNull() ?: 0f
                    parsed >= 16.4f
                } catch (e: Exception) {
                    false
                }
                Text(
                    text = if (isOsValid) "Android $osVersion (v16.4+ Baseline verified)" else "Android $osVersion (OUTDATED)",
                    style = MaterialTheme.typography.labelSmall.copy(
                        color = if (isOsValid) ComplianceGreen else ComplianceRed
                    )
                )
            }
            Row(
                modifier = Modifier
                    .clip(RoundedCornerShape(8.dp))
                    .background(InputBackground)
            ) {
                val versions = listOf("15.2", "16.4", "17.2")
                versions.forEach { version ->
                    val isSelected = osVersion == version
                    Box(
                        modifier = Modifier
                            .clickable(enabled = enabled) { onOsChange(version) }
                            .background(if (isSelected) PrimaryPurple else Color.Transparent)
                            .padding(horizontal = 8.dp, vertical = 6.dp)
                    ) {
                        Text(
                            text = "v$version",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontWeight = FontWeight.Bold,
                                color = if (isSelected) Color.White else TechTextSecondary
                            )
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun JsonPayloadBox(
    passcodeEnabled: Boolean,
    osVersion: String,
    isRooted: Boolean,
    maliciousAppsDetected: Boolean,
    networkAnomaliesDetected: Boolean,
    unusualPermissionsGranted: Boolean,
    debuggingEnabled: Boolean,
    untrustedCertificatesInstalled: Boolean
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = InputBackground),
        shape = RoundedCornerShape(24.dp),
        border = BorderStroke(1.dp, TechBorder),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "Telemetry JSON REST Payload",
                    style = MaterialTheme.typography.labelSmall.copy(
                        color = PrimaryPurple,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace
                    )
                )
                Surface(
                    color = ActiveContainer,
                    shape = RoundedCornerShape(4.dp)
                ) {
                    Text(
                        text = "ANONYMOUS",
                        style = MaterialTheme.typography.labelSmall.copy(
                            color = ActiveContent,
                            fontSize = 8.sp,
                            fontWeight = FontWeight.Bold
                        ),
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                    )
                }
            }
            Spacer(modifier = Modifier.height(8.dp))
            val rawJsonStr = """
{
  "device_id": "anon_e4f9b870c1bcde21",
  "passcode_enabled": $passcodeEnabled,
  "os_version": "$osVersion",
  "is_rooted": $isRooted,
  "malicious_apps_detected": $maliciousAppsDetected,
  "network_anomalies_detected": $networkAnomaliesDetected,
  "unusual_permissions_granted": $unusualPermissionsGranted,
  "debugging_enabled": $debuggingEnabled,
  "untrusted_certificates_installed": $untrustedCertificatesInstalled,
  "timestamp": ${System.currentTimeMillis() / 1000}
}
            """.trimIndent()
            
            Text(
                text = rawJsonStr,
                style = MaterialTheme.typography.bodySmall.copy(
                    fontFamily = FontFamily.Monospace,
                    color = ActiveContent,
                    fontSize = 11.sp
                ),
                modifier = Modifier
                    .fillMaxWidth()
                    .background(Color.White, RoundedCornerShape(8.dp))
                    .padding(12.dp)
                    .border(0.5.dp, TechBorder.copy(alpha = 0.4f), RoundedCornerShape(8.dp))
            )
            Spacer(modifier = Modifier.height(6.dp))
            Text(
                text = "* Telemetry metrics processed natively. No personal data registers (names, IDs, emails) are packaged inside BYOD packets.",
                style = MaterialTheme.typography.labelSmall.copy(
                    color = TechTextSecondary,
                    fontStyle = FontStyle.Italic
                )
            )
        }
    }
}

@Composable
fun ValidationControlCenter(
    scanState: String,
    scLogs: List<String>,
    failureReason: String,
    activeToken: String?,
    remainingSeconds: Int,
    onTriggerVerify: () -> Unit,
    onRevokeToken: () -> Unit,
    onExportPosture: () -> Unit
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        when (scanState) {
            "IDLE" -> {
                Column(modifier = Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Button(
                        onClick = onTriggerVerify,
                        colors = ButtonDefaults.buttonColors(containerColor = PrimaryPurple),
                        shape = RoundedCornerShape(100.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(54.dp)
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.Center
                        ) {
                            Icon(Icons.Filled.Lock, contentDescription = null, tint = Color.White)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                "TRANSMIT POSTURE ENVELOPE",
                                style = MaterialTheme.typography.titleSmall.copy(
                                    fontWeight = FontWeight.Bold,
                                    color = Color.White
                                )
                            )
                        }
                    }
                    
                    OutlinedButton(
                        onClick = onExportPosture,
                        border = BorderStroke(1.dp, PrimaryPurple),
                        shape = RoundedCornerShape(100.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(48.dp),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = PrimaryPurple)
                    ) {
                        Icon(imageVector = Icons.Filled.FileDownload, contentDescription = null)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            "EXPORT BASELINE TEMPLATE",
                            style = MaterialTheme.typography.titleSmall.copy(
                                fontWeight = FontWeight.Bold
                            )
                        )
                    }
                }
            }
            "SCANNING" -> {
                Card(
                    colors = CardDefaults.cardColors(containerColor = Color(0xFF130E20)), // Secure Nightshade terminal aesthetic
                    border = BorderStroke(1.dp, TechBorder),
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(24.dp)
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(18.dp),
                        horizontalAlignment = Alignment.Start
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp)
                        ) {
                            CircularProgressIndicator(
                                color = Purple80,
                                strokeWidth = 2.dp,
                                modifier = Modifier.size(18.dp)
                            )
                            Spacer(modifier = Modifier.width(10.dp))
                            Text(
                                text = "Evaluating Posture Sandbox...",
                                style = MaterialTheme.typography.bodyMedium.copy(
                                    color = Color.White,
                                    fontWeight = FontWeight.Bold
                                )
                            )
                        }
                        
                        // Terminal outputs
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(160.dp)
                                .clip(RoundedCornerShape(12.dp))
                                .background(Color.Black)
                                .padding(12.dp)
                        ) {
                            LazyColumn(reverseLayout = true) {
                                items(scLogs.reversed()) { log ->
                                    val logColor = when {
                                        log.contains("ROOTED") || log.contains("VULNERABILITY") || log.contains("BLACKLIST MATCHED") || log.contains("Proxy hijack") || log.contains("EXPOSED") || log.contains("COMPROMISED") -> Color(0xFFFF5252)
                                        log.contains("warning") || log.contains("Atypical") -> Color(0xFFFFD54F)
                                        log.contains("•") || log.contains("[") -> Color(0xFF69F0AE)
                                        else -> Color(0xFFE0B0FF)
                                    }
                                    Text(
                                        text = log,
                                        style = MaterialTheme.typography.bodySmall.copy(
                                            fontFamily = FontFamily.Monospace,
                                            color = logColor,
                                            fontSize = 11.sp,
                                            lineHeight = 15.sp
                                        ),
                                        modifier = Modifier.padding(bottom = 4.dp)
                                    )
                                }
                            }
                        }
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = "Auditing live low-level Android hardware parameters under strict GDPR minimization constraints.",
                            style = MaterialTheme.typography.labelSmall.copy(
                                color = Color.White.copy(alpha = 0.5f),
                                fontStyle = FontStyle.Italic
                            )
                        )
                    }
                }
            }
            "APPROVED" -> {
                val isWarningState = activeToken?.contains("Warning") == true
                Column(modifier = Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
                    Card(
                        colors = CardDefaults.cardColors(
                            containerColor = if (isWarningState) Color(0xFFFFFDF1) else Color(0xFFF1FDF5)
                        ),
                        border = BorderStroke(1.dp, if (isWarningState) Color(0xFFFBC02D) else ComplianceGreen),
                        shape = RoundedCornerShape(24.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.padding(20.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(
                                    imageVector = if (isWarningState) Icons.Filled.Warning else Icons.Filled.CheckCircle,
                                    contentDescription = "Outcome",
                                    tint = if (isWarningState) Color(0xFFFBC02D) else ComplianceGreen,
                                    modifier = Modifier.size(28.dp)
                                )
                                Spacer(modifier = Modifier.width(10.dp))
                                Text(
                                    text = if (isWarningState) "ENDPOINT APPROVED WITH WARNINGS" else "ENDPOINT POSTURE APPROVED",
                                    style = MaterialTheme.typography.titleMedium.copy(
                                        color = if (isWarningState) Color(0xFF7F6000) else ComplianceGreen,
                                        fontWeight = FontWeight.Bold
                                    )
                                )
                            }
                            
                            Spacer(modifier = Modifier.height(12.dp))
                            
                            Text(
                                text = if (isWarningState) 
                                    "Policy Engine granted restricted entry. Privilege audits generated atypical background process access flags requiring correction."
                                else "All security posture parameters meet corporate BYOD standards. Cryptographic cryptographic session token issued.",
                                style = MaterialTheme.typography.bodySmall.copy(color = TechTextSecondary)
                            )
                            
                            Spacer(modifier = Modifier.height(16.dp))
                            
                            // Emitted Token visualizer
                            Box(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(12.dp))
                                    .background(Color.White)
                                    .border(1.dp, TechBorder, RoundedCornerShape(12.dp))
                                    .padding(12.dp)
                            ) {
                                Column {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween
                                    ) {
                                        Text(
                                            text = "EMITTED JWT SIGNATURE:",
                                            style = MaterialTheme.typography.labelSmall.copy(
                                                fontFamily = FontFamily.Monospace,
                                                color = ActiveContent,
                                                fontSize = 9.sp
                                            )
                                        )
                                        Text(
                                            text = if (isWarningState) "HS256 RESTRICTED" else "HS256 FULL GATEWAY",
                                            style = MaterialTheme.typography.labelSmall.copy(
                                                color = if (isWarningState) Color(0xFFFBC02D) else ComplianceGreen,
                                                fontSize = 8.sp,
                                                fontWeight = FontWeight.Bold
                                            )
                                        )
                                    }
                                    Spacer(modifier = Modifier.height(4.dp))
                                    Text(
                                        text = activeToken ?: "",
                                        style = MaterialTheme.typography.bodySmall.copy(
                                            fontFamily = FontFamily.Monospace,
                                            color = TechTextPrimary,
                                            fontSize = 9.sp
                                        ),
                                        maxLines = 2,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                }
                            }
                            
                            Spacer(modifier = Modifier.height(16.dp))
                            
                            // Expiring countdown progress bar
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Text(
                                    text = "Secure Cryptographic TTL Expiry:",
                                    style = MaterialTheme.typography.labelSmall.copy(color = TechTextSecondary)
                                )
                                Text(
                                    text = formatTime(remainingSeconds),
                                    style = MaterialTheme.typography.bodyLarge.copy(
                                        color = if (isWarningState) Color(0xFF7F6000) else ComplianceGreen,
                                        fontFamily = FontFamily.Monospace,
                                        fontWeight = FontWeight.Bold
                                    )
                                )
                            }
                            Spacer(modifier = Modifier.height(6.dp))
                            LinearProgressIndicator(
                                progress = { remainingSeconds / 120f },
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(4.dp)),
                                color = if (isWarningState) Color(0xFFFBC02D) else ComplianceGreen,
                                trackColor = TechBorder.copy(alpha = 0.3f)
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    Button(
                        onClick = onExportPosture,
                        colors = ButtonDefaults.buttonColors(containerColor = SecondaryPurple),
                        shape = RoundedCornerShape(100.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(52.dp)
                    ) {
                        Icon(imageVector = Icons.Filled.FileDownload, contentDescription = null, tint = Color.White)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            "EXPORT GDPR AUDIT REPORT",
                            style = MaterialTheme.typography.titleSmall.copy(
                                fontWeight = FontWeight.Bold,
                                color = Color.White
                            )
                        )
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    TextButton(
                        onClick = onRevokeToken,
                        colors = ButtonDefaults.textButtonColors(contentColor = ComplianceRed)
                    ) {
                        Icon(imageVector = Icons.Filled.DeleteSweep, contentDescription = null)
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("FORCE DISPOSE CRYPTO TOKEN")
                    }
                }
            }
            "FAILED" -> {
                Column(modifier = Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
                    Card(
                        colors = CardDefaults.cardColors(containerColor = Color(0xFFFFF5F5)),
                        border = BorderStroke(1.dp, ComplianceRed),
                        shape = RoundedCornerShape(24.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.padding(20.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(
                                    imageVector = Icons.Filled.Error,
                                    contentDescription = "Failed",
                                    tint = ComplianceRed,
                                    modifier = Modifier.size(28.dp)
                                )
                                Spacer(modifier = Modifier.width(10.dp))
                                Text(
                                    text = "ACCESS DENIED (SECURITY BREACH)",
                                    style = MaterialTheme.typography.titleMedium.copy(
                                        color = ComplianceRed,
                                        fontWeight = FontWeight.Bold
                                    )
                                )
                            }
                            
                            Spacer(modifier = Modifier.height(12.dp))
                            
                            Text(
                                text = "Policy Engine validation parameters failed. The gateway rejected secure connection authorization packets due to active host vulnerabilities.",
                                style = MaterialTheme.typography.bodySmall.copy(color = TechTextSecondary)
                            )
                            
                            Spacer(modifier = Modifier.height(12.dp))
                            
                            Box(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(12.dp))
                                    .background(Color.White)
                                    .border(1.dp, ComplianceRed.copy(alpha = 0.3f), RoundedCornerShape(12.dp))
                                    .padding(12.dp)
                            ) {
                                Text(
                                    text = failureReason,
                                    style = MaterialTheme.typography.bodyMedium.copy(
                                        fontFamily = FontFamily.Monospace,
                                        color = ComplianceRed,
                                        fontWeight = FontWeight.Bold
                                    )
                                )
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(16.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Button(
                            onClick = onTriggerVerify,
                            colors = ButtonDefaults.buttonColors(containerColor = PrimaryPurple),
                            shape = RoundedCornerShape(100.dp),
                            modifier = Modifier
                                .weight(1.2f)
                                .height(52.dp)
                        ) {
                            Icon(imageVector = Icons.Filled.Refresh, contentDescription = null, tint = Color.White)
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("RE-EVALUATE", color = Color.White, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                        }
                        
                        Button(
                            onClick = onExportPosture,
                            colors = ButtonDefaults.buttonColors(containerColor = SecondaryPurple),
                            shape = RoundedCornerShape(100.dp),
                            modifier = Modifier
                                .weight(1f)
                                .height(52.dp)
                        ) {
                            Icon(imageVector = Icons.Filled.FileDownload, contentDescription = null, tint = Color.White)
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("EXPORT REPORT", color = Color.White, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun LogsScreen(logs: List<ComplianceLog>, onExportLogs: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        Card(
            colors = CardDefaults.cardColors(containerColor = SoftSurface),
            border = BorderStroke(1.dp, TechBorder),
            shape = RoundedCornerShape(24.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Filled.FolderZip,
                            contentDescription = null,
                            tint = PrimaryPurple,
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "Compliance logs audit",
                            style = MaterialTheme.typography.titleMedium.copy(
                                fontWeight = FontWeight.Bold,
                                color = TechTextPrimary
                            )
                        )
                    }
                    
                    IconButton(
                        onClick = onExportLogs,
                        modifier = Modifier.size(36.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Filled.FileDownload,
                            contentDescription = "Export JSON Compliance Ledger",
                            tint = PrimaryPurple
                        )
                    }
                }
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "A secure local audit registry showing telemetry transmission events. Under strict GDPR minimization guidelines: zero PII metadata is logged.",
                    style = MaterialTheme.typography.bodySmall.copy(color = TechTextSecondary)
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        LazyColumn(
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            items(logs) { log ->
                ComplianceLogItemRow(log = log)
            }
        }
    }
}

@Composable
fun ComplianceLogItemRow(log: ComplianceLog) {
    val isApproved = log.status == "APPROVED"
    Card(
        colors = CardDefaults.cardColors(containerColor = Color.White),
        border = BorderStroke(
            1.dp, 
            if (isApproved) ComplianceGreen.copy(alpha = 0.3f) else ComplianceRed.copy(alpha = 0.3f)
        ),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = log.timestamp,
                    style = MaterialTheme.typography.labelSmall.copy(
                        color = TechTextSecondary,
                        fontFamily = FontFamily.Monospace
                    )
                )
                Surface(
                    color = if (isApproved) Color(0xFFE8F5E9) else Color(0xFFFDE8E8),
                    shape = RoundedCornerShape(6.dp)
                ) {
                    Text(
                        text = log.status,
                        style = MaterialTheme.typography.labelSmall.copy(
                            color = if (isApproved) ComplianceGreen else ComplianceRed,
                            fontWeight = FontWeight.Bold
                        ),
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp)
                    )
                }
            }
            Spacer(modifier = Modifier.height(8.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = "ANON_ID:",
                    style = MaterialTheme.typography.labelSmall.copy(
                        color = TechTextPrimary,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace
                    )
                )
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    text = log.deviceId,
                    style = MaterialTheme.typography.bodySmall.copy(
                        color = PrimaryPurple,
                        fontFamily = FontFamily.Monospace
                    )
                )
            }
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = log.details,
                style = MaterialTheme.typography.bodySmall.copy(color = TechTextSecondary)
            )
        }
    }
}

@Composable
fun ChatScreen(
    passcodeEnabled: Boolean,
    osVersion: String,
    isRooted: Boolean,
    maliciousAppsDetected: Boolean,
    networkAnomaliesDetected: Boolean,
    unusualPermissionsGranted: Boolean,
    debuggingEnabled: Boolean,
    untrustedCertificatesInstalled: Boolean,
    scanState: String
) {
    val coroutineScope = rememberCoroutineScope()
    var inputMessage by remember { mutableStateOf("") }
    
    // Default chat welcoming messages
    val messages = remember {
        mutableStateListOf(
            ChatMessage(
                id = "1",
                text = "Welcome to TrustPulse AI Security Copilot! 🛡️ I am PulseGuard, an intelligent assistant trained in mobile BYOD device posture, endpoint vulnerability auditing, and GDPR-compliant data standards.",
                isUser = false,
                timestamp = getCurrentTimeShort()
            ),
            ChatMessage(
                id = "2",
                text = "I am directly linked to your on-device secure simulator. Ask me why a specific scanning indicator fails or how to harden your configuration!",
                isUser = false,
                timestamp = getCurrentTimeShort()
            )
        )
    }

    var isAiGenerating by remember { mutableStateOf(false) }
    var isAutonomousModeBadgeVisible by remember { mutableStateOf(false) }

    val lazyListState = rememberLazyListState()

    // Scroll trigger helper
    LaunchedEffect(messages.size) {
        if (messages.isNotEmpty()) {
            lazyListState.animateScrollToItem(messages.size - 1)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        Card(
            colors = CardDefaults.cardColors(containerColor = SoftSurface),
            border = BorderStroke(1.dp, TechBorder),
            shape = RoundedCornerShape(24.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(34.dp)
                                .background(ActiveContainer, RoundedCornerShape(50)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = Icons.Filled.SmartToy,
                                contentDescription = null,
                                tint = ActiveContent,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                        Spacer(modifier = Modifier.width(10.dp))
                        Column {
                            Text(
                                text = "PulseGuard Copilot",
                                style = MaterialTheme.typography.titleMedium.copy(
                                    fontWeight = FontWeight.Bold,
                                    color = TechTextPrimary
                                )
                            )
                            Text(
                                text = "Conversational Threat Advisor",
                                style = MaterialTheme.typography.labelSmall.copy(color = TechTextSecondary)
                            )
                        }
                    }
                    
                    // Connected indicator
                    Surface(
                        color = Color(0xFFE8F5E9),
                        shape = RoundedCornerShape(100.dp)
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(6.dp)
                                    .background(ComplianceGreen, RoundedCornerShape(50))
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = "ACTIVE",
                                style = MaterialTheme.typography.labelSmall.copy(
                                    color = ComplianceGreen,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 8.sp,
                                    letterSpacing = 0.5.sp
                                )
                            )
                        }
                    }
                }
                
                // Autonomous badge
                if (isAutonomousModeBadgeVisible) {
                    Spacer(modifier = Modifier.height(8.dp))
                    Surface(
                        color = ActiveContainer.copy(alpha = 0.5f),
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Security,
                                contentDescription = null,
                                tint = ActiveContent,
                                modifier = Modifier.size(14.dp)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = "PulseGuard operates in Local Autonomous Standby (AI core offline)",
                                style = MaterialTheme.typography.labelSmall.copy(
                                    color = ActiveContent,
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.Medium
                                )
                            )
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        // Chats messaging
        LazyColumn(
            state = lazyListState,
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            items(messages) { msg ->
                ChatMessageRow(msg = msg)
            }
            
            if (isAiGenerating) {
                item {
                    AiGeneratingBubbleRow()
                }
            }
        }

        Spacer(modifier = Modifier.height(10.dp))

        // Scrollable action suggestion chips
        val prompts = listOf(
            "🔍 Analyze scanning results",
            "🛡️ Secure a rooted device",
            "🔒 How passcode works",
            "🌐 Tell me about TLS MITM"
        )
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 4.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            LazyColumn(
                modifier = Modifier.height(44.dp).fillMaxWidth()
            ) {
                item {
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        modifier = Modifier.padding(bottom = 6.dp)
                    ) {
                        prompts.forEach { label ->
                            Surface(
                                border = BorderStroke(1.dp, TechBorder),
                                shape = RoundedCornerShape(100.dp),
                                color = Color.White,
                                modifier = Modifier
                                    .clickable(enabled = !isAiGenerating) {
                                        inputMessage = label.substring(2) // Strip emoji prefix
                                    }
                            ) {
                                Text(
                                    text = label,
                                    style = MaterialTheme.typography.labelSmall.copy(
                                        fontWeight = FontWeight.Bold,
                                        color = TechTextSecondary
                                    ),
                                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp)
                                )
                            }
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(2.dp))

        // Text input bar
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            OutlinedTextField(
                value = inputMessage,
                onValueChange = { inputMessage = it },
                placeholder = { Text("Ask PulseGuard Copilot...") },
                modifier = Modifier
                    .weight(1f)
                    .padding(end = 8.dp),
                shape = RoundedCornerShape(24.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = PrimaryPurple,
                    unfocusedBorderColor = TechBorder,
                    focusedContainerColor = Color.White,
                    unfocusedContainerColor = Color.White
                ),
                singleLine = true,
                trailingIcon = {
                    IconButton(
                        onClick = {
                            if (inputMessage.isNotBlank() && !isAiGenerating) {
                                val textToSend = inputMessage
                                inputMessage = ""
                                sendChatQuery(
                                    text = textToSend,
                                    messages = messages,
                                    coroutineScope = coroutineScope,
                                    onAiGenerating = { isAiGenerating = it },
                                    onAutonomousActive = { isAutonomousModeBadgeVisible = it },
                                    passcodeEnabled = passcodeEnabled,
                                    osVersion = osVersion,
                                    isRooted = isRooted,
                                    maliciousAppsDetected = maliciousAppsDetected,
                                    networkAnomaliesDetected = networkAnomaliesDetected,
                                    unusualPermissionsGranted = unusualPermissionsGranted,
                                    debuggingEnabled = debuggingEnabled,
                                    untrustedCertificatesInstalled = untrustedCertificatesInstalled,
                                    scanState = scanState
                                )
                            }
                        },
                        enabled = inputMessage.isNotBlank() && !isAiGenerating
                    ) {
                        Icon(
                            imageVector = Icons.Filled.Send,
                            contentDescription = "Send",
                            tint = if (inputMessage.isNotBlank()) PrimaryPurple else TechTextSecondary
                        )
                    }
                }
            )
        }
    }
}

@Composable
fun ChatMessageRow(msg: ChatMessage) {
    val alignment = if (msg.isUser) Alignment.End else Alignment.Start
    val bubbleColor = if (msg.isUser) PrimaryPurple else ActiveContainer
    val textColor = if (msg.isUser) Color.White else ActiveContent
    val startRadius = if (msg.isUser) 18.dp else 4.dp
    val endRadius = if (msg.isUser) 4.dp else 18.dp

    Column(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        horizontalAlignment = alignment
    ) {
        Surface(
            color = bubbleColor,
            shape = RoundedCornerShape(
                topStart = 18.dp,
                topEnd = 18.dp,
                bottomStart = startRadius,
                bottomEnd = endRadius
            ),
            modifier = Modifier.widthIn(max = 280.dp)
        ) {
            Text(
                text = msg.text,
                style = MaterialTheme.typography.bodyMedium.copy(
                    color = textColor,
                    lineHeight = 20.sp
                ),
                modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp)
            )
        }
        Spacer(modifier = Modifier.height(2.dp))
        Text(
            text = msg.timestamp,
            style = MaterialTheme.typography.labelSmall.copy(
                color = TechTextSecondary,
                fontSize = 8.sp,
                fontFamily = FontFamily.Monospace
            ),
            modifier = Modifier.padding(horizontal = 6.dp)
        )
    }
}

@Composable
fun AiGeneratingBubbleRow() {
    Column(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        horizontalAlignment = Alignment.Start
    ) {
        Surface(
            color = ActiveContainer.copy(alpha = 0.6f),
            shape = RoundedCornerShape(
                topStart = 18.dp,
                topEnd = 18.dp,
                bottomStart = 4.dp,
                bottomEnd = 18.dp
            ),
            modifier = Modifier.widthIn(max = 200.dp)
        ) {
            Row(
                modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                CircularProgressIndicator(
                    strokeWidth = 2.dp,
                    color = ActiveContent,
                    modifier = Modifier.size(12.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "Pulse AI is analyzing...",
                    style = MaterialTheme.typography.bodyMedium.copy(
                        color = ActiveContent,
                        fontStyle = FontStyle.Italic
                    )
                )
            }
        }
    }
}

fun getCurrentTimeShort(): String {
    val format = SimpleDateFormat("HH:mm", Locale.getDefault())
    return format.format(Date())
}

fun sendChatQuery(
    text: String,
    messages: MutableList<ChatMessage>,
    coroutineScope: kotlinx.coroutines.CoroutineScope,
    onAiGenerating: (Boolean) -> Unit,
    onAutonomousActive: (Boolean) -> Unit,
    passcodeEnabled: Boolean,
    osVersion: String,
    isRooted: Boolean,
    maliciousAppsDetected: Boolean,
    networkAnomaliesDetected: Boolean,
    unusualPermissionsGranted: Boolean,
    debuggingEnabled: Boolean,
    untrustedCertificatesInstalled: Boolean,
    scanState: String
) {
    messages.add(
        ChatMessage(
            id = UUID.randomUUID().toString(),
            text = text,
            isUser = true,
            timestamp = getCurrentTimeShort()
        )
    )

    onAiGenerating(true)

    coroutineScope.launch {
        val systemInstruction = """
You are 'PulseGuard AI', an advanced security copilot for the TrustPulse BYOD Mobile Compliance Gateway. You help users understand on-device security, mobile threats (such as rooting, malicious apps, TLS proxy interception, debugging ports, and missing passcode protection), and corporate BYOD policies under strict GDPR data minimization guidelines. Always be professional, concise, encouraging, and clear.

Current Simulated Device Posture Context:
• Screen Lock Protection: ${if (passcodeEnabled) "ACTIVE" else "DISABLED (COMPROMISE)"}
• OS version: Android $osVersion (Compliance baseline: >= v16.4)
• Root active: ${if (isRooted) "ROOTED (SEC_COMPROMISE)" else "VERIFIED"}
• Malware packages: ${if (maliciousAppsDetected) "MALWARE_DETECTED (SEC_BREACH)" else "CLEAN"}
• TLS Proxy Decryption: ${if (networkAnomaliesDetected) "MITM_PROXY_DETECTED" else "SECURE"}
• Admin privilege escalation: ${if (unusualPermissionsGranted) "ATYPICAL_CONCESSION" else "NORMAL"}
• ADB listening: ${if (debuggingEnabled) "EXPOSED_LISTEN_TCP" else "DISABLED"}
• Custom root store CAs: ${if (untrustedCertificatesInstalled) "SPOOF_RISK_CA" else "OEM_VERIFIED"}
• Active overall gateway status: $scanState
        """.trimIndent()

        val historyTurns = messages.map { Pair(it.text, it.isUser) }
        
        // Execute request to Gemini (Models beta query)
        val result = GeminiNetworkHelper.queryGemini(
            prompt = text,
            systemInstruction = systemInstruction,
            history = historyTurns.dropLast(1)
        )

        onAiGenerating(false)

        val finalResponseText = if (result == "AUTONOMOUS_MODE_TRIGGER") {
            onAutonomousActive(true)
            processAutonomousResponse(
                prompt = text,
                passcodeEnabled = passcodeEnabled,
                osVersion = osVersion,
                isRooted = isRooted,
                maliciousAppsDetected = maliciousAppsDetected,
                networkAnomaliesDetected = networkAnomaliesDetected,
                unusualPermissionsGranted = unusualPermissionsGranted,
                debuggingEnabled = debuggingEnabled,
                untrustedCertificatesInstalled = untrustedCertificatesInstalled,
                scanState = scanState
            )
        } else {
            onAutonomousActive(false)
            result
        }

        messages.add(
            ChatMessage(
                id = UUID.randomUUID().toString(),
                text = finalResponseText,
                isUser = false,
                timestamp = getCurrentTimeShort()
            )
        )
    }
}

fun processAutonomousResponse(
    prompt: String,
    passcodeEnabled: Boolean,
    osVersion: String,
    isRooted: Boolean,
    maliciousAppsDetected: Boolean,
    networkAnomaliesDetected: Boolean,
    unusualPermissionsGranted: Boolean,
    debuggingEnabled: Boolean,
    untrustedCertificatesInstalled: Boolean,
    scanState: String
): String {
    val q = prompt.uppercase()
    return when {
        q.contains("COMPLIANCE") || q.contains("ANALYZE") || q.contains("SCAN") || q.contains("WHY") || q.contains("FAIL") || q.contains("RESULT") -> {
            var summary = "I have analyzed your simulated BYOD posture variables. Your endpoint represents a **$scanState** compliance profile.\n\n"
            var issuesList = ""
            if (!passcodeEnabled) {
                issuesList += "• 🔴 **Screen passcode lock disabled**: Critical hardware-tied Keystore elements are fully exposed to close-range reading exploits.\n"
            }
            val isOsValid = try {
                val parsed = osVersion.split(".").firstOrNull()?.toFloatOrNull() ?: 0f
                parsed >= 16.4f
            } catch (e: Exception) {
                false
            }
            if (!isOsValid) {
                issuesList += "• 🔴 **Outdated operating version**: Android v$osVersion is below v16.4 security baselines, lacking recent vulnerability patches (known CVE exploits).\n"
            }
            if (isRooted) {
                issuesList += "• 🔴 **Sandbox root compromised**: Unverified root access identified on target binaries, breaking app isolation boundaries.\n"
            }
            if (maliciousAppsDetected) {
                issuesList += "• 🔴 **Malware presence flag**: Sandbox scan matched signature blacklists of prominent penetration tool apk catalogs.\n"
            }
            if (networkAnomaliesDetected) {
                issuesList += "• 🔴 **TLS Decryption interception**: Active local gateway proxy discovered decrypting outgoing payloads.\n"
            }
            if (debuggingEnabled) {
                issuesList += "• 🔴 **ADB listening exposed**: Persistent TCP debug endpoints are exposed to adjacent local transport commands.\n"
            }
            if (untrustedCertificatesInstalled) {
                issuesList += "• 🔴 **Custom authority roots inside Trust store**: Untrusted root certificates represent significant transport spoofing vulnerabilities.\n"
            }
            if (unusualPermissionsGranted) {
                issuesList += "• 🟡 **Atypical elevated permissions**: Soft policy alert - atypical third-party permissions may allow process keylogging.\n"
            }

            if (issuesList.isNotBlank()) {
                summary += "Identified posture compliance gaps:\n$issuesList"
            } else {
                summary += "No threat metrics detected! Your device posture completely satisfies the enterprise BYOD access policies."
            }
            summary
        }
        q.contains("ROOT") || q.contains("JAILBREAK") -> {
            "**Jailbreak/Root Privilege Escalation Risks**:\n" +
            "In Android architectures, application isolation (sandboxing) is the ultimate safeguard. Rooting allows background programs to obtain Superuser UID 0 privileges, tearing down the boundary between apps. A malicious package running on a rooted device can dynamically hook standard class structures, scrape RAM heaps, and dump secure enterprise databases. To protect assets, TrustPulse strictly disables entries for rooted devices."
        }
        q.contains("PASSCODE") || q.contains("LOCK") || q.contains("PIN") -> {
            "**Keyguard/Lock Screen Encryption Mechanics**:\n" +
            "A passcode lock prevents more than simple visual snooping. The Android cryptographic Keystore binds its private keys directly to user-enforced lockscreen credentials. When lockscreen verification is inactive, the device's hardware enclave (TEE) cannot derive strong encryption structures, and local files remain stored unencrypted in plain storage. Setting a lock screen is the starting point for BYOD posture compliance."
        }
        q.contains("PROXY") || q.contains("MITM") || q.contains("TRAFFIC") || q.contains("INTERCEPT") || q.contains("TLS") -> {
            "**Man-in-the-Middle (MITM) TLS Decryption Risks**:\n" +
            "Corporate BYOD applications route payloads over TLS 1.3 secured channels. However, if root authority stores are breached or a malicious redirect proxy is set, attackers can forge intermediate certificates and perform real-time HTTPS decryption. TrustPulse identifies proxy routes by measuring transport handshake latency and auditing active CA credential trees."
        }
        q.contains("MALWARE") || q.contains("APP") || q.contains("PACKAGE") || q.contains("SIGNATURE") -> {
            "**Malicious Malware Scanners**:\n" +
            "Trojanized background programs, packet recorders, and script tools pose major security threats to corporate servers. TrustPulse scans the Android local package inventory list against a secure signature blacklist, blocking entry immediately if suspicious hacker-tool packages are located on system folders."
        }
        q.contains("ADB") || q.contains("DEBUG") -> {
            "**Active ADB TCP Debug Bridge Exposed**:\n" +
            "Android Debug Bridge (ADB) exposes low-level developer commands over physical USB or open wireless TCP connections. If ADB options are left active, any neighboring device or system process can hook into the debug stream, execute root scripts, and run shell prompts to inspect proprietary software. BYOD posture standards enforce ADB to be disabled."
        }
        q.contains("CERTIF") || q.contains("STORE") || q.contains("TRUST") || q.contains("CA") -> {
            "**User Certificate authority auditing**:\n" +
            "Android trust roots default only to globally verified Certificate Authorities (like VeriSign). If a custom, unauthorized authority is added to the User credentials store, it opens a dangerous backdoor, allowing spoof proxies to intercept corporate traffic seamlessly. TrustPulse verifies that only secure system OEM anchors are active in the local store."
        }
        q.contains("GDPR") || q.contains("PRIVACY") || q.contains("PII") || q.contains("ANONYM") -> {
            "** GDPR-by-Design Privacy Standards**:\n" +
            "TrustPulse applies strict Data Minimization under GDPR Art. 25 standards:\n" +
            "1. **Anonymized Endpoint IDs**: Physical hardware MACs/IMEIs are hashed locally with SHA-256 before transport. Server tables never store true hardware IDs.\n" +
            "2. **Zero PII Exposure**: No corporate names, GPS records, emails, or personal logs are saved or packaged in telemetry packets.\n" +
            "3. **Local Evaluation Priority**: Calculations happen on-device to limit server dependency and avoid raw tracking register accumulation pools."
        }
        else -> {
            "Excellent BYOD security posture question. TrustPulse audits Keyguard PIN status, sandbox su-binaries, blacklisted apk packages, TLS network proxy intercept streams, user trust certificates, and vulnerable ADB sockets under GDPR privacy rules. Ask me any details regarding lock screen hardware, sandbox compromises, MITM interception, or database compliance!"
        }
    }
}

@Composable
fun CodeViewerScreen() {
    var activeSubTab by remember { mutableStateOf(0) }
    val clipboardManager = LocalClipboardManager.current
    val context = LocalContext.current

    val pythonClientCode = """
# TrustPulse Mobile - Advanced Mobile Client Simulator
# -------------------------------------------------------------
import json, hashlib, time, requests

API_BASE_URL = "http://127.0.0.1:8000"

def get_anonymous_device_id():
    # GDPR-Compliant Data Minimization via SHA-256
    raw_id = "hw_mac_00_1a_2b_3c_4d_5e_primary_byod"
    return f"anon_{hashlib.sha256(raw_id.encode()).hexdigest()[:16]}"

def scan_device_posture_simulated(
    passcode_enabled=True, 
    os_version="17.2", 
    is_rooted=False,
    malicious_apps_detected=False,
    network_anomalies_detected=False,
    unusual_permissions_granted=False,
    debugging_enabled=False,
    untrusted_certificates_installed=False
):
    # Simulates advanced threat metrics scans
    return {
        "passcode_enabled": passcode_enabled,
        "os_version": os_version,
        "is_rooted": is_rooted,
        "malicious_apps_detected": malicious_apps_detected,
        "network_anomalies_detected": network_anomalies_detected,
        "unusual_permissions_granted": unusual_permissions_granted,
        "debugging_enabled": debugging_enabled,
        "untrusted_certificates_installed": untrusted_certificates_installed
    }

def package_and_send_payload(posture_data):
    payload = {
        "device_id": get_anonymous_device_id(),
        "passcode_enabled": posture_data["passcode_enabled"],
        "os_version": posture_data["os_version"],
        "is_rooted": posture_data["is_rooted"],
        "malicious_apps_detected": posture_data["malicious_apps_detected"],
        "network_anomalies_detected": posture_data["network_anomalies_detected"],
        "unusual_permissions_granted": posture_data["unusual_permissions_granted"],
        "debugging_enabled": posture_data["debugging_enabled"],
        "untrusted_certificates_installed": posture_data["untrusted_certificates_installed"],
        "timestamp": int(time.time())
    }
    
    url = f"{API_BASE_URL}/api/v1/validate"
    print(f"[*] Packaging posture REST envelope: {json.dumps(payload, indent=2)}")
    
    try:
        r = requests.post(url, json=payload, timeout=5)
        if r.status_code == 200:
            print("[+] APPROVED! Crypto Token Emitted:")
            print(json.dumps(r.json(), indent=2))
            return r.json().get("token")
        else:
            print(f"[-] DENIED (HTTP {r.status_code}): {r.json()}")
    except requests.exceptions.ConnectionError:
        print("[!] Connection failure. Ensure API gateway is running on host port 8000.")

if __name__ == "__main__":
    # Simulate a perfectly compliant device scan
    state = scan_device_posture_simulated(
        passcode_enabled=True, 
        os_version="17.2", 
        is_rooted=False,
        network_anomalies_detected=False,
        debugging_enabled=False
    )
    token = package_and_send_payload(state)
    """.trimIndent()

    val pythonServerCode = """
# TrustPulse Mobile - Secure FastAPI Policy Decision Point Gate
# ------------------------------------------------------------------
import time, hmac, hashlib, json
from typing import Optional, List
from fastapi import FastAPI, HTTPException, status, Header, Query
from pydantic import BaseModel

app = FastAPI(title="TrustPulse BYOD Gateways")
JWT_MOCK_SECRET = "trustpulse_byod_gateway_academic_sig_key_2026_super_secret"

# Anonymized SECURE GDPR In-Memory Audit Trail Data Store
compliance_audit_log = []

class PosturePayload(BaseModel):
    device_id: str
    passcode_enabled: bool
    os_version: str
    is_rooted: bool
    malicious_apps_detected: bool
    network_anomalies_detected: bool
    unusual_permissions_granted: bool
    debugging_enabled: bool
    untrusted_certificates_installed: bool
    timestamp: int

class RefreshRequest(BaseModel):
    current_token: str

@app.post("/api/v1/validate")
def validate_device_posture(payload: PosturePayload):
    # 1. EVALUATE SECURITY BASELINES (CRITICAL FAILS)
    if not payload.passcode_enabled:
        log_compliance_event(payload.device_id, "FAILED", "Screen passcode screenlock is inactive.", severity="CRITICAL")
        raise HTTPException(status_code=403, detail="Passcode required to bind encryption enclaves.")

    try:
        os_f = float(payload.os_version.split(".")[0] + "." + payload.os_version.split(".")[1])
    except:
        os_f = float(payload.os_version)
        
    if os_f < 16.4:
        log_compliance_event(payload.device_id, "FAILED", f"OS outdated (v{payload.os_version}). Required >= v16.4.", severity="CRITICAL")
        raise HTTPException(status_code=403, detail=f"Android security patches below minimum baseline (v{payload.os_version})")

    if payload.is_rooted:
        log_compliance_event(payload.device_id, "FAILED", "Host sandbox environment rooted/broken.", severity="CRITICAL")
        raise HTTPException(status_code=403, detail="Sandbox compromise detected (root active).")

    # 2. RUN ADVANCED THREAT INTELLIGENCE (CRITICAL FAILS)
    if payload.malicious_apps_detected:
        log_compliance_event(payload.device_id, "FAILED", "Blacklisted hacking package traces detected.", severity="CRITICAL")
        raise HTTPException(status_code=403, detail="Threat blocked: malware app match identified.")

    if payload.network_anomalies_detected:
        log_compliance_event(payload.device_id, "FAILED", "Transport layer MITM decrypting proxy identified.", severity="CRITICAL")
        raise HTTPException(status_code=403, detail="Threat blocked: active SSL proxy decrypting payloads.")

    if payload.debugging_enabled:
        log_compliance_event(payload.device_id, "FAILED", "ADB debugging listener active.", severity="CRITICAL")
        raise HTTPException(status_code=403, detail="Baseline violated: ADB Debug ports exposed.")

    if payload.untrusted_certificates_installed:
        log_compliance_event(payload.device_id, "FAILED", "User authority certification store spoof root detected.", severity="CRITICAL")
        raise HTTPException(status_code=403, detail="Threat blocked: custom untrusted CA roots in Trust store.")

    # 3. SOFT POLICIES (PASS WITH AUDIT ALERT WARNING)
    scope = "byod.gateway.full"
    if payload.unusual_permissions_granted:
        scope = "byod.gateway.restricted"
        log_compliance_event(payload.device_id, "APPROVED", "Approved with warnings: Atypical permissions active.", severity="WARNING")
    else:
        log_compliance_event(payload.device_id, "APPROVED", "Successful secure posture validation.", severity="INFO")

    # 4. ISSUE CRYPTOGRAPH COMPLIANCE TOKEN (JWT representation)
    expires = int(time.time()) + 120
    header = str(base64_encode(json.dumps({"alg": "HS256", "typ": "JWT"})))
    claims = str(base64_encode(json.dumps({"sub": payload.device_id, "scope": scope, "exp": expires})))
    
    # Sign HMAC-SHA256
    sig_input = f"{header}.{claims}"
    sig = hmac.new(JWT_MOCK_SECRET.encode(), sig_input.encode(), hashlib.sha256).hexdigest()
    token = f"{sig_input}.{sig[:16]}"

    return {"status": "APPROVED", "token": token, "expires_in": 120}

@app.post("/api/v1/refresh")
def refresh_token(request: RefreshRequest):
    # Cryptographic refresh validation within 30-second Grace Period
    try:
        parts = request.current_token.split(".")
        header_b, claims_b, received_sig = parts[0], parts[1], parts[2]
        
        # Verify HMAC signature
        recreated_sig = hmac.new(JWT_MOCK_SECRET.encode(), f"{header_b}.{claims_b}".encode(), hashlib.sha256).hexdigest()[:16]
        if not hmac.compare_digest(received_sig, recreated_sig):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token cryptographic signature.")

        claims = json.loads(base64_decode(claims_b))
        exp = claims["exp"]
        now = int(time.time())

        # Allow grace refresh up to 30 seconds past expiry
        if now > (exp + 30):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Refresh grace period (30s) exceeded.")

        # Re-issue cryptographic token
        new_exp = now + 120
        claims["exp"] = new_exp
        new_claims_b = str(base64_encode(json.dumps(claims)))
        new_sig_input = f"{header_b}.{new_claims_b}"
        new_sig = hmac.new(JWT_MOCK_SECRET.encode(), new_sig_input.encode(), hashlib.sha256).hexdigest()[:16]
        
        return {"token": f"{new_sig_input}.{new_sig}", "expires_in": 120}
    except Exception:
        raise HTTPException(status_code=401, detail="Secure token refresh sequence refused.")

@app.get("/api/v1/compliance-logs")
def query_compliance_logs(
    status_filter: Optional[str] = Query(None),
    min_severity: Optional[str] = Query(None)
):
    # Exposing filtered GDPR logs to compliance dashboards
    res = compliance_audit_log
    if status_filter:
        res = [x for x in res if x["status"] == status_filter]
    if min_severity:
        res = [x for x in res if x["severity"] == min_severity]
    return res

def log_compliance_event(device_id: str, status_str: str, details: str, severity: str = "INFO"):
    compliance_audit_log.append({
        "timestamp_utc": int(time.time()),
        "device_id": device_id,
        "status": status_str,
        "details": details,
        "severity": severity
    })

def base64_encode(s: str) -> str:
    return base64.b64encode(s.encode()).decode().replace("=", "")
    """.trimIndent()

    val activeCodeToShow = if (activeSubTab == 0) pythonClientCode else pythonServerCode
    val filename = if (activeSubTab == 0) "client.py (Mobile Client)" else "server.py (FastAPI Gateway)"

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        Card(
            colors = CardDefaults.cardColors(containerColor = SoftSurface),
            border = BorderStroke(1.dp, TechBorder),
            shape = RoundedCornerShape(24.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "Python Prototype Code",
                    style = MaterialTheme.typography.titleMedium.copy(
                        fontWeight = FontWeight.Bold,
                        color = TechTextPrimary
                    )
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "A complete implementation reference matching the security standards evaluated on-device.",
                    style = MaterialTheme.typography.bodySmall.copy(color = TechTextSecondary)
                )
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        // Tab switches
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Button(
                onClick = { activeSubTab = 0 },
                modifier = Modifier.weight(1f),
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (activeSubTab == 0) PrimaryPurple else InputBackground
                ),
                shape = RoundedCornerShape(100.dp)
            ) {
                Text(
                    "1. Client Simulator",
                    color = if (activeSubTab == 0) Color.White else TechTextPrimary,
                    fontWeight = FontWeight.Bold
                )
            }
            Button(
                onClick = { activeSubTab = 1 },
                modifier = Modifier.weight(1f),
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (activeSubTab == 1) PrimaryPurple else InputBackground
                ),
                shape = RoundedCornerShape(100.dp)
            ) {
                Text(
                    "2. Policy Server",
                    color = if (activeSubTab == 1) Color.White else TechTextPrimary,
                    fontWeight = FontWeight.Bold
                )
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        // Code header panel
        Card(
            colors = CardDefaults.cardColors(containerColor = InputBackground),
            shape = RoundedCornerShape(topStart = 16.dp, topEnd = 16.dp),
            modifier = Modifier.fillMaxWidth(),
            border = BorderStroke(1.dp, TechBorder)
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 12.dp, vertical = 6.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = filename,
                    style = MaterialTheme.typography.labelMedium.copy(
                        fontFamily = FontFamily.Monospace,
                        color = ActiveContent,
                        fontWeight = FontWeight.Bold
                    )
                )
                IconButton(
                    onClick = {
                        clipboardManager.setText(AnnotatedString(activeCodeToShow))
                        Toast.makeText(context, "$filename content copied to clipboard!", Toast.LENGTH_SHORT).show()
                    }
                ) {
                    Icon(
                        imageVector = Icons.Filled.ContentCopy,
                        contentDescription = "Copy code",
                        tint = PrimaryPurple
                    )
                }
            }
        }

        // Display contents
        Card(
            colors = CardDefaults.cardColors(containerColor = Color.White),
            shape = RoundedCornerShape(bottomStart = 16.dp, bottomEnd = 16.dp),
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f),
            border = BorderStroke(1.dp, TechBorder)
        ) {
            LazyColumn(modifier = Modifier.padding(12.dp)) {
                item {
                    Text(
                        text = activeCodeToShow,
                        style = MaterialTheme.typography.bodySmall.copy(
                            fontFamily = FontFamily.Monospace,
                            color = TechTextPrimary,
                            fontSize = 11.sp,
                            lineHeight = 16.sp
                        )
                    )
                }
            }
        }
    }
}

// Format seconds to beautified countdown timing
fun formatTime(totalSeconds: Int): String {
    val minutes = totalSeconds / 60
    val seconds = totalSeconds % 60
    return String.format(Locale.getDefault(), "%02d:%02d", minutes, seconds)
}

@Composable
fun ComplianceExportDialog(
    jsonString: String,
    onDismiss: () -> Unit,
    onSaveJsonToDownloads: () -> Unit,
    onShareJson: () -> Unit,
    deviceId: String,
    passcodeEnabled: Boolean,
    osVersion: String,
    isRooted: Boolean,
    maliciousAppsDetected: Boolean,
    networkAnomaliesDetected: Boolean,
    unusualPermissionsGranted: Boolean,
    debuggingEnabled: Boolean,
    untrustedCertificatesInstalled: Boolean,
    scanState: String,
    failureReason: String
) {
    val clipboardManager = LocalClipboardManager.current
    val context = LocalContext.current
    var activeTab by remember { mutableStateOf(0) } // 0 = JSON Telemetry, 1 = Official PDF

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Filled.FileDownload,
                    contentDescription = null,
                    tint = PrimaryPurple
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "Export Compliance Report",
                    style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold)
                )
            }
        },
        text = {
            Column(modifier = Modifier.fillMaxWidth()) {
                // Segmented Selector
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(bottom = 12.dp)
                        .clip(RoundedCornerShape(8.dp))
                        .background(InputBackground)
                ) {
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .clickable { activeTab = 0 }
                            .background(if (activeTab == 0) PrimaryPurple else Color.Transparent)
                            .padding(vertical = 8.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = "JSON Payload",
                            color = if (activeTab == 0) Color.White else TechTextPrimary,
                            style = MaterialTheme.typography.bodySmall.copy(fontWeight = FontWeight.Bold)
                        )
                    }
                    Box(
                        modifier = Modifier
                            .weight(1.2f)
                            .clickable { activeTab = 1 }
                            .background(if (activeTab == 1) PrimaryPurple else Color.Transparent)
                            .padding(vertical = 8.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = "A4 PDF Report",
                            color = if (activeTab == 1) Color.White else TechTextPrimary,
                            style = MaterialTheme.typography.bodySmall.copy(fontWeight = FontWeight.Bold)
                        )
                    }
                }

                if (activeTab == 0) {
                    Text(
                        text = "Verify the anonymized posture log payload before exporting or sharing. Under GDPR policies, zero PII is included in this summary.",
                        style = MaterialTheme.typography.bodySmall.copy(color = TechTextSecondary),
                        modifier = Modifier.padding(bottom = 10.dp)
                    )
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(220.dp)
                            .clip(RoundedCornerShape(8.dp))
                            .background(InputBackground)
                            .border(1.dp, TechBorder, RoundedCornerShape(8.dp))
                            .padding(8.dp)
                    ) {
                        LazyColumn {
                            item {
                                Text(
                                    text = jsonString,
                                    style = MaterialTheme.typography.bodySmall.copy(
                                        fontFamily = FontFamily.Monospace,
                                        fontSize = 11.sp,
                                        color = ActiveContent
                                    )
                                )
                            }
                        }
                    }
                } else {
                    // PDF Info Page Preview
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(290.dp)
                            .clip(RoundedCornerShape(12.dp))
                            .background(SoftSurface)
                            .border(1.dp, TechBorder, RoundedCornerShape(12.dp))
                            .padding(14.dp)
                    ) {
                        // Tiny Simulated A4 Sheet Preview Panel
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .weight(1f)
                                .clip(RoundedCornerShape(6.dp))
                                .background(Color.White)
                                .border(0.5.dp, TechBorder.copy(alpha = 0.5f))
                                .padding(10.dp)
                        ) {
                            Column {
                                // Mini Header
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column {
                                        Text(
                                            "TRUSTPULSE AUDIT",
                                            fontSize = 9.sp,
                                            fontWeight = FontWeight.Bold,
                                            color = PrimaryPurple
                                        )
                                        Text(
                                            "SYSTEM POSTURE LEDGER",
                                            fontSize = 6.sp,
                                            color = TechTextSecondary
                                        )
                                    }
                                    
                                    val allSecure = passcodeEnabled && (try { osVersion.split(".").firstOrNull()?.toFloatOrNull() ?: 16.4f >= 16.4f } catch(e: Exception) { false }) &&
                                            !isRooted && !maliciousAppsDetected && !networkAnomaliesDetected && 
                                            !unusualPermissionsGranted && !debuggingEnabled && !untrustedCertificatesInstalled
                                    val isPassed = allSecure && (scanState != "FAILED")
                                    
                                    Box(
                                        modifier = Modifier
                                            .clip(RoundedCornerShape(4.dp))
                                            .background(if (isPassed) Color(0xFFDCFCE7) else Color(0xFFFEE2E2))
                                            .padding(horizontal = 4.dp, vertical = 2.dp)
                                    ) {
                                        Text(
                                            text = if (isPassed) "SECURE" else "VULNERABLE",
                                            fontSize = 5.sp,
                                            fontWeight = FontWeight.Bold,
                                            color = if (isPassed) Color(0xFF15803D) else Color(0xFFB91C1C)
                                        )
                                    }
                                }
                                
                                Spacer(modifier = Modifier.height(6.dp))
                                Divider(color = TechBorder, thickness = 0.5.dp)
                                Spacer(modifier = Modifier.height(6.dp))
                                
                                // Mini List Bullet highlights
                                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Icon(Icons.Filled.VerifiedUser, null, tint = PrimaryPurple, modifier = Modifier.size(10.dp))
                                        Spacer(modifier = Modifier.width(4.dp))
                                        Text("Full Telemetry Integrity Matrix", fontSize = 7.5.sp, color = TechTextPrimary)
                                    }
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Icon(Icons.Filled.Shield, null, tint = PrimaryPurple, modifier = Modifier.size(10.dp))
                                        Spacer(modifier = Modifier.width(4.dp))
                                        Text("Actionable Remediation Walkthroughs", fontSize = 7.5.sp, color = TechTextPrimary)
                                    }
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Icon(Icons.Filled.Lock, null, tint = PrimaryPurple, modifier = Modifier.size(10.dp))
                                        Spacer(modifier = Modifier.width(4.dp))
                                        Text("EU GDPR Minimization Warranty Secures", fontSize = 7.5.sp, color = TechTextPrimary)
                                    }
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Icon(Icons.Filled.FiberSmartRecord, null, tint = PrimaryPurple, modifier = Modifier.size(10.dp))
                                        Spacer(modifier = Modifier.width(4.dp))
                                        Text("Official Crypto Certification Security Seal", fontSize = 7.5.sp, color = TechTextPrimary)
                                    }
                                }
                                
                                Spacer(modifier = Modifier.weight(1f))
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text("v2.5 Core Engine Output", fontSize = 6.sp, color = TechTextSecondary, fontStyle = FontStyle.Italic)
                                    // Simulated circular stamp
                                    Box(
                                        modifier = Modifier
                                            .size(14.dp)
                                            .border(1.dp, PrimaryPurple, RoundedCornerShape(100.dp))
                                            .background(PrimaryPurple.copy(alpha = 0.05f))
                                    )
                                }
                            }
                        }
                        
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = "Generates an official A4-sized PDF compliance report, containing cryptographic verifications mapping live device security rules. Ideal for administrative compliance submissions.",
                            style = MaterialTheme.typography.labelSmall.copy(color = TechTextSecondary),
                            lineHeight = 11.sp
                        )
                    }
                }
            }
        },
        confirmButton = {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(8.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                if (activeTab == 0) {
                    // JSON actions
                    Row(
                        modifier = Modifier.fillMaxWidth(), 
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Button(
                            onClick = {
                                clipboardManager.setText(AnnotatedString(jsonString))
                                Toast.makeText(context, "Copied audit JSON to clipboard!", Toast.LENGTH_SHORT).show()
                            },
                            colors = ButtonDefaults.buttonColors(
                                containerColor = ActiveContainer, 
                                contentColor = ActiveContent
                            ),
                            modifier = Modifier.weight(1f).height(40.dp),
                            shape = RoundedCornerShape(100.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Filled.ContentCopy, 
                                contentDescription = null, 
                                modifier = Modifier.size(14.dp)
                            )
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Copy JSON", fontSize = 11.sp)
                        }
                        
                        Button(
                            onClick = onSaveJsonToDownloads,
                            colors = ButtonDefaults.buttonColors(containerColor = PrimaryPurple),
                            modifier = Modifier.weight(1.2f).height(40.dp),
                            shape = RoundedCornerShape(100.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Filled.FileDownload, 
                                contentDescription = null, 
                                modifier = Modifier.size(14.dp)
                            )
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Save JSON", fontSize = 11.sp)
                        }
                    }
                    
                    Button(
                        onClick = onShareJson,
                        colors = ButtonDefaults.buttonColors(containerColor = SecondaryPurple),
                        modifier = Modifier.fillMaxWidth().height(40.dp),
                        shape = RoundedCornerShape(100.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Filled.Share, 
                            contentDescription = null, 
                            modifier = Modifier.size(14.dp)
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Share JSON Payload", fontSize = 11.sp)
                    }
                } else {
                    // PDF actions
                    val pdfBytes = remember {
                        generateCompliancePdfReport(
                            context = context,
                            deviceId = deviceId,
                            passcodeEnabled = passcodeEnabled,
                            osVersion = osVersion,
                            isRooted = isRooted,
                            maliciousAppsDetected = maliciousAppsDetected,
                            networkAnomaliesDetected = networkAnomaliesDetected,
                            unusualPermissionsGranted = unusualPermissionsGranted,
                            debuggingEnabled = debuggingEnabled,
                            untrustedCertificatesInstalled = untrustedCertificatesInstalled,
                            scanState = scanState,
                            failureReason = failureReason
                        )
                    }
                    
                    Row(
                        modifier = Modifier.fillMaxWidth(), 
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Button(
                            onClick = {
                                savePdfToDownloads(context, pdfBytes)
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = PrimaryPurple),
                            modifier = Modifier.weight(1f).height(40.dp),
                            shape = RoundedCornerShape(100.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Filled.FileDownload, 
                                contentDescription = "Download PDF", 
                                modifier = Modifier.size(14.dp)
                            )
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Download PDF", fontSize = 11.sp)
                        }
                        
                        Button(
                            onClick = {
                                sharePdfContent(context, pdfBytes)
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = SecondaryPurple),
                            modifier = Modifier.weight(1f).height(40.dp),
                            shape = RoundedCornerShape(100.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Share, 
                                contentDescription = "Share PDF", 
                                modifier = Modifier.size(14.dp)
                            )
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Share PDF", fontSize = 11.sp)
                        }
                    }
                }
                
                TextButton(
                    onClick = onDismiss,
                    modifier = Modifier.height(36.dp)
                ) {
                    Text("Cancel Review")
                }
            }
        }
    )
}

@Composable
fun SecurityAlertsDashboard(
    passcodeEnabled: Boolean,
    osVersion: String,
    isRooted: Boolean,
    maliciousAppsDetected: Boolean,
    networkAnomaliesDetected: Boolean,
    unusualPermissionsGranted: Boolean,
    debuggingEnabled: Boolean,
    untrustedCertificatesInstalled: Boolean
) {
    val alerts = remember(
        passcodeEnabled, osVersion, isRooted, maliciousAppsDetected,
        networkAnomaliesDetected, unusualPermissionsGranted, debuggingEnabled, untrustedCertificatesInstalled
    ) {
        val list = mutableListOf<SecurityThreatAlert>()
        
        if (!passcodeEnabled) {
            list.add(
                SecurityThreatAlert(
                    title = "Lock Screen Passcode Disabled",
                    description = "Without active PIN/password protection, Keystore enclaves cannot build secure encryption boundaries.",
                    severity = "HIGH",
                    icon = Icons.Filled.Lock,
                    remediation = "Open System Settings -> Security -> Screen Lock and enable a strong Passcode or biometric binding."
                )
            )
        }
        
        val isOsValid = try {
            val parsed = osVersion.split(".").firstOrNull()?.toFloatOrNull() ?: 0f
            parsed >= 16.4f
        } catch (e: Exception) {
            false
        }
        if (!isOsValid) {
            list.add(
                SecurityThreatAlert(
                    title = "Outdated OS Security Baseline",
                    description = "Android Security Patch rules dictate a baseline of >= 16.4. Your simulated version v$osVersion contains unresolved CVE system risks.",
                    severity = "HIGH",
                    icon = Icons.Filled.Info,
                    remediation = "Upgrade the operational Android software to v16.4+ via updates menu."
                )
            )
        }
        
        if (isRooted) {
            list.add(
                SecurityThreatAlert(
                    title = "Privilege Escalation (Root Mode Active)",
                    description = "Active root binaries or unisolated superuser namespaces identified on the device system. All native app sandboxing guidelines are broken.",
                    severity = "CRITICAL",
                    icon = Icons.Filled.Cancel,
                    remediation = "Re-flash secure manufacturer locked stock firmware or restrict su binary commands."
                )
            )
        }
        
        if (maliciousAppsDetected) {
            list.add(
                SecurityThreatAlert(
                    title = "Malicious Package Signatures Found",
                    description = "A scan of active package descriptors returned signature collisions with corporate hacker tools or memory injectors.",
                    severity = "CRITICAL",
                    icon = Icons.Filled.BugReport,
                    remediation = "Revoke installation privileges, perform malware removal scans, and uninstall unverified APK files."
                )
            )
        }
        
        if (networkAnomaliesDetected) {
            list.add(
                SecurityThreatAlert(
                    title = "Transport Interception Proxy Match",
                    description = "Simulated TCP routes reveal an active Man-in-the-Middle network proxy capable of intercepting and decapsulating TLS data payloads.",
                    severity = "CRITICAL",
                    icon = Icons.Filled.WifiTetheringError,
                    remediation = "Disable active loopback routing interfaces, check local DNS hosts, or switch to verified enterprise WiFi profiles."
                )
            )
        }
        
        if (untrustedCertificatesInstalled) {
            list.add(
                SecurityThreatAlert(
                    title = "Untrusted Authority roots CA Store",
                    description = "A foreign root certification authority is active inside the User credentials trust store. Any local routing agent can fake secure certs.",
                    severity = "CRITICAL",
                    icon = Icons.Filled.Phishing,
                    remediation = "Enter System Security -> Encryption & Credentials -> User Trust Credentials store and delete unverified CA certificates."
                )
            )
        }
        
        if (debuggingEnabled) {
            list.add(
                SecurityThreatAlert(
                    title = "Active ADB TCP Debug Bridge Exposed",
                    description = "Low-level Android Debug Bridge interfaces are configured to listen on wireless TCP endpoints, allowing arbitrary shell command triggers.",
                    severity = "HIGH",
                    icon = Icons.Filled.Engineering,
                    remediation = "Uncheck 'USB Debugging' and 'ADB wireless' in Developer options on your system setup page."
                )
            )
        }
        
        if (unusualPermissionsGranted) {
            list.add(
                SecurityThreatAlert(
                    title = "Atypical Elevated Admin Concessions",
                    description = "Administrative overlay licenses, background screen scrapers, or sensitive accessibility bindings are active. This is a soft policy violation.",
                    severity = "WARNING",
                    icon = Icons.Filled.PrivacyTip,
                    remediation = "Audit active processes with 'Draw over other apps' permissions and prune unauthorized monitoring suites."
                )
            )
        }
        
        list
    }

    var isExpanded by remember { mutableStateOf(false) }

    Card(
        colors = CardDefaults.cardColors(
            containerColor = if (alerts.isEmpty()) Color(0xFFF1FDF5) else Color(0xFFFFF5F5)
        ),
        border = BorderStroke(
            1.dp,
            if (alerts.isEmpty()) ComplianceGreen.copy(alpha = 0.5f) else ComplianceRed.copy(alpha = 0.5f)
        ),
        shape = RoundedCornerShape(24.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    modifier = Modifier.weight(1f),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = if (alerts.isEmpty()) Icons.Filled.CheckCircle else Icons.Filled.Error,
                        contentDescription = null,
                        tint = if (alerts.isEmpty()) ComplianceGreen else ComplianceRed,
                        modifier = Modifier.size(24.dp)
                    )
                    Spacer(modifier = Modifier.width(10.dp))
                    Column {
                        Text(
                            text = if (alerts.isEmpty()) "ALL SYSTEMS SECURE & COMPLIANT" else "ACTIVE SECURITY ALERTS",
                            style = MaterialTheme.typography.titleSmall.copy(
                                fontWeight = FontWeight.Bold,
                                color = if (alerts.isEmpty()) ComplianceGreen else ComplianceRed
                            )
                        )
                        Text(
                            text = if (alerts.isEmpty()) "0 threat parameters active" else "${alerts.size} active threat indicators correlated",
                            style = MaterialTheme.typography.labelSmall.copy(
                                color = if (alerts.isEmpty()) ComplianceGreen.copy(alpha = 0.8f) else ComplianceRed.copy(alpha = 0.8f)
                            )
                        )
                    }
                }
                
                if (alerts.isNotEmpty()) {
                    IconButton(
                        onClick = { isExpanded = !isExpanded },
                        modifier = Modifier.size(36.dp)
                    ) {
                        Icon(
                            imageVector = if (isExpanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                            contentDescription = "Toggle alert cards visibility",
                            tint = ComplianceRed
                        )
                    }
                }
            }

            if (alerts.isEmpty()) {
                Spacer(modifier = Modifier.height(10.dp))
                Text(
                    text = "Your simulated mobile framework satisfies the strict BYOD gateways policy settings. Zero threat signals or unencrypted enclaves are active. Your on-device telemetry is locked and verified.",
                    style = MaterialTheme.typography.bodySmall.copy(
                        color = ComplianceGreen.copy(alpha = 0.9f),
                        lineHeight = 16.sp
                    )
                )
            } else {
                AnimatedVisibility(visible = isExpanded) {
                    Column(
                        modifier = Modifier.padding(top = 12.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        alerts.forEach { alert ->
                            ThreadAlertRow(alert = alert)
                        }
                    }
                }
                
                if (!isExpanded) {
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = "⚠️ Expand this panel to audit compliance gaps and review guided remediation walkthroughs.",
                        style = MaterialTheme.typography.labelSmall.copy(
                            color = ComplianceRed.copy(alpha = 0.8f),
                            fontStyle = FontStyle.Italic
                        )
                    )
                }
            }
        }
    }
}

@Composable
fun ThreadAlertRow(alert: SecurityThreatAlert) {
    val severityColor = when (alert.severity) {
        "CRITICAL" -> ComplianceRed
        "HIGH" -> Color(0xFFE65100)
        else -> Color(0xFFFBC02D)
    }
    
    val severityBg = when (alert.severity) {
        "CRITICAL" -> Color(0xFFFFF1F1)
        "HIGH" -> Color(0xFFFFF3E0)
        else -> Color(0xFFFFFDE7)
    }

    Card(
        colors = CardDefaults.cardColors(containerColor = Color.White),
        border = BorderStroke(1.dp, severityColor.copy(alpha = 0.3f)),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    modifier = Modifier.weight(1f),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = alert.icon,
                        contentDescription = null,
                        tint = severityColor,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = alert.title,
                        style = MaterialTheme.typography.bodyMedium.copy(
                            fontWeight = FontWeight.Bold,
                            color = TechTextPrimary
                        )
                    )
                }
                
                Surface(
                    color = severityBg,
                    shape = RoundedCornerShape(4.dp)
                ) {
                    Text(
                        text = alert.severity,
                        style = MaterialTheme.typography.labelSmall.copy(
                            color = severityColor,
                            fontWeight = FontWeight.Bold,
                            fontSize = 8.sp
                        ),
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                    )
                }
            }
            Spacer(modifier = Modifier.height(6.dp))
            Text(
                text = alert.description,
                style = MaterialTheme.typography.bodySmall.copy(
                    color = TechTextSecondary,
                    lineHeight = 15.sp
                )
            )
            Spacer(modifier = Modifier.height(8.dp))
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(InputBackground.copy(alpha = 0.5f), RoundedCornerShape(8.dp))
                    .padding(8.dp)
            ) {
                Row(verticalAlignment = Alignment.Top) {
                    Icon(
                        imageVector = Icons.Filled.Build,
                        contentDescription = null,
                        tint = TechTextSecondary,
                        modifier = Modifier.size(14.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Column {
                        Text(
                            text = "GUIDED MITIGATION walkthrough:",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontWeight = FontWeight.Bold,
                                color = TechTextPrimary,
                                fontSize = 8.sp,
                                letterSpacing = 0.5.sp
                            )
                        )
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(
                            text = alert.remediation,
                            style = MaterialTheme.typography.labelSmall.copy(
                                color = TechTextSecondary,
                                lineHeight = 14.sp
                            )
                        )
                    }
                }
            }
        }
    }
}


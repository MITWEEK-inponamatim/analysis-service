"""Deterministic APK analysis rules and investigation gate.

Correlates manifest permissions with decompiled code patterns to produce
conclusive findings. Gate decides whether to run agent-based investigation.
"""

from typing import Any

from .risk import finding
from .schemas import Finding


def code_pattern_findings(manifest: dict[str, Any], decompiled: dict[str, Any]) -> list[Finding]:
    """
    Correlate manifest + decompiled code → conclusive findings.
    
    Rules:
    - Permission + matching code = high severity
    - Code pattern without permission = medium (capability present but not declared)
    - Package name vs app label mismatch = brand impersonation
    """
    findings: list[Finding] = []
    
    permissions = set(manifest.get("permissions", []))
    package = decompiled.get("package_name", "unknown")
    app_label = manifest.get("app_label", "")
    code_patterns = decompiled.get("code_patterns", {})
    native_libs = decompiled.get("native_libs", {})
    extracted_urls = decompiled.get("extracted_urls", [])
    api_calls = decompiled.get("api_calls", {})
    
    # SMS forwarding: READ_SMS/RECEIVE_SMS + sendTextMessage code
    if ("android.permission.READ_SMS" in permissions or "android.permission.RECEIVE_SMS" in permissions):
        if "sms_forwarding" in code_patterns:
            matches = code_patterns["sms_forwarding"]
            findings.append(finding(
                "SMS diteruskan ke nomor lain (kode sendTextMessage ditemukan)",
                "code_correlation",
                "high",
                metadata={
                    "permissions": ["READ_SMS", "SEND_SMS"],
                    "code_matches": [m["match"] for m in matches[:2]],
                    "classes": [m["class"] for m in matches[:2]],
                },
            ))
    
    # Overlay attack: SYSTEM_ALERT_WINDOW + WindowManager.addView
    if "android.permission.SYSTEM_ALERT_WINDOW" in permissions:
        if "overlay_attack" in code_patterns:
            matches = code_patterns["overlay_attack"]
            findings.append(finding(
                "Overlay attack terdeteksi (WindowManager.addView dengan TYPE_SYSTEM_ALERT)",
                "code_correlation",
                "critical",
                metadata={
                    "permission": "SYSTEM_ALERT_WINDOW",
                    "code_matches": [m["match"] for m in matches[:2]],
                    "classes": [m["class"] for m in matches[:2]],
                },
            ))
    
    # Accessibility abuse: BIND_ACCESSIBILITY_SERVICE + AccessibilityService code
    if "android.permission.BIND_ACCESSIBILITY_SERVICE" in permissions:
        if "accessibility_abuse" in code_patterns:
            matches = code_patterns["accessibility_abuse"]
            findings.append(finding(
                "Accessibility service disalahgunakan untuk otomasi atau keylogging",
                "code_correlation",
                "high",
                metadata={
                    "permission": "BIND_ACCESSIBILITY_SERVICE",
                    "code_matches": [m["match"] for m in matches[:2]],
                    "classes": [m["class"] for m in matches[:2]],
                },
            ))
    
    # Data exfiltration: contacts/location permission + network code
    exfil_permissions = {
        "android.permission.READ_CONTACTS",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.READ_CALL_LOG",
        "android.permission.READ_PHONE_STATE",
    }
    if exfil_permissions & permissions:
        if "data_exfiltration" in code_patterns and "c2_communication" in code_patterns:
            findings.append(finding(
                f"Data sensitif (kontak/lokasi) dikirim ke server eksternal",
                "code_correlation",
                "high",
                metadata={
                    "permissions": sorted(exfil_permissions & permissions),
                    "network_urls": extracted_urls[:3],
                    "exfil_classes": [m["class"] for m in code_patterns["data_exfiltration"][:2]],
                },
            ))
    
    # Native lib + network = stage-2 loader
    if native_libs and ("c2_communication" in code_patterns or extracted_urls):
        lib_count = sum(len(libs) for libs in native_libs.values())
        findings.append(finding(
            f"Native library ({lib_count} file) dengan komunikasi jaringan (kemungkinan stage-2 payload)",
            "code_correlation",
            "high",
            metadata={
                "native_libs": native_libs,
                "network_urls": extracted_urls[:3],
            },
        ))
    
    # Package impersonation: brand keyword in label, mismatch with package
    if app_label:
        brand = _detect_brand_claim(app_label, package)
        if brand and not _package_matches_brand(package, brand):
            findings.append(finding(
                f"Package name '{package}' tidak cocok dengan label '{app_label}' (kemungkinan impersonasi brand '{brand}')",
                "code_correlation",
                "high",
                metadata={
                    "package": package,
                    "app_label": app_label,
                    "suspected_brand": brand,
                },
            ))
    
    # Dynamic loading without clear purpose
    if "dynamic_loading" in code_patterns:
        matches = code_patterns["dynamic_loading"]
        # Medium if just capability, high if combined with obfuscation or anti-analysis
        severity = "high" if (decompiled.get("obfuscation_detected") or "anti_analysis" in code_patterns) else "medium"
        findings.append(finding(
            f"Dynamic code loading terdeteksi (DexClassLoader/PathClassLoader) - runtime behavior tidak tervalidasi",
            "code_correlation",
            severity,
            metadata={
                "code_matches": [m["match"] for m in matches[:2]],
                "classes": [m["class"] for m in matches[:2]],
            },
        ))
    
    # C2 URLs extracted (standalone, no permission needed)
    if extracted_urls:
        suspicious_urls = [url for url in extracted_urls if _is_suspicious_url(url)]
        if suspicious_urls:
            findings.append(finding(
                f"URL mencurigakan ditemukan di code ({len(suspicious_urls)} endpoint)",
                "code_correlation",
                "medium",
                metadata={
                    "urls": suspicious_urls[:5],
                },
            ))
    
    # Anti-analysis techniques
    if "anti_analysis" in code_patterns:
        matches = code_patterns["anti_analysis"]
        findings.append(finding(
            "Teknik anti-analysis terdeteksi (debugger check, emulator detection)",
            "code_correlation",
            "medium",
            metadata={
                "code_matches": [m["match"] for m in matches[:2]],
                "classes": [m["class"] for m in matches[:2]],
            },
        ))
    
    # Notification listener abuse (Tria stealer pattern)
    if "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" in permissions:
        if "notification_listener" in code_patterns:
            matches = code_patterns["notification_listener"]
            findings.append(finding(
                "Notification listener abuse terdeteksi (steal OTP dari notifikasi apps)",
                "code_correlation",
                "critical",
                metadata={
                    "permission": "BIND_NOTIFICATION_LISTENER_SERVICE",
                    "code_matches": [m["match"] for m in matches[:2]],
                    "classes": [m["class"] for m in matches[:2]],
                },
            ))
    
    # Telegram bot exfiltration (C2 via Telegram)
    if "telegram_bot" in code_patterns:
        matches = code_patterns["telegram_bot"]
        findings.append(finding(
            "Telegram bot API terdeteksi (data dikirim ke Telegram sebagai C2 channel)",
            "code_correlation",
            "critical",
            metadata={
                "code_matches": [m["match"] for m in matches[:2]],
                "classes": [m["class"] for m in matches[:2]],
            },
        ))
    
    # Banking trojan: query installed packages for banking apps
    if "banking_trojan" in code_patterns:
        matches = code_patterns["banking_trojan"]
        findings.append(finding(
            "Banking trojan behavior: query installed packages untuk target banking apps",
            "code_correlation",
            "high",
            metadata={
                "code_matches": [m["match"] for m in matches[:2]],
                "classes": [m["class"] for m in matches[:2]],
            },
        ))
    
    # Device admin abuse (prevent uninstall, lock device)
    if "android.permission.BIND_DEVICE_ADMIN" in permissions:
        if "device_admin" in code_patterns:
            matches = code_patterns["device_admin"]
            findings.append(finding(
                "Device admin abuse terdeteksi (lock device, prevent uninstall, wipe data)",
                "code_correlation",
                "critical",
                metadata={
                    "permission": "BIND_DEVICE_ADMIN",
                    "code_matches": [m["match"] for m in matches[:2]],
                    "classes": [m["class"] for m in matches[:2]],
                },
            ))
    
    return findings


def investigation_gate(
    findings: list[Finding],
    manifest: dict[str, Any],
    decompiled: dict[str, Any],
    unavailable: list[str],
) -> tuple[bool, list[str]]:
    """
    Decide whether to run agent investigation.
    
    Run agents only when deterministic evidence leaves security questions open.
    
    Returns:
        (enabled, reasons)
    """
    
    # Skip if already conclusive (critical/high severity)
    if any(f.severity in {"critical", "high"} for f in findings):
        return False, ["conclusive_deterministic_finding"]
    
    reasons: list[str] = []
    
    code_patterns = decompiled.get("code_patterns", {})
    native_libs = decompiled.get("native_libs", {})
    permissions = set(manifest.get("permissions", []))
    obfuscation = decompiled.get("obfuscation_detected", False)
    
    # Native libs present but behavior unclear
    if native_libs and not any("native" in f.source or f.indicator.startswith("Native") for f in findings):
        lib_count = sum(len(libs) for libs in native_libs.values())
        if lib_count > 2:  # multiple native libs = suspicious
            reasons.append("native_lib_behavior_unclear")
    
    # Obfuscated + sensitive permissions (ProGuard: a.b.c.d classes)
    sensitive_perms = {
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
        "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.READ_CONTACTS",
        "android.permission.ACCESS_FINE_LOCATION",
    }
    if obfuscation and (sensitive_perms & permissions):
        reasons.append("obfuscated_with_sensitive_permissions")
    
    # Medium findings with "suspected" indicator (not conclusive)
    if any(f.severity == "medium" and ("kemungkinan" in f.indicator or "suspected" in f.indicator.lower()) for f in findings):
        reasons.append("suspected_behavior_unconfirmed")
    
    # Dynamic loading present (runtime behavior unknown)
    if "dynamic_loading" in code_patterns:
        reasons.append("dynamic_code_loading")
    
    # Permission declared but no matching code found (hidden functionality?)
    high_risk_perms = {
        "android.permission.SEND_SMS",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
        "android.permission.BIND_DEVICE_ADMIN",
    }
    declared_high_risk = high_risk_perms & permissions
    if declared_high_risk:
        # Check if we found corresponding code
        if "android.permission.SEND_SMS" in declared_high_risk and "sms_forwarding" not in code_patterns:
            reasons.append("sms_permission_usage_unclear")
        if "android.permission.SYSTEM_ALERT_WINDOW" in declared_high_risk and "overlay_attack" not in code_patterns:
            reasons.append("overlay_permission_usage_unclear")
        if "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" in declared_high_risk and "notification_listener" not in code_patterns:
            reasons.append("notification_listener_usage_unclear")
        if "android.permission.BIND_DEVICE_ADMIN" in declared_high_risk and "device_admin" not in code_patterns:
            reasons.append("device_admin_usage_unclear")
    
    # Crypto usage detected (may hide C2 communication)
    if "crypto_usage" in code_patterns and "c2_communication" in code_patterns:
        reasons.append("encrypted_communication_detected")
    
    # Jadx unavailable
    if "jadx_decompile" in unavailable:
        reasons.append("decompilation_failed")
    
    return bool(reasons), reasons or ["deterministic_evidence_sufficient"]


def _detect_brand_claim(label: str, package: str) -> str:
    """Detect brand keyword in app label or package."""
    BRAND_KEYWORDS = (
        "bank", "bca", "bri", "bni", "mandiri", "bsi", "cimb", "permata", "danamon",
        "dana", "ovo", "gopay", "shopeepay", "linkaja", "jenius", "jago", "paypal",
        "whatsapp", "instagram", "facebook", "telegram", "tokopedia", "shopee", "lazada",
        "netflix", "spotify", "google", "microsoft", "apple", "tiktok", "bukalapak",
    )
    
    haystack = f"{label} {package}".casefold()
    for brand in BRAND_KEYWORDS:
        if brand in haystack:
            return brand
    return ""


def _package_matches_brand(package: str, brand: str) -> bool:
    """Check if package name legitimately matches brand."""
    package_lower = package.casefold()
    
    # Official domains/packages for known brands
    OFFICIAL_PACKAGES = {
        "bca": ["com.bca", "id.co.bca"],
        "bri": ["com.bri", "id.co.bri"],
        "mandiri": ["com.mandiri", "id.co.bankmandiri"],
        "dana": ["id.dana"],
        "ovo": ["ovo.id"],
        "gopay": ["com.gojek", "com.gopay"],
        "tokopedia": ["com.tokopedia"],
        "shopee": ["com.shopee"],
        "whatsapp": ["com.whatsapp"],
        "instagram": ["com.instagram"],
        "facebook": ["com.facebook"],
    }
    
    official = OFFICIAL_PACKAGES.get(brand, [])
    return any(package_lower.startswith(pkg) for pkg in official)


def _is_suspicious_url(url: str) -> bool:
    """Heuristic: check if URL looks suspicious."""
    url_lower = url.lower()
    
    # Short domains with numeric TLD
    if re.match(r"https?://[a-z0-9-]{1,8}\.(tk|ga|ml|cf|gq|xyz|top)", url_lower):
        return True
    
    # IP address URLs
    if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url_lower):
        return True
    
    # Suspicious keywords
    suspicious = ["phish", "scam", "hack", "crack", "dump", "leak", "admin", "panel", "c2", "malware"]
    if any(kw in url_lower for kw in suspicious):
        return True
    
    return False


import re

"""Jadx-based APK decompilation and code pattern extraction.

Runs jadx-cli in isolated worker to decompile APK and extract behavioral patterns.
"""

import asyncio
import json
import os
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


# Malicious code patterns (regex on decompiled Java/Kotlin)
MALICIOUS_PATTERNS = {
    "sms_forwarding": [
        rb"SmsManager\..*sendTextMessage\(",
        rb"telephony\.SmsMessage",
        rb"getSmsManager\(\)",
    ],
    "notification_listener": [
        rb"NotificationListenerService",
        rb"onNotificationPosted|StatusBarNotification",
        rb"getActiveNotifications",
    ],
    "overlay_attack": [
        rb"WindowManager\.addView\(",
        rb"TYPE_SYSTEM_ALERT|TYPE_APPLICATION_OVERLAY",
        rb"LayoutParams.*FLAG_NOT_TOUCH",
    ],
    "accessibility_abuse": [
        rb"AccessibilityService",
        rb"performGlobalAction|findAccessibilityNodeInfosByText",
        rb"AccessibilityEvent\.TYPE_",
    ],
    "c2_communication": [
        rb"HttpURLConnection|OkHttpClient|Retrofit",
        rb"https?://[^\s\"\'<>]{8,300}",
    ],
    "telegram_bot": [
        rb"api\.telegram\.org/bot[^\s\"\'<>]+",
        rb"sendMessage.*chat_id",
        rb"t\.me/[a-zA-Z0-9_]{5,32}",
    ],
    "data_exfiltration": [
        rb"ContentResolver\.query.*ContactsContract",
        rb"TelephonyManager\.getDeviceId|getSubscriberId",
        rb"LocationManager\.getLastKnownLocation",
    ],
    "banking_trojan": [
        rb"getInstalledPackages|queryIntentActivities",
        rb"com\..*\.bank|id\.co\..*bank",
        rb"PackageManager\.getApplicationInfo",
    ],
    "device_admin": [
        rb"DeviceAdminReceiver|DevicePolicyManager",
        rb"lockNow|wipeData|resetPassword",
        rb"ACTION_DEVICE_ADMIN_ENABLED",
    ],
    "dynamic_loading": [
        rb"DexClassLoader|InMemoryDexClassLoader|PathClassLoader",
        rb"Class\.forName\(",
        rb"loadClass\(",
    ],
    "anti_analysis": [
        rb"Debug\.isDebuggerConnected",
        rb"Build\.FINGERPRINT.*generic|goldfish",
        rb"checkCallingOrSelfPermission",
    ],
    "crypto_usage": [
        rb"javax\.crypto\.Cipher",
        rb"SecretKeySpec|KeyGenerator",
    ],
}

# Suspicious API calls
SUSPICIOUS_APIS = {
    "sms": ["SmsManager.sendTextMessage", "SmsManager.sendDataMessage"],
    "notification": ["NotificationListenerService.onNotificationPosted", "StatusBarNotification.getPackageName"],
    "overlay": ["WindowManager.addView", "WindowManager.updateViewLayout"],
    "contacts": ["ContactsContract.Contacts.CONTENT_URI", "ContentResolver.query"],
    "location": ["LocationManager.getLastKnownLocation", "requestLocationUpdates"],
    "phone_state": ["TelephonyManager.getDeviceId", "getLine1Number", "getSubscriberId"],
    "device_admin": ["DevicePolicyManager.lockNow", "DevicePolicyManager.wipeData"],
    "package_query": ["PackageManager.getInstalledPackages", "PackageManager.queryIntentActivities"],
    "reflection": ["Class.forName", "getDeclaredMethod", "invoke"],
}


async def decompile_apk(apk_bytes: bytes, timeout: int = 60) -> dict[str, Any]:
    """
    Decompile APK using jadx-cli and extract behavioral patterns.
    
    Args:
        apk_bytes: APK file content
        timeout: decompilation timeout in seconds
    
    Returns:
        {
            "manifest": parsed AndroidManifest.xml dict,
            "package_name": "com.example.app",
            "classes": ["com.example.MainActivity", ...],
            "native_libs": {"arm64-v8a": ["libfoo.so"], ...},
            "key_sources": {class_name: source_snippet},
            "code_patterns": {pattern: matches},
            "api_calls": {api: count},
            "extracted_urls": [urls],
            "obfuscation_detected": bool,
            "code_index": {class_name: {file, line_count}},
        }
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        apk_path = tmp_path / "sample.apk"
        output_dir = tmp_path / "decompiled"
        
        # Write APK
        apk_path.write_bytes(apk_bytes)
        
        # Run jadx (no-res: skip resources for speed, no-debug-info: smaller output)
        try:
            proc = await asyncio.create_subprocess_exec(
                "jadx",
                "-d", str(output_dir),
                "--no-res",  # skip resources (faster)
                "--no-debug-info",
                str(apk_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            
            if proc.returncode != 0:
                raise RuntimeError(f"jadx failed: {stderr.decode()[:500]}")
        
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except:
                pass
            raise RuntimeError("jadx timeout")
        
        # Parse output
        return _extract_features(output_dir)


def _extract_features(decompiled_dir: Path) -> dict[str, Any]:
    """Extract features from jadx output directory."""
    
    manifest = _parse_manifest(decompiled_dir / "resources" / "AndroidManifest.xml")
    
    # Find sources directory
    sources_dir = decompiled_dir / "sources"
    if not sources_dir.exists():
        return {
            "manifest": manifest,
            "package_name": manifest.get("package", "unknown"),
            "classes": [],
            "native_libs": {},
            "key_sources": {},
            "code_patterns": {},
            "api_calls": {},
            "extracted_urls": [],
            "obfuscation_detected": False,
            "code_index": {},
        }
    
    # Collect Java/Kotlin files
    java_files = list(sources_dir.rglob("*.java")) + list(sources_dir.rglob("*.kt"))
    
    classes = []
    code_patterns: dict[str, list[dict]] = {}
    api_calls: dict[str, int] = {}
    extracted_urls = set()
    key_sources = {}
    code_index = {}
    
    # Obfuscation detection: check for single-char class names
    obfuscation_score = 0
    
    for file_path in java_files[:200]:  # limit to first 200 files
        relative = file_path.relative_to(sources_dir)
        class_name = str(relative.with_suffix("")).replace(os.sep, ".")
        classes.append(class_name)
        
        # Obfuscation heuristic: a.b.c, single-char package/class names
        if re.search(r"\b[a-z]\.[a-z]\.[a-z]", class_name) or re.search(r"\.[a-z]\.(?:[A-Z][a-z]?|[a-z])$", class_name):
            obfuscation_score += 1
        
        try:
            content = file_path.read_bytes()
            
            # Pattern matching
            for pattern_name, regexes in MALICIOUS_PATTERNS.items():
                for regex in regexes:
                    matches = re.findall(regex, content)
                    if matches:
                        if pattern_name not in code_patterns:
                            code_patterns[pattern_name] = []
                        
                        for match in matches[:3]:  # first 3 matches
                            code_patterns[pattern_name].append({
                                "class": class_name,
                                "match": match.decode("utf-8", errors="ignore")[:100],
                            })
            
            # Extract URLs
            urls = re.findall(rb"https?://[^\s\"\'<>]{8,300}", content)
            for url in urls[:10]:
                try:
                    extracted_urls.add(url.decode("utf-8", errors="ignore"))
                except:
                    pass
            
            # API call counting
            content_str = content.decode("utf-8", errors="ignore")
            for api_category, apis in SUSPICIOUS_APIS.items():
                for api in apis:
                    count = content_str.count(api)
                    if count > 0:
                        api_calls[api] = api_calls.get(api, 0) + count
            
            # Key sources: classes with suspicious patterns (store snippet)
            if any(pattern_name in code_patterns for pattern_name in ["sms_forwarding", "overlay_attack", "data_exfiltration"]):
                snippet = content[:4000].decode("utf-8", errors="ignore")
                key_sources[class_name] = snippet
            
            # Code index
            line_count = content.count(b"\n")
            code_index[class_name] = {
                "file": str(relative),
                "line_count": line_count,
            }
        
        except Exception:
            continue
    
    # Native libs
    native_libs = _find_native_libs(decompiled_dir)
    
    obfuscation_detected = obfuscation_score > 5 or (len(classes) > 20 and obfuscation_score / len(classes) > 0.3)
    
    return {
        "manifest": manifest,
        "package_name": manifest.get("package", "unknown"),
        "classes": classes[:100],  # truncate for response size
        "native_libs": native_libs,
        "key_sources": key_sources,
        "code_patterns": {k: v[:5] for k, v in code_patterns.items()},  # max 5 matches per pattern
        "api_calls": dict(sorted(api_calls.items(), key=lambda x: -x[1])[:20]),  # top 20
        "extracted_urls": sorted(extracted_urls)[:20],
        "obfuscation_detected": obfuscation_detected,
        "code_index": code_index,
    }


def _parse_manifest(manifest_path: Path) -> dict[str, Any]:
    """Parse AndroidManifest.xml."""
    if not manifest_path.exists():
        return {}
    
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        
        # Strip namespace
        ns = {"android": "http://schemas.android.com/apk/res/android"}
        
        package = root.get("package", "unknown")
        
        # Permissions
        permissions = [
            elem.get("{http://schemas.android.com/apk/res/android}name", "")
            for elem in root.findall("uses-permission")
        ]
        
        # Application label
        app_elem = root.find("application")
        app_label = ""
        if app_elem is not None:
            app_label = app_elem.get("{http://schemas.android.com/apk/res/android}label", "")
        
        return {
            "package": package,
            "permissions": permissions,
            "app_label": app_label,
        }
    except Exception:
        return {}


def _find_native_libs(decompiled_dir: Path) -> dict[str, list[str]]:
    """Find native libraries by architecture."""
    libs: dict[str, list[str]] = {}
    
    lib_dir = decompiled_dir / "resources" / "lib"
    if not lib_dir.exists():
        return libs
    
    for arch_dir in lib_dir.iterdir():
        if arch_dir.is_dir():
            arch = arch_dir.name
            so_files = [f.name for f in arch_dir.glob("*.so")]
            if so_files:
                libs[arch] = sorted(so_files)[:20]  # max 20 per arch
    
    return libs

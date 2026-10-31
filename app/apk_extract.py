"""Static feature extraction for untrusted APK samples.

The sample is never executed. Extraction runs in an isolated, network-less container
(``analysis-worker``); this module is also importable in-process so local development
and unit tests degrade gracefully instead of crashing when Androguard is absent.

Rules of engagement (see handoff 7.5a):
* reject zip bombs before anything is parsed;
* every extractor is wrapped so a single failing accessor cannot abort the scan;
* missing tooling is reported as ``incomplete`` with a machine-readable reason.
"""

import io
import os
import re
import tempfile
import zipfile
from typing import Any, Callable

DEFAULT_LIMITS = {
    "max_entries": 20000,
    "max_uncompressed_bytes": 500 << 20,
    "max_entry_bytes": 100 << 20,
    "max_compression_ratio": 200,
    "max_dex_bytes": 64 << 20,
    "max_asset_bytes": 1 << 20,
}

DEX_HEADER = b"dex\n"

TELEGRAM_TOKEN = re.compile(rb"\b\d{8,10}:[A-Za-z0-9_-]{35}\b")
URL_PATTERN = re.compile(rb"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,300}")
IPV4_PATTERN = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_PATTERN = re.compile(rb"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|id|xyz|top|info|biz|ru|cn|tk|cc|io|co|me|link|online|site|shop|app|live|pro|club)\b", re.IGNORECASE)

PACKER_MARKERS = (
    "libjiagu", "libshell", "libmobisec", "libdexhelper", "libsecshell", "libnesec",
    "libexec.so", "libexecmain", "libbaiduprotect", "libapkprotect", "libddog",
    "ijiami", "libkwscmm", "libtup.so", "assets/dexopt", "assets/classes.jar",
)

DYNAMIC_LOADER_MARKERS = (
    "DexClassLoader", "InMemoryDexClassLoader", "PathClassLoader", "dalvik.system",
)

MANIFEST_INDICATORS = {
    "BIND_ACCESSIBILITY_SERVICE": "aksesibilitas (accessibility service)",
    "BIND_NOTIFICATION_LISTENER_SERVICE": "pembaca notifikasi (notification listener)",
    "BIND_DEVICE_ADMIN": "admin perangkat (device admin)",
    "SYSTEM_ALERT_WINDOW": "overlay di atas aplikasi lain",
    "REQUEST_INSTALL_PACKAGES": "pemasangan paket aplikasi lain",
    "SEND_SMS": "pengiriman SMS",
    "READ_SMS": "pembacaan SMS",
    "RECEIVE_SMS": "penerimaan SMS",
}

SENSITIVE_PERMISSIONS = {
    "android.permission.SEND_SMS": "sms_send",
    "android.permission.READ_SMS": "sms_read",
    "android.permission.RECEIVE_SMS": "sms_receive",
    "android.permission.READ_CALL_LOG": "call_log",
    "android.permission.CALL_PHONE": "call",
    "android.permission.SYSTEM_ALERT_WINDOW": "overlay",
    "android.permission.REQUEST_INSTALL_PACKAGES": "install_packages",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "accessibility",
    "android.permission.BIND_DEVICE_ADMIN": "device_admin",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": "notification_listener",
    "android.permission.READ_CONTACTS": "contacts",
    "android.permission.READ_PHONE_STATE": "phone_state",
    "android.permission.CAMERA": "camera",
    "android.permission.RECORD_AUDIO": "microphone",
    "android.permission.READ_EXTERNAL_STORAGE": "storage",
    "android.permission.QUERY_ALL_PACKAGES": "package_enumeration",
}

BRAND_KEYWORDS = (
    "bank", "bca", "bri", "bni", "mandiri", "bsi", "cimb", "permata", "danamon",
    "dana", "ovo", "gopay", "shopeepay", "linkaja", "jenius", "jago", "paypal",
    "whatsapp", "instagram", "facebook", "telegram", "tokopedia", "shopee", "lazada",
    "netflix", "spotify", "google", "microsoft", "apple", "tiktok",
)


class ArchiveLimitExceeded(Exception):
    def __init__(self, reason: str, details: dict[str, Any] | None = None):
        super().__init__(reason)
        self.reason = reason
        self.details = details or {}


def _env_limit(key: str, default: int) -> int:
    try:
        value = int(os.getenv(key, ""))
    except ValueError:
        return default
    return value if value > 0 else default


def archive_limits() -> dict[str, int]:
    limits = dict(DEFAULT_LIMITS)
    limits["max_entries"] = _env_limit("MAX_APK_ENTRIES", limits["max_entries"])
    limits["max_uncompressed_bytes"] = _env_limit("MAX_APK_UNCOMPRESSED_MB", limits["max_uncompressed_bytes"] >> 20) << 20
    limits["max_entry_bytes"] = _env_limit("MAX_APK_ENTRY_MB", limits["max_entry_bytes"] >> 20) << 20
    limits["max_compression_ratio"] = _env_limit("MAX_APK_COMPRESSION_RATIO", limits["max_compression_ratio"])
    return limits


def precheck_archive(data: bytes, limits: dict[str, int] | None = None) -> dict[str, Any]:
    """Validate the ZIP container before parsing. Raises ArchiveLimitExceeded."""
    limits = limits or archive_limits()
    if len(data) < 4 or data[:4] != b"PK\x03\x04":
        raise ArchiveLimitExceeded("not_a_zip", {"size_bytes": len(data)})
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        entries = archive.infolist()
    except (zipfile.BadZipFile, OSError, ValueError) as error:
        raise ArchiveLimitExceeded("corrupt_archive", {"error": type(error).__name__}) from error

    if len(entries) > limits["max_entries"]:
        raise ArchiveLimitExceeded("too_many_entries", {"entries": len(entries), "limit": limits["max_entries"]})

    total_uncompressed = 0
    total_compressed = 0
    names: list[str] = []
    for info in entries:
        if info.file_size > limits["max_entry_bytes"]:
            raise ArchiveLimitExceeded("entry_too_large", {"name": info.filename[:200], "size": info.file_size})
        total_uncompressed += info.file_size
        total_compressed += info.compress_size
        names.append(info.filename)
        if total_uncompressed > limits["max_uncompressed_bytes"]:
            raise ArchiveLimitExceeded("uncompressed_too_large", {"uncompressed": total_uncompressed})

    if total_uncompressed > 0:
        ratio = total_uncompressed / max(total_compressed, 1)
        if ratio > limits["max_compression_ratio"]:
            raise ArchiveLimitExceeded("compression_ratio_too_high", {"ratio": int(ratio), "limit": limits["max_compression_ratio"]})

    return {"entries": len(entries), "uncompressed_bytes": total_uncompressed, "compressed_bytes": total_compressed, "names": names}


def _safe(call: Callable[..., Any], default: Any = None) -> Any:
    try:
        return call()
    except Exception:
        return default


def _load_apk_class():
    for module_path in ("androguard.core.apk", "androguard.core.bytecodes.apk"):
        try:
            module = __import__(module_path, fromlist=["APK"])
            return getattr(module, "APK")
        except Exception:
            continue
    return None


def _cert_fingerprint(cert: Any) -> str:
    """Androguard returns asn1crypto certificates, whose ``sha256`` is raw digest bytes."""
    digest = getattr(cert, "sha256", None)
    if isinstance(digest, (bytes, bytearray)):
        return bytes(digest).hex()
    return str(digest or "").lower()


def _strings_from_dex(archive: zipfile.ZipFile, limits: dict[str, int]) -> tuple[bytes, list[str]]:
    collected = bytearray()
    read: list[str] = []
    for info in archive.infolist():
        lower = info.filename.casefold()
        is_dex = lower.startswith("classes") and lower.endswith(".dex")
        is_asset_text = lower.startswith("assets/") and lower.endswith((".json", ".txt", ".xml")) and info.file_size <= limits["max_asset_bytes"]
        if not is_dex and not is_asset_text:
            continue
        if len(collected) >= limits["max_dex_bytes"]:
            break
        if info.compress_size > limits["max_entry_bytes"]:
            continue
        try:
            payload = archive.read(info)
        except Exception:
            continue
        if is_dex and not payload.startswith(DEX_HEADER):
            continue
        collected.extend(payload[: limits["max_dex_bytes"] - len(collected)])
        read.append(info.filename)
    return bytes(collected), read


def _unique(values, limit: int = 40) -> list[str]:
    seen: list[str] = []
    for value in values:
        if value is None:
            continue
        text = value if isinstance(value, str) else value.decode("utf-8", "ignore")
        text = text.strip()
        if text and text not in seen:
            seen.append(text)
        if len(seen) >= limit:
            break
    return seen


def extract_apk_features(data: bytes, limits: dict[str, int] | None = None) -> dict[str, Any]:
    """Extract static features. Returns {"available", "features", "incomplete_reasons"}."""
    limits = limits or archive_limits()
    reasons: list[str] = []
    features: dict[str, Any] = {
        "package_name": None,
        "app_label": None,
        "version_name": None,
        "signer_sha256": [],
        "permissions": [],
        "sensitive_permissions": [],
        "manifest_indicators": [],
        "component_counts": {},
        "hidden_launcher_icon": False,
        "hardcoded_urls": [],
        "hardcoded_domains": [],
        "hardcoded_ips": [],
        "telegram_bot_token": False,
        "native_libs": [],
        "packer_hints": [],
        "dynamic_code_loading": False,
        "dex_files": [],
    }

    summary = precheck_archive(data, limits)
    names = summary["names"]
    lowered = [name.casefold() for name in names]
    features["native_libs"] = _unique([name for name in names if name.casefold().startswith("lib/") and name.casefold().endswith(".so")], 60)
    joined = " ".join(lowered)
    features["packer_hints"] = [marker for marker in PACKER_MARKERS if marker in joined]
    if not any(name.casefold().startswith("classes") and name.casefold().endswith(".dex") for name in names):
        reasons.append("no_dex_payload")
        features["dex_missing"] = True

    archive = zipfile.ZipFile(io.BytesIO(data))
    strings, dex_names = _strings_from_dex(archive, limits)
    features["dex_files"] = dex_names
    if strings:
        features["hardcoded_urls"] = _unique(URL_PATTERN.findall(strings), 40)
        features["hardcoded_ips"] = _unique(IPV4_PATTERN.findall(strings), 20)
        features["hardcoded_domains"] = _unique(DOMAIN_PATTERN.findall(strings), 40)
        features["telegram_bot_token"] = bool(TELEGRAM_TOKEN.search(strings))
        blob = strings.decode("latin-1", "ignore")
        features["dynamic_code_loading"] = any(marker in blob for marker in DYNAMIC_LOADER_MARKERS)
    else:
        reasons.append("dex_strings_unavailable")

    apk_class = _load_apk_class()
    if apk_class is None:
        reasons.append("androguard_missing")
        return {"available": False, "features": features, "incomplete_reasons": reasons}

    try:
        handle, path = tempfile.mkstemp(suffix=".apk")
    except OSError:
        reasons.append("tempfile_unavailable")
        return {"available": False, "features": features, "incomplete_reasons": sorted(set(reasons))}
    try:
        with os.fdopen(handle, "wb") as file:
            file.write(data)
        try:
            apk = apk_class(path)
        except Exception:
            reasons.append("apk_unparseable")
            return {"available": False, "features": features, "incomplete_reasons": sorted(set(reasons))}
        if _safe(lambda: apk.is_valid_APK(), True) is False:
            reasons.append("invalid_apk")
        features["package_name"] = _safe(apk.get_package)
        features["app_label"] = _safe(apk.get_app_name)
        features["version_name"] = _safe(apk.get_androidversion_name)
        features["permissions"] = _unique(_safe(lambda: [str(p) for p in apk.get_permissions()], []), 120)
        features["sensitive_permissions"] = [
            tag for permission, tag in SENSITIVE_PERMISSIONS.items() if permission in features["permissions"]
        ]
        features["signer_sha256"] = _unique(
            _safe(lambda: [_cert_fingerprint(cert) for cert in apk.get_certificates()], []), 5
        )
        for kind, getter in (
            ("activities", "get_activities"),
            ("services", "get_services"),
            ("receivers", "get_receivers"),
            ("providers", "get_providers"),
        ):
            method = getattr(apk, getter, None)
            values = _safe(lambda m=method: [str(item) for item in m()] if m else [], [])
            features["component_counts"][kind] = len(values)
        main_activity = _safe(getattr(apk, "get_main_activity", lambda: None))
        features["hidden_launcher_icon"] = not bool(main_activity)
        manifest_text = ""
        xml_getter = getattr(apk, "get_android_manifest_xml", None)
        if xml_getter is not None:
            try:
                import xml.etree.ElementTree as ElementTree

                manifest_text = ElementTree.tostring(xml_getter(), encoding="unicode")
            except Exception:
                reasons.append("manifest_unreadable")
        if manifest_text:
            features["manifest_indicators"] = [
                label for token, label in MANIFEST_INDICATORS.items() if token in manifest_text
            ]
        else:
            reasons.append("manifest_unavailable")
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass

    return {"available": True, "features": features, "incomplete_reasons": sorted(set(reasons))}

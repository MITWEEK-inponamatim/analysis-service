"""Deterministic risk rules for APK static evidence.

The LLM never decides the verdict: it only contributes findings with traceable evidence.
These combination rules live in code so they are cheap to test and audit (handoff 7.5a, 7.7).
"""

from typing import Any

from .apk_extract import BRAND_KEYWORDS
from .risk import finding
from .schemas import Finding

SOURCE = "static_analysis"
RULE_SOURCE = "static_analysis_rules"

SENSITIVE_LABELS = {
    "sms_send": "mengirim SMS",
    "sms_read": "membaca SMS",
    "sms_receive": "menerima SMS",
    "accessibility": "memakai layanan aksesibilitas",
    "install_packages": "memasang aplikasi lain",
    "overlay": "menampilkan overlay di atas aplikasi lain",
    "device_admin": "meminta hak admin perangkat",
    "notification_listener": "membaca notifikasi aplikasi lain",
    "call_log": "membaca riwayat panggilan",
    "contacts": "membaca kontak",
    "package_enumeration": "mendaftar seluruh aplikasi terpasang",
}


def features_to_findings(features: dict[str, Any]) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    limitations: list[str] = []

    permissions = set(features.get("permissions") or [])
    sensitive = list(features.get("sensitive_permissions") or [])
    label = str(features.get("app_label") or "")
    package = str(features.get("package_name") or "")
    claim = _brand_claim(label, package)

    sms = {"sms_send", "sms_read", "sms_receive"} & set(sensitive)
    if "sms_send" in sms:
        findings.append(finding("Aplikasi meminta izin mengirim SMS.", SOURCE, "medium", {"permission": "SEND_SMS"}))
    if {"sms_read", "sms_receive"} & sms:
        findings.append(finding("Aplikasi meminta izin membaca atau menerima SMS.", SOURCE, "medium", {"permissions": sorted(sms)}))

    for tag in sensitive:
        if tag in ("sms_send", "sms_read", "sms_receive"):
            continue
        if tag in SENSITIVE_LABELS:
            severity = "medium" if tag in ("accessibility", "install_packages", "device_admin", "overlay", "notification_listener") else "low"
            findings.append(finding(f"Aplikasi meminta izin atau kemampuan: {SENSITIVE_LABELS[tag]}.", SOURCE, severity, {"capability": tag}))

    indicators = features.get("manifest_indicators") or []
    control_tokens = ("aksesibilitas", "pembaca notifikasi", "admin perangkat", "overlay")
    if any(token in item for item in indicators for token in control_tokens):
        findings.append(finding("Manifest mendeklarasikan layanan sensitif untuk mengendalikan perangkat atau notifikasi.", SOURCE, "medium", {"indicators": indicators}))

    control = {"accessibility", "overlay", "device_admin", "install_packages", "notification_listener"} & set(sensitive)
    if sms and control:
        combinations = sorted({"sms", *control})
        findings.append(finding(
            "Kombinasi berbahaya: izin SMS disertai kemampuan mengendalikan perangkat atau aplikasi lain.",
            RULE_SOURCE, "high", {"combination": combinations},
        ))

    if claim and control:
        findings.append(finding(
            f"Aplikasi memakai nama yang mengklaim brand \"{claim}\" tetapi meminta kemampuan berbahaya yang tidak wajar untuk aplikasi resmi.",
            RULE_SOURCE, "high", {"claimed_brand": claim, "package": package, "capabilities": sorted(control)},
        ))
    elif claim and sms:
        findings.append(finding(
            f"Aplikasi memakai nama yang mengklaim brand \"{claim}\" dan meminta izin SMS; verifikasi penerbit resminya.",
            RULE_SOURCE, "medium", {"claimed_brand": claim, "package": package},
        ))

    if features.get("telegram_bot_token"):
        findings.append(finding("APK mengandung token bot Telegram yang tertanam; pola ini lazim pada aplikasi pencuri data (info stealer).", RULE_SOURCE, "high", {}))

    if features.get("hidden_launcher_icon"):
        findings.append(finding("APK tidak punya launcher activity sehingga ikon aplikasi dapat disembunyikan.", SOURCE, "medium", {}))

    if features.get("dynamic_code_loading"):
        findings.append(finding("APK memuat kode tambahan saat berjalan (dynamic code loading).", SOURCE, "medium", {}))

    urls = features.get("hardcoded_urls") or []
    ips = features.get("hardcoded_ips") or []
    if urls:
        findings.append(finding("APK menyimpan URL yang tertanam di dalam kode.", SOURCE, "info", {"count": len(urls), "sample": urls[:10]}))
    if ips:
        findings.append(finding("APK menyimpan alamat IP literal yang tertanam di dalam kode.", SOURCE, "info", {"count": len(ips), "sample": ips[:10]}))

    packers = features.get("packer_hints") or []
    if packers:
        limitations.append("APK terindikasi dikemas (packed/obfuscated); analisis statis tidak lengkap sehingga tidak ditemukannya indikator bukan bukti aman.")
    if features.get("dex_missing"):
        limitations.append("APK tidak memuat classes.dex yang bisa dibaca; analisis kode tidak dijalankan.")

    native = features.get("native_libs") or []
    if native:
        findings.append(finding("APK memuat native library.", SOURCE, "info", {"sample": native[:10]}))

    if not features.get("permissions") and not features.get("package_name"):
        limitations.append("Metadata manifest tidak dapat dibaca, sehingga hasil hanya mencakup pemeriksaan tingkat arsip.")

    return findings, limitations


def _brand_claim(label: str, package: str) -> str:
    haystack = f"{label} {package}".casefold()
    for brand in BRAND_KEYWORDS:
        if brand in haystack:
            return brand
    return ""

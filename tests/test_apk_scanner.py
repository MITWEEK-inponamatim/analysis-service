import asyncio
import io
import zipfile

import pytest

from app import apk_extract, apk_scanner, file_client, storage, virustotal

TELEGRAM_TOKEN = b"123456789:" + b"A" * 35


def fake_apk(extra_entries: int = 0) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("classes.dex", b"dex\n035\x00" + b"https://evil.example/panel " + TELEGRAM_TOKEN)
        archive.writestr("AndroidManifest.xml", b"<manifest/>")
        for index in range(extra_entries):
            archive.writestr(f"assets/extra-{index}.txt", b"x")
    return buffer.getvalue()


def test_dex_strings_and_telegram_token_are_extracted(monkeypatch):
    monkeypatch.setattr(apk_extract, "_load_apk_class", lambda: None)
    result = apk_extract.extract_apk_features(fake_apk())
    assert result["available"] is False
    assert "androguard_missing" in result["incomplete_reasons"]
    assert result["features"]["telegram_bot_token"] is True
    assert any("evil.example" in url for url in result["features"]["hardcoded_urls"])


def test_archive_entry_limit_is_enforced(monkeypatch):
    monkeypatch.setenv("MAX_APK_ENTRIES", "2")
    with pytest.raises(apk_extract.ArchiveLimitExceeded) as error:
        apk_extract.precheck_archive(fake_apk(extra_entries=1))
    assert error.value.reason == "too_many_entries"


def test_oversized_entry_is_rejected():
    limits = dict(apk_extract.DEFAULT_LIMITS, max_entry_bytes=8)
    with pytest.raises(apk_extract.ArchiveLimitExceeded) as error:
        apk_extract.precheck_archive(fake_apk(), limits)
    assert error.value.reason in {"entry_too_large", "compression_ratio_too_high"}


def test_non_zip_payload_is_rejected():
    with pytest.raises(apk_extract.ArchiveLimitExceeded) as error:
        apk_extract.precheck_archive(b"not a zip")
    assert error.value.reason == "not_a_zip"


class FakeAPK:
    def __init__(self, _path):
        self._permissions = [
            "android.permission.SEND_SMS",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.SYSTEM_ALERT_WINDOW",
        ]

    def is_valid_APK(self):
        return True

    def get_package(self):
        return "com.fake.bankid"

    def get_app_name(self):
        return "BankID Cepat"

    def get_androidversion_name(self):
        return "1.0"

    def get_permissions(self):
        return list(self._permissions)

    def get_certificates(self):
        class Cert:
            sha256 = b"\x01\x02"

        return [Cert()]

    def get_activities(self):
        return ["com.fake.bankid.Main"]

    def get_services(self):
        return []

    def get_receivers(self):
        return []

    def get_providers(self):
        return []

    def get_main_activity(self):
        return None

    def get_android_manifest_xml(self):
        import xml.etree.ElementTree as ElementTree

        manifest = ElementTree.Element("manifest")
        ElementTree.SubElement(manifest, "uses-permission", {"name": "android.permission.BIND_ACCESSIBILITY_SERVICE"})
        return manifest


def test_androguard_path_extracts_manifest_and_signer(monkeypatch):
    monkeypatch.setattr(apk_extract, "_load_apk_class", lambda: FakeAPK)
    result = apk_extract.extract_apk_features(fake_apk())
    features = result["features"]
    assert result["available"] is True
    assert features["package_name"] == "com.fake.bankid"
    assert features["app_label"] == "BankID Cepat"
    assert features["signer_sha256"] == ["0102"]
    assert "sms_send" in features["sensitive_permissions"]
    assert "accessibility" in features["sensitive_permissions"]
    assert features["hidden_launcher_icon"] is True
    assert features["manifest_indicators"]


def _patch_scanner(monkeypatch, extraction, *, malicious=None, upload_allowed=True, uploads=None):
    async def download(*_args, **_kwargs):
        return fake_apk()

    async def analyze(*_args, **_kwargs):
        return extraction

    async def lookup(_sha256):
        return malicious

    async def upload(_data, _filename):
        if uploads is not None:
            uploads.append(_filename)
        return {"analysis_id": "x"} if upload_allowed else None

    monkeypatch.setattr(storage, "download_object", download)
    monkeypatch.setattr(file_client, "analyze_file", analyze)
    monkeypatch.setattr(virustotal, "api_key", lambda: "unit-test-key")
    monkeypatch.setattr(virustotal, "lookup_file_hash", lookup)
    monkeypatch.setattr(virustotal, "upload_sample", upload)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)


def test_virustotal_hash_detection_confirms_threat(monkeypatch):
    payload = {
        "bucket": "uploads",
        "storage_path": "user-1/scan-1/sample.apk",
        "mime": "application/vnd.android.package-archive",
        "filename": "sample.apk",
    }
    _patch_scanner(
        monkeypatch,
        {"available": True, "features": {"permissions": [], "sensitive_permissions": []}, "incomplete_reasons": []},
        malicious={"found": True, "malicious": 7, "suspicious": 1, "total": 60},
        upload_allowed=False,
    )
    report = asyncio.run(apk_scanner.scan_application("scan-1", "user-1", payload))
    assert report.outcome == "confirmed_threat"
    assert report.risk["level"] == "high"
    assert any(item.source == "virustotal" for item in report.findings)
    assert "virustotal_hash_lookup" in report.risk["coverage"]["checks_run"]


def test_sample_is_not_uploaded_without_consent(monkeypatch):
    uploads = []
    payload = {"bucket": "uploads", "storage_path": "user-1/scan-1/sample.apk", "filename": "sample.apk"}
    _patch_scanner(
        monkeypatch,
        {"available": True, "features": {"permissions": [], "sensitive_permissions": []}, "incomplete_reasons": []},
        malicious={"found": False, "malicious": 0, "suspicious": 0, "total": 0},
        uploads=uploads,
    )
    report = asyncio.run(apk_scanner.scan_application("scan-1", "user-1", payload, {"consent_external_upload": False}))
    assert uploads == []
    assert "virustotal_sample_upload" in report.risk["coverage"]["checks_unavailable"]
    assert any("consent_external_upload" in text for text in report.limitations)


def test_sample_is_uploaded_only_with_consent(monkeypatch):
    uploads = []
    payload = {"bucket": "uploads", "storage_path": "user-1/scan-1/sample.apk", "filename": "sample.apk"}
    _patch_scanner(
        monkeypatch,
        {"available": True, "features": {"permissions": [], "sensitive_permissions": []}, "incomplete_reasons": []},
        malicious={"found": False, "malicious": 0, "suspicious": 0, "total": 0},
        uploads=uploads,
    )
    report = asyncio.run(apk_scanner.scan_application("scan-1", "user-1", payload, {"consent_external_upload": True}))
    assert uploads == ["sample.apk"]
    assert "virustotal_sample_upload" in report.risk["coverage"]["checks_run"]


def test_dangerous_permission_combination_escalates(monkeypatch):
    payload = {"bucket": "uploads", "storage_path": "user-1/scan-1/sample.apk", "filename": "sample.apk"}
    _patch_scanner(
        monkeypatch,
        {
            "available": True,
            "features": {
                "permissions": ["android.permission.SEND_SMS", "android.permission.BIND_ACCESSIBILITY_SERVICE"],
                "sensitive_permissions": ["sms_send", "accessibility"],
                "app_label": "BankID Cepat",
                "package_name": "com.fake.bankid",
            },
            "incomplete_reasons": [],
        },
        malicious=None,
    )
    report = asyncio.run(apk_scanner.scan_application("scan-1", "user-1", payload))
    assert report.outcome == "suspicious"
    assert report.risk["level"] == "high"
    assert any(item.source == "static_analysis_rules" and item.severity == "high" for item in report.findings)


def test_missing_static_analysis_keeps_scan_honest(monkeypatch):
    payload = {"bucket": "uploads", "storage_path": "user-1/scan-1/sample.apk", "filename": "sample.apk"}
    _patch_scanner(
        monkeypatch,
        {"available": False, "reason": "androguard_missing", "features": {}, "incomplete_reasons": ["androguard_missing"]},
        malicious=None,
    )
    report = asyncio.run(apk_scanner.scan_application("scan-1", "user-1", payload))
    unavailable = report.risk["coverage"]["checks_unavailable"]
    assert "apk_static_analysis" in unavailable
    assert "jadx_decompile" in unavailable and "dynamic_analysis" in unavailable
    assert report.outcome == "suspicious"


def test_archive_rejection_returns_scan_failed(monkeypatch):
    payload = {"bucket": "uploads", "storage_path": "user-1/scan-1/sample.apk", "filename": "sample.apk"}

    async def download(*_args, **_kwargs):
        return b"not a zip"

    monkeypatch.setattr(storage, "download_object", download)
    report = asyncio.run(apk_scanner.scan_application("scan-1", "user-1", payload))
    assert report.outcome == "scan_failed"
    assert report.error["code"] == "archive_rejected"
    assert any("not_a_zip" in text for text in report.limitations)

import asyncio

import pytest

from app import file_client, scanners, storage
from app.image_scanner import scan_image
from app.risk import assess, finding

PAYLOAD = {"bucket": "uploads", "storage_path": "user-1/scan-1/shot.png", "mime": "image/png", "filename": "shot.png"}


def _patch(monkeypatch, extraction, url_pipeline=None):
    async def download(*_args, **_kwargs):
        return b"\x89PNG\r\n\x1a\n"

    async def analyze(*_args, **_kwargs):
        return extraction

    monkeypatch.setattr(storage, "download_object", download)
    monkeypatch.setattr(file_client, "analyze_file", analyze)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    if url_pipeline is not None:
        monkeypatch.setattr(scanners, "scan_url_pipeline", url_pipeline)


def test_ocr_text_flows_through_message_and_url_scanners(monkeypatch):
    async def url_pipeline(scan_id, url, user_id):
        return assess(
            scan_id, "url",
            [finding("Formulir kata sandi mengirimkan kredensial ke domain berbeda.", "browser_inspection", "high")],
            ["url_syntax", "browser_inspection"], ["safe_browsing"],
        )

    _patch(
        monkeypatch,
        {"available": True, "reason": None, "text": "Selamat Anda dapat hadiah. Verifikasi di https://evil.example/login", "languages": "ind+eng"},
        url_pipeline,
    )
    report = asyncio.run(scan_image("scan-1", "user-1", PAYLOAD))

    checks = report.risk["coverage"]["checks_run"]
    assert "ocr" in checks
    assert "message_heuristics" in checks
    assert "url_scan" in checks
    assert any(item.source == "heuristic" for item in report.findings)
    assert any(item.indicator.startswith("Tautan ") for item in report.findings)
    assert report.risk["level"] == "high"
    assert report.artifacts["ocr"]["available"] is True
    assert report.artifacts["ocr"]["characters"] > 0


def test_missing_ocr_is_unavailable_not_safe(monkeypatch):
    _patch(monkeypatch, {"available": False, "reason": "ocr_unavailable", "text": "", "languages": None})
    report = asyncio.run(scan_image("scan-1", "user-1", PAYLOAD))
    assert report.outcome == "insufficient_evidence"
    assert "ocr" in report.risk["coverage"]["checks_unavailable"]
    assert any("OCR" in text for text in report.limitations)
    assert report.artifacts["ocr"]["reason"] == "ocr_unavailable"


def test_failed_url_scan_is_recorded_per_scan(monkeypatch):
    async def url_pipeline(*_args, **_kwargs):
        raise RuntimeError("browser unavailable")

    _patch(monkeypatch, {"available": True, "reason": None, "text": "Cek https://evil.example/ sekarang", "languages": "eng"}, url_pipeline)
    report = asyncio.run(scan_image("scan-1", "user-1", PAYLOAD))
    assert "url_scan" in report.risk["coverage"]["checks_unavailable"]
    assert any("tidak selesai" in text for text in report.limitations)
    assert report.outcome != "confirmed_threat"


def test_unsafe_storage_path_fails_the_scan(monkeypatch):
    async def download(*_args, **_kwargs):
        raise storage.UnsafeStoragePath("nope")

    monkeypatch.setattr(storage, "download_object", download)
    report = asyncio.run(scan_image("scan-1", "user-1", PAYLOAD))
    assert report.outcome == "scan_failed"
    assert report.error["code"] == "unsafe_storage_path"


def test_two_urls_are_deduplicated_and_limited(monkeypatch):
    seen = []

    async def url_pipeline(scan_id, url, user_id):
        seen.append(url)
        return assess(scan_id, "url", [], ["url_syntax"], [])

    _patch(monkeypatch, {"available": True, "reason": None, "text": "https://a.example/ https://b.example/ https://c.example/", "languages": "eng"}, url_pipeline)
    asyncio.run(scan_image("scan-1", "user-1", PAYLOAD))
    assert seen == ["https://a.example/", "https://b.example/"]


def test_vision_is_skipped_without_vision_model(monkeypatch):
    _patch(monkeypatch, {"available": True, "reason": None, "text": "cek hadiah", "languages": "eng"})
    monkeypatch.setattr("app.vision.vision_analyzer", lambda: None)
    report = asyncio.run(scan_image("scan-1", "user-1", PAYLOAD))
    assert "llm_vision" in report.risk["coverage"]["checks_unavailable"]


def test_vision_findings_are_merged_when_configured(monkeypatch):
    _patch(monkeypatch, {"available": True, "reason": None, "text": "cek hadiah", "languages": "eng"})

    class StubVision:
        async def ainvoke(self, _messages):
            class Parsed:
                findings = [type("F", (), {"indicator": "tampilan menyerupai bank resmi", "severity": "high", "confidence": "medium"})()]

            return {"parsed": Parsed(), "raw": None}

    monkeypatch.setattr("app.vision.vision_analyzer", lambda: StubVision())
    report = asyncio.run(scan_image("scan-1", "user-1", PAYLOAD))
    assert "llm_vision" in report.risk["coverage"]["checks_run"]
    assert any(item.source == "llm_vision" for item in report.findings)
    assert report.risk["level"] == "high"

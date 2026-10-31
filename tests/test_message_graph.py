import asyncio

from app import scanners
from app.risk import assess, finding
from app.scanners import scan_message


def test_message_scan_forwards_extracted_urls_to_the_url_scanner(monkeypatch):
    seen = []

    async def url_pipeline(scan_id, url, user_id):
        seen.append(url)
        return assess(scan_id, "url", [finding("URL memakai pemendek", "url_heuristic", "medium")], ["url_syntax"], [])

    monkeypatch.setattr(scanners, "scan_url_pipeline", url_pipeline)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    report = asyncio.run(scan_message("scan-1", "Verifikasi di https://evil.example/login sebelum akun diblokir"))

    assert seen == ["https://evil.example/login"]
    assert "url_scan" in report.risk["coverage"]["checks_run"]
    assert any(item.indicator.startswith("Tautan ") for item in report.findings)
    assert any(item.source == "heuristic" for item in report.findings)


def test_message_scan_skips_url_scanner_without_links(monkeypatch):
    async def url_pipeline(*_args, **_kwargs):
        raise AssertionError("url scanner must not run without links")

    monkeypatch.setattr(scanners, "scan_url_pipeline", url_pipeline)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    report = asyncio.run(scan_message("scan-1", "Halo, apa kabar?"))
    assert "url_scan" not in report.risk["coverage"]["checks_run"]
    assert report.outcome == "insufficient_evidence"


def test_message_scan_is_bounded_to_the_url_limit(monkeypatch):
    seen = []

    async def url_pipeline(scan_id, url, user_id):
        seen.append(url)
        return assess(scan_id, "url", [], ["url_syntax"], [])

    monkeypatch.setattr(scanners, "scan_url_pipeline", url_pipeline)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("MESSAGE_URL_SCAN_LIMIT", "2")
    asyncio.run(scan_message("scan-1", "https://a.example/ https://b.example/ https://c.example/"))
    assert seen == ["https://a.example/", "https://b.example/"]


def test_heuristic_findings_are_not_duplicated(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    report = asyncio.run(scan_message("scan-1", "kirim OTP sekarang"))
    otp = [item for item in report.findings if item.indicator.endswith("otp")]
    assert len(otp) == 1


def test_message_scan_records_timeout_as_unavailable(monkeypatch):
    async def url_pipeline(*_args, **_kwargs):
        raise RuntimeError("timeout")

    monkeypatch.setattr(scanners, "scan_url_pipeline", url_pipeline)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    report = asyncio.run(scan_message("scan-1", "cek https://a.example/"))
    assert "url_scan" in report.risk["coverage"]["checks_unavailable"]
    assert any("tidak selesai" in text for text in report.limitations)

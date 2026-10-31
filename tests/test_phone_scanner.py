import asyncio

import pytest

from app import phone_scanner

INDONESIAN_NUMBER = "0812-3456-7890"


def test_normalizes_indonesian_mobile_to_e164():
    result = phone_scanner.normalize_number(INDONESIAN_NUMBER, "ID")
    assert result.e164 == "+6281234567890"
    assert result.valid is True
    assert result.region == "ID"
    assert result.parsed_by == "phonenumbers"


def test_fallback_normalisation_matches_e164_shape(monkeypatch):
    monkeypatch.setattr(phone_scanner, "PHONENUMBERS_AVAILABLE", False)
    result = phone_scanner.normalize_number(INDONESIAN_NUMBER, "ID")
    assert result.e164 == "+6281234567890"
    assert result.parsed_by == "fallback"


def _reports_mock(monkeypatch, rows):
    async def fetch(*_args, **_kwargs):
        return rows

    monkeypatch.setattr(phone_scanner, "fetch_reports", fetch)


def test_verified_community_reports_raise_risk(monkeypatch):
    # High severity needs independent corroboration: several verified reports from
    # several different reporters, not one account repeating itself.
    _reports_mock(monkeypatch, [
        {"category": "penipuan", "status": "verified", "source": "report", "reported_by": f"user-{index}"}
        for index in range(3)
    ])
    report = asyncio.run(phone_scanner.scan_phone("scan", INDONESIAN_NUMBER, "ID"))
    assert report.outcome == "suspicious"
    assert report.risk["level"] == "high"
    assert report.risk["confidence"] == "medium"
    assert any(item.source == "phone_reports" for item in report.findings)
    assert "phone_reports" in report.risk["coverage"]["checks_run"]


def test_unverified_reports_are_low_confidence(monkeypatch):
    _reports_mock(monkeypatch, [{"category": "spam", "status": "pending", "source": "report"}])
    report = asyncio.run(phone_scanner.scan_phone("scan", INDONESIAN_NUMBER, "ID"))
    assert report.outcome == "insufficient_evidence"
    assert report.risk["level"] == "unknown"
    assert any(item.source == "phone_reports" and item.severity == "low" for item in report.findings)


def test_missing_report_source_is_reported_as_unavailable(monkeypatch):
    _reports_mock(monkeypatch, None)
    report = asyncio.run(phone_scanner.scan_phone("scan", INDONESIAN_NUMBER, "ID"))
    assert "phone_reports" in report.risk["coverage"]["checks_unavailable"]
    assert any("laporan komunitas" in text for text in report.limitations)


def test_spoofing_and_ownership_limitations_always_present(monkeypatch):
    _reports_mock(monkeypatch, [])
    report = asyncio.run(phone_scanner.scan_phone("scan", INDONESIAN_NUMBER, "ID"))
    assert any("dipalsukan" in text for text in report.limitations)
    assert any("berpindah pemilik" in text for text in report.limitations)
    assert any("bukan bukti nomor aman" in text for text in report.limitations)
    assert report.type == "phone"


def test_invalid_number_does_not_claim_safety(monkeypatch):
    _reports_mock(monkeypatch, [])
    report = asyncio.run(phone_scanner.scan_phone("scan", "12", "ID"))
    assert report.outcome == "insufficient_evidence"
    assert any(item.source == "phone_validation" for item in report.findings)


@pytest.mark.parametrize("number", ["+12025550123", "+447700900123"])
def test_other_regions_normalise(monkeypatch, number):
    _reports_mock(monkeypatch, [])
    report = asyncio.run(phone_scanner.scan_phone("scan", number, "US"))
    assert report.risk["level"] in {"unknown", "medium", "high"}
    assert any("Nomor dinormalisasi ke" in report.evidence_summary for _ in [0])

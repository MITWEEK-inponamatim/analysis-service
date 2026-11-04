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


# People write one number several ways, and "+62 0812…" keeps the trunk 0 after the country
# code. If that 0 survives, the report and the search land on different keys and the number
# looks unreported — so every spelling has to produce exactly one E.164.
@pytest.mark.parametrize("written", [
    "081234567890",
    "6281234567890",
    "+6281234567890",
    "+62 0812-3456-7890",
    "62 0812 3456 7890",
])
def test_every_spelling_of_one_number_shares_one_key(written):
    assert phone_scanner.normalize_number(written, "ID").e164 == "+6281234567890"


@pytest.mark.parametrize("written", ["081234567890", "6281234567890", "+62 0812-3456-7890"])
def test_fallback_path_shares_the_same_key(monkeypatch, written):
    monkeypatch.setattr(phone_scanner, "PHONENUMBERS_AVAILABLE", False)
    assert phone_scanner.normalize_number(written, "ID").e164 == "+6281234567890"


def test_trunk_zero_removal_does_not_reach_the_country_code():
    # Only the 0 directly after 62 is dropped: a fixed line keeps its area code, and a foreign
    # number must never pick up a 62 prefix from the canonicalisation step.
    assert phone_scanner.normalize_number("0214214214", "ID").e164 == "+62214214214"
    foreign = phone_scanner.normalize_number("+12025550123", "ID")
    assert foreign.e164 == "+12025550123"
    assert foreign.domestic is False


def test_canonical_digits_is_the_shared_rule():
    assert phone_scanner.canonical_digits("+62 0812-3456-7890") == "6281234567890"
    assert phone_scanner.canonical_digits("081234567890") == "081234567890"
    assert phone_scanner.canonical_digits("abc") == ""


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


@pytest.mark.parametrize("number", ["+12025550123", "+447700900123", "+60123456789"])
def test_non_indonesian_numbers_are_out_of_scope(monkeypatch, number):
    looked_up = []

    async def fetch(*args, **kwargs):
        looked_up.append(args)
        return []

    monkeypatch.setattr(phone_scanner, "fetch_reports", fetch)
    report = asyncio.run(phone_scanner.scan_phone("scan", number, "ID"))
    assert report.outcome == "insufficient_evidence"
    assert report.risk["level"] == "unknown"
    assert any("di luar cakupan" in item.indicator for item in report.findings)
    assert looked_up == []
    assert not report.artifacts["community_reviews"]


def test_community_reviews_are_listed_anonymously(monkeypatch):
    _reports_mock(monkeypatch, [
        {"id": "r1", "category": "penipuan", "status": "verified", "source": "user_report",
         "created_at": "2026-11-01T00:00:00+00:00", "reported_by": "reporter-one-uuid"},
        {"id": "r2", "category": "spam", "status": "pending", "source": "user_report",
         "created_at": "2026-10-01T00:00:00+00:00", "reported_by": "reporter-two-uuid"},
        {"id": "r3", "category": "penipuan", "status": "rejected_spam", "source": "user_report",
         "created_at": "2026-10-02T00:00:00+00:00", "reported_by": "reporter-three-uuid"},
    ])
    report = asyncio.run(phone_scanner.scan_phone("scan", INDONESIAN_NUMBER, "ID"))
    reviews = report.artifacts["community_reviews"]
    assert [item["id"] for item in reviews] == ["r1", "r2"]
    assert [item["status"] for item in reviews] == ["verified", "pending"]
    assert reviews[0]["category"] == "penipuan"
    assert reviews[0]["age_days"] is not None
    assert report.artifacts["community_review_count"] == 2
    # The report must never carry the reporter's account id to the client.
    assert "reporter-one-uuid" not in report.model_dump_json()

"""Community phone reports: normalisation contract, trust summary, and moderation.

These tests stay offline: nothing here may reach Supabase or OpenAI (see conftest.py).
"""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import phone_reports, phone_scanner
from app.main import app

SERVICE_KEY = "unit-test-service-key"
HEADERS = {"X-Service-Key": SERVICE_KEY}
REPORT_ID = "7f1b3c2d-4e5f-4a6b-8c9d-0e1f2a3b4c5d"


@pytest.fixture(autouse=True)
def service_key(monkeypatch):
    monkeypatch.setenv("SERVICE_API_KEY", SERVICE_KEY)


def _report(status: str, category: str = "penipuan", reporter: str = "user-1", days_ago: int = 1) -> dict:
    moment = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return {"category": category, "status": status, "reported_by": reporter, "created_at": moment.isoformat()}


# ---------------------------------------------------------------- normalisation contract


def test_normalize_payload_exposes_the_shared_contract():
    payload = phone_scanner.normalize_payload("0812-3456-7890", "ID")
    assert payload["e164"] == "+6281234567890"
    assert payload["valid"] is True
    assert payload["region"] == "ID"
    assert set(payload) >= {"e164", "valid", "possible", "region", "line_type", "carrier", "parsed_by"}


def test_normalize_endpoint_requires_the_service_key():
    assert TestClient(app).post("/internal/v1/phone/normalize", json={"number": "081234567890"}).status_code == 401


def test_normalize_endpoint_returns_e164_for_go():
    response = TestClient(app).post(
        "/internal/v1/phone/normalize", headers=HEADERS,
        json={"number": "0812-3456-7890", "default_region": "ID"},
    )
    assert response.status_code == 200
    assert response.json()["e164"] == "+6281234567890"


def test_normalize_endpoint_rejects_regions_outside_the_allowlist():
    response = TestClient(app).post(
        "/internal/v1/phone/normalize", headers=HEADERS,
        json={"number": "081234567890", "default_region": "ZZ"},
    )
    assert response.status_code == 422


# ---------------------------------------------------------------- explainable trust summary


def test_summary_counts_reporters_verification_and_categories():
    rows = [_report("verified", "penipuan", "u1"), _report("verified", "penagih_utang", "u2"), _report("pending", "spam", "u3", days_ago=12)]
    summary = phone_scanner.summarize_reports(rows)
    assert summary["reports"] == 3
    assert summary["verified"] == 2
    assert summary["pending"] == 1
    assert summary["distinct_reporters"] == 3
    assert summary["categories"] == ["penagih utang", "penipuan", "spam"]
    assert summary["last_report_days"] == 1


def test_rejected_reports_are_not_evidence():
    rows = [_report("rejected_spam", "penipuan", "u1")]
    summary = phone_scanner.summarize_reports(rows)
    assert summary["verified"] == 0
    assert summary["pending"] == 0
    assert summary["categories"] == []
    assert phone_scanner._report_finding("+6281234567890", rows) is None


def test_two_verified_reports_from_two_reporters_reach_high():
    rows = [_report("verified", "penipuan", "u1"), _report("verified", "penipuan", "u2")]
    found = phone_scanner._report_finding("+6281234567890", rows)
    assert found is not None
    assert found.severity == "high"
    assert found.source == "phone_reports"
    assert found.confidence == "medium"


def test_three_verified_reports_from_one_reporter_do_not_claim_high():
    rows = [_report("verified", "penipuan", "u1") for _ in range(3)]
    assert phone_scanner._report_finding("+6281234567890", rows).severity == "medium"


def test_single_verified_report_stays_medium():
    found = phone_scanner._report_finding("+6281234567890", [_report("verified", "penipuan", "u1")])
    assert found.severity == "medium"
    assert "1 laporan terverifikasi" in found.indicator


def test_many_pending_reports_from_one_reporter_stay_low():
    rows = [_report("pending", "spam", "u1") for _ in range(5)]
    found = phone_scanner._report_finding("+6281234567890", rows)
    assert found.severity == "low"
    assert found.confidence == "low"


def test_three_pending_reports_from_two_reporters_are_medium():
    rows = [_report("pending", "spam", "u1"), _report("pending", "spam", "u2"), _report("pending", "penipuan", "u2")]
    assert phone_scanner._report_finding("+6281234567890", rows).severity == "medium"


def test_recency_is_mentioned_in_the_finding():
    rows = [_report("verified", "penipuan", "u1", days_ago=9)]
    assert "9 hari lalu" in phone_scanner._report_finding("+6281234567890", rows).indicator


# ---------------------------------------------------------------- categories and ids


def test_categories_are_a_closed_vocabulary():
    assert phone_reports.category_label("penagih_utang") == "penagih utang"
    assert phone_reports.category_label("PENIPUAN") == "penipuan"
    assert phone_reports.category_label("ditulis bebas") == "lainnya"
    assert phone_reports.category_label(None) == "lainnya"


def test_report_id_validation_accepts_uuid_only():
    assert phone_reports.valid_report_id(REPORT_ID) is True
    assert phone_reports.valid_report_id("1 or 1=1") is False
    assert phone_reports.valid_report_id("") is False


# ---------------------------------------------------------------- moderation endpoint


def test_moderation_endpoint_updates_status(monkeypatch):
    captured = {}

    async def fake_set_status(report_id: str, status: str):
        captured["args"] = (report_id, status)
        return {"id": report_id, "number_e164": "+6281234567890", "status": status}

    monkeypatch.setattr("app.main.phone_reports.set_status", fake_set_status)
    response = TestClient(app).patch(f"/internal/v1/phone-reports/{REPORT_ID}", headers=HEADERS, json={"status": "verified"})
    assert response.status_code == 200
    assert response.json()["status"] == "verified"
    assert captured["args"] == (REPORT_ID, "verified")


def test_moderation_endpoint_rejects_unknown_status_and_bad_id():
    client = TestClient(app)
    assert client.patch(f"/internal/v1/phone-reports/{REPORT_ID}", headers=HEADERS, json={"status": "maybe"}).status_code == 422
    assert client.patch("/internal/v1/phone-reports/not-a-uuid", headers=HEADERS, json={"status": "verified"}).status_code == 400


def test_moderation_endpoint_maps_missing_report_to_404(monkeypatch):
    async def missing(_report_id: str, _status: str):
        raise phone_reports.ReportsUnavailable("report_not_found")

    monkeypatch.setattr("app.main.phone_reports.set_status", missing)
    response = TestClient(app).patch(f"/internal/v1/phone-reports/{REPORT_ID}", headers=HEADERS, json={"status": "verified"})
    assert response.status_code == 404


def test_moderation_endpoint_reports_unconfigured_store(monkeypatch):
    async def unconfigured(_report_id: str, _status: str):
        raise phone_reports.ReportsUnavailable("supabase_not_configured")

    monkeypatch.setattr("app.main.phone_reports.set_status", unconfigured)
    response = TestClient(app).patch(f"/internal/v1/phone-reports/{REPORT_ID}", headers=HEADERS, json={"status": "rejected"})
    assert response.status_code == 503

from fastapi.testclient import TestClient
import pytest

from app import file_worker

WORKER_KEY = "unit-test-worker-key"


def _client(monkeypatch) -> TestClient:
    monkeypatch.setenv("FILE_WORKER_SERVICE_KEY", WORKER_KEY)
    return TestClient(file_worker.app)


def test_worker_requires_service_key(monkeypatch):
    client = _client(monkeypatch)
    assert client.get("/internal/v1/health").status_code == 401
    assert client.get("/internal/v1/health", headers={"X-Service-Key": "wrong"}).status_code == 401
    response = client.get("/internal/v1/health", headers={"X-Service-Key": WORKER_KEY})
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_worker_refuses_to_start_without_derived_key(monkeypatch):
    monkeypatch.setenv("FILE_WORKER_SERVICE_KEY", "")
    with pytest.raises(RuntimeError, match="FILE_WORKER_SERVICE_KEY"):
        with TestClient(file_worker.app):
            pass


def test_worker_has_no_image_endpoint(monkeypatch):
    client = _client(monkeypatch)
    response = client.post("/internal/v1/analyze/image", headers={"X-Service-Key": WORKER_KEY}, content=b"PK\x03\x04")
    assert response.status_code == 404


def test_worker_rejects_oversized_payload(monkeypatch):
    client = _client(monkeypatch)
    monkeypatch.setattr(file_worker, "MAX_BODY_BYTES", 8)
    response = client.post("/internal/v1/analyze/application", headers={"X-Service-Key": WORKER_KEY}, content=b"x" * 64)
    assert response.status_code == 413


def test_worker_reports_invalid_apk_without_crashing(monkeypatch):
    client = _client(monkeypatch)
    response = client.post("/internal/v1/analyze/application", headers={"X-Service-Key": WORKER_KEY}, content=b"PK\x03\x04broken")
    assert response.status_code == 200
    body = response.json()
    assert body["available"] is False
    assert body["reason"] in {"corrupt_archive", "extraction_failed", "apk_parse_failed"}

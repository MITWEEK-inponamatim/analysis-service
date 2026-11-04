"""Evidence images for community reports: folder, limits, and cleanup guards.

Offline by design — the Cloudinary SDK is replaced with a stub, so no test reaches the cloud.
Async helpers go through ``asyncio.run`` like the rest of the suite (pytest-asyncio is installed
here but never configured, so a bare ``async def`` test would be skipped without failing).
"""

import asyncio
import base64
import sys
import types

import pytest
from fastapi.testclient import TestClient

from app import phone_evidence
from app.main import app

SERVICE_KEY = "unit-test-service-key"
HEADERS = {"X-Service-Key": SERVICE_KEY}
USER_ID = "7f1b3c2d-4e5f-4a6b-8c9d-0e1f2a3b4c5d"
REFERENCE = "a1b2c3d4-0000-4000-8000-000000000000"
PNG = base64.b64encode(b"\x89PNG\r\n\x1a\nfake-image-bytes").decode()


class _StubUploader:
    def __init__(self):
        self.uploads = []
        self.destroyed = []
        self.configs = []

    def upload(self, data, **kwargs):
        self.uploads.append({"data": data, **kwargs})
        return {"secure_url": f"https://res.cloudinary.com/demo/{kwargs['public_id']}", "public_id": kwargs["public_id"]}

    def destroy(self, public_id, **kwargs):
        self.destroyed.append({"public_id": public_id, **kwargs})
        return {"result": "ok"}


@pytest.fixture(autouse=True)
def service_key(monkeypatch):
    # conftest.py pins SERVICE_API_KEY to "" so every test starts offline and unauthenticated.
    monkeypatch.setenv("SERVICE_API_KEY", SERVICE_KEY)


@pytest.fixture
def cloudinary(monkeypatch):
    stub = _StubUploader()
    module = types.ModuleType("cloudinary")
    module.config = lambda **kwargs: stub.configs.append(kwargs)
    module.uploader = stub
    monkeypatch.setitem(sys.modules, "cloudinary", module)
    monkeypatch.setitem(sys.modules, "cloudinary.uploader", module)
    monkeypatch.setenv("CLOUDINARY_URL", "cloudinary://apikey:secret@demo_cloud")
    return stub


def _store(mime="image/png", user_id=USER_ID, reference=REFERENCE, data=PNG):
    return asyncio.run(phone_evidence.store_image(user_id, reference, mime, data))


# ---------------------------------------------------------------- store


def test_evidence_lands_in_its_own_folder_with_an_unpredictable_suffix(cloudinary):
    first = _store()
    second = _store()
    assert first and second
    assert first["url"].startswith("https://res.cloudinary.com/demo/threatlens/phone-reports/")
    assert first["public_id"].startswith(f"{phone_evidence.EVIDENCE_FOLDER}/{USER_ID}/{REFERENCE}-")
    assert first["public_id"] != second["public_id"], "two uploads must not overwrite one another"
    assert cloudinary.uploads[0]["overwrite"] is False
    assert cloudinary.uploads[0]["data"].startswith("data:image/png;base64,")
    assert first["size_bytes"] > 0


@pytest.mark.parametrize("mime", ["image/svg+xml", "application/x-httpd-php", "video/mp4"])
def test_only_allowed_image_types_are_kept(cloudinary, mime):
    assert _store(mime=mime) is None


def test_identifiers_are_validated_before_anything_is_uploaded(cloudinary):
    assert _store(user_id="not-a-uuid") is None
    assert _store(reference="short") is None
    assert _store(reference="../../etc/passwd") is None
    assert cloudinary.uploads == []


def test_oversized_and_unusable_payloads_are_refused(cloudinary, monkeypatch):
    assert _store(data="") is None
    assert _store(data="this is not base64 at all !!!") is None
    monkeypatch.setenv("CLOUDINARY_URL", "")
    assert _store() is None


def test_upload_failure_is_reported_as_unavailable(cloudinary, monkeypatch):
    def boom(_data, **_kwargs):
        raise RuntimeError("cloudinary is down")

    monkeypatch.setattr(cloudinary, "upload", boom)
    assert _store() is None


def test_the_url_supplies_credentials_and_the_name_can_override_the_host(cloudinary, monkeypatch):
    # A real deployment carries both variables, and its CLOUDINARY_URL host was stale while
    # CLOUDINARY_CLOUD_NAME named the right cloud: the key and secret must still come from the
    # URL, and the explicit name must win. Passing the URL to the SDK alone did neither.
    monkeypatch.setenv("CLOUDINARY_CLOUD_NAME", "some_other_cloud")
    assert _store() is not None
    assert cloudinary.configs[-1] == {"cloud_name": "some_other_cloud", "api_key": "apikey", "api_secret": "secret"}


def test_the_url_host_is_used_when_no_cloud_name_is_configured(cloudinary, monkeypatch):
    monkeypatch.delenv("CLOUDINARY_CLOUD_NAME", raising=False)
    assert _store() is not None
    assert cloudinary.configs[-1]["cloud_name"] == "demo_cloud"


# ---------------------------------------------------------------- destroy


def test_destroy_only_reaches_the_report_folder(cloudinary):
    stored = _store()
    assert asyncio.run(phone_evidence.discard(stored["public_id"])) is True
    assert asyncio.run(phone_evidence.discard(f"threatlens/scans/{USER_ID}/scan-9")) is False
    assert asyncio.run(phone_evidence.discard("")) is False
    assert cloudinary.destroyed == [{"public_id": stored["public_id"], "resource_type": "image", "invalidate": True}]


# ---------------------------------------------------------------- HTTP contract


def test_evidence_endpoints_require_the_service_key():
    client = TestClient(app)
    body = {"user_id": USER_ID, "reference": REFERENCE, "mime": "image/png", "data_base64": PNG}
    assert client.post("/internal/v1/phone-reports/evidence", json=body).status_code == 401
    assert client.request("DELETE", "/internal/v1/phone-reports/evidence", json={"public_id": "x"}).status_code == 401


def test_evidence_endpoint_returns_the_reference_for_go(cloudinary):
    response = TestClient(app).post(
        "/internal/v1/phone-reports/evidence", headers=HEADERS,
        json={"user_id": USER_ID, "reference": REFERENCE, "mime": "image/png", "data_base64": PNG},
    )
    assert response.status_code == 201
    assert set(response.json()) == {"url", "public_id", "mime", "size_bytes"}


def test_a_refused_image_is_503_not_a_quiet_empty_answer(cloudinary):
    response = TestClient(app).post(
        "/internal/v1/phone-reports/evidence", headers=HEADERS,
        json={"user_id": USER_ID, "reference": REFERENCE, "mime": "text/html", "data_base64": PNG},
    )
    assert response.status_code == 503
    assert response.json()["detail"] == "evidence_unavailable"


def test_oversized_base64_is_rejected_by_the_schema(cloudinary):
    response = TestClient(app).post(
        "/internal/v1/phone-reports/evidence", headers=HEADERS,
        json={"user_id": USER_ID, "reference": REFERENCE, "mime": "image/png", "data_base64": "A" * 7_000_001},
    )
    assert response.status_code == 422

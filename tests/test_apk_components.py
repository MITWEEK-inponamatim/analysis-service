import asyncio
import json
from pathlib import Path

import httpx

from app import apk_signature, virustotal
from app.file_auth import file_service_key


FIXTURE = Path(__file__).parents[1].parent / "malware_sample" / "undangan-uji-eicar.apk"


class _Response:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


class _Client:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    async def get(self, *_args, **_kwargs):
        if self.error:
            raise self.error
        return self.response


def test_signed_fixture_extracts_certificate_metadata():
    result = apk_signature.verify_signature(FIXTURE.read_bytes())
    assert result["signed"] is True
    assert result["v1_signed"] is True
    assert result["v2_signed"] is True
    assert result["certificates"]
    assert result["certificates"][0]["sha256"]


def test_unsigned_or_invalid_apk_is_reported_without_raising():
    result = apk_signature.verify_signature(b"not-an-apk")
    assert result["signed"] is False
    assert result["certificates"] == []
    assert result["error"]


def test_jadx_manifest_fallback_reads_apk_metadata():
    from app.jadx_decompile import _manifest_from_apk

    manifest = _manifest_from_apk(FIXTURE.read_bytes())
    assert manifest["package"] == "org.example.undanganscannertest"
    assert manifest["app_label"] == "Undangan Uji Scanner"




def test_virustotal_missing_api_key_skips_network(monkeypatch):
    def fail_client(*_args, **_kwargs):
        raise AssertionError("network must not be attempted")

    monkeypatch.setattr(virustotal.httpx, "AsyncClient", fail_client)
    result = asyncio.run(virustotal.check_hash("a" * 64, ""))
    assert result == {"found": False, "error": "no_api_key"}


def test_virustotal_404_is_not_found(monkeypatch):
    monkeypatch.setattr(virustotal.httpx, "AsyncClient", lambda **_kwargs: _Client(_Response(404, {})))
    assert asyncio.run(virustotal.check_hash("a" * 64, "key")) == {"found": False}


def test_virustotal_found_normalizes_vendor_counts(monkeypatch):
    payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 2, "undetected": 3},
                "last_analysis_results": {
                    "A": {"category": "malicious", "result": "Android/Stealer"},
                    "B": {"category": "undetected", "result": None},
                },
            }
        }
    }
    monkeypatch.setattr(virustotal.httpx, "AsyncClient", lambda **_kwargs: _Client(_Response(200, payload)))
    result = asyncio.run(virustotal.check_hash("a" * 64, "key"))
    assert result["found"] is True
    assert result["malicious"] == 2
    assert result["total"] == 5
    assert result["names"] == ["Android/Stealer"]
    json.dumps(result)


def test_virustotal_timeout_is_unavailable(monkeypatch):
    monkeypatch.setattr(
        virustotal.httpx,
        "AsyncClient",
        lambda **_kwargs: _Client(error=httpx.ReadTimeout("timed out")),
    )
    assert asyncio.run(virustotal.check_hash("a" * 64, "key")) == {"found": False, "error": "timeout"}


def test_worker_auth_derivation_is_deterministic():
    first = file_service_key("service-key")
    assert first == file_service_key("service-key")
    assert first != file_service_key("different-service-key")
    assert len(first) == 64

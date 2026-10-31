import asyncio

from app import dynamic


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


def _configure(monkeypatch, url="https://sandbox.example", key="token"):
    monkeypatch.setenv("DYNAMIC_ANALYSIS_URL", url)
    monkeypatch.setenv("DYNAMIC_ANALYSIS_API_KEY", key)


def test_unavailable_without_configuration(monkeypatch):
    monkeypatch.delenv("DYNAMIC_ANALYSIS_URL", raising=False)
    assert dynamic.available() is False
    assert asyncio.run(dynamic.analyze_sample(b"PK\x03\x04", "sample.apk")) is None


def test_returns_summary_of_requested_keys(monkeypatch):
    _configure(monkeypatch)

    async def fake_request(_client, _method, _url, **_kwargs):
        return FakeResponse({"network": ["https://c2.example/collect"], "sms": True, "overlay": False, "ignored": "x"})

    monkeypatch.setattr(dynamic, "json_request", fake_request)
    result = asyncio.run(dynamic.analyze_sample(b"PK\x03\x04data", "sample.apk"))
    assert result["available"] is True
    assert result["summary"]["network"] == ["https://c2.example/collect"]
    assert result["summary"]["sms"] is True
    assert "ignored" not in result["summary"]


def test_failure_is_reported_as_none(monkeypatch):
    _configure(monkeypatch)

    async def boom(*_args, **_kwargs):
        raise RuntimeError("sandbox down")

    monkeypatch.setattr(dynamic, "json_request", boom)
    assert asyncio.run(dynamic.analyze_sample(b"PK\x03\x04data", "sample.apk")) is None


def test_summarize_handles_nested_summary_key():
    summary = dynamic.summarize({"summary": {"network": {"host": "c2.example"}, "files": ["/data/a"]}})
    assert summary["network"] == {"host": "c2.example"}
    assert summary["files"] == ["/data/a"]

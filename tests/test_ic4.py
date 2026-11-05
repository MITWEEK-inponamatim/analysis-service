import asyncio

from app.ic4 import ic4_lookup


def test_ic4_unavailable_when_no_config(monkeypatch):
    monkeypatch.delenv("IC4_API_URL", raising=False)
    result = asyncio.run(ic4_lookup("http://example.com"))
    assert result is None


def test_ic4_returns_empty_for_clean_url(monkeypatch):
    async def mock_request(_client, _method, _url, **_kwargs):
        class Response:
            def json(self):
                return {"code": 200, "message": "phish_link_not_found", "quota": {"used": 1, "quota": 10}, "data": None}
        return Response()

    monkeypatch.setattr("app.ic4.json_request", mock_request)
    result = asyncio.run(ic4_lookup("http://example.com"))
    assert result == []


def test_ic4_returns_finding_for_phishing_url(monkeypatch):
    async def mock_request(_client, _method, _url, **_kwargs):
        class Response:
            def json(self):
                return {"code": 200, "message": "phish_link_found", "data": {"url": "phishing.example", "reported": "2026-10-31"}}
        return Response()

    monkeypatch.setattr("app.ic4.json_request", mock_request)
    result = asyncio.run(ic4_lookup("http://phishing.example"))
    assert result is not None
    assert len(result) == 1
    assert result[0].source == "ic4"
    assert result[0].severity == "high"
    assert "IC4" in result[0].indicator


def test_ic4_normalizes_url_without_scheme(monkeypatch):
    captured = {}

    async def mock_request(_client, _method, url, **kwargs):
        captured["params"] = kwargs.get("params", {})
        captured["json"] = kwargs.get("json", {})
        class Response:
            def json(self):
                return {"code": 200, "message": "phish_link_not_found", "data": None}
        return Response()

    monkeypatch.setattr("app.ic4.json_request", mock_request)
    asyncio.run(ic4_lookup("https://example.com/path?query=1"))
    assert captured["params"]["q"] == "example.com"
    assert captured["json"]["url"] == "example.com"


def test_ic4_handles_api_error_gracefully(monkeypatch):
    async def mock_request(_client, _method, _url, **_kwargs):
        raise Exception("Network error")

    monkeypatch.setattr("app.ic4.json_request", mock_request)
    result = asyncio.run(ic4_lookup("http://example.com"))
    assert result is None


def test_ic4_handles_unknown_response_format(monkeypatch):
    async def mock_request(_client, _method, _url, **_kwargs):
        class Response:
            def json(self):
                return {"code": 500, "message": "internal_error"}
        return Response()

    monkeypatch.setattr("app.ic4.json_request", mock_request)
    result = asyncio.run(ic4_lookup("http://example.com"))
    assert result is None

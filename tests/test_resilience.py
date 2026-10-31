import asyncio

import httpx
import pytest

from app import resilience


def test_retries_transient_failure_then_succeeds():
    calls = {"n": 0}

    async def operation():
        calls["n"] += 1
        if calls["n"] < 3:
            raise httpx.ConnectError("connection reset")
        return "ok"

    assert asyncio.run(resilience.call_with_retry(operation, name="probe", base_delay=0, max_delay=0)) == "ok"
    assert calls["n"] == 3


def test_validation_errors_are_not_retried():
    calls = {"n": 0}

    async def operation():
        calls["n"] += 1
        raise ValueError("bad input")

    with pytest.raises(ValueError):
        asyncio.run(resilience.call_with_retry(operation, base_delay=0))
    assert calls["n"] == 1


def test_client_errors_are_not_retried():
    request = httpx.Request("GET", "https://example.test/")
    response = httpx.Response(404, request=request)
    calls = {"n": 0}

    async def operation():
        calls["n"] += 1
        raise httpx.HTTPStatusError("not found", request=request, response=response)

    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(resilience.call_with_retry(operation, base_delay=0))
    assert calls["n"] == 1


def test_server_errors_are_retried_until_attempts_exhausted():
    request = httpx.Request("GET", "https://example.test/")
    response = httpx.Response(503, request=request)
    calls = {"n": 0}

    async def operation():
        calls["n"] += 1
        raise httpx.HTTPStatusError("unavailable", request=request, response=response)

    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(resilience.call_with_retry(operation, base_delay=0, max_delay=0, attempts=3))
    assert calls["n"] == 3


def test_json_request_raises_on_client_error_without_retry():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(404, request=request)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await resilience.json_request(client, "GET", "https://example.test/api")

    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(run())
    assert calls["n"] == 1

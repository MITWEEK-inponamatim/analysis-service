import asyncio

import httpx

from app import retention


def test_skips_when_supabase_is_not_configured(monkeypatch):
    monkeypatch.delenv("SUPABASE_URL", raising=False)
    monkeypatch.delenv("SUPABASE_SECRET_KEY", raising=False)
    summary = asyncio.run(retention.purge_expired())
    assert summary["status"] == "skipped"
    assert summary["rows"] == 0


def test_deletes_expired_objects_and_rows(monkeypatch):
    monkeypatch.setenv("SUPABASE_URL", "https://project.supabase.co")
    monkeypatch.setenv("SUPABASE_SECRET_KEY", "test-secret")
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        if request.method == "GET" and request.url.path.endswith("/rest/v1/files"):
            assert "expires_at" in str(request.url)
            return httpx.Response(200, json=[
                {"id": "f1", "bucket": "uploads", "storage_path": "user/scan/a.png"},
                {"id": "f2", "bucket": "scan-artifacts", "storage_path": "user/scan/page.png"},
            ])
        if request.method == "DELETE" and "/storage/v1/object/" in request.url.path:
            return httpx.Response(200, json={"message": "ok"})
        if request.method == "DELETE" and request.url.path.endswith("/rest/v1/files"):
            return httpx.Response(204)
        return httpx.Response(404)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await retention.purge_expired(client=client)

    summary = asyncio.run(run())
    assert summary["status"] == "ok"
    assert summary["objects"] == 2
    assert summary["rows"] == 2
    assert summary["storage_failed"] == 0
    assert any(path.startswith("/storage/v1/object/uploads") for _, path in seen)
    assert any(path.startswith("/storage/v1/object/scan-artifacts") for _, path in seen)


def test_storage_failure_keeps_row_accounting_honest(monkeypatch):
    monkeypatch.setenv("SUPABASE_URL", "https://project.supabase.co")
    monkeypatch.setenv("SUPABASE_SECRET_KEY", "test-secret")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=[{"id": "f1", "bucket": "uploads", "storage_path": "user/scan/a.png"}])
        if "/storage/v1/object/" in request.url.path:
            return httpx.Response(500, json={"message": "boom"})
        return httpx.Response(204)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await retention.purge_expired(client=client)

    summary = asyncio.run(run())
    assert summary["objects"] == 0
    assert summary["storage_failed"] == 1
    assert summary["rows"] == 1


def test_empty_batch_is_a_no_op(monkeypatch):
    monkeypatch.setenv("SUPABASE_URL", "https://project.supabase.co")
    monkeypatch.setenv("SUPABASE_SECRET_KEY", "test-secret")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[])

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await retention.purge_expired(client=client)

    summary = asyncio.run(run())
    assert summary["rows"] == 0 and summary["objects"] == 0

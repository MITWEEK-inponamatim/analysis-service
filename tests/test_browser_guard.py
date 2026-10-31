import asyncio
import base64
import socket

import pytest

from app.browser_guard import UnsafeTarget, parse_target, resolve_public, validate_browser_target, validate_target
from app.pinned_proxy import PinnedEgressProxy, egress_token


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/",
    "http://10.1.2.3/",
    "http://192.168.1.2/",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]/",
    "http://[fc00::1]/",
    "http://[fe80::1]/",
    "http://192.0.0.9/",
    "http://192.0.2.10/",
    "http://[2001::1]/",
    "http://[2001:db8::1]/",
    "http://[2002:0808:0808::1]/",
    "http://[64:ff9b::a00:1]/",
])
def test_private_and_reserved_ip_literals_rejected(url):
    _, host, port = parse_target(url)
    with pytest.raises(UnsafeTarget):
        resolve_public(host, port)


@pytest.mark.parametrize("url", ["file:///etc/passwd", "gopher://127.0.0.1/", "https://example.com:8443/"])
def test_unsupported_schemes_and_ports_rejected(url):
    with pytest.raises(UnsafeTarget):
        parse_target(url)


@pytest.mark.parametrize("url", ["http://localhost/", "http://service.internal/", "http://127.0.0.1/", "http://169.254.169.254/"])
def test_browser_route_rejects_local_targets(url):
    with pytest.raises(UnsafeTarget):
        validate_browser_target(url)


def test_localhost_and_mixed_dns_addresses_rejected(monkeypatch):
    def local_dns(*_args, **_kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))]

    monkeypatch.setattr("app.browser_guard.socket.getaddrinfo", local_dns)
    with pytest.raises(UnsafeTarget):
        resolve_public("localhost", 80)

    def mixed_dns(*_args, **_kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 80)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 80)),
        ]

    monkeypatch.setattr("app.browser_guard.socket.getaddrinfo", mixed_dns)
    with pytest.raises(UnsafeTarget):
        resolve_public("mixed.example", 80)


def test_pinned_proxy_uses_resolved_ip_and_requires_service_key(monkeypatch):
    opened = []

    class Writer:
        def __init__(self):
            self.output = bytearray()

        def write(self, data):
            self.output.extend(data)

        def writelines(self, lines):
            for line in lines:
                self.write(line)

        async def drain(self):
            return None

        def close(self):
            return None

        async def wait_closed(self):
            return None

    async def open_connection(host, port):
        opened.append((host, port))
        reader = asyncio.StreamReader()
        reader.feed_data(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        reader.feed_eof()
        return reader, Writer()

    monkeypatch.setattr("app.pinned_proxy.resolve_public", lambda _host, _port: ["8.8.8.8"])
    monkeypatch.setattr("app.pinned_proxy.asyncio.open_connection", open_connection)
    proxy = PinnedEgressProxy(token="secret")

    async def run():
        reader = asyncio.StreamReader()
        reader.feed_data(b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n")
        reader.feed_eof()
        denied = Writer()
        await proxy._handle(reader, denied)
        assert b"407 Proxy Authentication Required" in denied.output

        reader = asyncio.StreamReader()
        authorization = base64.b64encode(b"00000000-0000-0000-0000-000000000001:secret")
        reader.feed_data(b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic " + authorization + b"\r\n\r\n")
        reader.feed_eof()
        allowed = Writer()
        await proxy._handle(reader, allowed)
        assert b"200 OK" in allowed.output

    asyncio.run(run())
    assert opened == [("8.8.8.8", 80)]


def test_validate_target_rejects_file_url():
    with pytest.raises(UnsafeTarget):
        asyncio.run(validate_target("file:///etc/passwd"))


def test_proxy_rejects_invalid_authorization():
    proxy = PinnedEgressProxy(token="expected-secret")

    async def run():
        async def no_op(*_args):
            return None

        reader = asyncio.StreamReader()
        reader.feed_data(b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic invalid\r\n\r\n")
        reader.feed_eof()
        writer = type("Writer", (), {"output": bytearray(), "write": lambda self, data: self.output.extend(data), "drain": no_op, "close": lambda self: None, "wait_closed": no_op})()
        await proxy._handle(reader, writer)
        assert b"407 Proxy Authentication Required" in writer.output

    asyncio.run(run())


def test_proxy_rejects_request_body_over_limit():
    proxy = PinnedEgressProxy(token="secret")
    authorization = base64.b64encode(b"00000000-0000-0000-0000-000000000001:secret")

    async def run():
        async def no_op(*_args):
            return None

        reader = asyncio.StreamReader()
        reader.feed_data(b"POST http://example.com/upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 2097153\r\nProxy-Authorization: Basic " + authorization + b"\r\n\r\n")
        reader.feed_eof()
        writer = type("Writer", (), {"output": bytearray(), "write": lambda self, data: self.output.extend(data), "drain": no_op, "close": lambda self: None, "wait_closed": no_op})()
        await proxy._handle(reader, writer)
        assert b"403 Forbidden" in writer.output

    asyncio.run(run())


def test_proxy_revalidates_redirected_private_destination(monkeypatch):
    opened = []

    class Writer:
        def __init__(self):
            self.output = bytearray()

        def write(self, data):
            self.output.extend(data)

        def writelines(self, lines):
            for line in lines:
                self.write(line)

        async def drain(self):
            return None

        def close(self):
            return None

        async def wait_closed(self):
            return None

    async def open_connection(host, port):
        opened.append((host, port))
        reader = asyncio.StreamReader()
        reader.feed_data(b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/latest/meta-data/\r\nContent-Length: 0\r\n\r\n")
        reader.feed_eof()
        return reader, Writer()

    def resolve(host, port):
        if host == "127.0.0.1":
            raise UnsafeTarget("non_public_address")
        return ["93.184.216.34"]

    monkeypatch.setattr("app.pinned_proxy.resolve_public", resolve)
    monkeypatch.setattr("app.pinned_proxy.asyncio.open_connection", open_connection)
    proxy = PinnedEgressProxy(token="secret")
    authorization = base64.b64encode(b"00000000-0000-0000-0000-000000000001:secret")

    async def run():
        reader = asyncio.StreamReader()
        reader.feed_data(b"GET http://example.com/redirect HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic " + authorization + b"\r\n\r\n")
        reader.feed_eof()
        redirect = Writer()
        await proxy._handle(reader, redirect)
        assert b"302 Found" in redirect.output

        reader = asyncio.StreamReader()
        reader.feed_data(b"GET http://127.0.0.1/latest/meta-data/ HTTP/1.1\r\nHost: 127.0.0.1\r\nProxy-Authorization: Basic " + authorization + b"\r\n\r\n")
        reader.feed_eof()
        blocked = Writer()
        await proxy._handle(reader, blocked)
        assert b"403 Forbidden" in blocked.output

    asyncio.run(run())
    assert opened == [("93.184.216.34", 80)]


def test_proxy_closes_tunnel_after_per_scan_byte_budget():
    proxy = PinnedEgressProxy(token="secret")

    async def run():
        scan_id = "00000000-0000-0000-0000-000000000001"
        assert await proxy._register_scan(scan_id)
        assert await proxy._consume(scan_id, proxy.max_scan_bytes - 1)
        assert not await proxy._consume(scan_id, 2)

    asyncio.run(run())


def test_internal_keys_are_separate_and_deterministic():
    from app.browser_auth import browser_service_key

    assert browser_service_key("go-python-key") != "go-python-key"
    assert egress_token(browser_service_key("go-python-key")) != browser_service_key("go-python-key")
    assert browser_service_key("go-python-key") == browser_service_key("go-python-key")


def test_proxy_enforces_per_scan_request_limit(monkeypatch):
    import app.pinned_proxy as proxy_module

    monkeypatch.setattr(proxy_module, "MAX_REQUESTS_PER_SCAN", 2)
    proxy = PinnedEgressProxy(token="secret")

    async def run():
        scan_id = "00000000-0000-0000-0000-000000000001"
        assert await proxy._register_request(scan_id)
        assert await proxy._register_request(scan_id)
        assert not await proxy._register_request(scan_id)

    asyncio.run(run())

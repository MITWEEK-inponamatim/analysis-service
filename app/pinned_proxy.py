import asyncio
import base64
import hashlib
import hmac
import os
from collections import deque
from uuid import UUID

from .browser_guard import UnsafeTarget, parse_target, resolve_public

MAX_TUNNEL_BYTES = min(100, max(1, int(os.getenv("BROWSER_MAX_RESPONSE_MB", "20")))) << 20
MAX_REQUEST_BODY_BYTES = 2 << 20
MAX_CONNECTIONS = 16
MAX_REQUESTS_PER_SCAN = 80


def egress_token(service_key: str) -> str:
    return hmac.new(service_key.encode(), b"threatlens-browser-egress", hashlib.sha256).hexdigest()


class PinnedEgressProxy:
    def __init__(self, host="127.0.0.1", port=0, token=""):
        self.host = host
        self.port = port
        self.token = token
        self.server = None
        self._url = None
        self.budgets = {}
        self.active_scans = {}
        self.scan_requests = {}
        self.connection_count = 0
        self.connection_lock = asyncio.Lock()
        self.budget_lock = asyncio.Lock()

    async def __aenter__(self):
        self.server = await asyncio.start_server(self._handle, self.host, self.port, limit=16 * 1024)
        address = self.server.sockets[0].getsockname()
        self._url = f"http://{address[0]}:{address[1]}"
        return self

    async def __aexit__(self, *_exc):
        self.server.close()
        await self.server.wait_closed()

    @property
    def url(self):
        return self._url

    async def _handle(self, reader, writer):
        upstream_reader = upstream_writer = None
        scan_id = ""
        registered = False
        try:
            async with self.connection_lock:
                if self.connection_count >= MAX_CONNECTIONS:
                    writer.write(b"HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                    await writer.drain()
                    return
                self.connection_count += 1
                registered = True
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=3)
            lines = head.split(b"\r\n")
            method, target, version = lines[0].decode("ascii").split(" ", 2)
            authorization = next((line.partition(b":")[2].strip() for line in lines[1:] if line.lower().startswith(b"proxy-authorization:")), b"")
            try:
                principal, separator, _ = base64.b64decode(authorization.removeprefix(b"Basic "), validate=True).partition(b":")
                scan_id = str(UUID(principal.decode("ascii")))
            except (ValueError, UnicodeError):
                scan_id, separator = "", b""
            expected = b"Basic " + base64.b64encode(scan_id.encode() + b":" + self.token.encode())
            if not self.token or not separator or not hmac.compare_digest(authorization, expected):
                writer.write(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"ThreatLens\"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                return
            if not await self._register_scan(scan_id):
                writer.write(b"HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                return
            if not await self._register_request(scan_id):
                writer.write(b"HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                return
            if method.upper() == "CONNECT":
                _, host, port = parse_target(f"https://{target}/")
                addresses = await asyncio.wait_for(asyncio.to_thread(resolve_public, host, port), timeout=3)
                upstream_reader, upstream_writer = await asyncio.wait_for(asyncio.open_connection(addresses[0], port), timeout=3)
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()
                await asyncio.gather(self._relay(reader, upstream_writer, scan_id), self._relay(upstream_reader, writer, scan_id))
                return

            parsed, host, port = parse_target(target)
            addresses = await asyncio.wait_for(asyncio.to_thread(resolve_public, host, port), timeout=3)
            upstream_reader, upstream_writer = await asyncio.wait_for(asyncio.open_connection(addresses[0], port), timeout=3)
            request_headers = [line for line in lines[1:] if line]
            if any(line.lower().startswith(b"transfer-encoding:") for line in request_headers):
                raise ValueError("chunked proxy requests are unsupported")
            content_lengths = [line.partition(b":")[2].strip() for line in request_headers if line.lower().startswith(b"content-length:")]
            if len(content_lengths) > 1:
                raise ValueError("duplicate content-length")
            body_size = int(content_lengths[0]) if content_lengths else 0
            if body_size < 0 or body_size > MAX_REQUEST_BODY_BYTES:
                raise ValueError("request body too large")
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            output = [f"{method} {path} {version}\r\n".encode("ascii")]
            output.append(f"Host: {parsed.netloc}\r\n".encode("ascii"))
            for line in lines[1:]:
                if line and not line.lower().startswith((b"host:", b"connection:", b"proxy-connection:", b"proxy-authorization:")):
                    output.extend((line, b"\r\n"))
            output.append(b"Connection: close\r\n\r\n")
            upstream_writer.writelines(output)
            await upstream_writer.drain()
            if body_size:
                body = await reader.readexactly(body_size)
                if not await self._consume(scan_id, len(body)):
                    raise ValueError("scan network budget exceeded")
                upstream_writer.write(body)
                await upstream_writer.drain()
            while chunk := await asyncio.wait_for(upstream_reader.read(65536), timeout=10):
                if not await self._consume(scan_id, len(chunk)):
                    raise ValueError("scan network budget exceeded")
                writer.write(chunk)
                await writer.drain()
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError, OSError, UnicodeError, ValueError, UnsafeTarget):
            try:
                writer.write(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
            except OSError:
                pass
        finally:
            if upstream_writer:
                upstream_writer.close()
                try:
                    await upstream_writer.wait_closed()
                except OSError:
                    pass
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
            if scan_id:
                await self._release_scan(scan_id)
            if registered:
                async with self.connection_lock:
                    self.connection_count -= 1

    async def _register_scan(self, scan_id: str) -> bool:
        async with self.budget_lock:
            now = asyncio.get_running_loop().time()
            for key, (deadline, _) in list(self.active_scans.items()):
                if deadline <= now:
                    self.active_scans.pop(key, None)
            for key, (_, deadline) in list(self.budgets.items()):
                if deadline <= now:
                    self.budgets.pop(key, None)
            active = sum(refs > 0 for _, refs in self.active_scans.values())
            current = self.active_scans.get(scan_id)
            if (not current or current[0] <= now or current[1] == 0) and active >= 2:
                return False
            deadline = current[0] if current and current[0] > now else now + 180
            refs = current[1] if current and current[0] > now else 0
            used, budget_deadline = self.budgets.get(scan_id, (0, deadline))
            if current and current[0] <= now:
                used, budget_deadline = 0, deadline
            self.active_scans[scan_id] = (deadline, refs + 1)
            self.budgets[scan_id] = (used, budget_deadline)
            return True

    async def _register_request(self, scan_id: str) -> bool:
        async with self.budget_lock:
            now = asyncio.get_running_loop().time()
            requests = self.scan_requests.get(scan_id, deque())
            while requests and now - requests[0] >= 180:
                requests.popleft()
            if len(requests) >= MAX_REQUESTS_PER_SCAN:
                return False
            requests.append(now)
            self.scan_requests[scan_id] = requests
            for key, history in list(self.scan_requests.items()):
                if not history or now - history[-1] >= 180:
                    self.scan_requests.pop(key, None)
            return True

    async def _release_scan(self, scan_id: str):
        async with self.budget_lock:
            if current := self.active_scans.get(scan_id):
                deadline, refs = current
                now = asyncio.get_running_loop().time()
                self.active_scans[scan_id] = (deadline if refs > 1 else now + 180, max(0, refs - 1))

    async def _consume(self, scan_id: str, byte_count: int) -> bool:
        async with self.budget_lock:
            now = asyncio.get_running_loop().time()
            if self.active_scans.get(scan_id, (0, 0))[0] <= now:
                return False
            used, expires = self.budgets.get(scan_id, (0, now + 180))
            if expires <= now:
                return False
            used += byte_count
            self.budgets[scan_id] = (used, expires)
            for key, (_, deadline) in list(self.budgets.items()):
                if deadline <= now:
                    self.budgets.pop(key, None)
                    self.active_scans.pop(key, None)
            return used <= self.max_scan_bytes

    @property
    def max_scan_bytes(self):
        return MAX_TUNNEL_BYTES

    async def _relay(self, reader, writer, scan_id: str):
        try:
            while chunk := await asyncio.wait_for(reader.read(65536), timeout=10):
                if not await self._consume(scan_id, len(chunk)):
                    writer.close()
                    break
                writer.write(chunk)
                await writer.drain()
        except (OSError, asyncio.CancelledError):
            pass
        finally:
            try:
                if not writer.is_closing():
                    writer.close()
            except (OSError, AttributeError, RuntimeError):
                pass

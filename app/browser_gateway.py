import hmac
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, urlopen

MAX_BODY = 64 << 10
MAX_RESPONSE = 5 << 20
slots = threading.BoundedSemaphore(4)
GATEWAY_LIMITS = {}
LIMIT_LOCK = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    server_version = "ThreatLensGateway"

    def do_POST(self):
        if self.path != "/internal/v1/inspect" or not self.valid_key():
            self.reply(404 if self.path != "/internal/v1/inspect" else 401, b'{"detail":"unauthorized"}')
            return
        length = self.headers.get("Content-Length", "")
        if not length.isdecimal() or int(length) > MAX_BODY:
            self.reply(413, b'{"detail":"request_too_large"}')
            return
        if not slots.acquire(blocking=False):
            self.reply(429, b'{"detail":"busy"}')
            return
        try:
            self.connection.settimeout(3)
            payload = self.rfile.read(int(length))
            if len(payload) != int(length):
                self.reply(400, b'{"detail":"incomplete_request"}')
                return
            if not self.take_slot():
                self.reply(429, b'{"detail":"rate_limited"}')
                return
            request = Request(
                "http://browser-worker:8001/internal/v1/inspect",
                data=payload,
                headers={"Content-Type": "application/json", "X-Service-Key": os.environ["BROWSER_SERVICE_KEY"]},
                method="POST",
            )
            with urlopen(request, timeout=40) as response:
                data = response.read(MAX_RESPONSE + 1)
                if len(data) > MAX_RESPONSE:
                    self.reply(502, b'{"detail":"response_too_large"}')
                else:
                    self.reply(response.status, data)
        except Exception:
            self.reply(502, b'{"detail":"browser_unavailable"}')
        finally:
            slots.release()

    def do_GET(self):
        if self.path != "/internal/v1/health":
            self.reply(404, b'{"detail":"not_found"}')
        elif not self.valid_key():
            self.reply(401, b'{"detail":"unauthorized"}')
        else:
            self.reply(200, b'{"status":"ok"}')

    def valid_key(self):
        expected = os.environ.get("BROWSER_SERVICE_KEY", "")
        supplied = self.headers.get("X-Service-Key", "")
        return bool(expected and supplied and hmac.compare_digest(supplied, expected))

    def take_slot(self):
        key = self.client_address[0]
        now = time.monotonic()
        with LIMIT_LOCK:
            requests = [timestamp for timestamp in GATEWAY_LIMITS.get(key, []) if now - timestamp < 60]
            if len(requests) >= 20:
                GATEWAY_LIMITS[key] = requests
                return False
            requests.append(now)
            GATEWAY_LIMITS[key] = requests
            if len(GATEWAY_LIMITS) > 4096:
                for address, timestamps in list(GATEWAY_LIMITS.items()):
                    if not timestamps or now - timestamps[-1] >= 60:
                        GATEWAY_LIMITS.pop(address, None)
            return True

    def reply(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


def main():
    if not os.environ.get("BROWSER_SERVICE_KEY"):
        raise RuntimeError("BROWSER_SERVICE_KEY is required")
    ThreadingHTTPServer(("0.0.0.0", 8002), Handler).serve_forever()


if __name__ == "__main__":
    main()

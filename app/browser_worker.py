import asyncio
import base64
import hmac
import os
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from .browser_guard import UnsafeTarget, validate_browser_target
from .pinned_proxy import egress_token

app = FastAPI(title="ThreatLens Browser Worker", docs_url=None, redoc_url=None)
slots = asyncio.Semaphore(2)
MAX_REQUESTS = 80
MAX_SCREENSHOT_BYTES = 3 << 20


class InspectRequest(BaseModel):
    url: str = Field(max_length=2048)
    scan_id: str
    user_id: str


def require_service_key(key: str | None):
    import os

    expected = os.getenv("BROWSER_SERVICE_KEY", "")
    if not expected or not key or not hmac.compare_digest(key, expected):
        raise HTTPException(status_code=401, detail="unauthorized")


def safe_evidence_url(value: str) -> str:
    try:
        parts = urlsplit(value)
        host = parts.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        if parts.port:
            host += f":{parts.port}"
        return urlunsplit((parts.scheme, host, "/", "", ""))[:1024]
    except ValueError:
        return ""


@app.get("/internal/v1/health")
async def health(x_service_key: str | None = Header(default=None)):
    require_service_key(x_service_key)
    return {"status": "ok"}


@app.post("/internal/v1/inspect")
async def inspect(request: InspectRequest, x_service_key: str | None = Header(default=None)):
    require_service_key(x_service_key)
    try:
        UUID(request.scan_id)
        UUID(request.user_id)
        validate_browser_target(request.url)
    except (ValueError, UnsafeTarget, asyncio.TimeoutError, OSError) as exc:
        raise HTTPException(status_code=422, detail="unsafe_target") from exc

    from playwright.async_api import TimeoutError as PlaywrightTimeoutError
    from playwright.async_api import async_playwright

    async with slots:
        blocked: list[str] = []
        requested: set[str] = set()
        request_count = 0
        ssrf_attempts = 0
        redirects: list[dict[str, object]] = []
        failed_requests: list[str] = []
        blocked_methods: list[str] = []
        network_requests: list[dict[str, object]] = []
        network_entries = {}
        browser = context = None
        page_text = ""
        forms: list[dict[str, object]] = []
        screenshot = None
        final_url = ""
        title = ""
        failure = None
        async with async_playwright() as playwright:
            browser = context = None
            proxy_key = os.getenv("BROWSER_SERVICE_KEY", "")
            if not proxy_key:
                raise RuntimeError("browser egress proxy unavailable")
            browser_env = {key: os.environ[key] for key in ("PATH", "HOME", "PLAYWRIGHT_BROWSERS_PATH", "LANG", "TZ") if key in os.environ}
            proxy_url = os.getenv("BROWSER_EGRESS_PROXY_URL", "http://172.29.254.2:8888")
            browser = await playwright.chromium.launch(headless=True, chromium_sandbox=False, env=browser_env, proxy={"server": proxy_url, "username": request.scan_id, "password": egress_token(proxy_key), "bypass": ""}, args=["--disable-quic", "--disable-webrtc", "--disable-background-networking", "--disable-sync", "--disable-component-update", "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 172.29.254.2"])
            context = await browser.new_context(accept_downloads=False, viewport={"width": 1280, "height": 720}, service_workers="block")
            page = await context.new_page()

            async def guard(route):
                nonlocal request_count, ssrf_attempts
                target = route.request.url
                request_count += 1
                if request_count > MAX_REQUESTS:
                    blocked.append("request_limit")
                    await route.abort("blockedbyclient")
                    return
                if route.request.method.upper() not in {"GET", "HEAD", "OPTIONS"}:
                    blocked_methods.append(route.request.method.upper()[:12])
                    await route.abort("blockedbyclient")
                    return
                try:
                    validate_browser_target(target)
                    requested.add(target)
                    await route.continue_()
                except (UnsafeTarget, ValueError):
                    ssrf_attempts += 1
                    rejected = safe_evidence_url(target)
                    blocked.append(rejected)
                    await route.abort("blockedbyclient")

            await page.route("**/*", guard)

            def on_response(response):
                if entry := network_entries.get(id(response.request)):
                    entry["status"] = response.status
                if response.request.is_navigation_request() and len(redirects) < 10:
                    try:
                        if response.request.frame == page.main_frame:
                            redirects.append({"url": safe_evidence_url(response.url), "status": response.status})
                    except Exception:
                        pass

            page.on("response", on_response)

            def on_request(browser_request):
                if len(network_requests) < MAX_REQUESTS:
                    entry = {"url": safe_evidence_url(browser_request.url), "method": browser_request.method[:12], "resource_type": browser_request.resource_type[:24]}
                    network_requests.append(entry)
                    network_entries[id(browser_request)] = entry

            page.on("request", on_request)

            def on_request_failed(browser_request):
                if len(failed_requests) < 100:
                    failed_requests.append({"url": safe_evidence_url(browser_request.url), "reason": (browser_request.failure or "request_failed").splitlines()[0][:120]})
                if entry := network_entries.get(id(browser_request)):
                    entry["failed"] = True

            page.on("requestfailed", on_request_failed)
            page.set_default_timeout(2500)
            try:
                await page.goto(request.url, wait_until="domcontentloaded", timeout=15000)
                final_url = safe_evidence_url(page.url)
                title = (await page.title())[:300]
                try:
                    page_text = (await page.locator("body").inner_text(timeout=2500))[:12000]
                except Exception:
                    pass
                try:
                    forms = await page.locator("form").evaluate_all("""forms => forms.slice(0, 30).map(form => ({
                        method: (form.method || 'get').toUpperCase(),
                        action: form.action,
                        password_fields: form.querySelectorAll('input[type=password]').length,
                        input_types: Array.from(form.querySelectorAll('input')).slice(0, 20).map(input => input.type || 'text')
                    }))""")
                    forms = [{**item, "action": safe_evidence_url(item.get("action", "")), "password_fields": min(20, max(0, int(item.get("password_fields", 0)))), "input_types": item.get("input_types", [])[:20]} for item in forms]
                except Exception:
                    forms = []
                try:
                    data = await page.screenshot(type="png", full_page=False, animations="disabled", timeout=3000)
                    if len(data) <= MAX_SCREENSHOT_BYTES:
                        screenshot = base64.b64encode(data).decode("ascii")
                except Exception:
                    pass
            except PlaywrightTimeoutError:
                failure = "navigation_timeout"
            except Exception:
                failure = "navigation_failed"
            finally:
                if context:
                    await context.close()
                if browser:
                    await browser.close()

    original_host = (urlsplit(request.url).hostname or "").casefold().rstrip(".")
    domains = set()
    for target in requested:
        try:
            host = (urlsplit(target).hostname or "").casefold().rstrip(".")
            if host and host != original_host:
                domains.add(host[:253])
        except ValueError:
            continue
    return {
        "final_url": final_url,
        "title": title,
        "visible_text": page_text,
        "forms": forms,
        "external_domains": sorted(domains)[:100],
        "redirect_chain": redirects,
        "network_requests": network_requests,
        "blocked_requests": blocked[:100],
        "failed_requests": failed_requests,
        "blocked_methods": blocked_methods[:100],
        "ssrf_blocked": bool(ssrf_attempts or failed_requests),
        "screenshot_base64": screenshot,
        "error": failure,
    }

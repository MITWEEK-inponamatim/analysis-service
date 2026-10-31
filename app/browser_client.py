import base64
import hashlib
import os
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import httpx
from .browser_auth import browser_service_key


async def inspect_website(url: str, scan_id: str, user_id: str) -> dict:
    base = os.getenv("BROWSER_WORKER_URL", "http://browser-gateway:8002").rstrip("/")
    key = os.getenv("SERVICE_API_KEY", "")
    async with httpx.AsyncClient(timeout=httpx.Timeout(35, connect=3)) as client:
        response = await client.post(
            f"{base}/internal/v1/inspect",
            headers={"X-Service-Key": browser_service_key(key)},
            json={"url": url, "scan_id": scan_id, "user_id": user_id},
        )
        response.raise_for_status()
        result = response.json()

    screenshot = result.pop("screenshot_base64", None)
    if screenshot:
        data = base64.b64decode(screenshot, validate=True)
        supabase = os.getenv("SUPABASE_URL", "").rstrip("/")
        secret = os.getenv("SUPABASE_SECRET_KEY", "")
        if supabase and secret:
            path = f"{user_id}/{scan_id}/page.png"
            uploaded = False
            try:
                async with httpx.AsyncClient(timeout=12) as client:
                    async with client.stream(
                        "POST",
                        f"{supabase}/storage/v1/object/scan-artifacts/{quote(path, safe='/')}",
                        headers={"apikey": secret, "Authorization": f"Bearer {secret}", "Content-Type": "image/png", "x-upsert": "true"},
                        content=data,
                    ) as upload:
                        upload.raise_for_status()
                    uploaded = True
                    metadata = {"user_id": user_id, "scan_id": scan_id, "bucket": "scan-artifacts", "storage_path": path, "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data), "mime": "image/png", "expires_at": (datetime.now(timezone.utc) + timedelta(days=int(os.getenv("FILE_RETENTION_DAYS", "7")))).isoformat()}
                    async with client.stream("POST", f"{supabase}/rest/v1/files", headers={"apikey": secret, "Authorization": f"Bearer {secret}", "Content-Type": "application/json", "Prefer": "return=minimal"}, json=metadata) as record:
                        record.raise_for_status()
                result["screenshot_path"] = path
            except Exception:
                if uploaded:
                    try:
                        async with httpx.AsyncClient(timeout=5) as client:
                            async with client.stream("DELETE", f"{supabase}/storage/v1/object/scan-artifacts", headers={"apikey": secret, "Authorization": f"Bearer {secret}", "Content-Type": "application/json"}, json={"prefixes": [path]}) as cleanup:
                                cleanup.raise_for_status()
                    except Exception:
                        pass
                result["screenshot_path"] = None
                result["screenshot_unavailable"] = True
        else:
            result["screenshot_path"] = None
            result["screenshot_unavailable"] = True
    else:
        result["screenshot_path"] = None
    return result

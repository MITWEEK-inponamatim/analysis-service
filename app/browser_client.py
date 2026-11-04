import base64
import os

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
        cloudinary_url = os.getenv("CLOUDINARY_URL", "")
        
        if cloudinary_url:
            try:
                import cloudinary
                import cloudinary.uploader
                
                # Configure Cloudinary from URL. The SDK parses CLOUDINARY_URL only when
                # CLOUDINARY_CLOUD_NAME is absent, and this project sets both, so the key and
                # secret are read from the URL here; an explicit CLOUDINARY_CLOUD_NAME outranks
                # the URL host. Without this the upload silently had no api_key at all.
                from urllib.parse import unquote, urlparse

                parts = urlparse(cloudinary_url)
                cloudinary.config(
                    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME", "").strip() or str(parts.hostname or ""),
                    api_key=unquote(parts.username or ""),
                    api_secret=unquote(parts.password or ""),
                )
                
                public_id = f"threatlens/scans/{user_id}/{scan_id}"
                
                # Synchronous upload (Cloudinary SDK doesn't have async)
                # Run in thread to avoid blocking
                import asyncio
                loop = asyncio.get_event_loop()
                upload_result = await loop.run_in_executor(
                    None,
                    lambda: cloudinary.uploader.upload(
                        f"data:image/png;base64,{screenshot}",
                        public_id=public_id,
                        overwrite=True,
                    )
                )
                
                # Return Cloudinary URL
                result["screenshot_path"] = upload_result.get("secure_url")
                result["screenshot_public_id"] = upload_result.get("public_id")
                
            except Exception:
                result["screenshot_path"] = None
                result["screenshot_unavailable"] = True
        else:
            result["screenshot_path"] = None
            result["screenshot_unavailable"] = True
    else:
        result["screenshot_path"] = None
    
    return result


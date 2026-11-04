"""Evidence images attached to community phone reports.

A report is only accepted with an image, so this module is a deliberately thin Cloudinary
wrapper: it stores, it destroys, and it says plainly when it cannot. The write path stays in Go
(the user identity lives there), so this is reached only through the service-key endpoints.
Assets land in their own folder with a random suffix so a report image cannot be enumerated.
"""

import asyncio
import base64
import os
import re
import secrets
from typing import Any

EVIDENCE_FOLDER = "threatlens/phone-reports"
MAX_EVIDENCE_BYTES = 5 << 20
ALLOWED_EVIDENCE_MIME = {"image/jpeg", "image/png", "image/webp", "image/heic", "image/heif"}
UUID_SHAPE = re.compile(r"[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
REFERENCE_SHAPE = re.compile(r"[A-Za-z0-9_-]{8,64}")


def configured() -> bool:
    return bool(os.getenv("CLOUDINARY_URL", "").strip())


def _configure() -> None:
    import cloudinary
    from urllib.parse import unquote, urlparse

    # The SDK parses CLOUDINARY_URL only when CLOUDINARY_CLOUD_NAME is absent, and this project
    # sets both, so handing it the URL alone silently produced a config without credentials.
    # Key and secret come from the URL; an explicit CLOUDINARY_CLOUD_NAME outranks the URL host,
    # which is the precedence the SDK itself uses (and this deployment's URL host is stale).
    parts = urlparse(os.getenv("CLOUDINARY_URL", "").strip())
    cloudinary.config(
        cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME", "").strip() or str(parts.hostname or ""),
        api_key=unquote(parts.username or ""),
        api_secret=unquote(parts.password or ""),
    )


def _decode(data_base64: str) -> bytes | None:
    try:
        raw = base64.b64decode(data_base64 or "", validate=True)
    except Exception:
        return None
    return raw if 0 < len(raw) <= MAX_EVIDENCE_BYTES else None


def _identifiers(user_id: str, reference: str) -> bool:
    return bool(UUID_SHAPE.fullmatch(user_id or "") and REFERENCE_SHAPE.fullmatch(reference or ""))


async def store_image(user_id: str, reference: str, mime: str, data_base64: str) -> dict[str, Any] | None:
    """Upload one evidence image and return ``{url, public_id}``, or None when it cannot be kept.

    None is the only acceptable failure answer: the caller must not store a report whose evidence
    did not survive, otherwise "bukti wajib" becomes a suggestion.
    """
    if not configured() or not _identifiers(user_id, reference) or mime not in ALLOWED_EVIDENCE_MIME:
        return None
    raw = _decode(data_base64)
    if raw is None:
        return None
    public_id = f"{EVIDENCE_FOLDER}/{user_id}/{reference}-{secrets.token_urlsafe(8)}"
    try:
        await asyncio.to_thread(_configure)
        import cloudinary.uploader

        result = await asyncio.to_thread(
            cloudinary.uploader.upload,
            f"data:{mime};base64,{data_base64}",
            public_id=public_id,
            resource_type="image",
            folder=EVIDENCE_FOLDER,
            overwrite=False,
        )
    except Exception:
        return None
    url = str(result.get("secure_url") or "")
    if not url:
        return None
    return {"url": url, "public_id": str(result.get("public_id") or public_id), "mime": mime, "size_bytes": len(raw)}


async def discard(public_id: str) -> bool:
    """Delete an evidence asset. Refuses anything outside the phone-report folder.

    The screenshots taken by the URL scanner live under ``threatlens/scans``; a bug in the caller
    must not be able to reach those, or any other asset in the cloud, through this endpoint.
    """
    if not configured() or not str(public_id or "").startswith(f"{EVIDENCE_FOLDER}/"):
        return False
    try:
        await asyncio.to_thread(_configure)
        import cloudinary.uploader

        # invalidate purges the delivery CDN too: a deleted report must stop showing its proof
        # image, not merely lose the copy in the cloud.
        result = await asyncio.to_thread(
            cloudinary.uploader.destroy, public_id, resource_type="image", invalidate=True
        )
    except Exception:
        return False
    return str(result.get("result") or "").lower() in {"ok", "success"}

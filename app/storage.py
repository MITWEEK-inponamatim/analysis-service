"""Supabase Storage helpers for the analysis service.

Python only ever reads objects from the private buckets. The Go backend writes them,
so every path is re-verified here: an object must live under ``{user_id}/{scan_id}/``.
"""

import os
from urllib.parse import quote

import httpx

ALLOWED_BUCKETS = {"uploads", "scan-artifacts"}
DEFAULT_MAX_DOWNLOAD_BYTES = 60 << 20


def _max_download_bytes() -> int:
    try:
        configured = int(os.getenv("MAX_DOWNLOAD_MB", ""))
    except ValueError:
        configured = 0
    return (configured or 60) << 20


class StorageUnavailable(Exception):
    """Storage is not configured or the object could not be fetched."""


class UnsafeStoragePath(Exception):
    """The requested object is outside the caller's own folder."""


def validate_object_path(user_id: str, scan_id: str, storage_path: str) -> str:
    if not user_id or not scan_id or not storage_path:
        raise UnsafeStoragePath("missing user, scan, or object path")
    if "\\" in storage_path or storage_path.startswith("/") or "\x00" in storage_path:
        raise UnsafeStoragePath("object path is not a relative POSIX path")
    parts = storage_path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise UnsafeStoragePath("object path contains an empty or traversal segment")
    if len(parts) < 3 or parts[0] != user_id or parts[1] != scan_id:
        raise UnsafeStoragePath("object path is not owned by this user and scan")
    return storage_path


def _supabase_config() -> tuple[str, str]:
    url = os.getenv("SUPABASE_URL", "").rstrip("/")
    secret = os.getenv("SUPABASE_SECRET_KEY", "")
    if not url or not secret:
        raise StorageUnavailable("Supabase storage is not configured")
    return url, secret


async def download_object(bucket: str, storage_path: str, user_id: str, scan_id: str, max_bytes: int | None = None) -> bytes:
    if bucket not in ALLOWED_BUCKETS:
        raise UnsafeStoragePath("bucket is not allowed")
    validate_object_path(user_id, scan_id, storage_path)
    url, secret = _supabase_config()
    limit = min(max_bytes or _max_download_bytes(), _max_download_bytes())
    endpoint = f"{url}/storage/v1/object/{bucket}/{quote(storage_path, safe='/')}"
    collected = bytearray()
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(30, connect=5)) as client:
            async with client.stream(
                "GET",
                endpoint,
                headers={"apikey": secret, "Authorization": f"Bearer {secret}"},
            ) as response:
                response.raise_for_status()
                async for chunk in response.aiter_bytes():
                    collected.extend(chunk)
                    if len(collected) > limit:
                        raise StorageUnavailable("object exceeds the configured download limit")
    except StorageUnavailable:
        raise
    except httpx.HTTPError as error:
        raise StorageUnavailable("object download failed") from error
    if not collected:
        raise StorageUnavailable("object is empty")
    return bytes(collected)

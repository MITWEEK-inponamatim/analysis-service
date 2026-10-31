"""Indicator extraction from untrusted text (messages, OCR output, APK strings)."""

import re
from urllib.parse import urlsplit

URL_PATTERN = re.compile(r"https?://[^\s<>\"'`\])}]+", re.IGNORECASE)
BARE_HOST_PATTERN = re.compile(r"\b(?:www\.)?[a-z0-9-]{2,}\.[a-z]{2,}(?:/[^\s<>\"'`\])}]*)?", re.IGNORECASE)
SHORTENER_HOSTS = ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rebrand.ly", "s.id", "linktr.ee")
TRAILING_PUNCTUATION = ".,;:!?'\"”’)]}>"


def _clean(candidate: str) -> str:
    return candidate.strip().rstrip(TRAILING_PUNCTUATION)


def _is_public_host(candidate: str) -> bool:
    host = (urlsplit(candidate).hostname or "").casefold()
    if not host or "." not in host:
        return False
    if host in ("localhost",) or host.endswith(".local"):
        return False
    return True


def extract_urls(text: str, limit: int = 3) -> list[str]:
    """Extract candidate URLs, keeping order and de-duplicating by host+path."""
    if not text:
        return []
    candidates = [_clean(match) for match in URL_PATTERN.findall(text)]
    if not candidates:
        bare = [_clean(match) for match in BARE_HOST_PATTERN.findall(text)]
        candidates = [f"https://{match}" for match in bare if match.casefold().startswith(SHORTENER_HOSTS)]
    urls: list[str] = []
    for candidate in candidates:
        if candidate.startswith("https://") or candidate.startswith("http://"):
            if not _is_public_host(candidate):
                continue
            if candidate not in urls:
                urls.append(candidate)
        if len(urls) >= limit:
            break
    return urls

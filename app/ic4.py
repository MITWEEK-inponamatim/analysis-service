"""IC4 (Indonesia Cyber Crime Center) phishing URL lookup.

Optional, best-effort threat intel for Indonesian URLs. If the API key is missing or the
request fails, callers record ``ic4`` in ``checks_unavailable``.
"""

import os

import httpx

from .resilience import json_request
from .risk import finding
from .schemas import Finding

IC4_API_URL = "https://api.ic4.id/api/public/link"


def ic4_available() -> bool:
    """IC4 API available when base URL is configured (public endpoint, no key required)."""
    return bool(os.getenv("IC4_API_URL", IC4_API_URL))


async def ic4_lookup(url: str) -> list[Finding] | None:
    """Check URL against IC4 phishing database.
    
    Returns:
        None if check unavailable/failed
        [] if URL not found in database (clean)
        [Finding] if URL is known phishing
    """
    if not ic4_available():
        return None
    
    # IC4 expects domain without scheme
    normalized = url.replace("https://", "").replace("http://", "").split("/")[0].split("?")[0]
    
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            response = await json_request(
                client,
                "POST",
                os.getenv("IC4_API_URL", IC4_API_URL),
                params={"q": normalized},
                json={"url": normalized}
            )
            data = response.json()
            
            # Response structure: {"code": 200, "message": "...", "data": {...}}
            code = data.get("code")
            message = data.get("message", "")
            result_data = data.get("data")
            
            # "phish_link_not_found" means clean
            if code == 200 and message == "phish_link_not_found":
                return []
            
            # "phish_link_found" or data present means threat
            if code == 200 and (message == "phish_link_found" or result_data):
                return [finding(
                    "URL terdaftar sebagai phishing di database IC4 (Indonesia Cyber Crime Center).",
                    "ic4",
                    "high",
                    {"ic4_message": message}
                )]
            
            # Unknown response → treat as unavailable
            return None
            
    except Exception:
        return None

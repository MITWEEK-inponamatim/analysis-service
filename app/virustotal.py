"""VirusTotal API v3 client for APK hash lookups."""
import hashlib
import asyncio
from typing import Optional
import httpx


async def check_hash(sha256: str, api_key: str, timeout: int = 10) -> dict:
    """
    Query VirusTotal v3 API for file hash.
    
    Returns:
        {
            "found": bool,
            "malicious": int,  # vendor count
            "suspicious": int,
            "undetected": int,
            "harmless": int,
            "engines": int,  # total engines
            "first_seen": str,  # ISO timestamp
            "last_analysis": str,  # ISO timestamp
            "names": list[str],  # detected malware names
            "vendors": {vendor: {"category": str, "result": str}},
        }
    """
    if not api_key:
        return {"found": False, "error": "no_api_key"}
    
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": api_key}
    
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url, headers=headers)
            
            if resp.status_code == 404:
                return {"found": False}
            
            if resp.status_code != 200:
                return {"found": False, "error": f"http_{resp.status_code}"}
            
            data = resp.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            results = attrs.get("last_analysis_results", {})
            
            # Extract unique malware names
            names = set()
            vendors = {}
            for vendor, result in results.items():
                category = result.get("category", "undetected")
                malware_name = result.get("result")
                vendors[vendor] = {"category": category, "result": malware_name or ""}
                if category == "malicious" and malware_name:
                    names.add(malware_name)
            
            return {
                "found": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "harmless": stats.get("harmless", 0),
                "engines": sum(stats.values()),
                "first_seen": attrs.get("first_submission_date", 0),
                "last_analysis": attrs.get("last_analysis_date", 0),
                "names": sorted(names),
                "vendors": vendors,
            }
    except asyncio.TimeoutError:
        return {"found": False, "error": "timeout"}
    except Exception as e:
        return {"found": False, "error": str(e)}


def compute_sha256(data: bytes) -> str:
    """Compute SHA256 hash of bytes."""
    return hashlib.sha256(data).hexdigest()

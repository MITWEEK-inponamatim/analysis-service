"""Save scan evidence to Supabase for audit/analysis."""
import os
from datetime import datetime, timedelta, timezone
import httpx


async def save_scan_evidence(
    scan_id: str,
    user_id: str,
    threat_intel: dict,
    recon_data: dict,
    browser_data: dict
) -> bool:
    """Save scan evidence to scan_evidence table."""
    supabase_url = os.getenv("SUPABASE_URL", "").rstrip("/")
    secret = os.getenv("SUPABASE_SECRET_KEY", "")
    
    if not supabase_url or not secret:
        return False
    
    retention_days = int(os.getenv("FILE_RETENTION_DAYS", "7"))
    expires_at = (datetime.now(timezone.utc) + timedelta(days=retention_days)).isoformat()
    
    payload = {
        "scan_id": scan_id,
        "user_id": user_id,
        "threat_intel": threat_intel,
        "recon_data": recon_data,
        "browser_data": browser_data,
        "expires_at": expires_at
    }
    
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                f"{supabase_url}/rest/v1/scan_evidence",
                headers={
                    "apikey": secret,
                    "Authorization": f"Bearer {secret}",
                    "Content-Type": "application/json",
                    "Prefer": "return=minimal"
                },
                json=payload
            )
            resp.raise_for_status()
            return True
    except Exception:
        return False

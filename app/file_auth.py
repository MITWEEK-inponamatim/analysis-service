import hashlib
import hmac


def file_service_key(service_key: str) -> str:
    """Derive the analysis-worker key so the worker never holds SERVICE_API_KEY."""
    return hmac.new(service_key.encode(), b"threatlens-file-service", hashlib.sha256).hexdigest()

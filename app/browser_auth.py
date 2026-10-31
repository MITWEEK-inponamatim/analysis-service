import hashlib
import hmac


def browser_service_key(service_key: str) -> str:
    return hmac.new(service_key.encode(), b"threatlens-browser-service", hashlib.sha256).hexdigest()

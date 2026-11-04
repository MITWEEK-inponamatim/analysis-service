"""APK signature verification using androguard."""
import hashlib
from typing import Optional
from androguard.core.apk import APK


def verify_signature(apk_bytes: bytes) -> dict:
    """
    Extract and verify APK signature.
    
    Returns:
        {
            "signed": bool,
            "certificates": [{"subject": str, "issuer": str, "sha256": str, "valid_from": str, "valid_to": str}],
            "v1_signed": bool,  # JAR signature
            "v2_signed": bool,  # APK Signature Scheme v2
            "v3_signed": bool,  # APK Signature Scheme v3
            "package_name": str,
            "version_name": str,
            "version_code": int,
            "min_sdk": int,
            "target_sdk": int,
        }
    """
    try:
        apk = APK(apk_bytes, raw=True)
        
        certs = []
        for cert in apk.get_certificates():
            certs.append({
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "sha256": hashlib.sha256(cert.public_bytes_raw).hexdigest(),
                "valid_from": cert.not_valid_before_utc.isoformat(),
                "valid_to": cert.not_valid_after_utc.isoformat(),
            })
        
        # Check signature schemes
        v1 = apk.is_signed_v1()
        v2 = apk.is_signed_v2()
        v3 = apk.is_signed_v3()
        
        return {
            "signed": bool(certs),
            "certificates": certs,
            "v1_signed": v1,
            "v2_signed": v2,
            "v3_signed": v3,
            "package_name": apk.get_package(),
            "version_name": apk.get_androidversion_name() or "",
            "version_code": int(apk.get_androidversion_code() or 0),
            "min_sdk": int(apk.get_min_sdk_version() or 0),
            "target_sdk": int(apk.get_target_sdk_version() or 0),
        }
    except Exception as e:
        return {
            "signed": False,
            "certificates": [],
            "v1_signed": False,
            "v2_signed": False,
            "v3_signed": False,
            "package_name": "",
            "version_name": "",
            "version_code": 0,
            "min_sdk": 0,
            "target_sdk": 0,
            "error": str(e),
        }

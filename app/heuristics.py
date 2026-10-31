"""Deterministic message indicators shared by the message scanner and the agent tools."""

SUSPICIOUS_TERMS = (
    "bit.ly",
    "tinyurl.com",
    "undian",
    "hadiah",
    "otp",
    "verifikasi akun",
    "kata sandi",
    "bank anda",
    "rekening",
    "transfer",
    "kurir",
    "paket anda",
    "akun diblokir",
)

MAX_MESSAGE_CHARS = 20000


def message_terms(text: str) -> list[str]:
    lowered = (text or "").casefold()
    return [term for term in SUSPICIOUS_TERMS if term in lowered]

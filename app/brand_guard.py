"""Lookalike-domain detection: typosquatting, character substitution, homoglyphs.

Deterministic and offline. It answers "does this host imitate a known brand?" — not
"is this page malicious". Findings therefore use ``source="brand_guard"`` and never count as
confirmed threats; the risk engine may raise the level to suspicious/high at most.
"""

import ipaddress
import json
import os
import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from .risk import finding
from .schemas import Finding

DEFAULT_PATH = Path(__file__).parent / "data" / "brands.json"
MAX_FINDINGS_PER_HOST = 3
MIN_TYPOSQUAT_LENGTH = 5

MULTI_LABEL_SUFFIXES = {
    "co.id", "ac.id", "or.id", "web.id", "my.id", "biz.id", "sch.id", "ponpes.id", "net.id",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "co.nz", "com.au", "net.au", "org.au",
    "com.my", "net.my", "org.my", "com.sg", "edu.sg", "com.ph", "com.vn", "co.th", "co.in",
    "co.jp", "co.kr", "com.br", "com.mx", "com.ar", "com.co", "com.pe", "com.tr", "com.cn",
    "com.hk", "com.tw", "com.sa", "com.eg", "com.ng", "com.pk", "com.ua", "co.za",
}
BRAND_LEVEL_SUFFIXES = {"com", "net", "org", "co", "id", "io", "me", "app", "dev", "info", "biz"}

CONFUSABLES = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0445": "x",
    "\u0443": "y", "\u0456": "i", "\u0455": "s", "\u0501": "d", "\u0261": "g",
    "\u04cf": "l", "\u04c0": "l", "\u043a": "k", "\u043c": "m", "\u043d": "h", "\u0442": "t",
    "\u03b1": "a", "\u03b5": "e", "\u03b9": "i", "\u03ba": "k", "\u03bf": "o", "\u03c1": "p",
    "\u03c4": "t", "\u03c5": "u", "\u03bd": "v", "\u03b7": "n", "\u03c7": "x",
}
DIGIT_LOOKALIKES = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "6": "b", "7": "t", "8": "b", "9": "g",
})
TECHNIQUE_TEXT = {
    "homograph": "penipuan homograph (huruf dari aksara lain yang tampak sama)",
    "char_substitution": "substitusi karakter (mis. angka 0 menggantikan huruf o)",
    "typosquat": "typosquatting (ejaan domain menyerupai domain resmi)",
    "brand_token": "penyisipan nama brand ke domain yang bukan milik brand tersebut",
    "brand_subdomain": "pemakaian nama brand sebagai subdomain domain lain",
    "brand_domain_elsewhere": "pemakaian nama brand sebagai label di bawah domain lain",
    "brand_tld_other": "pemakaian nama brand pada TLD yang bukan domain resminya",
}
TECHNIQUE_SEVERITY = {
    "homograph": "high",
    "char_substitution": "high",
    "typosquat": "high",
    "brand_token": "high",
    "brand_subdomain": "medium",
    "brand_domain_elsewhere": "high",
    "brand_tld_other": "medium",
}
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
BRAND_RE = re.compile(r"^[a-z0-9]{2,32}$")


@dataclass(frozen=True)
class BrandMatch:
    host: str
    brand: str
    technique: str
    severity: str
    registrable: str
    official_domains: tuple[str, ...]


def allowlist_path() -> Path:
    override = os.getenv("BRAND_ALLOWLIST_PATH", "").strip()
    return Path(override) if override else DEFAULT_PATH


@lru_cache(maxsize=4)
def _load(path: str) -> tuple[tuple[str, tuple[str, ...]], ...]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return ()
    brands = payload.get("brands") if isinstance(payload, dict) else None
    if not isinstance(brands, dict):
        return ()
    loaded: list[tuple[str, tuple[str, ...]]] = []
    for name, domains in brands.items():
        slug = str(name).strip().casefold()
        if not BRAND_RE.match(slug) or not isinstance(domains, list):
            continue
        official = tuple(str(domain).strip().casefold().rstrip(".") for domain in domains if str(domain).strip())
        if official:
            loaded.append((slug, official))
    return tuple(loaded)


def load_brands() -> dict[str, tuple[str, ...]]:
    return dict(_load(str(allowlist_path())))


def clear_cache() -> None:
    _load.cache_clear()


def brand_count() -> int:
    return len(_load(str(allowlist_path())))


def _decode_label(label: str) -> str:
    if not label.startswith("xn--"):
        return label
    try:
        return label.encode("ascii", "ignore").decode("idna")
    except Exception:
        return label


def _normalize(host: str) -> list[str]:
    value = (host or "").strip().strip(".").casefold()
    if not value:
        return []
    try:
        value = value.encode("idna").decode("ascii")
    except Exception:
        pass
    labels = [_decode_label(label) for label in value.split(".") if label]
    return labels


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def registrable_domain(host: str) -> str:
    labels = [label for label in (host or "").strip().strip(".").casefold().split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-3:]) in MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-4:])
    if ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _is_official(host: str, official: tuple[str, ...]) -> bool:
    for domain in official:
        if host == domain or host.endswith("." + domain):
            return True
    return False


def _brand_zone(labels: list[str], brand: str) -> bool:
    """brand.ccTLD or brand.co.id: the brand label owns a real public suffix.

    Single-label generic TLDs (brand.com, brand.app) are intentionally *not* treated as
    official here, because a brand may not own that TLD; they surface as a weaker signal.
    """
    if len(labels) < 2 or labels[0] != brand:
        return False
    rest = labels[1:]
    if len(rest) == 1:
        return len(rest[0]) == 2 and rest[0].isalpha()
    return ".".join(rest) in MULTI_LABEL_SUFFIXES


def _to_latin(text: str) -> str:
    output = []
    for ch in unicodedata.normalize("NFKC", text).casefold():
        output.append(CONFUSABLES.get(ch, ch))
    return "".join(output)


def skeleton(label: str) -> str:
    text = _to_latin(label).translate(DIGIT_LOOKALIKES)
    text = text.replace("rn", "m").replace("vv", "w")
    return re.sub(r"[^a-z0-9]", "", text)


def _tokens(label: str) -> list[str]:
    return [skeleton(part) for part in re.split(r"[^0-9A-Za-z]+", _to_latin(label)) if part]


def levenshtein(a: str, b: str, limit: int = 2) -> int:
    if a == b:
        return 0
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        if min(current) > limit:
            return limit + 1
        previous = current
    return previous[-1]


def _classify(host: str, labels: list[str], registrable: str, brand: str, official: tuple[str, ...]) -> str | None:
    label = labels[0]
    if _is_official(host, official) or _brand_zone(labels, brand):
        return None
    if label == brand:
        # brand.tld: the brand may own other TLDs, so this is a weaker signal than
        # brand.domain.tld (where the real registrable domain is somebody else's).
        return "brand_domain_elsewhere" if len(labels) > 2 else "brand_tld_other"

    skeleton_label = skeleton(label)
    if not label.isascii() and (skeleton_label == brand or brand in _tokens(label)):
        return "homograph"
    if skeleton_label == brand:
        return "char_substitution"
    if label.isascii() and len(brand) >= MIN_TYPOSQUAT_LENGTH and abs(len(label) - len(brand)) <= 1:
        distance = levenshtein(label, brand, limit=1)
        if distance == 1:
            return "typosquat"
        if len(brand) >= 8 and levenshtein(label, brand, limit=2) == 2:
            return "typosquat"
    if brand in _tokens(label):
        return "brand_token"
    for other in labels[1:-1]:
        if brand in _tokens(other):
            return "brand_subdomain"
    return None


def detect(host: str, brands: dict[str, tuple[str, ...]] | None = None) -> list[BrandMatch]:
    value = (host or "").strip().casefold().strip(".")
    if not value or is_ip(value):
        return []
    if ":" in value:
        value = urlsplit(f"//{value}").hostname or value
    labels = _normalize(value)
    if len(labels) < 2:
        return []
    host_ascii = ".".join(label.encode("idna").decode("ascii") if not label.isascii() else label for label in labels)
    registrable = registrable_domain(host_ascii)
    catalog = brands if brands is not None else load_brands()
    matches: list[BrandMatch] = []
    for brand, official in catalog.items():
        technique = _classify(host_ascii, labels, registrable, brand, official)
        if technique is None:
            continue
        matches.append(BrandMatch(
            host=host_ascii,
            brand=brand,
            technique=technique,
            severity=TECHNIQUE_SEVERITY.get(technique, "medium"),
            registrable=registrable,
            official_domains=tuple(official[:3]),
        ))
    if not matches:
        return []
    matches.sort(key=lambda item: (SEVERITY_RANK.get(item.severity, 0), -len(item.brand)), reverse=True)
    deduped: list[BrandMatch] = []
    seen: set[tuple[str, str]] = set()
    for match in matches:
        key = (match.brand, match.technique)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(match)
        if len(deduped) >= MAX_FINDINGS_PER_HOST:
            break
    return deduped


def brand_findings(host: str, brands: dict[str, tuple[str, ...]] | None = None) -> list[Finding]:
    results: list[Finding] = []
    for match in detect(host, brands):
        official = ", ".join(match.official_domains[:2]) or "-"
        results.append(finding(
            f"Domain \"{match.host}\" terindikasi {TECHNIQUE_TEXT.get(match.technique, 'menyerupai domain resmi')} milik brand \"{match.brand}\" (domain resmi: {official}).",
            "brand_guard",
            match.severity,
            {
                "host": match.host,
                "brand": match.brand,
                "technique": match.technique,
                "registrable_domain": match.registrable,
                "official_domains": list(match.official_domains),
            },
            confidence="medium",
        ))
    return results

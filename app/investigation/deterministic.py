"""Deterministic investigation rules shared by the gate, planner, and skills.

Everything here is pure and offline: no network, no LLM. Agents may interpret the
output, but they never replace these checks.
"""
import ipaddress
import re
from typing import Any, Iterable
from urllib.parse import urlsplit

from ..brand_guard import MULTI_LABEL_SUFFIXES

KNOWN_PROCESSORS = (
    "stripe.com", "paypal.com", "checkout.com", "adyen.com", "xendit.co",
    "midtrans.com", "duitku.com", "nicepay.co.id", "google.com", "microsoft.com",
    "okta.com", "auth0.com", "cloudflare.com", "amazonaws.com",
)
SHORTENER_HOSTS = (
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rb.gy", "shorturl.at", "s.id", "linktr.ee",
)
LOGIN_HINTS = (
    "login", "signin", "sign-in", "sign_in", "masuk", "account", "akun",
    "verify", "verifikasi", "auth", "otp", "password", "secure", "my",
)
SENSITIVE_NAME_PATTERNS = {
    "password": re.compile(r"pass(wd|word)|pwd|sandi|kata.?sandi", re.I),
    "otp": re.compile(r"otp|2fa|mfa|verification|verifikasi|kode|token", re.I),
    "identity": re.compile(r"email|username|user|login|nik|ktp|phone|telp|hp|nama|name", re.I),
    "payment": re.compile(r"card|ccv|cvv|expiry|iban|rekening|account.?number", re.I),
}
DIGIT_LOOKALIKES = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "6": "b", "7": "t", "8": "b", "9": "g"})
CONFUSABLES = str.maketrans({"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ѕ": "s", "α": "a", "ε": "e", "ι": "i", "κ": "k", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "ν": "v", "η": "n", "χ": "x"})
THREAT_INTEL_CHECKS = {"ic4", "malwarebytes", "safe_browsing", "virustotal"}


def normalize_host(value: str) -> str:
    """Hostname -> lowercase, IDNA, no port, no trailing dot. Empty when invalid."""
    raw = (value or "").strip()
    if not raw:
        return ""
    try:
        host = urlsplit(raw).hostname if "://" in raw else urlsplit(f"//{raw}").hostname
    except ValueError:
        return ""
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return ""
    try:
        return host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return host


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def registrable_domain(host: str) -> str:
    normalized = normalize_host(host)
    if not normalized or is_ip(normalized):
        return normalized
    labels = normalized.split(".")
    if len(labels) <= 2:
        return normalized
    for index in range(1, len(labels) - 1):
        suffix = ".".join(labels[index:])
        if suffix in MULTI_LABEL_SUFFIXES:
            return ".".join(labels[index - 1:])
    return ".".join(labels[-2:])


def same_host(left: str, right: str) -> bool:
    return bool(left) and normalize_host(left) == normalize_host(right)


def same_registrable_domain(left: str, right: str) -> bool:
    left_domain = registrable_domain(left)
    return bool(left_domain) and left_domain == registrable_domain(right)


def is_shortener(host: str) -> bool:
    normalized = normalize_host(host)
    return any(normalized == item or normalized.endswith(f".{item}") for item in SHORTENER_HOSTS)


def _skeleton(host: str) -> str:
    base = registrable_domain(host).split(".")[0]
    return re.sub(r"[^a-z0-9]", "", base.translate(CONFUSABLES).translate(DIGIT_LOOKALIKES))


def _brand_key(brand: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (brand or "").casefold())


def lookalike_rules(host: str, brand: str) -> list[str]:
    """Deterministic rule names explaining host/brand similarity. No severity here."""
    normalized = normalize_host(host)
    key = _brand_key(brand)
    if not normalized or not key:
        return []
    rules: list[str] = []
    labels = normalized.split(".")
    skeleton = _skeleton(normalized)
    if skeleton == key:
        rules.append("skeleton_match")
    if key in "".join(labels[:-1]) and skeleton != key:
        rules.append("brand_token_present")
    if any(key in label and label != key for label in labels[:-1]):
        rules.append("brand_subdomain_or_extra_label")
    if re.search(r"[0-9]", skeleton) and skeleton == key:
        rules.append("digit_substitution")
    if re.search(r"[^\x00-\x7f]", normalized):
        rules.append("homograph")
    if "-" in normalized and key in normalized:
        rules.append("brand_with_hyphen")
    return sorted(set(rules))


def domain_relation(host: str, official_domains: Iterable[str]) -> str:
    normalized = normalize_host(host)
    if not normalized:
        return "unknown"
    official = [normalize_host(item) for item in official_domains if normalize_host(item)]
    if not official:
        return "unknown"
    if normalized in official:
        return "exact"
    if any(normalized.endswith(f".{item}") for item in official):
        return "subdomain"
    registrable = registrable_domain(normalized)
    if any(registrable == registrable_domain(item) for item in official):
        return "same_registrable"
    return "unrelated"


def is_private_or_invalid_host(host: str) -> bool:
    normalized = normalize_host(host)
    if not normalized:
        return True
    if is_ip(normalized):
        try:
            address = ipaddress.ip_address(normalized)
        except ValueError:
            return True
        return not address.is_global or address.is_private or address.is_loopback or address.is_link_local
    return normalized in {"localhost"} or normalized.endswith((".local", ".internal"))


def classify_destination(action_host: str, page_host: str) -> str:
    normalized = normalize_host(action_host)
    if is_private_or_invalid_host(normalized):
        return "private_or_invalid"
    if same_host(normalized, page_host):
        return "same_host"
    if any(normalized == item or normalized.endswith(f".{item}") for item in KNOWN_PROCESSORS):
        return "known_processor"
    if same_registrable_domain(normalized, page_host):
        return "same_registrable_domain"
    return "third_party_unknown"


def resolve_action(action: str, page_url: str) -> str:
    from urllib.parse import urljoin

    value = (action or "").strip()
    if not value:
        return page_url
    return urljoin(page_url, value)


def form_sensitive_categories(form: dict[str, Any]) -> list[str]:
    """Deterministic category names for a form's fields. Values are never read."""
    fields = list(form.get("fields") or [])
    if not fields:
        types = list(form.get("input_types") or [])
        names = list(form.get("input_names") or [])
        fields = [
            {"type": types[index] if index < len(types) else "", "name": names[index] if index < len(names) else ""}
            for index in range(max(len(types), len(names)))
        ]
    categories: set[str] = set()
    for field in fields:
        field_type = str(field.get("type") or "").lower()
        name = str(field.get("name") or "")
        if field_type == "password":
            categories.add("password")
        for category, pattern in SENSITIVE_NAME_PATTERNS.items():
            if pattern.search(name):
                categories.add(category)
    if int(form.get("password_fields") or 0) > 0:
        categories.add("password")
    if form.get("has_otp"):
        categories.add("otp")
    if form.get("has_email") or form.get("has_username"):
        categories.add("identity")
    return sorted(categories)


def redirect_facts(chain: Iterable[dict[str, Any]], page_host: str) -> dict[str, Any]:
    hops = [hop for hop in chain if isinstance(hop, dict)]
    hosts = [normalize_host(hop.get("url") or "") for hop in hops]
    domains = [registrable_domain(host) for host in hosts]
    schemes = [urlsplit(str(hop.get("url") or "")).scheme for hop in hops]
    return {
        "hop_count": len(hops),
        "host_changes": sum(1 for previous, current in zip(hosts, hosts[1:]) if previous != current),
        "registrable_domain_changes": sum(1 for previous, current in zip(domains, domains[1:]) if previous != current),
        "redirected": bool(hops),
        "left_page_host": any(host and host != normalize_host(page_host) for host in hosts),
        "https_downgrade": any(left == "https" and right == "http" for left, right in zip(schemes, schemes[1:])),
        "shortener_hops": sorted({host for host in hosts if is_shortener(host)}),
    }


def sensitive_forms(browser_evidence: dict[str, Any], page_host: str) -> list[dict[str, Any]]:
    results = []
    for index, form in enumerate(browser_evidence.get("forms") or []):
        if not isinstance(form, dict):
            continue
        action = resolve_action(str(form.get("action") or ""), f"https://{page_host}/" if page_host else "")
        action_host = normalize_host(action)
        categories = form_sensitive_categories(form)
        if not categories and same_host(action_host, page_host):
            continue
        results.append(
            {
                "index": index,
                "action": action,
                "action_host": action_host,
                "destination": classify_destination(action_host, page_host),
                "sensitive_categories": categories,
                "method": str(form.get("method") or "GET").upper(),
            }
        )
    return results


def login_candidates(links: Iterable[dict[str, Any]], page_host: str) -> list[dict[str, Any]]:
    """Same-registrable-domain links that look like a next step in a login flow."""
    candidates = []
    seen: set[str] = set()
    for link in links:
        if not isinstance(link, dict):
            continue
        href = str(link.get("href") or "")
        if not href.startswith(("http://", "https://")):
            continue
        host = normalize_host(href)
        if not host or not same_registrable_domain(host, page_host):
            continue
        path = urlsplit(href).path.lower()
        if not any(hint in path for hint in LOGIN_HINTS):
            continue
        if href in seen:
            continue
        seen.add(href)
        candidates.append({"url": href, "host": host, "path": path})
        if len(candidates) >= 3:
            break
    return candidates


def _severity(item: Any) -> str:
    return str(getattr(item, "severity", None) or (item.get("severity") if isinstance(item, dict) else "") or "")


def _source(item: Any) -> str:
    return str(getattr(item, "source", None) or (item.get("source") if isinstance(item, dict) else "") or "")


def _metadata(item: Any) -> dict[str, Any]:
    value = getattr(item, "metadata", None)
    if value is None and isinstance(item, dict):
        value = item.get("metadata")
    return value if isinstance(value, dict) else {}


def investigation_gate(
    findings: Iterable[Any],
    browser_evidence: dict[str, Any] | None,
    unavailable: Iterable[str],
    page_url: str,
) -> tuple[bool, list[str]]:
    """Run agents only when deterministic evidence leaves a real security question open."""
    items = list(findings)
    if not browser_evidence:
        return False, ["no_browser_evidence"]
    if any(_severity(item) in {"critical", "high"} for item in items):
        return False, ["conclusive_deterministic_finding"]

    page_host = normalize_host(page_url)
    reasons: list[str] = []
    forms = sensitive_forms(browser_evidence, page_host)
    if any(form["sensitive_categories"] for form in forms):
        reasons.append("sensitive_form")
    if any(form["destination"] == "third_party_unknown" for form in forms):
        reasons.append("cross_host_form_destination")

    redirects = redirect_facts(browser_evidence.get("redirect_chain") or [], page_host)
    if redirects["registrable_domain_changes"] or redirects["shortener_hops"]:
        reasons.append("multi_hop_redirect")

    if (browser_evidence.get("js_obfuscation") or {}).get("detected"):
        reasons.append("javascript_obfuscation")

    if any(_source(item) == "brand_guard" for item in items):
        reasons.append("brand_mismatch_signal")

    if any(int(_metadata(item).get("age_days") or 9999) < 30 for item in items if _source(item) == "rdap_inspection"):
        reasons.append("young_domain")

    if str(browser_evidence.get("final_url") or "") and normalize_host(str(browser_evidence.get("final_url"))) != page_host:
        reasons.append("final_host_changed")

    if set(unavailable) & THREAT_INTEL_CHECKS:
        reasons.append("threat_intel_incomplete")

    return bool(reasons), reasons or ["deterministic_evidence_sufficient"]

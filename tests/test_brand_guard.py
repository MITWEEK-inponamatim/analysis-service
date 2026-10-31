import json

import pytest

from app import brand_guard


def techniques(host: str) -> list[str]:
    return [match.technique for match in brand_guard.detect(host)]


def severities(host: str) -> list[str]:
    return [match.severity for match in brand_guard.detect(host)]


def test_default_brand_list_is_large_enough():
    assert brand_guard.brand_count() >= 50


@pytest.mark.parametrize("host", [
    "g00gle.com",
    "paypa1.com",
    "micros0ft.com",
    "faceb00k.com",
    "whatsappp.com",
])
def test_character_substitution_and_typosquat_are_high(host):
    matches = brand_guard.detect(host)
    assert matches, host
    assert matches[0].severity == "high"
    assert matches[0].technique in {"char_substitution", "typosquat"}


@pytest.mark.parametrize("host", [
    "goggle.com",
    "gooogle.com",
    "paypa1.co",
    "linkedln.com",
    "instagrarn.com",
])
def test_typosquat_detection(host):
    assert "high" in severities(host), host


@pytest.mark.parametrize("host", [
    "google-login.xyz",
    "bca-verifikasi.top",
    "dana-login.site",
    "shopee-promo.click",
    "mandiri-secure.xyz",
])
def test_brand_token_in_leftmost_label(host):
    assert "brand_token" in techniques(host)
    assert "high" in severities(host)


@pytest.mark.parametrize("host", [
    "google.com.secure-login.xyz",
    "bca.co.id.evil.com",
    "shopee.co.id.verify-now.io",
    "paypal.com.account-check.top",
])
def test_brand_as_subdomain_of_foreign_domain(host):
    assert "brand_domain_elsewhere" in techniques(host)
    assert "high" in severities(host)


@pytest.mark.parametrize("host", [
    "login.google.security-check.xyz",
    "secure.bca.attacker.example",
])
def test_brand_in_inner_subdomain_is_medium(host):
    assert "brand_subdomain" in techniques(host)
    assert "medium" in severities(host)


def test_brand_on_other_tld_is_only_medium():
    assert techniques("bca.com") == ["brand_tld_other"]
    assert severities("bca.com") == ["medium"]


def test_cyrillic_homograph_is_detected():
    host = "g\u043e\u043egle.com"
    assert "homograph" in techniques(host)
    assert "high" in severities(host)


def test_punycode_homograph_is_detected():
    host = "xn--80ak6aa92e.com"
    assert "homograph" in techniques(host)
    assert "high" in severities(host)


@pytest.mark.parametrize("host", [
    "google.com",
    "mail.google.com",
    "google.co.id",
    "google.co.uk",
    "bca.co.id",
    "klikbca.com",
    "shopee.co.id",
    "ovo.id",
    "dana.id",
    "whatsapp.com",
    "wa.me",
    "github.com",
])
def test_official_domains_are_not_flagged(host):
    assert brand_guard.detect(host) == [], host


@pytest.mark.parametrize("host", [
    "notgoogle.com",
    "mybca.xyz",
    "random-login.xyz",
    "danamon.co.id",
    "paninbank.co.id",
    "example.com",
    "127.0.0.1",
    "",
])
def test_unrelated_or_lookalike_free_domains_are_clean(host):
    assert brand_guard.detect(host) == [], host


def test_findings_use_the_brand_guard_source_and_carry_metadata():
    findings = brand_guard.brand_findings("g00gle.com")
    assert findings
    item = findings[0]
    assert item.source == "brand_guard"
    assert item.severity == "high"
    assert item.metadata["brand"] == "google"
    assert item.metadata["technique"] == "char_substitution"
    assert "google.com" in item.metadata["official_domains"]


def test_brand_guard_can_be_replaced_via_env(monkeypatch, tmp_path):
    custom = tmp_path / "brands.json"
    custom.write_text(json.dumps({"brands": {"acmebank": ["acmebank.co.id"]}}), encoding="utf-8")
    monkeypatch.setenv("BRAND_ALLOWLIST_PATH", str(custom))
    brand_guard.clear_cache()
    try:
        assert brand_guard.brand_count() == 1
        assert brand_guard.detect("acmebank-login.xyz")
        assert brand_guard.detect("google-login.xyz") == []
        assert brand_guard.detect("acmebank.co.id") == []
    finally:
        monkeypatch.delenv("BRAND_ALLOWLIST_PATH", raising=False)
        brand_guard.clear_cache()


def test_registrable_domain_handles_multi_label_suffixes():
    assert brand_guard.registrable_domain("bca.co.id") == "bca.co.id"
    assert brand_guard.registrable_domain("mail.google.com") == "google.com"
    assert brand_guard.registrable_domain("shopee.co.id.evil.com") == "evil.com"
    assert brand_guard.registrable_domain("a.b.example.co.uk") == "example.co.uk"

from app.apk_rules import features_to_findings
from app.risk import assess


def _report(features):
    findings, limitations = features_to_findings(features)
    return assess("scan", "application", findings, ["apk_static_analysis"], ["mobsf", "jadx"], limitations=limitations)


def test_sms_with_accessibility_is_high_rule_not_llm():
    report = _report({
        "permissions": ["android.permission.SEND_SMS", "android.permission.BIND_ACCESSIBILITY_SERVICE"],
        "sensitive_permissions": ["sms_send", "accessibility"],
        "app_label": "Pengirim Paket",
        "package_name": "com.example.parcel",
    })
    assert report.outcome == "suspicious"
    assert report.risk["level"] == "high"
    assert any(item.source == "static_analysis_rules" and item.severity == "high" for item in report.findings)


def test_brand_claim_with_control_capability_escalates():
    report = _report({
        "app_label": "BRImo",
        "package_name": "com.bri.fakeupdate",
        "permissions": ["android.permission.BIND_ACCESSIBILITY_SERVICE"],
        "sensitive_permissions": ["accessibility"],
    })
    assert any("mengklaim brand" in item.indicator for item in report.findings)
    assert report.risk["level"] == "high"


def test_telegram_token_is_high_on_its_own():
    report = _report({"telegram_bot_token": True})
    assert report.risk["level"] == "high"
    assert any("Telegram" in item.indicator for item in report.findings)


def test_no_indicators_is_insufficient_evidence_not_low():
    report = _report({})
    assert report.outcome == "insufficient_evidence"
    assert report.risk["level"] == "unknown"


def test_packed_sample_reports_incomplete_analysis():
    report = _report({"packer_hints": ["libjiagu"], "permissions": ["android.permission.INTERNET"]})
    assert any("dikemas" in text for text in report.limitations)
    assert report.outcome == "insufficient_evidence"


def test_hardcoded_indicators_are_info_only():
    report = _report({"hardcoded_urls": ["https://example.test/a"], "hardcoded_ips": ["203.0.113.9"]})
    assert all(item.severity == "info" for item in report.findings)
    assert report.risk["level"] == "unknown"

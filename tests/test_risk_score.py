from app.risk import assess, calibrated_score, finding, positive_check_count, score_level


def test_confirmed_threat_scores_high():
    report = assess("scan", "url", [finding("listed as malware", "safe_browsing", "high")], ["safe_browsing", "virustotal", "browser_inspection"], [])
    assert report.risk["level"] == "high"
    assert report.risk["score"] >= 70
    assert report.outcome == "confirmed_threat"


def test_clean_evidence_with_enough_checks_may_report_low():
    report = assess("scan", "url", [], ["url_syntax", "safe_browsing", "virustotal", "browser_inspection"], [])
    assert report.risk["level"] == "low"
    assert report.risk["score"] <= 8
    assert report.outcome == "insufficient_evidence"
    assert any("bukan jaminan aman" in text for text in report.recommended_actions)


def test_missing_findings_without_coverage_is_unknown_not_low():
    report = assess("scan", "url", [], ["url_syntax"], ["safe_browsing", "virustotal"])
    assert report.risk["level"] == "unknown"
    assert report.risk["score"] == 0


def test_single_source_cannot_reach_high_score():
    findings = [finding(f"medium {index}", "llm_analysis", "medium") for index in range(6)]
    score = calibrated_score(findings, ["llm_analysis"])
    assert score <= 60
    assert score_level(score) in {"medium", "low", "unknown"}


def test_accumulated_medium_findings_escalate_level():
    findings = [finding(f"medium {index}", "browser_inspection", "medium") for index in range(4)]
    report = assess("scan", "url", findings, ["safe_browsing", "browser_inspection"], [])
    assert report.risk["level"] == "high"
    assert report.outcome == "suspicious"


def test_llm_weight_is_lower_than_threat_intel():
    intel = calibrated_score([finding("x", "virustotal", "high")], ["virustotal", "safe_browsing"])
    model = calibrated_score([finding("x", "llm_analysis", "high")], ["virustotal", "safe_browsing"])
    assert intel > model


def test_positive_check_count_ignores_syntax_checks():
    assert positive_check_count(["url_syntax", "ssrf_guard", "safe_browsing"]) == 1


def test_failed_report_has_no_score():
    from app.risk import fail_report

    report = fail_report("scan", "url", "timeout", "too slow")
    assert report.risk["score"] is None
    assert report.outcome == "scan_failed"

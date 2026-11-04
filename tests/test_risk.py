from app.risk import assess, finding

def test_threat_finding_is_high():
    report = assess("scan", "url", [finding("credential theft", "safe_browsing", "high")], ["safe_browsing"], [])
    assert report.outcome == "confirmed_threat"
    assert report.risk["level"] == "high"

def test_no_evidence_is_unknown_not_safe():
    report = assess("scan", "url", [], ["url_syntax"], ["safe_browsing"])
    assert report.outcome == "insufficient_evidence"
    assert report.risk["level"] == "unknown"

def test_high_heuristic_is_not_confirmed_threat():
    report = assess("scan", "url", [finding("urgent", "heuristic", "high")], ["brand_guard"], [])
    assert report.outcome == "suspicious"
    assert report.risk["level"] == "high"


def test_finding_preserves_model_confidence():
    item = finding("evidence", "llm_analysis", "low", confidence="low")
    assert item.confidence == "low"

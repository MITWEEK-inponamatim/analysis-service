"""Unit tests for APK deterministic code pattern analysis."""

import pytest
from app.apk_deterministic import code_pattern_findings, investigation_gate


class TestCodePatternFindings:
    """Test deterministic code correlation rules."""
    
    def test_sms_forwarding_high_severity(self):
        """SMS permission + sendTextMessage API → high severity."""
        manifest = {
            "permissions": ["android.permission.READ_SMS", "android.permission.SEND_SMS"],
            "package": "com.example.app",
            "app_label": "MyApp",
        }
        decompiled = {
            "code_patterns": {
                "sms_forwarding": [{"class": "MainActivity", "match": "sendTextMessage"}],
            },
            "api_calls": {"SmsManager.sendTextMessage": 2},
        }
        
        findings = code_pattern_findings(manifest, decompiled)
        
        assert len(findings) > 0
        sms_finding = next((f for f in findings if "SMS" in f.indicator), None)
        assert sms_finding is not None
        assert sms_finding.severity == "high"
        assert sms_finding.source == "code_correlation"
    
    def test_overlay_attack_critical_severity(self):
        """SYSTEM_ALERT_WINDOW + WindowManager.addView → critical."""
        manifest = {
            "permissions": ["android.permission.SYSTEM_ALERT_WINDOW"],
            "package": "com.malware.overlay",
            "app_label": "Overlay",
        }
        decompiled = {
            "code_patterns": {
                "overlay_attack": [{"class": "OverlayService", "match": "WindowManager.addView"}],
            },
            "api_calls": {"WindowManager.addView": 1},
        }
        
        findings = code_pattern_findings(manifest, decompiled)
        
        overlay_finding = next((f for f in findings if "overlay" in f.indicator.lower()), None)
        assert overlay_finding is not None
        assert overlay_finding.severity == "critical"
    
    def test_package_label_mismatch_high_severity(self):
        """Package name != app label → suspicious (repackaging)."""
        manifest = {
            "permissions": [],
            "package": "com.random.abc123",
            "app_label": "Bank BCA",  # Suspicious mismatch
        }
        decompiled = {
            "package_name": "com.random.abc123",
            "code_patterns": {},
        }
        
        findings = code_pattern_findings(manifest, decompiled)
        
        mismatch_finding = next((f for f in findings if "tidak cocok" in f.indicator.lower()), None)
        assert mismatch_finding is not None
        assert mismatch_finding.severity == "high"
    
    def test_native_lib_with_network_high_severity(self):
        """Native library + network permission → potential data exfiltration."""
        manifest = {
            "permissions": ["android.permission.INTERNET"],
            "package": "com.app.native",
            "app_label": "Native App",
        }
        decompiled = {
            "native_libs": {
                "arm64-v8a": ["libpayload.so"],
                "x86": ["libpayload.so"],
            },
            "code_patterns": {"c2_communication": [{"class": "Loader", "match": "OkHttpClient"}]},
            "extracted_urls": ["https://198.51.100.10/c2"],
        }
        
        findings = code_pattern_findings(manifest, decompiled)
        
        native_finding = next((f for f in findings if "native" in f.indicator.lower()), None)
        assert native_finding is not None
        assert native_finding.severity == "high"
    
    def test_benign_app_no_findings(self):
        """Clean app with normal permissions → no findings."""
        manifest = {
            "permissions": ["android.permission.INTERNET", "android.permission.CAMERA"],
            "package": "com.example.camera",
            "app_label": "Camera",
        }
        decompiled = {
            "code_patterns": {},
            "api_calls": {},
        }
        
        findings = code_pattern_findings(manifest, decompiled)
        
        # May have low-severity findings, but no high/critical
        high_critical = [f for f in findings if f.severity in ("high", "critical")]
        assert len(high_critical) == 0


class TestInvestigationGate:
    """Test investigation gate decision logic."""
    
    def test_gate_skip_when_critical_finding_exists(self):
        """Critical deterministic finding → skip investigation (conclusive)."""
        findings = [
            type("Finding", (), {
                "indicator": "Overlay attack detected",
                "severity": "critical",
            })(),
        ]
        manifest = {"permissions": [], "package": "com.test", "app_label": "Test"}
        decompiled = {"code_patterns": {}}
        unavailable = []
        
        should_investigate, reasons = investigation_gate(findings, manifest, decompiled, unavailable)
        
        assert should_investigate is False
        assert len(reasons) == 1
        assert "conclusive_deterministic_finding" in reasons[0]
    
    def test_gate_skip_when_multiple_high_findings(self):
        """Multiple high severity findings → skip (sufficient evidence)."""
        findings = [
            type("Finding", (), {"indicator": "SMS forwarding", "severity": "high"})(),
            type("Finding", (), {"indicator": "Native lib network", "severity": "high"})(),
        ]
        manifest = {"permissions": [], "package": "com.test", "app_label": "Test"}
        decompiled = {"code_patterns": {}}
        unavailable = []
        
        should_investigate, reasons = investigation_gate(findings, manifest, decompiled, unavailable)
        
        assert should_investigate is False
        assert "conclusive_deterministic_finding" in reasons[0]
    
    def test_gate_trigger_on_obfuscation_with_sensitive_perms(self):
        """Obfuscated code + sensitive permissions → investigate."""
        findings = []
        manifest = {
            "permissions": ["android.permission.READ_SMS", "android.permission.SEND_SMS"],
            "package": "com.a.b.c",  # Obfuscated
            "app_label": "App",
        }
        decompiled = {
            "obfuscation_detected": True,
            "code_patterns": {},
        }
        unavailable = []
        
        should_investigate, reasons = investigation_gate(findings, manifest, decompiled, unavailable)
        
        assert should_investigate is True
        assert any("obfuscated_with_sensitive_permissions" in r for r in reasons)
    
    def test_gate_trigger_on_dynamic_loading(self):
        """Dynamic code loading pattern → investigate."""
        findings = []
        manifest = {"permissions": [], "package": "com.test", "app_label": "Test"}
        decompiled = {
            "code_patterns": {
                "dynamic_loading": [{"class": "Loader", "match": "DexClassLoader"}],
            },
        }
        unavailable = []
        
        should_investigate, reasons = investigation_gate(findings, manifest, decompiled, unavailable)
        
        assert should_investigate is True
        assert any("dynamic_code_loading" in r for r in reasons)
    
    def test_gate_trigger_on_sms_unclear(self):
        """SMS permission without clear usage → investigate."""
        findings = []
        manifest = {
            "permissions": ["android.permission.SEND_SMS"],
            "package": "com.test",
            "app_label": "Test",
        }
        decompiled = {
            "code_patterns": {},  # No SMS forwarding pattern
        }
        unavailable = []
        
        should_investigate, reasons = investigation_gate(findings, manifest, decompiled, unavailable)
        
        assert should_investigate is True
        assert any("sms_permission_usage_unclear" in r for r in reasons)
    
    def test_gate_skip_on_clean_app(self):
        """Clean app, no suspicious patterns → skip investigation."""
        findings = []
        manifest = {
            "permissions": ["android.permission.INTERNET"],
            "package": "com.example.clean",
            "app_label": "Clean App",
        }
        decompiled = {
            "obfuscation_detected": False,
            "code_patterns": {},
        }
        unavailable = []
        
        should_investigate, reasons = investigation_gate(findings, manifest, decompiled, unavailable)
        
        # Clean app should skip (no investigation needed)
        assert should_investigate is False
        assert len(reasons) == 1
        assert reasons[0] == "deterministic_evidence_sufficient"



def test_brand_impersonation_uses_decompiled_package_name():
    findings = code_pattern_findings(
        {"permissions": [], "package": "com.random.abc123", "app_label": "Bank BCA"},
        {"package_name": "com.random.abc123", "code_patterns": {}},
    )
    finding_result = next(f for f in findings if "tidak cocok" in f.indicator.lower())
    assert finding_result.source == "code_correlation"
    assert finding_result.metadata["suspected_brand"] == "bank"


def test_yara_result_is_json_serializable(monkeypatch):
    yara = pytest.importorskip("yara")
    from app import yara_scanner

    monkeypatch.setattr(yara_scanner, "_compiled_rules", None)
    raw = b"api.telegram.org/bot123:ABC sendMessage chat_id=456 NotificationListenerService"
    result = yara_scanner.scan_decompiled({"key_sources": {"Stealer": raw.decode()}}, raw)
    import json

    json.dumps(result)
    assert result["total_matches"] >= 1
    assert all(isinstance(item["data"], str) for match in result["matches"] for item in match["strings"])

if __name__ == "__main__":
    pytest.main([__file__, "-v"])

"""YARA scanner for APK decompiled sources."""
import yara
from typing import Optional
from .yara_rules import ANDROID_MALWARE_RULES


# Compile rules once at module load
_compiled_rules: Optional[yara.Rules] = None


def get_compiled_rules() -> yara.Rules:
    """Get or compile YARA rules (cached)."""
    global _compiled_rules
    if _compiled_rules is None:
        _compiled_rules = yara.compile(source=ANDROID_MALWARE_RULES)
    return _compiled_rules


def scan_decompiled(decompiled: dict, apk_bytes: bytes) -> dict:
    """
    Scan decompiled APK with YARA rules.
    
    Args:
        decompiled: Output from jadx_decompile (key_sources, code_index)
        apk_bytes: Raw APK bytes for binary scanning
    
    Returns:
        {
            "matches": [
                {
                    "rule": str,
                    "tags": list[str],
                    "meta": dict,
                    "strings": [{"offset": int, "identifier": str, "data": bytes}],
                    "matched_classes": list[str],  # classes where rule matched
                }
            ],
            "total_matches": int,
            "families": list[str],  # unique malware families detected
            "max_severity": str,  # "critical" | "high" | "medium" | "low"
        }
    """
    rules = get_compiled_rules()
    
    # Scan raw APK bytes first
    binary_matches = rules.match(data=apk_bytes)
    
    # Scan decompiled source files
    source_matches = {}
    key_sources = decompiled.get("key_sources", {})
    for class_name, source_code in key_sources.items():
        if isinstance(source_code, str):
            matches = rules.match(data=source_code.encode("utf-8", errors="ignore"))
            if matches:
                source_matches[class_name] = matches
    
    # Merge results
    all_rules = {}
    for match in binary_matches:
        all_rules[match.rule] = {
            "rule": match.rule,
            "tags": list(match.tags),
            "meta": dict(match.meta),
            "strings": [
                {"offset": s.instances[0][0], "identifier": s.identifier, "data": s.instances[0][2]}
                for s in match.strings
            ],
            "matched_classes": [],
        }
    
    for class_name, matches in source_matches.items():
        for match in matches:
            if match.rule in all_rules:
                all_rules[match.rule]["matched_classes"].append(class_name)
            else:
                all_rules[match.rule] = {
                    "rule": match.rule,
                    "tags": list(match.tags),
                    "meta": dict(match.meta),
                    "strings": [
                        {"offset": s.instances[0][0], "identifier": s.identifier, "data": s.instances[0][2]}
                        for s in match.strings
                    ],
                    "matched_classes": [class_name],
                }
    
    # Extract families and severity
    families = set()
    severity_levels = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    max_severity_score = 0
    max_severity = "low"
    
    for rule_data in all_rules.values():
        meta = rule_data["meta"]
        if "family" in meta:
            families.add(meta["family"])
        severity = meta.get("severity", "low")
        score = severity_levels.get(severity, 1)
        if score > max_severity_score:
            max_severity_score = score
            max_severity = severity
    
    return {
        "matches": list(all_rules.values()),
        "total_matches": len(all_rules),
        "families": sorted(families),
        "max_severity": max_severity,
    }

"""APK investigation executor with deterministic skills.

Skills analyze decompiled code to answer specific security questions:
- inspect_permission_usage: correlate permissions with API calls
- trace_sms_flow: trace SMS read/send logic
- analyze_overlay_attack: check overlay + form field patterns
- trace_data_exfiltration: follow sensitive data → network
"""

import json
import re
from typing import Any

from .envelopes import InvestigationFinding, Observation, SkillEnvelope
from .evidence import EvidenceStore


MAX_SKILL_CALLS = 6


class APKExecutor:
    """Execute deterministic skills over decompiled APK evidence."""
    
    ALLOWED_SKILLS = {
        "inspect_permission_usage",
        "trace_sms_flow",
        "analyze_overlay_attack",
        "trace_data_exfiltration",
        "inspect_telegram_bot",
        "analyze_banking_trojan",
        "classify_obfuscation",
        "analyze_native_payload",
        "inspect_dynamic_loading",
        "analyze_anti_analysis",
    }
    
    def __init__(
        self,
        store: EvidenceStore,
        scan_id: str,
        features: dict[str, Any],
        decompiled_index: dict[str, Any],
        code_patterns: dict[str, Any],
    ):
        self.store = store
        self.scan_id = scan_id
        self.features = features
        self.code_index = decompiled_index  # {class_name: {file, line_count}}
        self.code_patterns = code_patterns  # {pattern: [matches]}
        self.calls = 0
        self.executed: list[str] = []
        self.evidence_created: list[tuple[str, str]] = []  # (type, evidence_id)
    
    @property
    def call_count(self) -> int:
        return self.calls
    
    def tool_for(self, skill: str):
        """Return LangChain tool wrapper for skill."""
        from langchain_core.tools import StructuredTool
        
        async def run_skill(params: dict[str, Any] | None = None) -> str:
            envelope = await self.run(skill, params or {})
            return json.dumps({
                "status": envelope.status,
                "observations": [
                    {"type": obs[0], "fact": obs[2]} for obs in envelope.observations
                ],
                "findings": [
                    {"indicator": f.indicator, "severity": f.severity, "evidence_ids": f.evidence_ids}
                    for f in envelope.findings
                ],
                "gaps": envelope.gaps,
            }, ensure_ascii=False)
        
        descriptions = {
            "inspect_permission_usage": "Correlate declared permission with actual API calls in code. Params: {permission: str}",
            "trace_sms_flow": "Trace SMS read/send flow from source to sink. No params required.",
            "analyze_overlay_attack": "Analyze WindowManager overlay usage and form fields. No params required.",
            "trace_data_exfiltration": "Trace sensitive data (contacts/location) to network endpoints. Params: {data_type: str}",
            "inspect_telegram_bot": "Extract Telegram bot token and analyze C2 exfiltration. No params required.",
            "analyze_banking_trojan": "Analyze banking app targeting behavior. No params required.",
            "classify_obfuscation": "Classify obfuscation technique and level. No params required.",
            "analyze_native_payload": "Analyze native library purpose. Params: {lib_name: str}",
            "inspect_dynamic_loading": "Inspect dynamic code loading (DexClassLoader). No params required.",
            "analyze_anti_analysis": "Analyze anti-debugging and emulator detection. No params required.",
        }
        
        return StructuredTool.from_function(
            coroutine=run_skill,
            name=skill.replace("_", "-"),
            description=descriptions.get(skill, "Run skill"),
        )
    
    async def run(self, skill: str, params: dict[str, Any]) -> SkillEnvelope:
        """Execute skill and return envelope."""
        if self.calls >= MAX_SKILL_CALLS:
            return SkillEnvelope(skill=skill, status="failed", gaps=["call_limit_reached"])
        
        if skill not in self.ALLOWED_SKILLS:
            return SkillEnvelope(skill=skill, status="failed", gaps=["skill_not_allowed"])
        
        self.calls += 1
        self.executed.append(skill)
        
        # Route to handler
        if skill == "inspect_permission_usage":
            return await self._inspect_permission_usage(params)
        elif skill == "trace_sms_flow":
            return await self._trace_sms_flow(params)
        elif skill == "analyze_overlay_attack":
            return await self._analyze_overlay_attack(params)
        elif skill == "trace_data_exfiltration":
            return await self._trace_data_exfiltration(params)
        elif skill == "classify_obfuscation":
            return await self._classify_obfuscation(params)
        elif skill == "analyze_native_payload":
            return await self._analyze_native_payload(params)
        elif skill == "inspect_dynamic_loading":
            return await self._inspect_dynamic_loading(params)
        elif skill == "analyze_anti_analysis":
            return await self._analyze_anti_analysis(params)
        else:
            return SkillEnvelope(skill=skill, status="failed")
    
    def _envelope(
        self,
        skill: str,
        observations: list[tuple[str, dict, str]] | None = None,
        findings: list[InvestigationFinding] | None = None,
        gaps: list[str] | None = None,
    ) -> SkillEnvelope:
        """Build skill envelope."""
        evidence_ids = [ev_id for _, ev_id in self.evidence_created if ev_id]
        return SkillEnvelope(
            skill=skill,
            status="completed",
            observations=[Observation(type=t, payload=p, fact=f) for t, p, f in (observations or [])],
            findings=findings or [],
            gaps=gaps or [],
            evidence_ids=evidence_ids,
            tool_calls=1,
        )
    
    async def _inspect_permission_usage(self, params: dict[str, Any]) -> SkillEnvelope:
        """Correlate permission with code usage."""
        permission = str(params.get("permission", "")).strip()
        if not permission:
            return SkillEnvelope(skill="inspect_permission_usage", status="failed", gaps=["permission_missing"])
        
        manifest = self.features.get("manifest", {})
        permissions = manifest.get("permissions", [])
        
        if permission not in permissions:
            return SkillEnvelope(skill="inspect_permission_usage", status="completed", gaps=["permission_not_declared"])
        
        # Check API calls related to permission
        api_calls = self.features.get("api_calls", {})
        
        findings: list[InvestigationFinding] = []
        
        # SMS permission
        if "SMS" in permission:
            sms_apis = [api for api in api_calls if "Sms" in api or "SMS" in api]
            if sms_apis:
                payload = {"permission": permission, "api_calls": sms_apis, "count": sum(api_calls.get(api, 0) for api in sms_apis)}
                evidence_id = self.store.add("api_usage", payload, skill="inspect_permission_usage", fact="sms_api_correlation")
                self.evidence_created.append(("api_usage", evidence_id))
                
                findings.append(InvestigationFinding(
                    indicator=f"Permission {permission} digunakan dalam {len(sms_apis)} API calls",
                    severity="medium",
                    evidence_ids=[evidence_id],
                ))
        
        # Contacts permission
        if "CONTACTS" in permission:
            contact_apis = [api for api in api_calls if "Contact" in api or "ContentResolver" in api]
            if contact_apis:
                payload = {"permission": permission, "api_calls": contact_apis}
                evidence_id = self.store.add("api_usage", payload, skill="inspect_permission_usage", fact="contacts_api_correlation")
                self.evidence_created.append(("api_usage", evidence_id))
                
                findings.append(InvestigationFinding(
                    indicator=f"Kontak dibaca menggunakan {', '.join(contact_apis[:2])}",
                    severity="medium",
                    evidence_ids=[evidence_id],
                ))
        
        return self._envelope("inspect_permission_usage", findings=findings)
    
    async def _trace_sms_flow(self, params: dict[str, Any]) -> SkillEnvelope:
        """Trace SMS handling flow."""
        sms_pattern = self.code_patterns.get("sms_forwarding", [])
        if not sms_pattern:
            return SkillEnvelope(skill="trace_sms_flow", status="completed", gaps=["no_sms_code_detected"])
        
        findings: list[InvestigationFinding] = []
        
        # Extract classes with SMS code
        sms_classes = list(set(m["class"] for m in sms_pattern))
        
        payload = {
            "classes": sms_classes[:5],
            "api_calls": [m["match"] for m in sms_pattern[:3]],
        }
        evidence_id = self.store.add("code_flow", payload, skill="trace_sms_flow", fact="sms_flow_analysis")
        self.evidence_created.append(("code_flow", evidence_id))
        
        findings.append(InvestigationFinding(
            indicator=f"SMS flow terdeteksi di {len(sms_classes)} class (kemungkinan forwarding)",
            severity="high",
            evidence_ids=[evidence_id],
        ))
        
        return self._envelope("trace_sms_flow", findings=findings)
    
    async def _analyze_overlay_attack(self, params: dict[str, Any]) -> SkillEnvelope:
        """Analyze overlay patterns."""
        overlay_pattern = self.code_patterns.get("overlay_attack", [])
        if not overlay_pattern:
            return SkillEnvelope(skill="analyze_overlay_attack", status="completed", gaps=["no_overlay_code"])
        
        findings: list[InvestigationFinding] = []
        
        overlay_classes = list(set(m["class"] for m in overlay_pattern))
        
        payload = {
            "classes": overlay_classes[:5],
            "api_calls": [m["match"] for m in overlay_pattern[:3]],
        }
        evidence_id = self.store.add("code_pattern", payload, skill="analyze_overlay_attack", fact="overlay_pattern_analysis")
        self.evidence_created.append(("code_pattern", evidence_id))
        
        findings.append(InvestigationFinding(
            indicator=f"Overlay attack pattern di {len(overlay_classes)} class (WindowManager.addView)",
            severity="high",
            evidence_ids=[evidence_id],
        ))
        
        return self._envelope("analyze_overlay_attack", findings=findings)
    
    async def _trace_data_exfiltration(self, params: dict[str, Any]) -> SkillEnvelope:
        """Trace data exfiltration paths."""
        data_type = str(params.get("data_type", "")).strip().lower()
        
        exfil_pattern = self.code_patterns.get("data_exfiltration", [])
        network_pattern = self.code_patterns.get("c2_communication", [])
        
        if not exfil_pattern or not network_pattern:
            return SkillEnvelope(skill="trace_data_exfiltration", status="completed", gaps=["insufficient_code_patterns"])
        
        findings: list[InvestigationFinding] = []
        
        exfil_classes = set(m["class"] for m in exfil_pattern)
        network_classes = set(m["class"] for m in network_pattern)
        
        # Check overlap (same class reads data and sends network)
        overlap = exfil_classes & network_classes
        
        payload = {
            "data_type": data_type or "sensitive",
            "exfil_classes": list(exfil_classes)[:5],
            "network_classes": list(network_classes)[:5],
            "overlap_classes": list(overlap),
        }
        evidence_id = self.store.add("data_flow", payload, skill="trace_data_exfiltration", fact="exfiltration_flow")
        self.evidence_created.append(("data_flow", evidence_id))
        
        if overlap:
            findings.append(InvestigationFinding(
                indicator=f"Data exfiltration terdeteksi: {len(overlap)} class membaca data sensitif dan mengirim ke network",
                severity="high",
                evidence_ids=[evidence_id],
            ))
        else:
            findings.append(InvestigationFinding(
                indicator=f"Data sensitif dibaca ({len(exfil_classes)} class) dan komunikasi network ada ({len(network_classes)} class) - flow belum terkonfirmasi",
                severity="medium",
                evidence_ids=[evidence_id],
            ))
        
        return self._envelope("trace_data_exfiltration", findings=findings)
    
    async def _classify_obfuscation(self, params: dict[str, Any]) -> SkillEnvelope:
        """Classify obfuscation method."""
        obfuscated = self.features.get("obfuscation_detected", False)
        if not obfuscated:
            return SkillEnvelope(skill="classify_obfuscation", status="completed", gaps=["no_obfuscation_detected"])
        
        findings: list[InvestigationFinding] = []
        
        classes = self.features.get("classes", [])
        single_char_classes = [c for c in classes if re.search(r"\b[a-z]\.[a-z]\.[a-z]", c)]
        
        # Heuristic: ProGuard/R8 (standard), DexGuard (heavy), custom
        if len(single_char_classes) > 20:
            level = "heavy (DexGuard atau custom)"
        elif len(single_char_classes) > 5:
            level = "moderate (ProGuard/R8)"
        else:
            level = "light"
        
        payload = {
            "level": level,
            "obfuscated_classes": len(single_char_classes),
            "total_classes": len(classes),
        }
        evidence_id = self.store.add("obfuscation", payload, skill="classify_obfuscation", fact="obfuscation_classification")
        self.evidence_created.append(("obfuscation", evidence_id))
        
        findings.append(InvestigationFinding(
            indicator=f"Obfuscation {level} terdeteksi ({len(single_char_classes)}/{len(classes)} class)",
            severity="medium",
            evidence_ids=[evidence_id],
        ))
        
        return self._envelope("classify_obfuscation", findings=findings)
    
    async def _analyze_native_payload(self, params: dict[str, Any]) -> SkillEnvelope:
        """Analyze native library."""
        lib_name = str(params.get("lib_name", "")).strip()
        
        native_libs = self.features.get("native_libs", {})
        if not native_libs:
            return SkillEnvelope(skill="analyze_native_payload", status="completed", gaps=["no_native_libs"])
        
        findings: list[InvestigationFinding] = []
        
        # Flatten all libs
        all_libs = [lib for libs in native_libs.values() for lib in libs]
        
        if lib_name:
            if lib_name not in all_libs:
                return SkillEnvelope(skill="analyze_native_payload", status="completed", gaps=["lib_not_found"])
            target_libs = [lib_name]
        else:
            target_libs = all_libs[:3]  # analyze first 3
        
        for lib in target_libs:
            # Heuristic: suspicious lib names
            suspicious = any(kw in lib.lower() for kw in ["shell", "jiagu", "sec", "protect", "crypt", "hide"])
            
            payload = {
                "lib_name": lib,
                "architectures": [arch for arch, libs in native_libs.items() if lib in libs],
                "suspicious": suspicious,
            }
            evidence_id = self.store.add("native_lib", payload, skill="analyze_native_payload", fact="native_lib_analysis")
            self.evidence_created.append(("native_lib", evidence_id))
            
            if suspicious:
                findings.append(InvestigationFinding(
                    indicator=f"Native library mencurigakan: {lib} (kemungkinan packer atau hidden payload)",
                    severity="medium",
                    evidence_ids=[evidence_id],
                ))
        
        return self._envelope("analyze_native_payload", findings=findings)
    
    async def _inspect_dynamic_loading(self, params: dict[str, Any]) -> SkillEnvelope:
        """Inspect dynamic code loading."""
        dynamic_pattern = self.code_patterns.get("dynamic_loading", [])
        if not dynamic_pattern:
            return SkillEnvelope(skill="inspect_dynamic_loading", status="completed", gaps=["no_dynamic_loading"])
        
        findings: list[InvestigationFinding] = []
        
        classes = list(set(m["class"] for m in dynamic_pattern))
        
        payload = {
            "classes": classes[:5],
            "loaders": [m["match"] for m in dynamic_pattern[:3]],
        }
        evidence_id = self.store.add("dynamic_loading", payload, skill="inspect_dynamic_loading", fact="dynamic_loading_analysis")
        self.evidence_created.append(("dynamic_loading", evidence_id))
        
        findings.append(InvestigationFinding(
            indicator=f"Dynamic loading di {len(classes)} class (DexClassLoader/PathClassLoader) - payload runtime tidak tervalidasi",
            severity="medium",
            evidence_ids=[evidence_id],
        ))
        
        return self._envelope("inspect_dynamic_loading", findings=findings)
    
    async def _inspect_telegram_bot(self, params: dict[str, Any]) -> SkillEnvelope:
        """Extract Telegram bot token and analyze C2 exfiltration."""
        telegram_pattern = self.code_patterns.get("telegram_bot", [])
        if not telegram_pattern:
            return SkillEnvelope(skill="inspect_telegram_bot", status="completed", gaps=["no_telegram_bot"])
        
        findings: list[InvestigationFinding] = []
        
        classes = list(set(m["class"] for m in telegram_pattern))
        bot_tokens = []
        chat_ids = []
        
        # Extract bot tokens and chat IDs from matches
        for match in telegram_pattern:
            match_str = match.get("match", "")
            # Extract bot token pattern: api.telegram.org/bot<TOKEN>
            if "api.telegram.org/bot" in match_str:
                token_part = match_str.split("/bot")[1] if "/bot" in match_str else ""
                if token_part and len(token_part) > 10:
                    bot_tokens.append(token_part[:50])  # Truncate for safety
            # Extract t.me links
            if "t.me/" in match_str:
                bot_tokens.append(match_str)
        
        payload = {
            "classes": classes[:5],
            "bot_indicators": bot_tokens[:3],
            "c2_channel": "telegram",
        }
        evidence_id = self.store.add("telegram_c2", payload, skill="inspect_telegram_bot", fact="telegram_bot_api_detected")
        self.evidence_created.append(("telegram_c2", evidence_id))
        
        findings.append(InvestigationFinding(
            indicator=f"Telegram bot API sebagai C2 channel di {len(classes)} class - data exfiltrated ke Telegram",
            severity="critical",
            evidence_ids=[evidence_id],
        ))
        
        return self._envelope("inspect_telegram_bot", findings=findings)
    
    async def _analyze_banking_trojan(self, params: dict[str, Any]) -> SkillEnvelope:
        """Analyze banking app targeting behavior."""
        banking_pattern = self.code_patterns.get("banking_trojan", [])
        if not banking_pattern:
            return SkillEnvelope(skill="analyze_banking_trojan", status="completed", gaps=["no_banking_trojan"])
        
        findings: list[InvestigationFinding] = []
        
        classes = list(set(m["class"] for m in banking_pattern))
        targeted_packages = []
        
        # Extract banking package references
        for match in banking_pattern:
            match_str = match.get("match", "")
            # Look for bank package patterns
            if "com." in match_str and "bank" in match_str.lower():
                targeted_packages.append(match_str)
            if "id.co." in match_str:
                targeted_packages.append(match_str)
        
        payload = {
            "classes": classes[:5],
            "targeted_packages": list(set(targeted_packages))[:10],
            "behavior": "query_installed_packages",
        }
        evidence_id = self.store.add("banking_trojan", payload, skill="analyze_banking_trojan", fact="banking_app_targeting")
        self.evidence_created.append(("banking_trojan", evidence_id))
        
        findings.append(InvestigationFinding(
            indicator=f"Banking trojan behavior di {len(classes)} class - query installed packages untuk target banking apps",
            severity="high",
            evidence_ids=[evidence_id],
        ))
        
        
        return self._envelope("analyze_banking_trojan", findings=findings)
    
    async def _analyze_anti_analysis(self, params: dict[str, Any]) -> SkillEnvelope:
        """Analyze anti-analysis techniques."""
        anti_pattern = self.code_patterns.get("anti_analysis", [])
        if not anti_pattern:
            return SkillEnvelope(skill="analyze_anti_analysis", status="completed", gaps=["no_anti_analysis"])
        
        findings: list[InvestigationFinding] = []
        
        classes = list(set(m["class"] for m in anti_pattern))
        
        payload = {
            "classes": classes[:5],
            "techniques": [m["match"] for m in anti_pattern[:3]],
        }
        evidence_id = self.store.add("anti_analysis", payload, skill="analyze_anti_analysis", fact="anti_analysis_techniques")
        self.evidence_created.append(("anti_analysis", evidence_id))
        
        findings.append(InvestigationFinding(
            indicator=f"Teknik anti-analysis di {len(classes)} class (debugger/emulator detection)",
            severity="medium",
            evidence_ids=[evidence_id],
        ))
        
        return self._envelope("analyze_anti_analysis", findings=findings)

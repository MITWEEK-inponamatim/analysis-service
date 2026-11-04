"""APK investigation agents: Behavior and Obfuscation analysts.

Behavior agent: what the APK does (SMS, overlay, exfiltration, network).
Obfuscation agent: why code is hidden (packer, native, anti-analysis).
"""

from typing import Any

from ..llm import chat_model
from .apk_executor import APKExecutor
from .apk_schemas import APKFinding, BehaviorAgentOutput, ObfuscationAgentOutput
from .envelopes import InvestigationFinding, SkillEnvelope
from .evidence import EvidenceStore


BEHAVIOR_AGENT_SYSTEM = """
Kamu behavior analyst menganalisis APK Android yang dicurigai malicious.

Fokus: APA YANG DILAKUKAN APK INI secara konkret.

Target behavior:
- SMS forwarding/interception
- Notification listener abuse (Tria stealer: steal OTP dari notifikasi apps)
- Overlay attacks (fake login screens over legitimate apps)
- Data exfiltration (contacts, location, call logs → network)
- Network communication (C2 servers, Telegram bot API, phishing endpoints)
- Banking trojan (query installed packages untuk target banking apps)

Tools available:
- inspect-permission-usage: correlate permission dengan actual API calls
- trace-sms-flow: trace SMS read/send dari source ke sink
- analyze-overlay-attack: check WindowManager overlay + form fields
- trace-data-exfiltration: trace sensitive data → network
- inspect-telegram-bot: extract Telegram bot token dan analyze C2 exfiltration
- analyze-banking-trojan: analyze banking app targeting behavior

Rules:
- Cite class names, methods, line numbers dari decompiled code
- Extract URLs, endpoints, phone numbers, Telegram bot tokens yang ditemukan
- Max severity: high (critical reserved untuk deterministic rules)
- Kalau obfuscated (com.a.b.c), fokus behavior patterns bukan naming
- Reference evidence IDs dari store
- NEVER claim threat tanpa konkret code evidence
- Return concise findings dengan traceable evidence only
"""


OBFUSCATION_AGENT_SYSTEM = """
Kamu obfuscation analyst menganalisis teknik hiding di APK Android.

Fokus: MENGAPA CODE DISEMBUNYIKAN dan APA YANG DILINDUNGI.

Target:
- Code obfuscation level (ProGuard/R8/DexGuard/custom)
- Native library payloads (lib/arm64-v8a/*.so purpose)
- Dynamic code loading (DexClassLoader, Class.forName)
- Anti-analysis techniques (debugger checks, emulator detection)

Tools available:
- classify-obfuscation: identify obfuscation method + level
- analyze-native-payload: analyze native library purpose
- inspect-dynamic-loading: trace DexClassLoader + loaded classes
- analyze-anti-analysis: understand evasion techniques

Rules:
- Explain WHY hiding (avoid detection, stage-2 payload, protect IP?)
- Link obfuscation to malicious intent (hiding SMS forwarding vs normal app protection)
- Extract URLs/domains dari native libs atau encrypted strings kalau ada
- Max severity: high
- Reference evidence IDs
- NEVER claim malicious tanpa linking obfuscation ke concrete malicious behavior
"""


async def run_behavior_agent(
    executor: APKExecutor,
    store: EvidenceStore,
    features: dict[str, Any],
    decompiled: dict[str, Any],
    deterministic_findings: list[Any],
) -> SkillEnvelope:
    """Run behavior agent: analyze what the APK does."""
    
    model = chat_model()
    if model is None:
        return SkillEnvelope(
            skill="behavior-agent",
            status="failed",
            unavailable=["llm_unavailable"],
        )
    
    # Build evidence index
    evidence_index = json.dumps(store.index(), ensure_ascii=False)[:6000]
    
    # Deterministic summary
    det_summary = "\n".join([
        f"- {getattr(f, 'indicator', f.get('indicator', 'N/A'))} ({getattr(f, 'severity', f.get('severity', 'N/A'))})"
        for f in deterministic_findings[:10]
    ])
    
    # Human prompt
    human = f"""
<target_apk>
Package: {decompiled.get("package_name", "unknown")}
App Label: {features.get("manifest", {}).get("app_label", "unknown")}
</target_apk>

<permissions>
{json.dumps(features.get("manifest", {}).get("permissions", []), indent=2)[:1000]}
</permissions>

<code_patterns>
{json.dumps(decompiled.get("code_patterns", {}), indent=2)[:2000]}
</code_patterns>

<api_calls>
{json.dumps(decompiled.get("api_calls", {}), indent=2)[:1000]}
</api_calls>

<extracted_urls>
{json.dumps(decompiled.get("extracted_urls", []), indent=2)[:800]}
</extracted_urls>

<deterministic_findings>
{det_summary}
</deterministic_findings>

<evidence_index>
{evidence_index}
</evidence_index>

Analyze: Apa behavior malicious konkret yang dilakukan APK ini? Gunakan tools untuk trace data flows dan confirm patterns. Return findings dengan evidence IDs.
"""
    
    # Tools
    tools = [
        executor.tool_for("inspect_permission_usage"),
        executor.tool_for("trace_sms_flow"),
        executor.tool_for("analyze_overlay_attack"),
        executor.tool_for("trace_data_exfiltration"),
        executor.tool_for("inspect_telegram_bot"),
        executor.tool_for("analyze_banking_trojan"),
    ]
    
    try:
        # Run agent with structured output
        structured_model = model.with_structured_output(BehaviorAgentOutput)
        result = await structured_model.bind_tools(tools).ainvoke(
            [
                {"role": "system", "content": BEHAVIOR_AGENT_SYSTEM},
                {"role": "user", "content": human},
            ],
            config={"timeout": 45},
        )
        
        # Extract token usage from response metadata
        tokens_used = 0
        if hasattr(result, "usage_metadata"):
            # LangChain 0.2+
            usage = result.usage_metadata
            tokens_used = getattr(usage, "total_tokens", 0)
        elif hasattr(result, "response_metadata"):
            # Older LangChain versions
            usage = result.response_metadata.get("token_usage", {})
            tokens_used = usage.get("total_tokens", 0)
        
        # Convert structured output to findings
        findings = [
            InvestigationFinding(
                indicator=f.indicator,
                severity=f.severity,
                evidence_ids=f.evidence_ids,
            )
            for f in result.findings
        ]
        
        return SkillEnvelope(
            skill="behavior-agent",
            status="completed",
            findings=findings,
            evidence_ids=[ev_id for _, ev_id in executor.evidence_created],
            tool_calls=result.tool_calls_needed,
            tokens=tokens_used,
        )
    
    except Exception as e:
        return SkillEnvelope(
            skill="behavior-agent",
            status="failed",
            unavailable=[f"execution_error: {str(e)[:100]}"],
        )


async def run_obfuscation_agent(
    executor: APKExecutor,
    store: EvidenceStore,
    features: dict[str, Any],
    decompiled: dict[str, Any],
    deterministic_findings: list[Any],
) -> SkillEnvelope:
    """Run obfuscation agent: analyze why code is hidden."""
    
    model = chat_model()
    if model is None:
        return SkillEnvelope(
            skill="obfuscation-agent",
            status="failed",
            unavailable=["llm_unavailable"],
        )
    
    evidence_index = json.dumps(store.index(), ensure_ascii=False)[:6000]
    
    native_libs = decompiled.get("native_libs", {})
    obfuscation_hints = decompiled.get("obfuscation_detected", False)
    
    human = f"""
<native_libraries>
{json.dumps(native_libs, indent=2)}
</native_libraries>

<obfuscation_indicators>
Detected: {obfuscation_hints}
Package: {decompiled.get("package_name", "unknown")}
Class count: {len(decompiled.get("classes", []))}
Sample classes: {json.dumps(decompiled.get("classes", [])[:10], indent=2)}
</obfuscation_indicators>

<code_patterns>
Dynamic loading: {bool(decompiled.get("code_patterns", {}).get("dynamic_loading"))}
Anti-analysis: {bool(decompiled.get("code_patterns", {}).get("anti_analysis"))}
Crypto usage: {bool(decompiled.get("code_patterns", {}).get("crypto_usage"))}
</code_patterns>

<evidence_index>
{evidence_index}
</evidence_index>

Analyze: Teknik hiding apa yang dipakai APK ini dan apa yang disembunyikan? Link obfuscation ke malicious intent kalau ada.
"""
    
    tools = [
        executor.tool_for("classify_obfuscation"),
        executor.tool_for("analyze_native_payload"),
        executor.tool_for("inspect_dynamic_loading"),
        executor.tool_for("analyze_anti_analysis"),
    ]
    
    try:
        # Run agent with structured output
        structured_model = model.with_structured_output(ObfuscationAgentOutput)
        result = await structured_model.bind_tools(tools).ainvoke(
            [
                {"role": "system", "content": OBFUSCATION_AGENT_SYSTEM},
                {"role": "user", "content": human},
            ],
            config={"timeout": 45},
        )
        
        # Extract token usage
        tokens_used = 0
        if hasattr(result, "usage_metadata"):
            usage = result.usage_metadata
            tokens_used = getattr(usage, "total_tokens", 0)
        elif hasattr(result, "response_metadata"):
            usage = result.response_metadata.get("token_usage", {})
            tokens_used = usage.get("total_tokens", 0)
        
        # Convert structured output to findings
        findings = [
            InvestigationFinding(
                indicator=f.indicator,
                severity=f.severity,
                evidence_ids=f.evidence_ids,
            )
            for f in result.findings
        ]
        
        return SkillEnvelope(
            skill="obfuscation-agent",
            status="completed",
            findings=findings,
            evidence_ids=[ev_id for _, ev_id in executor.evidence_created],
            tool_calls=result.tool_calls_needed,
            tokens=tokens_used,
        )
    
    except Exception as e:
        return SkillEnvelope(
            skill="obfuscation-agent",
            status="failed",
            unavailable=[f"execution_error: {str(e)[:100]}"],
        )



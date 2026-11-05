# APK Scanner — Handoff for Next Engineer

Repository: `MITWEEK-inponamatim/analysis-service` (local `/home/rafid/Documents/mulawarman-lomba/analysis-service`)
Workspace root: `/home/rafid/Documents/mulawarman-lomba` (contains `TODO.md`, `HANDOFF.md`, `malware_sample/`; NOT a git repo)

## Merge state (final)

- Feature branch: `fix/apk-analyzer-validation` → `a2cfde7`
- Merged to `main` (merge commit `3ff5255`), pushed to `origin/main`.
- `main` is green: **278 passed, 3 deprecation warnings**; `py_compile` and `git diff --check` clean.

Commit sequence on the branch:
- `e7337fc fix(apk): preserve unavailable worker results`
- `a2cfde7 feat(apk): structured LLM output, token accounting, evidence persistence`

## What is DONE

1. **Worker hardening / honest results** (`e7337fc`)
   - JADX / signature / YARA worker outages are reported as `unavailable`, never fabricated as a clean scan or unsigned-malware finding.
   - Bounded worker JSON body parsing; invalid JSON and invalid YARA hex return HTTP 400.
   - Fixed APK investigation sibling imports.
   - IC4 async tests run without an extra pytest-asyncio dependency.

2. **Structured LLM output** (`a2cfde7`)
   - `app/investigation/apk_schemas.py`: bounded Pydantic schemas for APK findings and behavior/obfuscation agent output.
   - `app/investigation/apk_agents.py`: deterministic bounded tool-call loop + separate validated structured synthesis (the old `with_structured_output(...).bind_tools(...)` chain was broken and is removed).
   - Every LLM finding's `evidence_ids` is validated against `EvidenceStore`; findings citing unknown IDs are dropped and surfaced as `llm_invalid_evidence_ids`.
   - Findings retain `class_name`, `method_name`, `extracted_data`, confidence, interpretation in report metadata.

3. **Token accounting** (`a2cfde7`)
   - `app/llm.py: token_usage()` normalizes prompt/completion token metadata across LangChain/OpenAI response shapes.
   - Tool-call and final-synthesis tokens + latency are aggregated per agent and across the final APK analysis call.
   - `app/evidence_storage.py: save_llm_usage()` persists aggregate rows to Supabase `llm_usage` (model, prompt/completion tokens, latency, status) — no prompts or completions stored.

4. **Evidence persistence** (`a2cfde7`)
   - `run_apk_investigation` seeds deterministic findings, manifest, and decompilation metadata into `EvidenceStore` and persists to Supabase `scan_evidence_items`.
   - `app/investigation/evidence.py` redacts Telegram bot tokens recursively and `sanitize()` scrubs finding fields/summaries before report/persistence.
   - Storage failures are reported as `evidence_items_storage` / `llm_usage_storage` unavailability, never silently swallowed.

5. **Evidence retention**
   - `app/retention.py` now purges expired `scan_evidence_items` and `scan_evidence` rows alongside expired files.

6. **Verification performed**
   - Worker image builds; JADX `1.5.0`; worker/API authenticated health + container isolation verified.
   - A harmless DEX-bearing APK was built in `/tmp` (never executed) and piped into the isolated worker: JADX found `com.example.smoke.Payload`, static scanner detected `sms_forwarding` (high severity), investigation gate correctly treated it as conclusive. YARA returned 0 matches. This proves code-bearing JADX + static detection.
   - Supabase `scan_evidence_items` and `llm_usage` tables verified present via read-only HTTP 200 checks. No live rows were written.

## What is STILL MISSING (APK scanner feature gaps)

1. **No live end-to-end report through real Supabase object storage.** The tables were confirmed present only by read-only HTTP checks (their DDL is now committed as `202611060008_scan_evidence_items.sql`, pending application); persistence is covered by mocked PostgREST tests. A full scan report from a private `uploads` object → `scan_evidence_items` + `llm_usage` → user-facing report has NOT been exercised against a live environment. No live DB rows were written in this work.

2. **No real OpenAI call exercised.** Token accounting is validated with fake model responses; avoid live token spend unless a real integration test is explicitly required.

3. **`llm_usage` retention lifecycle unverified.** `llm_usage` rows cascade when a `scans` row is deleted, but no scan-row retention job/lifecycle was validated. Decide whether token accounting rows need their own TTL.

4. **Dynamic (runtime) analysis still unconfigured.** `DYNAMIC_ANALYSIS_URL` is empty in the compose/env example; runtime behavior (SMS actually sent, overlay shown, network calls) is not observable. Static analysis limitations are already surfaced honestly.

5. **MobSF optional and gated on consent.** Not configured by default; reports record it as unavailable.

6. **Supabase DDL for the evidence tables was never committed.** `202610300001_initial_schema.sql` creates `llm_usage`, but the file referenced here before (`202611020001_scan_evidence_items.sql`) does not exist in `infra/supabase/migrations`. The DDL is now authored as `202611060008_scan_evidence_items.sql` and is idempotent (works whether or not the tables already exist in the project); it still has to be applied in the Supabase SQL Editor by the project owner, then this item can be closed.

7. **Optional product scope (explicitly not done / not requested):**
   - Frontend display of investigation artifacts — **explicitly excluded by user**.
   - AndroZoo integration — **explicitly excluded by user**.
   - Structured output for the URL/phone investigation path (unchanged; only APK agents were reworked).

## In progress / hand-back notes

- Nothing is actively mid-edit; the branch is merged. The only outstanding items are verification/product decisions above.
- The workspace-level `TODO.md` mirrors this status.
- **Fixed on 2026-11-06, after this handoff was written:**
  - `app/investigation/apk_orchestrator.py` built report `Finding` objects without the required `id`/`timestamp`/`confidence` (and passed a non-existent `category` field), so any APK scan whose agents returned at least one finding failed the whole report with `analysis_failed`. It now uses the `finding()` factory from `app/risk.py`, and `tests/test_apk_persistence.py::test_agent_findings_become_valid_report_findings` covers a non-empty envelope.
  - `app/graph/application.py::static_analysis` computed `features` but never returned it to the graph state, so `code_pattern_analysis`, `investigation_gate_check`, `run_investigation`, `analyze` and `assess_state` all read `{}`. It is returned now.
  - Evidence DDL committed as migration `202611060008_scan_evidence_items.sql` (see gap 6).
  - The Linux `venv/` that was committed by `16effde` is untracked (files stay on disk); `.dockerignore` now excludes it too. Re-create it locally with `python -m venv venv && pip install -r requirements.txt`.

## Guardrails for the next engineer

- Deterministic code owns workflow/state/validation/persistence/gates (Praetorian deterministic orchestration model). LLMs are bounded leaf analysts; never let an LLM decide verdicts or own state.
- Treat APK strings, manifest text, decompiled source, and tool output as untrusted prompt content.
- Never persist APK bytes, source dumps, prompts, or completions. Evidence is sanitized metadata only; the APK stays in the private `uploads` bucket.
- Use inline review (active `cx/gpt-6-luna` session); the user asked to avoid Cline subagents.
- Do not run APK code outside the isolated `analysis-worker` container.
- Do not write real Supabase rows during smoke tests without explicit authorization; use mocked PostgREST.

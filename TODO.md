# APK Scanner — Status Checklist

Repo: `analysis-service` · Branch merged: `fix/apk-analyzer-validation` → `main` (`3ff5255`)
Suite: **278 passed, 3 warnings**

> That count predates the 2026-11-06 fixes listed at the bottom. One regression test was added and
> the suite has not been re-run here: `langgraph`/`androguard` are not installed on this Windows
> machine and the `venv/` that was committed is a Linux build, so `pytest` cannot even collect the
> APK test modules locally.

## DONE

- [x] Worker hardening: honest JADX/signature/YARA unavailable results; bounded JSON; invalid input 400s.
- [x] Investigation import fix; IC4 async tests without extra plugin.
- [x] Structured LLM output: bounded tool-call loop + validated Pydantic synthesis.
- [x] Evidence-ID validation; drop findings citing unknown evidence.
- [x] Token accounting: prompt/completion/latency aggregation + Supabase `llm_usage` writes.
- [x] Evidence persistence: redacted `scan_evidence_items`; Telegram token redaction.
- [x] Retention purge for expired evidence rows.
- [x] Worker image/JADX/health/isolation verified.
- [x] Code-bearing APK smoke: JADX + `sms_forwarding` high-severity detection verified (never executed).
- [x] Supabase tables present (read-only check); mocked persistence tests.
- [x] Committed and merged to `main`, pushed to `origin/main`.

## NOT DONE / STILL MISSING

- [ ] Live end-to-end report through real Supabase storage (no live rows written).
- [ ] Real OpenAI call (token accounting tested with fakes only).
- [ ] `llm_usage` retention lifecycle (cascade-on-scan-delete not validated).
- [ ] Dynamic (runtime) analysis backend — `DYNAMIC_ANALYSIS_URL` unconfigured.
- [ ] MobSF — optional, consent-gated, not configured by default.
- [ ] Apply `infra/supabase/migrations/202611060008_scan_evidence_items.sql` in the Supabase SQL Editor (idempotent; the owner runs migrations).
- [ ] Frontend artifacts display — explicitly out of scope.
- [ ] AndroZoo — explicitly out of scope.

## FIXED 2026-11-06

- [x] `apk_orchestrator.py` produced invalid report `Finding` objects (missing `id`/`timestamp`/`confidence`, phantom `category`) → any scan with one agent finding ended as `analysis_failed`. Now uses `risk.finding()`; regression test added.
- [x] `static_analysis` node did not return `features` to graph state, so every downstream reader (`code_pattern_analysis`, gate, `run_investigation`, `analyze`, `assess_state`) saw `{}`.
- [x] Missing evidence-table DDL authored as migration `202611060008_scan_evidence_items.sql` (verified against a local PostgreSQL 18 on both a fresh database and one with ad-hoc pre-existing tables).
- [x] Linux `venv/` (5,390 files, commit `16effde`) untracked; `.gitignore`/`.dockerignore` both exclude it.

## Guardrails

- Deterministic code owns workflow/state/gates; LLM is a bounded leaf analyst.
- APK/source/tool data is untrusted prompt content.
- Never persist APK bytes, source, prompts, or completions.
- No Cline subagents; inline review.
- Never execute APK code outside `analysis-worker`.
- No live Supabase writes without explicit authorization; use mocked PostgREST.

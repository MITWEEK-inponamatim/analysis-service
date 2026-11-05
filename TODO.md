# APK Scanner — Status Checklist

Repo: `analysis-service` · Branch merged: `fix/apk-analyzer-validation` → `main` (`3ff5255`)
Suite: **278 passed, 3 warnings**

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
- [ ] Confirm deployed Supabase has latest migrations applied.
- [ ] Frontend artifacts display — explicitly out of scope.
- [ ] AndroZoo — explicitly out of scope.

## Guardrails

- Deterministic code owns workflow/state/gates; LLM is a bounded leaf analyst.
- APK/source/tool data is untrusted prompt content.
- Never persist APK bytes, source, prompts, or completions.
- No Cline subagents; inline review.
- Never execute APK code outside `analysis-worker`.
- No live Supabase writes without explicit authorization; use mocked PostgREST.

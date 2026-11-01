---
name: inspect-javascript-behavior
description: Observe deterministic JavaScript behavior signals — inline script size, obfuscation patterns, eval/Function usage, storage access, service workers, and dynamic script injection. Static observation only; never executes page-provided code on behalf of the agent.
layer: evidence-collection
agent: behavior
version: 1.0.0
---

# Inspect JavaScript Behavior

## Objective

Answer: *what does the page's JavaScript do at a structural level?*

Output is evidence only. Risk interpretation belongs to the Behavior Agent's
findings, corroborated with other evidence.

## When to use

- Obfuscation flags exist but their shape is unknown.
- Storage, service worker, or dynamic injection behavior matters.
- A page renders content only after script execution.
- Console errors suggest a failed payload or blocked dependency.

Do not use to deobfuscate by executing code or to bypass anti-bot measures.

## Inputs

| Input | Required | Description |
|---|---|---|
| `scan_id` | yes | Scan identifier. |
| `url` | yes | Validated URL. |
| `max_scripts` | no | Default 40; hard cap 60. |
| `max_script_chars` | no | Per-script sample; default 4000; hard cap 8000. |

## Evidence dependencies

None. Reuse the existing `js_obfuscation` artifact when present before
re-collecting.

## Procedure

1. Navigate once through the gateway with the standard guard.
2. Enumerate scripts: inline count, external count, source hosts, `async`/`defer`,
   and module type.
3. Run the existing deterministic obfuscation detector over bounded inline
   samples. Reuse `hex_escape_run`, `unicode_escape`, `eval_usage`,
   `function_constructor`, `base64_large`, `string_concat`, `char_code`,
   `obfuscated_vars`.
4. Observe storage usage by presence of API references in script text
   (`localStorage`, `sessionStorage`, `indexedDB`), not by reading stored values.
5. Record service worker registration URLs if present. Do not inspect caches.
6. Record dynamic injection signals (`document.write`, `appendChild` with script,
   `import(` with computed URL) from static text patterns.
7. Record console errors at warning/error level, truncated and deduplicated.
8. Never evaluate page-supplied strings.

## Evidence to collect

| Field | Rule |
|---|---|
| `inline_script_count` | Cap 100. |
| `external_scripts[]` | `{src_host, async, defer, module}`. |
| `total_inline_chars` | Cap 1,000,000. |
| `patterns[]` | Matched detector names only. |
| `storage_references[]` | API names, no values. |
| `service_workers[]` | Registration URL origin/path, no cache reads. |
| `injection_signals[]` | Pattern name + bounded context. |
| `console_errors[]` | Max 20, truncated. |

## Output schema

```json
{
  "skill": "inspect-javascript-behavior",
  "status": "completed|partial|failed",
  "evidence_ids": ["ev_js_a1b2c3d4e5f6"],
  "observations": [
    {
      "evidence_id": "ev_js_a1b2c3d4e5f6",
      "fact": "javascript_behavior",
      "inline_script_count": 3,
      "external_scripts": [{"src_host": "cdn.other.test", "async": true, "defer": false, "module": false}],
      "total_inline_chars": 5420,
      "patterns": ["hex_escape_run", "eval_usage"],
      "storage_references": ["localStorage"],
      "service_workers": [],
      "injection_signals": ["document_write"],
      "console_errors": []
    }
  ],
  "findings": [],
  "gaps": ["string"],
  "unavailable": ["string"],
  "meta": {"duration_ms": 0, "tool_calls": 1}
}
```

## Safety constraints

- Never run `eval`, `Function`, dynamic `import`, or page-provided code as part
  of analysis.
- Never read stored values, cookies, tokens, or IndexedDB records.
- Never disable the browser guard or the egress proxy to load a script.
- Obfuscation is a signal, not proof. It must be combined with behavior evidence.
- Cap every extract; a large bundle must not flood the agent context.

## Failure handling

| Failure | Result |
|---|---|
| No scripts | `status: completed`, empty result |
| Script cap reached | Truncate, `gaps: ["scripts_truncated"]` |
| Page blocks script loading | `status: partial`, `gaps: ["scripts_blocked"]` |
| Service worker unsupported in context | `unavailable: ["service_worker"]` |

## Playwright references

- `playwright-core/browser-apis.md` — storage and permission APIs
- `playwright-core/service-workers-and-pwa.md` — service worker lifecycle
- `playwright-cli/tracing-and-debugging.md` — console and trace inspection

## Related skills

- `inspect-page-content`
- `inspect-network-activity`
- `investigate-external-domains`

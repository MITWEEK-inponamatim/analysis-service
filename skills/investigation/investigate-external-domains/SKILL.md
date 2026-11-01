---
name: investigate-external-domains
description: Attribute third-party domains observed in form actions and network traffic — relationship to the page host, purpose class, age/reputation from existing evidence, and likelihood of being a data-collection destination. Deterministic classification first.
layer: security-investigation
agent: behavior
version: 1.0.0
---

# Investigate External Domains

## Objective

Answer: *which external domains matter, what role do they play, and is any of
them acting as a data-collection destination?*

## When to use

- External hosts appear in network evidence or form actions.
- A form or redirect targets a domain unrelated to the page host.
- A host needs purpose classification before severity is assigned.

Do not use to probe, fetch, or scan a domain.

## Inputs

| Input | Required | Description |
|---|---|---|
| `scan_id` | yes | Scan identifier. |
| `network_evidence_id` | no | From `inspect-network-activity`. |
| `form_evidence_id` | no | From `inspect-form-elements`. |
| `redirect_evidence_id` | no | From `investigate-redirect-chain`. |
| `brand_evidence_id` | no | From `investigate-brand-impersonation`. |
| `recon_summary` | yes | Existing DNS/RDAP/threat-intel data. |

At least one of the evidence inputs above is required.

## Evidence dependencies

- `inspect-network-activity` or `inspect-form-elements`
- Reuse threat-intel results already collected; do not trigger a new provider
  lookup unless the budget explicitly allows it.

## Procedure

1. Build a unique host list from network requests, form actions, and redirect
   hops. Drop the page host and duplicate hosts.
2. Normalize each host and compute its registrable domain.
3. Classify purpose deterministically using observed resource types and context:

   | Purpose | Deterministic signal |
   |---|---|
   | `cdn` | static assets, many image/script/font requests |
   | `analytics` | known host list or beacon-like patterns |
   | `payment` | form/iframe markers, known processor host |
   | `sso` | redirect or frame used for login |
   | `api` | XHR/fetch to a JSON-like endpoint path |
   | `collector` | form action, OTP/password context |
   | `unknown` | none of the above |

4. Compare each host against the claimed brand and its official domains.
5. Attach existing evidence: domain age, certificate, reputation verdicts. Mark
   missing data as `null`, never guessed.
6. Score deterministically:

   | Condition | Severity |
   |---|---|
   | CDN/analytics only | info |
   | Unknown host, no sensitive context | low |
   | Collector host receiving credential/OTP data | high |
   | Brand-lookalike host receiving data | high |
   | Host with existing malicious verdict | critical |

7. Use the LLM only to summarize relationships, citing evidence IDs.

## Evidence to collect

| Field | Rule |
|---|---|
| `domains[]` | `{host, registrable_domain, purpose, sources[], age_days, reputation, brand_relation}`. |
| `data_destinations[]` | Hosts receiving form data. |
| `unresolved[]` | Hosts with no available metadata. |
| `supporting_evidence_ids[]` | Valid IDs only. |

## Output schema

```json
{
  "skill": "investigate-external-domains",
  "status": "completed|partial|failed",
  "evidence_ids": ["ev_domain_a1b2c3d4e5f6"],
  "observations": [
    {
      "evidence_id": "ev_domain_a1b2c3d4e5f6",
      "fact": "external_domain_attribution",
      "page_host": "example-bank-login.test",
      "domains": [
        {
          "host": "collect.other.test",
          "registrable_domain": "other.test",
          "purpose": "collector",
          "sources": ["form_action", "network"],
          "age_days": 12,
          "reputation": "clean",
          "brand_relation": "unrelated"
        }
      ],
      "data_destinations": ["collect.other.test"],
      "unresolved": [],
      "supporting_evidence_ids": ["ev_net_a1b2c3d4e5f6", "ev_form_a1b2c3d4e5f6"]
    }
  ],
  "findings": [
    {
      "indicator": "Domain eksternal menerima data formulir kredensial dan tidak terkait dengan brand yang diklaim.",
      "severity": "high",
      "confidence": "medium",
      "evidence_ids": ["ev_net_a1b2c3d4e5f6", "ev_domain_a1b2c3d4e5f6"],
      "interpretation": "Peran collector didukung oleh aksi form dan trafik jaringan teramati."
    }
  ],
  "gaps": ["string"],
  "unavailable": ["string"],
  "meta": {"duration_ms": 0, "tool_calls": 0}
}
```

## Safety constraints

- Never fetch, scan, or port-probe an external domain.
- Never resolve reputation by guessing; only use collected evidence.
- A third-party host is not malicious by default.
- Do not include query strings or tokens in the domain list.
- Every finding must cite valid evidence IDs.

## Failure handling

| Failure | Result |
|---|---|
| No external hosts | `status: completed`, empty list |
| Metadata unavailable | `age_days: null`, `reputation: null`, add to `unresolved` |
| Too many hosts | Truncate to top 30 by request count, gap `hosts_truncated` |
| Conflicting purposes | Keep both, lower confidence, record gap |

## Playwright references

- `playwright-core/network-mocking.md` — request metadata model
- `playwright-core/websockets-and-realtime.md` — realtime origins
- `playwright-core/multi-context-and-popups.md` — popup origins
- `playwright-cli/tracing-and-debugging.md` — request inspection from traces

## Related skills

- `inspect-network-activity`
- `investigate-form-destination`
- `investigate-redirect-chain`
- `investigate-brand-impersonation`

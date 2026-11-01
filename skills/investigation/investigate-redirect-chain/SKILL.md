---
name: investigate-redirect-chain
description: Analyze an observed redirect chain for host changes, scheme downgrades, shortener hops, cross-brand destinations, and final landing behavior. Deterministic chain analysis first; no extra navigation beyond the hop budget.
layer: security-investigation
agent: behavior
version: 1.0.0
---

# Investigate Redirect Chain

## Objective

Answer: *what does the navigation path do, and is any hop inconsistent with the
site's claimed identity?*

## When to use

- Chain has more than one hop.
- Host or registrable domain changes mid-chain.
- HTTPS downgrades or unusual ports appear.
- A shortener or tracking domain is the entry point.

Do not use to follow chains beyond the configured hop budget.

## Inputs

| Input | Required | Description |
|---|---|---|
| `scan_id` | yes | Scan identifier. |
| `nav_evidence_id` | yes | From `inspect-navigation`. |
| `network_evidence_id` | no | From `inspect-network-activity`. |
| `brand_evidence_id` | no | From `investigate-brand-impersonation`. |
| `recon_summary` | yes | TLS/RDAP/DNS already collected. |

## Evidence dependencies

- `inspect-navigation` (required)

## Procedure

1. Reconstruct the chain in order. Discard hops without an observed URL/status.
2. Normalize each host; compute `registrable_domain` and scheme per hop.
3. Detect deterministically:
   - host change and registrable-domain change;
   - HTTPS → HTTP downgrade;
   - non-standard port (already blocked by the guard);
   - known shortener host;
   - cross-brand destination versus claimed brand;
   - loop or repeated hop.
4. Compare each hop's domain age and certificate against official brand data
   already collected.
5. Classify the chain:

   | Pattern | Severity |
   |---|---|
   | Same host, same scheme | info |
   | Host change within same registrable domain | low |
   | Cross-domain chain, no sensitive context | medium |
   | Cross-domain chain ending at credential collection | high |
   | Chain to unverified brand-lookalike destination | high |

6. Use the LLM only to explain the sequence, citing evidence IDs.

## Evidence to collect

| Field | Rule |
|---|---|
| `hops[]` | `{order, url, host, registrable_domain, scheme, status}`. |
| `host_changes` | Count. |
| `registrable_domain_changes` | Count. |
| `downgrade` | Boolean. |
| `shortener_hops[]` | Hosts matching the known list. |
| `final_destination` | Observed final URL. |
| `supporting_evidence_ids[]` | Valid IDs only. |

## Output schema

```json
{
  "skill": "investigate-redirect-chain",
  "status": "completed|partial|failed",
  "evidence_ids": ["ev_redirect_a1b2c3d4e5f6"],
  "observations": [
    {
      "evidence_id": "ev_redirect_a1b2c3d4e5f6",
      "fact": "redirect_chain_analysis",
      "hops": [
        {"order": 1, "url": "https://short.test/abc", "host": "short.test", "registrable_domain": "short.test", "scheme": "https", "status": 301},
        {"order": 2, "url": "https://example-bank-login.test/", "host": "example-bank-login.test", "registrable_domain": "example-bank-login.test", "scheme": "https", "status": 200}
      ],
      "host_changes": 1,
      "registrable_domain_changes": 1,
      "downgrade": false,
      "shortener_hops": ["short.test"],
      "final_destination": "https://example-bank-login.test/",
      "supporting_evidence_ids": ["ev_nav_a1b2c3d4e5f6"]
    }
  ],
  "findings": [
    {
      "indicator": "Rantai redirect berpindah dari pemendek URL ke domain yang mengklaim brand perbankan.",
      "severity": "medium",
      "confidence": "medium",
      "evidence_ids": ["ev_nav_a1b2c3d4e5f6", "ev_redirect_a1b2c3d4e5f6"],
      "interpretation": "Perpindahan domain teramati; perlu dikorelasikan dengan bukti form."
    }
  ],
  "gaps": ["string"],
  "unavailable": ["string"],
  "meta": {"duration_ms": 0, "tool_calls": 0}
}
```

## Safety constraints

- Never follow redirects beyond the hop budget.
- Never bypass the egress guard to resolve a blocked hop.
- A redirect alone is normal; severity must reflect context.
- Never present an inferred hop as observed.

## Failure handling

| Failure | Result |
|---|---|
| Chain empty | `status: partial`, gap `chain_unavailable` |
| Hop blocked by guard | Record blocked hop, gap `hop_blocked` |
| Loop detected | Stop at first repeat, gap `redirect_loop` |
| One hop only | `status: completed`, no redirect finding |

## Playwright references

- `playwright-core/assertions-and-waiting.md` — waiting for navigation state
- `playwright-core/configuration.md` — navigation timeout configuration
- `playwright-core/multi-context-and-popups.md` — popup versus redirect
- `playwright-cli/tracing-and-debugging.md` — trace-based navigation inspection

## Related skills

- `inspect-navigation`
- `investigate-external-domains`
- `investigate-brand-impersonation`

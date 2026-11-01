---
name: investigate-form-destination
description: Determine where a form would send data, which fields are sensitive, and whether the destination is related to the page host or claimed brand. Deterministic host comparison first; no form submission. Produces evidence-linked data-destination findings.
layer: security-investigation
agent: behavior
version: 1.0.0
---

# Investigate Form Destination

## Objective

Answer: *if a user typed into this form, where would the data go, and is that
consistent with the site's claimed identity?*

## When to use

- A form contains password, OTP, identity, or payment fields.
- Form action host differs from the page host.
- The action is relative, empty, or JavaScript-driven.
- A login form appears alongside brand-impersonation evidence.

Never submit, fill, or validate the form.

## Inputs

| Input | Required | Description |
|---|---|---|
| `scan_id` | yes | Scan identifier. |
| `form_evidence_id` | yes | From `inspect-form-elements`. |
| `page_evidence_id` | no | From `inspect-page-content`. |
| `network_evidence_id` | no | From `inspect-network-activity`. |
| `brand_evidence_id` | no | From `investigate-brand-impersonation`. |

## Evidence dependencies

- `inspect-form-elements` (required)
- `inspect-network-activity` (recommended for action corroboration)
- `investigate-brand-impersonation` (when brand context exists)

## Procedure

1. Resolve each form action deterministically:
   - absolute URL → use as-is;
   - protocol-relative → inherit scheme;
   - relative → resolve against final URL;
   - empty → treat as current URL, note it.
2. Normalize hosts: lowercase, strip `www.`, strip trailing dot. Compare exact
   host, then registrable domain, then public suffix.
3. Classify each destination:
   - `same_host`, `same_registrable_domain`, `related_subdomain`,
   - `third_party_known` (payment/SSO/CDN markers),
   - `third_party_unknown`, `private_or_invalid`.
4. Map sensitive field categories from form evidence to destination class.
5. Corroborate with network evidence: does the page actually contact the action
   host? Record observed versus declared only.
6. Check destination-domain age and reputation only through existing recon and
   threat-intel data; do not trigger new external lookups without budget.
7. Score deterministically:

   | Condition | Severity |
   |---|---|
   | Password/OTP + `third_party_unknown` | high |
   | Password/OTP + `same_host` + no brand mismatch | low |
   | Identity + `third_party_unknown` | medium |
   | Payment fields + known processor | info |
   | Invalid/private destination | medium |

8. Use the LLM only to explain the combination, citing evidence IDs.

## Evidence to collect

| Field | Rule |
|---|---|
| `forms[]` | `{index, method, action, action_host, destination_class, sensitive_categories, observed_contact}`. |
| `declared_vs_observed` | Boolean consistency per form. |
| `destination_age_days` | From existing RDAP only; nullable. |
| `supporting_evidence_ids[]` | Valid IDs only. |

## Output schema

```json
{
  "skill": "investigate-form-destination",
  "status": "completed|partial|failed",
  "evidence_ids": ["ev_domain_a1b2c3d4e5f6"],
  "observations": [
    {
      "evidence_id": "ev_domain_a1b2c3d4e5f6",
      "fact": "form_destination_analysis",
      "page_host": "example-bank-login.test",
      "forms": [
        {
          "index": 0,
          "method": "POST",
          "action": "https://collect.other.test/login",
          "action_host": "other.test",
          "destination_class": "third_party_unknown",
          "sensitive_categories": ["password", "identity"],
          "observed_contact": true
        }
      ],
      "declared_vs_observed": true,
      "destination_age_days": 12,
      "supporting_evidence_ids": ["ev_form_a1b2c3d4e5f6", "ev_net_a1b2c3d4e5f6"]
    }
  ],
  "findings": [
    {
      "indicator": "Formulir kata sandi mengirim data ke domain pihak ketiga yang tidak terkait dengan situs.",
      "severity": "high",
      "confidence": "high",
      "evidence_ids": ["ev_form_a1b2c3d4e5f6", "ev_domain_a1b2c3d4e5f6"],
      "interpretation": "Aksi form dan kontak jaringan sepakat menuju host eksternal."
    }
  ],
  "gaps": ["string"],
  "unavailable": ["string"],
  "meta": {"duration_ms": 0, "tool_calls": 0}
}
```

## Safety constraints

- Never submit, fill, focus, or dispatch events on a form.
- Never follow a JavaScript-only action by executing it.
- Never classify a destination as malicious from host mismatch alone; require
  sensitive fields or corroborating context.
- Known payment or SSO processors are not inherently malicious.
- Do not fetch the action URL to test it.

## Failure handling

| Failure | Result |
|---|---|
| Action unresolvable | `destination_class: private_or_invalid`, gap `action_unresolved` |
| No network evidence | `observed_contact: null`, confidence capped at medium |
| Cross-origin iframe form | Report origin only, gap `cross_origin_form` |
| Invalid evidence ID | Drop the claim, report `evidence_integrity_error` |

## Playwright references

- `playwright-core/forms-and-validation.md` — form and action semantics
- `playwright-core/network-mocking.md` — request observation model
- `playwright-core/iframes-and-shadow-dom.md` — scoping forms in frames

## Related skills

- `inspect-form-elements`
- `inspect-network-activity`
- `investigate-brand-impersonation`
- `investigate-external-domains`

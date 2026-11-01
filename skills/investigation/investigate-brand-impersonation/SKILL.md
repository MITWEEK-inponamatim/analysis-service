---
name: investigate-brand-impersonation
description: Synthesize brand identity findings from prior evidence steps. Interprets consistency status, severity, and generates impersonation findings with evidence linkage.
layer: security-investigation
agent: brand
version: 2.0.0
---

# Investigate Brand Impersonation

## Objective

Answer: *does this site claim a brand identity that does not belong to it?*

Synthesize evidence from prior brand investigation steps (`identify-claimed-brand`, `verify-official-domain`, `compare-brand-identity`) and generate findings with severity, confidence, and interpretation.

## When to use

- After `compare-brand-identity` completes
- When identity consistency status is known
- When claimed brand and domain relation are available
- Skip if consistency_status is "consistent" (no impersonation)

## Inputs

```json
{
  "claimed_brand": "BCA",
  "official_domains": ["bca.co.id", "klikbca.com"],
  "verification_status": "verified",
  "identity_consistency": "inconsistent",
  "domain_relation": "unrelated",
  "lookalike_rules": ["brand_token_present", "unexpected_tld"],
  "service_match_status": "inconsistent",
  "evidence_ids": {
    "brand_claims": "ev_brand_abc123",
    "domain_verification": "ev_brand_def456",
    "identity_comparison": "ev_brand_ghi789"
  }
}
```

All parameters from prior steps:
- From `identify-claimed-brand`: `claimed_brand`, `evidence_ids.brand_claims`
- From `verify-official-domain`: `official_domains`, `verification_status`, `evidence_ids.domain_verification`
- From `compare-brand-identity`: `identity_consistency`, `domain_relation`, `lookalike_rules`, `service_match_status`, `evidence_ids.identity_comparison`

## Process

### 1. Validate Evidence Chain

Verify all evidence IDs from prior steps exist in Evidence Store:
```python
valid_ids, invalid_ids = store.validate([
    evidence_ids["brand_claims"],
    evidence_ids["domain_verification"],
    evidence_ids["identity_comparison"]
])
```

If any invalid → gap: `evidence_integrity_error`

### 2. Skip Consistent Cases

If `identity_consistency == "consistent"`:
- No finding generated
- Return observation only: "Brand identity consistent with official domains"
- Status: `completed`

### 3. Determine Severity

**Rules:**

| Consistency | Domain Relation | Service Match | Forms | Severity |
|---|---|---|---|---|
| consistent | any | any | any | none (skip) |
| unknown | unknown | any | any | `low` |
| suspicious | unrelated | no_forms | none | `low` |
| suspicious | unrelated | no_forms | any | `medium` |
| inconsistent | unrelated | consistent | any | `medium` |
| inconsistent | unrelated | inconsistent | password only | `high` |
| inconsistent | unrelated | inconsistent | password + otp | `critical` |

**Severity definitions:**
- `low` — Cosmetic similarity, no credential collection
- `medium` — Brand claim + unrelated domain, but no cross-site forms
- `high` — Brand claim + unrelated domain + credential forms to third-party
- `critical` — Brand claim + unrelated domain + password + OTP to third-party

### 4. Compute Confidence

```python
confidence = "high"  # Start optimistic

if verification_status == "unverified":
    confidence = "medium"  # Official domain not strongly verified

if verification_status == "conflicting":
    confidence = "low"  # Ambiguous official domains

if len(lookalike_rules) == 0 and domain_relation == "unrelated":
    confidence = "medium"  # No lookalike signals

if verification_status == "not_found":
    confidence = "low"  # Cannot verify brand exists
```

### 5. Generate Interpretation

**Template:**

```
Situs mengklaim identitas {claimed_brand} pada domain {page_host} yang tidak terdaftar sebagai domain resmi. {detail}.
```

**Details based on signals:**
- Lookalike rules: "Domain menggunakan teknik lookalike: {rules}."
- Service mismatch: "Form kredensial mengarah ke domain pihak ketiga: {destinations}."
- Verification issues: "Domain resmi tidak dapat diverifikasi dengan kuat."

### 6. Create Finding

```python
finding = {
    "indicator": f"Situs mengklaim identitas {claimed_brand} pada domain yang tidak terdaftar sebagai domain resmi.",
    "severity": severity,  # from step 3
    "confidence": confidence,  # from step 4
    "evidence_ids": [
        evidence_ids["brand_claims"],
        evidence_ids["domain_verification"],
        evidence_ids["identity_comparison"]
    ],
    "interpretation": interpretation  # from step 5
}
```

## Output

### Observations

None — evidence already collected in prior steps.

### Findings

**Finding structure:**
```json
{
  "indicator": "Situs mengklaim identitas BCA pada domain yang tidak terdaftar sebagai domain resmi.",
  "severity": "high",
  "confidence": "high",
  "evidence_ids": [
    "ev_brand_abc123",
    "ev_brand_def456",
    "ev_brand_ghi789"
  ],
  "interpretation": "Domain menggunakan teknik lookalike: brand_token_present, unexpected_tld. Form kredensial mengarah ke domain pihak ketiga: phishing-collector.test."
}
```

### Gaps

- `evidence_integrity_error` - One or more evidence IDs invalid
- `insufficient_signals` - Not enough data to determine severity
- `official_domain_unverified` - Verification status "not_found" or "conflicting"

## Examples

### Example 1: Critical Impersonation
```json
Input:
{
  "claimed_brand": "BCA",
  "official_domains": ["bca.co.id"],
  "verification_status": "verified",
  "identity_consistency": "inconsistent",
  "domain_relation": "unrelated",
  "lookalike_rules": ["brand_token_present", "unexpected_tld"],
  "service_match_status": "inconsistent",
  "form_categories": ["password", "otp"]
}

Output:
{
  "indicator": "Situs mengklaim identitas BCA pada domain yang tidak terdaftar sebagai domain resmi.",
  "severity": "critical",
  "confidence": "high",
  "interpretation": "Domain menggunakan teknik lookalike. Form kredensial dengan password dan OTP mengarah ke pihak ketiga."
}
```

### Example 2: Suspicious (No Forms)
```json
Input:
{
  "claimed_brand": "BCA",
  "verification_status": "verified",
  "identity_consistency": "suspicious",
  "domain_relation": "unrelated",
  "service_match_status": "no_forms"
}

Output:
{
  "indicator": "Situs mengklaim identitas BCA pada domain yang tidak terkait dengan domain resmi.",
  "severity": "low",
  "confidence": "medium",
  "interpretation": "Klaim brand pada domain tidak resmi, namun tidak ditemukan form kredensial."
}
```

### Example 3: Consistent (No Finding)
```json
Input:
{
  "identity_consistency": "consistent",
  "domain_relation": "subdomain"
}

Output:
{
  "status": "completed",
  "findings": [],
  "observations": ["Brand identity consistent with official domains"]
}
```

### Example 4: Unknown Brand
```json
Input:
{
  "claimed_brand": "UnknownBrand",
  "verification_status": "not_found",
  "identity_consistency": "unknown"
}

Output:
{
  "indicator": "Situs mengklaim identitas UnknownBrand namun domain resmi tidak dapat diverifikasi.",
  "severity": "low",
  "confidence": "low",
  "interpretation": "Brand tidak ditemukan dalam verifikasi; tidak dapat memastikan impersonasi.",
  "gaps": ["official_domain_unverified"]
}
```

## Severity Logic (Pseudo-code)

```python
if identity_consistency == "consistent":
    return None  # No finding

if identity_consistency == "unknown":
    return "low"

if identity_consistency == "suspicious":
    if service_match_status == "no_forms":
        return "low"
    else:
        return "medium"

# identity_consistency == "inconsistent"
if service_match_status == "inconsistent":
    form_categories = get_sensitive_form_categories()
    if "password" in form_categories and "otp" in form_categories:
        return "critical"
    elif "password" in form_categories or "identity" in form_categories:
        return "high"
    else:
        return "medium"
else:
    return "medium"
```

## Safety Constraints

- Never generate findings without valid evidence IDs
- Never invent signals not provided by prior steps
- Severity must follow deterministic rules (no LLM-driven severity)
- Interpretation can use LLM for natural language, but facts come from params
- Consistent identity → no finding (false positives harm trust)
- Always cite all 3 evidence IDs from prior steps

## Failure Handling

| Failure | Result |
|---|---|
| Missing required param | `status: failed`, gap `missing_input_parameter` |
| Invalid evidence ID | `status: partial`, gap `evidence_integrity_error` |
| Identity consistency "unknown" | Finding with severity `low`, gap `official_domain_unverified` |
| No sensitive forms detected | Lower severity (low/medium, not high/critical) |

## Related Skills

- **Previous Steps:** `identify-claimed-brand`, `verify-official-domain`, `compare-brand-identity`
- **Evidence Dependencies:** All 3 prior brand skills must complete first
- **Replaces:** Old monolithic `investigate-brand-impersonation` (v1.0.0)

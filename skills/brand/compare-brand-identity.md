---
agent: brand
executor: yes
purpose: Compare claimed brand identity against verified official domains
---

# compare-brand-identity

**Layer:** evidence-collection  
**Agent:** brand  
**Executor:** Yes

## Purpose

Compare the site's claimed brand identity against verified official domains to determine identity consistency. Evaluates domain relationship, visual branding match, and service alignment (form actions).

## When to Use

- After `identify-claimed-brand` and `verify-official-domain` complete
- When both claimed brand and official domains are known
- Skip if no brand claimed or verification returned "not_found"

## Input Parameters

```json
{
  "claimed_brand": "BCA",
  "official_domains": ["bca.co.id", "klikbca.com"],
  "verification_status": "verified"
}
```

From prior steps:
- `claimed_brand` - Primary brand from identify step (highest confidence)
- `official_domains` - Verified domains from verify step
- `verification_status` - "verified" | "unverified" | "conflicting" | "not_found"

## Process

### 1. Domain Relation

Use `det.domain_relation(page_host, official_domains)`:

**Possible results:**
- `exact` - Page host matches official domain exactly
- `subdomain` - Page is subdomain of official domain
- `same_registrable` - Same registrable domain
- `unrelated` - No domain relationship
- `unknown` - Cannot determine (no official domains)

### 2. Visual Match

**Current Implementation:** Placeholder only

Returns `"insufficient"` - no logo image analysis implemented.

**Future enhancement:** Compare logo images via perceptual hash or visual model.

### 3. Service Match

Check form action destinations against official domains:

```python
forms = det.sensitive_forms(browser_evidence, page_host)
service_match_status = "consistent"

for form in forms:
    action_host = form["action_host"]
    if action_host and not det.same_registrable_domain(action_host, any_official):
        service_match_status = "inconsistent"
        break
```

**Service match logic:**
- `consistent` - All form actions point to official domains (or same page)
- `inconsistent` - At least one sensitive form points to third-party domain
- `no_forms` - No sensitive forms detected

### 4. Consistency Status

**Rules:**

| Domain Relation | Forms | Status |
|---|---|---|
| exact / subdomain / same_registrable | any | `consistent` |
| unrelated | no sensitive forms | `suspicious` |
| unrelated | sensitive forms to third-party | `inconsistent` |
| unknown | any | `unknown` |

**Lookalike consideration:**
- If `domain_relation = "unrelated"` AND `lookalike_rules` fires 2+ rules → `highly_suspicious`

## Output

### Observations

**Evidence Kind:** `brand`  
**Fact:** `identity_comparison`

**Payload:**
```json
{
  "page_host": "bca-login.test",
  "claimed_brand": "BCA",
  "official_domains": ["bca.co.id", "klikbca.com"],
  "verification_status": "verified",
  "domain_relation": "unrelated",
  "lookalike_rules": ["brand_token_present", "unexpected_tld"],
  "visual_match": "insufficient",
  "service_match": {
    "status": "inconsistent",
    "forms_checked": 2,
    "third_party_destinations": ["phishing-collector.test"]
  },
  "consistency_status": "inconsistent",
  "consistency_reasons": [
    "Domain unrelated to official domains",
    "Lookalike domain detected",
    "Form submits to third-party domain"
  ]
}
```

### Findings

None — evidence only. Findings in `investigate-brand-impersonation`.

### Gaps

- `visual_analysis_unavailable` - Logo comparison not implemented
- `no_official_domains` - Cannot compare without verified domains
- `ambiguous_forms` - Form actions could not be resolved

## Examples

### Example 1: Consistent (Official Subdomain)
```
page_host: "login.bca.co.id"
claimed_brand: "BCA"
official_domains: ["bca.co.id"]
→ domain_relation: "subdomain"
→ service_match: "consistent"
→ consistency_status: "consistent"
```

### Example 2: Inconsistent Impersonation
```
page_host: "bca-secure-login.xyz"
claimed_brand: "BCA"
official_domains: ["bca.co.id", "klikbca.com"]
Forms: action="https://phish-collect.test/grab"
→ domain_relation: "unrelated"
→ lookalike_rules: ["brand_token_present", "unexpected_tld"]
→ service_match: "inconsistent"
→ consistency_status: "inconsistent"
```

### Example 3: Suspicious (No Forms)
```
page_host: "bcabank-info.com"
claimed_brand: "BCA"
official_domains: ["bca.co.id"]
Forms: none detected
→ domain_relation: "unrelated"
→ lookalike_rules: ["brand_token_present"]
→ service_match: "no_forms"
→ consistency_status: "suspicious"
```

### Example 4: Unknown (Unverified Brand)
```
page_host: "exotic-brand.test"
claimed_brand: "ExoticBrand"
verification_status: "not_found"
→ domain_relation: "unknown"
→ consistency_status: "unknown"
→ gaps: ["no_official_domains"]
```

## Deterministic Logic

```python
# Domain relation
relation = det.domain_relation(page_host, official_domains)

# Lookalike check
lookalike_rules = det.lookalike_rules(page_host, claimed_brand) if relation == "unrelated" else []

# Service match
forms = det.sensitive_forms(browser_evidence, page_host)
third_party_destinations = []
for form in forms:
    action_host = form["action_host"]
    if action_host and not any(det.same_registrable_domain(action_host, official) for official in official_domains):
        if action_host != page_host:  # Skip same-page submissions
            third_party_destinations.append(action_host)

service_status = "inconsistent" if third_party_destinations else ("no_forms" if not forms else "consistent")

# Consistency
if relation in ["exact", "subdomain", "same_registrable"]:
    consistency = "consistent"
elif relation == "unrelated":
    if len(lookalike_rules) >= 2 and third_party_destinations:
        consistency = "inconsistent"
    elif third_party_destinations:
        consistency = "inconsistent"
    elif lookalike_rules:
        consistency = "suspicious"
    else:
        consistency = "suspicious"
else:  # unknown
    consistency = "unknown"
```

## Limitations

- No logo visual analysis (always returns "insufficient")
- No certificate subject comparison (CN/SAN vs brand name)
- No RDAP registrant analysis
- Form action resolution limited to visible forms (no JavaScript-injected forms)
- No subdomain reputation check (subdomain could still be malicious)

## Security Considerations

- `same_registrable_domain` alone does not prove legitimacy (subdomain takeover risk)
- Visual match placeholder prevents false negatives but allows false positives
- Form analysis only covers DOM-visible forms at page load time
- Domain relation "exact" does not guarantee non-compromised site

## Related Skills

- **Previous Steps:** `identify-claimed-brand`, `verify-official-domain`
- **Next Step:** `investigate-brand-impersonation`
- **Backend Tools:** `app/investigation/deterministic.py`

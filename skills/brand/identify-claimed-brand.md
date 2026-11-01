---
agent: brand
executor: yes
purpose: Identify brands claimed by target website from page evidence
---

# identify-claimed-brand

**Layer:** evidence-collection  
**Agent:** brand  
**Executor:** Yes

## Purpose

Extract and identify brand claims from page evidence (title, visible text, logos, metadata). Distinguish between explicit identity claims ("Login ke BCA") and mere mentions ("menggunakan teknologi BCA").

## When to Use

- Always as first step in brand investigation
- Re-run if initial identification returns ambiguous results
- When page contains multiple potential brand references

## Input Parameters

None required — uses existing browser evidence from Evidence Store.

## Available Evidence

The executor automatically provides:
- `title` - Page title
- `visible_text` - Extracted visible text content
- `meta` - Meta tags (description, keywords, og:site_name)
- `logo_candidates` - Logo image URLs and alt text
- `headings` - H1-H3 headings

## Process

### 1. Extract Brand Mentions

Search for brand names in:
- Page title (highest signal)
- Headings (high signal)
- Visible text (medium signal, require word boundaries)
- Meta description/og:site_name
- Logo alt text

### 2. Classify Claim Type

**Identity Claim** (high confidence):
- Brand name in title: "BCA Internet Banking"
- Login/masuk context: "Login ke Akun BCA"
- Official branding: "Portal Resmi BCA"

**Mention Only** (lower confidence):
- Informational: "Cara menggunakan BCA Mobile"
- Comparison: "BCA vs Mandiri"
- News/blog: "BCA meluncurkan fitur baru"

### 3. Confidence Scoring

- `high`: Brand in title + identity context
- `medium`: Brand in headings or multiple text mentions
- `low`: Single mention in body text only

### 4. Brand Extraction Rules

- Minimum 3 characters
- Word boundary match: `\bBCA\b` (not "ABCA")
- Case-insensitive for known brands
- Stop words filtered: "the", "bank" alone not a brand

## Output

### Observations

**Evidence Kind:** `brand`  
**Fact:** `brand_claims`

**Payload:**
```json
{
  "page_host": "bca-login.test",
  "claimed_brands": [
    {
      "name": "BCA",
      "confidence": "high",
      "claim_type": "identity",
      "evidence_sources": ["title", "heading"],
      "context_snippet": "Login ke BCA Internet Banking"
    },
    {
      "name": "Mandiri",
      "confidence": "low",
      "claim_type": "mention",
      "evidence_sources": ["text"],
      "context_snippet": "atau gunakan Mandiri Mobile"
    }
  ],
  "title": "BCA Internet Banking - Login",
  "text_excerpt": "Masukkan User ID dan Password BCA Anda..."
}
```

Returns top 3 claimed brands by confidence.

### Findings

None — this is evidence collection only. Findings generated in `investigate-brand-impersonation`.

### Gaps

- `no_brand_claim` - No clear brand identity claim found
- `ambiguous_brand` - Multiple brands with equal confidence
- `insufficient_context` - Brand mentioned but context unclear

## Examples

### Example 1: Clear Identity Claim
```
Title: "BCA KlikBCA - Login"
Headings: ["Selamat Datang di BCA"]
→ claimed_brands: [{"name": "BCA", "confidence": "high", "claim_type": "identity"}]
```

### Example 2: Mention Only
```
Title: "Cara Transfer ke BCA"
Text: "Tutorial transfer bank ke rekening BCA"
→ claimed_brands: [{"name": "BCA", "confidence": "medium", "claim_type": "mention"}]
```

### Example 3: Multiple Brands
```
Title: "Perbandingan BCA vs Mandiri"
→ claimed_brands: [
     {"name": "BCA", "confidence": "medium", "claim_type": "mention"},
     {"name": "Mandiri", "confidence": "medium", "claim_type": "mention"}
   ]
→ gaps: ["ambiguous_brand"]
```

## Limitations

- No logo image analysis (relies on alt text only)
- No language detection (assumes Indonesian/English mix)
- No OCR for image-based brand text
- Known brands from `brand_guard` used as hints, not exhaustive

## Related Skills

- **Next Step:** `verify-official-domain` (after brand identified)
- **Uses:** Browser evidence from `inspect-page-content`

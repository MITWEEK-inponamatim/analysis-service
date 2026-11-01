---
agent: brand, behavior
executor: yes
purpose: Search the web for claims or brand reputation using Exa
---

# investigate-external-claims

**Agent:** brand, behavior  
**Executor:** Yes  
**Purpose:** Search the web for claims or brand reputation using Exa.

## When to Use

- Brand claims legitimacy but domain is unrelated or lookalike
- Suspicious promotional offers or giveaways mentioned in page content
- Company/service mentioned but no official domain match
- Need to verify if a claim/offer has been reported as scam

## Parameters

```json
{
  "query": "string (required, 10-200 chars)"
}
```

**Query examples:**
- "Brand X official domain"
- "Brand X giveaway scam reports"  
- "Company Y phishing campaign"
- "Service Z customer complaints fraud"

## Returns

### Observations
- **Kind:** `search`
- **Fact:** `web_search_results`
- **Payload:**
```json
{
  "query": "Brand X official domain",
  "results": [
    {
      "title": "...",
      "url": "https://...",
      "text": "...",
      "published": "2024-10-15"
    }
  ],
  "result_count": 3
}
```

### Findings

**Low-confidence findings only** — search results are evidence to review, not proof:

- If results mention scam/phishing reports about the claimed brand or offer
- If no credible results found for claimed legitimate service
- If search contradicts page claims (e.g., real brand has different domain)

**Severity:** `low` (max)  
**Confidence:** `low` (always)

### Gaps

- `query_too_vague`: query returned unrelated results
- `no_relevant_results`: no results or all off-topic
- `exa_unavailable`: API key missing or service failed

## Examples

### Brand verification
```
Query: "BCA official domain internet banking"
→ Results confirm bca.co.id
→ Page domain: bca-login.test
→ Finding: domain mismatch, results show legitimate domain
```

### Scam report check
```
Query: "Shopee giveaway 10 juta scam"
→ Results: multiple reports on forum
→ Finding: claimed offer matches known scam pattern
```

## Safety

- Never trust search results as definitive proof
- Always mark findings confidence="low"
- Search results supplement deterministic checks, don't replace them
- Limit query to observable claims from the page, not speculation

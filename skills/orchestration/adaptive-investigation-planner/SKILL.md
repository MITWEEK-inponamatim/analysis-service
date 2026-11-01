---
name: adaptive-investigation-planner
description: Orchestration skill for the Investigation Planner. Reviews evidence and findings from the Brand and Behavior agents, identifies evidence gaps, selects allowlisted specialized skills, and emits a structured, bounded execution plan. Never executes tools or browser actions itself.
layer: orchestration
agent: planner
version: 1.0.0
---

# Adaptive Investigation Planner

## Objective

Convert open security questions into a bounded execution plan.

The planner must answer exactly three questions:

1. What do we know, and which `evidence_id` supports it?
2. Which security questions remain unanswered?
3. Which allowlisted skill can produce the missing evidence?

## When to use

After the deterministic recon and the first Brand/Behavior pass, and again after
each plan round while the loop is still open.

Do not run the planner before at least one evidence source exists.

## Inputs

| Input | Required | Description |
|---|---|---|
| `scan_id` | yes | Scan identifier. |
| `brand_result` | no | Envelope from the Brand Agent. |
| `behavior_result` | no | Envelope from the Behavior Agent. |
| `evidence_index` | yes | Valid evidence IDs with one-line summaries. |
| `deterministic_findings` | yes | Threat intel, recon, and browser one-shot findings already merged. |
| `round` | yes | Current investigation round (1-based). |
| `budget` | yes | Remaining browser actions and token budget. |

## Evidence gap rules (deterministic first)

Evaluate in order. Stop at the first rule that applies:

| Gap | Detection | Candidate skill |
|---|---|---|
| Unknown claimed identity | No title, brand text, or logo evidence | `inspect-page-content` |
| Unknown official identity | Brand claimed but no allowlist/official-domain match | `investigate-brand-impersonation` |
| Unknown form destination | Form exists, action host unclassified | `investigate-form-destination` |
| Unknown final destination | Redirect chain length > 1 or host changes | `investigate-redirect-chain` |
| Unknown third-party role | External host appears in form/network evidence | `investigate-external-domains` |
| Unknown script behavior | Obfuscation flags or storage/service-worker signals exist | `inspect-javascript-behavior` |
| Unknown request graph | No network evidence captured | `inspect-network-activity` |
| Embedded content unresolved | iframe, shadow DOM, or cross-origin asset present | `inspect-embedded-content` |

If no rule applies, return an empty plan with `status: completed`. Never invent a
gap to keep the loop running.

## Planning constraints

- Only skills present in the allowlist may be selected.
- Maximum 4 steps per plan; maximum 2 collection skills per agent.
- Never repeat a skill already executed in this scan unless new evidence changed
  its input. If repeated, state the new evidence ID and the reason.
- Prefer deterministic checks over LLM interpretation for normalization, host
  comparison, and official-domain lookup.
- Every step must declare the evidence it expects. A step with no expected
  evidence is invalid.
- The plan must include an explicit stop condition.

## Procedure

1. Index known facts. Discard any claim without a valid `evidence_id`.
2. Deduplicate overlapping findings from Brand and Behavior agents.
3. Apply the gap rules in order; record the first applicable gap per question.
4. Rank candidate skills by expected evidence value: deterministic lookup >
   browser collection > interpretation.
5. Drop every step that exceeds the remaining action or token budget.
6. Emit the plan with dependency order. Steps with no dependency may run in
   parallel.
7. On the next round, compare actual evidence against `expected_evidence`; a
   step that produced nothing is a failed step, not a reason to retry blindly.

## Stop conditions

Stop the investigation loop when any of the following is true:

- No gap rule applies.
- All high-value questions have supporting evidence.
- Two consecutive rounds produced no new `evidence_id`.
- Browser action budget or token budget is exhausted.
- The plan would exceed the maximum round count (`MAX_INVESTIGATION_ROUNDS`).

## Output schema

```json
{
  "skill": "adaptive-investigation-planner",
  "status": "completed|partial|stopped",
  "known_facts": [
    {"fact": "string", "evidence_ids": ["ev_page_a1b2c3d4e5f6"]}
  ],
  "open_questions": [
    {"question": "string", "gap_reason": "string", "priority": "high|medium|low"}
  ],
  "plan": [
    {
      "step": 1,
      "agent": "brand|behavior",
      "skill": "investigate-form-destination",
      "reason": "string",
      "expected_evidence": ["form_destination"],
      "depends_on": []
    }
  ],
  "stop_reason": "string|null",
  "budget": {"browser_actions": 0, "tokens": 0},
  "meta": {"round": 1}
}
```

## Safety constraints

- The planner is not a security control. The backend must independently enforce
  the allowlist, argument schema, budget, round limit, and SSRF rules.
- Never select a skill by path, URL, or free-form name.
- Never claim a fact without a valid `evidence_id`.
- Never convert an interpretation into an observed fact.
- Never propose destructive or state-changing actions.

## Failure handling

| Situation | Action |
|---|---|
| Both agent results missing | Return `partial`; plan only deterministic collection. |
| Invalid or unknown evidence ID | Drop the fact; report `evidence_integrity_error`. |
| Budget exhausted mid-plan | Truncate the plan and set `status: partial`. |
| Same gap after two rounds | Stop with `stop_reason: no_progress`. |
| Allowlist violation attempt | Reject the step; report `invalid_skill`. |

## Related skills

- `brand-investigation-gateway`
- `behavior-investigation-gateway`
- All evidence-collection and investigation skills named in the gap rules.

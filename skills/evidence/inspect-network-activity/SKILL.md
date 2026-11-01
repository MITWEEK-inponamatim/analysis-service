---
name: inspect-network-activity
description: Capture a bounded, read-only request and connection graph for a page — destination hosts, resource types, methods, status, WebSocket origins, and blocked/SSRF attempts. Does not replay or modify requests.
layer: evidence-collection
agent: behavior
version: 1.0.0
---

# Inspect Network Activity

## Objective

Produce an observed request graph that answers: *which hosts does this page
contact, and for what purpose?*

Output is evidence only. Third-party attribution belongs to
`investigate-external-domains`.

## When to use

- No network evidence exists for the scan.
- A form action or redirect target needs corroboration from observed traffic.
- WebSocket, SSE, or beacon endpoints are suspected.
- Requests were blocked and the reason needs recording.

Do not use to fetch arbitrary URLs or probe endpoints.

## Inputs

| Input | Required | Description |
|---|---|---|
| `scan_id` | yes | Scan identifier. |
| `url` | yes | Validated URL. |
| `max_requests` | no | Default 80; hard cap 120. |
| `capture_bodies` | no | Always `false`; bodies are never stored. |

## Evidence dependencies

None, but run after `inspect-navigation` when navigation failed, so failures are
not double-counted as network evidence.

## Procedure

1. Attach request, response, and request-failed listeners before navigation.
2. Navigate once through the gateway with the standard SSRF guard.
3. Record only metadata: URL, host, method, resource type, status, and whether
   the request was blocked.
4. Group by host. Compute per-host counts and resource-type mix.
5. Record WebSocket handshakes by origin only. Do not read frames.
6. Record every blocked request with its guard reason.
7. Stop at `max_requests`. Do not start a second navigation to fill gaps.

## Evidence to collect

| Field | Rule |
|---|---|
| `requests[]` | Max `max_requests`; no headers or bodies. |
| `hosts[]` | Unique host + count + methods + resource types. |
| `external_hosts[]` | Hosts not equal to the page host. |
| `websockets[]` | Origin URL only. |
| `blocked[]` | `{url, reason}` from the guard. |
| `failed[]` | `{url, reason}` first line only. |
| `beacon_like[]` | Requests with `ping`, `beacon`, or tiny POST bodies inferred from method only. |

Never store cookies, authorization headers, query secrets, or payloads.

## Output schema

```json
{
  "skill": "inspect-network-activity",
  "status": "completed|partial|failed",
  "evidence_ids": ["ev_net_a1b2c3d4e5f6"],
  "observations": [
    {
      "evidence_id": "ev_net_a1b2c3d4e5f6",
      "fact": "network_graph",
      "page_host": "example.test",
      "request_count": 42,
      "hosts": [
        {"host": "cdn.other.test", "count": 12, "methods": ["GET"], "resource_types": ["script", "image"]}
      ],
      "external_hosts": ["cdn.other.test"],
      "websockets": ["wss://socket.other.test/ws"],
      "blocked": [{"url": "http://169.254.169.254/latest/meta-data", "reason": "ssrf_blocked"}],
      "failed": [{"url": "https://x.test/a.js", "reason": "net::ERR_NAME_NOT_RESOLVED"}],
      "beacon_like": []
    }
  ],
  "findings": [],
  "gaps": ["string"],
  "unavailable": ["string"],
  "meta": {"duration_ms": 0, "tool_calls": 1}
}
```

## Safety constraints

- Read-only observation. Never call `route.fetch()` to probe a blocked host,
  never replay a request, never modify a response.
- Never capture bodies, headers, cookies, or credentials.
- Respect the request cap and per-scan byte budget enforced by the egress proxy.
- A blocked private-address request is a guard event, not proof of intent on its
  own; report it as evidence with context.

## Failure handling

| Failure | Result |
|---|---|
| No requests captured | `status: partial`, `gaps: ["network_empty"]` |
| Cap reached | Truncate, `gaps: ["requests_truncated"]` |
| Proxy budget exhausted | `status: partial`, `unavailable: ["egress_budget"]` |
| Listener error | Return collected subset, `unavailable: ["network_listener_error"]` |

## Playwright references

- `playwright-core/network-mocking.md` — request lifecycle and interception
  semantics (observe only; never fulfill or abort beyond the guard)
- `playwright-core/websockets-and-realtime.md` — WebSocket event model
- `playwright-cli/tracing-and-debugging.md` — request list and trace inspection

## Related skills

- `investigate-external-domains`
- `investigate-form-destination`
- `investigate-redirect-chain`

"""Agentic URL investigation package.

Deterministic platform around thin agents:

- skills: allowlisted JIT skill loader (no agent-supplied paths)
- evidence: normalized evidence store with stable IDs
- deterministic: host, domain, redirect, and activation rules
- executor: runs allowlisted evidence skills over collected browser evidence
- agents: bounded Brand and Behavior agents
- planner: gap-driven, bounded investigation plan
- orchestrator: LangGraph fan-out, planner loop, and finding merge
"""

from .orchestrator import investigation_enabled, run_investigation

__all__ = ["investigation_enabled", "run_investigation"]

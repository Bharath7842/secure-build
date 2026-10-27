"""One optional planning call. Invalid/empty plans leave the flat loop intact."""

from __future__ import annotations

import json

from ..active import loop_checks
from ..domain.agent import AgentBudget, Plan, agent_limits, parse_plan, target_key
from ..domain.active import order_targets
from ..domain.redaction import redact_text
from ..llm_utils import ask_json
from ..state import GraphState
from .analyze_apis import _endpoints

PLAN_SCHEMA = {"type": "object", "required": ["hypotheses"],
               "properties": {"hypotheses": {"type": "array", "items": {"type": "object"}}}}


def plan_tests(state: GraphState) -> GraphState:
    state["test_plan"], state["agent_budget"] = Plan(), None
    runtime = state.get("runtime")
    if not state.get("agent_mode") or not state.get("run_analysis", True) or runtime is None:
        return state
    if runtime.cancelled():
        state["stop_reason"] = "cancelled"
        return state
    checks = loop_checks(runtime.rule_set, runtime.skipped_degraded)
    endpoints = order_targets(_endpoints(state))[:int(runtime.effective.get("max_targets") or 15)]
    if not runtime.effective.get("allow_state_changing"):
        endpoints = [e for e in endpoints if not e.state_changing]
    if not checks or not endpoints:
        print("[plan] No loop-eligible work; keeping the ordinary endpoint loop.")
        return state
    total, per_hypothesis = agent_limits(state.get("max_agent_turns", 60), state.get("max_turns_per_hypothesis", 4),
                                        runtime.effective.get("model_routing") or {})
    secrets = tuple(runtime.credentials.secrets()) if runtime.credentials is not None else ()
    facts = {
        "endpoints": [{"target_key": target_key(e), "kind": e.kind,
                       "parameters": [{"name": p.name[:60], "location": p.location.value, "type": p.schema_type} for p in e.parameters][:20]}
                      for e in endpoints],
        "checks": [{"id": cid, "owasp": ec.check.standards.get("owasp", ()), "description": ec.check.description}
                   for cid, ec in checks.items()],
        "fingerprint": state.get("fingerprint", {}), "passive_findings": state.get("passive_analysis", {}),
        "identities": [{"label": s.label, "role": s.role_display} for s in runtime.identities],
        "max_hypotheses": min(total, len(endpoints)), "max_turns_per_hypothesis": per_hypothesis,
    }
    try:
        reply = ask_json(state["gateway"], "plan", redact_text(json.dumps(facts), secrets), PLAN_SCHEMA, temperature=0)
        # Rationale is also model output: redact before it can be retained or replayed.
        if reply is not None:
            reply = json.loads(redact_text(json.dumps(reply), secrets))
        plan = parse_plan(reply, endpoints, checks, max_hypotheses=min(total, len(endpoints)))
    except Exception as exc:  # planner availability must never suppress the normal tests
        print(f"[plan] Planner unavailable ({type(exc).__name__}); keeping the ordinary endpoint loop.")
        return state
    if not plan.hypotheses:
        print("[plan] No usable hypotheses; keeping the ordinary endpoint loop.")
        return state
    state["test_plan"] = plan
    state["agent_budget"] = AgentBudget(total, per_hypothesis)
    print(f"[plan] {len(plan.hypotheses)} hypothesis(es), at most {total} planned turns, {per_hypothesis} per hypothesis; dropped {sum(plan.dropped.values())}.")
    return state

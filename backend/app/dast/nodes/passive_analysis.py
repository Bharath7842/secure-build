"""NODE: passive_analysis (DAST-08-010): analyse what discovery already saw.

Reads the recorded traffic (and the preflight's root response); sends no request. The detector
is deterministic, then the configured model may enrich each finding's severity and reproduction
steps. Only checks the effective rule set enables run, findings go through the standard
writer deduplicated by `(check, header/cookie name)`, and the stage records which checks it ran
so the report can say. With the `passive-only` pack enabled alone, `route_after_passive` ends the
scan here.
"""

from __future__ import annotations

from ..domain.ruleset import EffectiveRuleSet
from ..passive import enabled_passive_checks, root_exchange, run_passive
from ..passive_enrichment import enrich_passive_rows
from ..state import GraphState


def has_active_work(rule_set: EffectiveRuleSet | None, skipped: list[dict]) -> bool:
    """Is anything left to run after the passive stage: an enabled, runnable, non-passive,
    non-assist-only check? With no rule set at all the answer is yes (nothing says otherwise)."""
    if rule_set is None:
        return True
    skipped_ids = {s.get("check_id") for s in skipped if s.get("status") == "skipped"}
    return any(
        not ec.check.passive and ec.mode.value not in ("assist-only",) and ec.check_id not in skipped_ids
        for ec in rule_set.enabled_checks()
    )


def passive_analysis(state: GraphState) -> GraphState:
    runtime = state["runtime"]
    state["passive_analysis"] = {}
    if runtime.cancelled():
        state["stop_reason"] = "cancelled"
        return state
    traffic = list(runtime.traffic)
    seen = {exchange.url for exchange in traffic}
    root = root_exchange(runtime.target_url, state.get("root_response"))
    if root is not None and root.url not in seen:
        traffic.insert(0, root)
    enabled = enabled_passive_checks(runtime.rule_set, runtime.skipped_degraded)
    if not enabled:
        print("[passive] No passive checks are enabled for this scan; nothing to analyse.")
        return state
    credentials = getattr(runtime, "credentials", None)
    secrets = list(credentials.secrets()) if credentials is not None and hasattr(credentials, "secrets") else []
    rows, summary = run_passive(traffic, runtime.rule_set, runtime.skipped_degraded, secrets=secrets)
    rows = enrich_passive_rows(rows, runtime.gateway)
    print(f"[passive] Analysed {summary['exchanges']} recorded response(s) with {summary['checks_run']} passive check(s) (no requests sent).")
    if not summary["cors"]["assessable"] and summary["cors"]["assessable"] is not None:
        print(f"[passive] CORS: {summary['cors']['note']}")
    if rows and runtime.findings_writer is not None:
        runtime.findings_writer("passive analysis", rows)
    print(f"[passive] {summary['findings']} finding(s).")
    state["passive_analysis"] = summary
    runtime.counters.set("passive_findings", summary["findings"])
    return state


def route_after_passive(state: GraphState) -> str:
    """Stop here when only passive checks are left to run (the passive-only pack), or the scan was cancelled."""
    runtime = state["runtime"]
    if runtime.cancelled() or state.get("stop_reason") == "cancelled":
        return "end"
    if not has_active_work(runtime.rule_set, runtime.skipped_degraded):
        print("[passive] Only passive checks are enabled; the scan ends after this stage.")
        return "end"
    return "analyze_apis"

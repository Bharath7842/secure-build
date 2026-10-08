"""Programmatic entry point for the DAST pipeline.

`app.py` (CLI) and `server.py` (Flask) drive the same graph interactively; this
module is what the FastAPI backend calls (`services/engine_adapter.run_dast_scan`).
It runs the graph over a `ScanRuntime` and condenses the final state into a JSON-safe
`discovery` dict (the same shape the frontend's DastDiscovery type expects).

The runtime (`app/dast/runtime.py`) brings every collaborator: the model gateway, the guarded
request executor, a browser factory (which launches Playwright only if a stage needs a browser)
and the credential holder. The engine never constructs a model client, an HTTP client or a
browser itself, and importing this module needs none of those packages.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any, Callable

from .url_utils import NOISE_QUERY_KEYS_DEFAULT

MAX_RUNTIME_MINUTES = 10
MAX_PER_PATTERN = 3


def _json_safe(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str))


MAX_INVENTORY_ENTRIES = 500  # endpoints listed in the persisted discovery summary


def _form_summaries(forms: list) -> list:
    """Forms as stored: names and types only. Default and hidden values (CSRF tokens) stay in memory."""
    out = []
    for form in _json_safe(forms):
        form["inputs"] = [{k: v for k, v in i.items() if k != "value"} for i in form.get("inputs") or []]
        out.append(form)
    return out


def build_discovery(target_url: str, state: dict) -> dict[str, Any]:
    """Condense the graph's final state into the persisted discovery dict."""
    pages = [
        {
            "url": p.get("url"),
            "depth": p.get("depth", 0),
            "title": p.get("title") or "",
            "forms": _form_summaries(p.get("forms") or []),
            "links_count": len(p.get("links") or []),
            "new_link_count": p.get("new_link_count", 0),
            "screenshot": p.get("screenshot"),
            **({"identity": p["identity"]} if p.get("identity") else {}),
        }
        for p in state.get("pages_data") or []
    ]
    api_analysis = _json_safe(state.get("api_analysis") or [])
    analysis_summary = {
        "apis_tested": len(api_analysis),
        "fail": sum(a.get("counts", {}).get("fail", 0) for a in api_analysis),
        "pass": sum(a.get("counts", {}).get("pass", 0) for a in api_analysis),
        "inconclusive": sum(a.get("counts", {}).get("inconclusive", 0) for a in api_analysis),
        "apis_failing": sum(1 for a in api_analysis if a.get("overall_verdict") == "FAIL"),
    }
    inventory = state.get("inventory")
    runtime = state.get("runtime")
    traffic = list(getattr(runtime, "traffic", None) or [])
    discovery = {
        "target_url": target_url,
        "connection_ok": bool(state.get("connection_ok")),
        "connection_error": state.get("connection_error") or "",
        "login_type": state.get("login_type") or "",
        "login_success": bool(state.get("login_success")),
        "login_error": state.get("login_error") or "",
        "stop_reason": state.get("stop_reason") or "",
        "crawl_stop_reason": state.get("crawl_stop_reason") or "",
        "pages": pages,
        "api_calls": _json_safe(state.get("api_calls") or []),
        "forms_count": sum(len(p["forms"]) for p in pages),
        "skipped_duplicate_patterns": _json_safe(state.get("skipped_duplicate_patterns") or []),
        "failed_urls": _json_safe(state.get("failed_urls") or []),
        "warnings": _json_safe(state.get("warnings") or []),
        "api_analysis": api_analysis,
        "analysis_summary": analysis_summary,
    }
    if state.get("passive_analysis"):
        discovery["passive_analysis"] = _json_safe(state["passive_analysis"])
    if state.get("active_testing"):
        discovery["active_testing"] = _json_safe(state["active_testing"])
        analysis_summary["tests_sent"] = state["active_testing"].get("tests_sent", 0)
    if state.get("browser_probe"):
        discovery["browser_probe"] = _json_safe(state["browser_probe"])
    if state.get("authorization"):
        discovery["authorization"] = _json_safe(state["authorization"])
    if state.get("fingerprint"):
        discovery["fingerprint"] = _json_safe(state["fingerprint"])
    if state.get("preflight"):
        discovery["preflight"] = _json_safe(state["preflight"])
    if inventory is not None:
        discovery["inventory"] = _json_safe(inventory.to_summary()[:MAX_INVENTORY_ENTRIES])
        discovery["inventory_count"] = len(inventory)
    if state.get("inventory_diff"):
        discovery["inventory_diff"] = _json_safe(state["inventory_diff"])
    if state.get("identity_results"):
        discovery["identities"] = _json_safe(state["identity_results"])
    if state.get("authentication_failed"):
        discovery["authentication_failed"] = state["authentication_failed"]
    if state.get("credentials_lost"):
        discovery["credentials_lost"] = True
        discovery["credentials_lost_reason"] = state.get("credentials_lost_reason") or ""
    if traffic:
        discovery["traffic"] = {
            "exchanges": len(traffic),
            "api_exchanges": sum(1 for t in traffic if not t.asset),
            "assets": sum(1 for t in traffic if t.asset),
        }
    skipped = getattr(runtime, "skipped_degraded", None)
    if skipped:
        discovery["skipped_degraded"] = _json_safe(skipped)
    return discovery


def run_dast_scan(
    *,
    runtime: Any,  # a `ScanRuntime` (app.dast.runtime): gateway, guarded executor, browser, credentials
    run_analysis: bool = True,
    discovery_writer: Callable[[dict], None] | None = None,
    findings_writer: Callable[[str, list[dict]], None] | None = None,
    should_abort: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Run the pipeline for one scan. Everything it touches (model, HTTP, browser, credentials)
    arrives in `runtime`; budgets come from `runtime.effective`, the scan's frozen settings."""
    from .graph import build_graph
    from .sessions import SessionStore
    from .state import make_initial_state

    eff = runtime.effective
    args = SimpleNamespace(
        url=runtime.target_url,
        login_url="",
        username="",
        password="",
        max_depth=int(eff.get("max_depth") or 3),
        max_pages=int(eff.get("max_pages") or 30),
        max_runtime_minutes=float(eff.get("max_runtime_minutes") or MAX_RUNTIME_MINUTES),
        max_per_pattern=int(eff.get("max_per_pattern") or MAX_PER_PATTERN),
        same_domain_mode=str(eff.get("same_domain_mode") or "exact"),
        storage_state=None,
        verbose=True,
        run_analysis=run_analysis,
        dast_max_apis=int(eff["max_targets"]) if eff.get("max_targets") else None,
        dast_max_tests_per_api=int(eff["max_tests_per_target"]) if eff.get("max_tests_per_target") else None,
        findings_writer=findings_writer or runtime.findings_writer,
        should_abort=should_abort,
        runtime=runtime,
        sessions=SessionStore(list(runtime.identities)),
    )
    noise_params = [p.strip() for p in NOISE_QUERY_KEYS_DEFAULT.split(",") if p.strip()]

    try:
        state = make_initial_state(args, runtime.gateway, noise_params)
        if discovery_writer is not None:
            runtime.publish_discovery = lambda st, _url=runtime.target_url, _write=discovery_writer: _write(
                build_discovery(_url, st)
            )
        final_state = build_graph().invoke(state)
    finally:
        if runtime.browser is not None:
            try:
                runtime.browser.close()
            except Exception:  # noqa: BLE001 - cleanup must not mask the scan's own outcome
                pass

    print("### DAST: finishing")
    discovery = build_discovery(runtime.target_url, final_state)
    summary = discovery["analysis_summary"]
    print(
        f"Pages: {len(discovery['pages'])}, forms: {discovery['forms_count']}, "
        f"API endpoints: {len(discovery['api_calls'])}, "
        f"APIs tested: {summary['apis_tested']} "
        f"({summary['fail']} failing, {summary['pass']} passed)"
    )
    if discovery_writer:
        discovery_writer(discovery)
    return {"discovery": discovery}

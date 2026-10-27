"""Builds the LangGraph pipeline from the node modules.

    check_connection -> fingerprint -> authenticate -> discover -> passive_analysis -> [plan_tests] -> analyze_apis -> browser_probe -> check_authorization -> END

* `check_connection` (the preflight) ends the run if the target is unreachable.
* `fingerprint` decides the target's shape, how it is authenticated and whether it publishes an
  API description; later stages run only what fits (an API-only target skips the browser crawl,
  token and saved-session identities skip form login).
* `authenticate` establishes one isolated session per identity; any failure ends the run naming
  the identity.
* `discover` crawls per identity, reads schemas and builds the inventory. If an identity's session
  is lost it routes back to `authenticate` once for that identity (`route_after_discover`), then
  resumes where it stopped.
* `passive_analysis` reads the recorded traffic (no requests, no model); with only passive checks
  enabled the scan ends there (`route_after_passive`).
* `plan_tests` optionally ranks existing endpoints/checks for bounded adaptive follow-ups; failures keep the flat loop.
* `analyze_apis` runs the active tests (the construct/validate/baseline/test/detect/rule loop).
* `browser_probe` types inert markers into crawled inputs and confirms reflected XSS in the browser.
* `check_authorization` replays what each identity reached as every other identity and Anonymous.
"""

from langgraph.graph import END, StateGraph

from .nodes.analyze_apis import analyze_apis
from .nodes.authenticate import authenticate, route_after_authenticate
from .nodes.browser_probe import browser_probe
from .nodes.check_authorization import check_authorization
from .nodes.check_connection import check_connection
from .nodes.discover import discover, route_after_discover
from .nodes.fingerprint import fingerprint
from .nodes.passive_analysis import passive_analysis, route_after_passive
from .nodes.plan_tests import plan_tests
from .domain.session import MAX_RELOGIN_ATTEMPTS  # noqa: F401  (the per-identity bound; see discover)
from .state import GraphState


def _with_banner(label: str | None, node):
    """Print a `### DAST: <label>` banner before the node runs, so the FastAPI
    log tail (scan_progress.PROGRESS_MARKERS / the frontend's step parser) can
    tell which phase the run is in. `label=None` leaves the banner to the node itself (discover
    prints `crawling` and `ingesting schemas` only for the work it actually does)."""

    def wrapped(state):
        if label:
            print(f"### DAST: {label}")
        return node(state)

    wrapped.__name__ = getattr(node, "__name__", label or "node")
    return wrapped


def route_entry(state: GraphState) -> str:
    """Every scan starts with the preflight. (A saved session used to skip straight to the crawl;
    it is now a pre-authenticated identity, handled by `authenticate`.)"""
    return "check_connection"


def route_after_check(state: GraphState) -> str:
    return "fingerprint" if state.get("connection_ok") else END


def route_after_active(state: GraphState) -> str:
    """Browser input probes follow the active tests unless the scan was cancelled."""
    runtime = state["runtime"]
    if runtime is not None and (runtime.cancelled() or state.get("stop_reason") == "cancelled"):
        return "end"
    return "browser_probe"


def route_after_browser(state: GraphState) -> str:
    """The authorization replays follow the browser probes unless the scan was cancelled."""
    runtime = state["runtime"]
    if runtime is not None and (runtime.cancelled() or state.get("stop_reason") == "cancelled"):
        return "end"
    return "check_authorization"


def build_graph():
    graph = StateGraph(GraphState)

    graph.add_node("check_connection", _with_banner("checking connection", check_connection))
    graph.add_node("fingerprint", _with_banner("fingerprinting", fingerprint))
    graph.add_node("authenticate", _with_banner("logging in", authenticate))
    graph.add_node("discover", _with_banner(None, discover))
    graph.add_node("passive_analysis", _with_banner("passive analysis", passive_analysis))
    graph.add_node("plan_tests", _with_banner("planning tests", plan_tests))
    graph.add_node("analyze_apis", _with_banner("testing apis", analyze_apis))
    graph.add_node("browser_probe", _with_banner("probing browser inputs", browser_probe))
    graph.add_node("check_authorization", _with_banner("checking authorization", check_authorization))

    graph.set_conditional_entry_point(route_entry, {"check_connection": "check_connection"})
    graph.add_conditional_edges("check_connection", route_after_check, {"fingerprint": "fingerprint", END: END})
    graph.add_edge("fingerprint", "authenticate")
    graph.add_conditional_edges("authenticate", route_after_authenticate, {"discover": "discover", "end": END})
    graph.add_conditional_edges(
        "discover", route_after_discover, {"authenticate": "authenticate", "passive_analysis": "passive_analysis", "end": END}
    )
    graph.add_conditional_edges("passive_analysis", route_after_passive, {"analyze_apis": "analyze_apis", "plan_tests": "plan_tests", "end": END})
    graph.add_edge("plan_tests", "analyze_apis")
    graph.add_conditional_edges("analyze_apis", route_after_active, {"browser_probe": "browser_probe", "end": END})
    graph.add_conditional_edges("browser_probe", route_after_browser, {"check_authorization": "check_authorization", "end": END})
    graph.add_edge("check_authorization", END)

    return graph.compile()

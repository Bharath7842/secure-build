"""NODE 4: discover (DAST-07-010 .. -060): build one deduplicated inventory of the target's
endpoints from a guarded browser crawl per identity, the traffic that crawl recorded, and the API
descriptions the target publishes; then say where observed and documented surface differ.

* The crawl runs once per authenticated identity (or once as Anonymous when there is none), each
  in that identity's own guarded browser context, sharing the page and time budgets evenly. An
  API-only target skips it entirely and never constructs a browser (`runtime.browser` stays unused).
* If an identity's session is lost mid-crawl, a form-login identity is sent back through
  `authenticate` once (the graph's bounded re-login hop) and its crawl resumes; any other identity,
  or a second loss, fails the scan with the reason, keeping what was gathered so far.
* Schema ingestion (OpenAPI, GraphQL introspection) and the observed-vs-documented diff run after
  the crawls.
"""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import urljoin

from ..domain.entities import EndpointSource, Location, Parameter
from ..domain.fingerprint import Fingerprint, routing_plan
from ..domain.identities import AuthMethod
from ..domain.inventory import Inventory, compare_observed_vs_documented, observed
from ..domain.ruleset import EffectiveRuleSet
from ..domain.session import DenialTracker, may_relogin, new_denials
from ..domain.traffic import parameters_from_body
from ..forced_browse import run_forced_browse
from ..inventory_findings import CHECK_ID, undocumented_findings
from ..js_harvest import harvest_scripts
from ..sessions import ANONYMOUS, PENDING, IdentitySession, SessionStore
from ..state import GraphState
from ..url_utils import NOISE_QUERY_KEYS_DEFAULT
from . import crawl as crawl_node
from . import ingest_schemas

DEFAULT_CRAWL_MINUTES = 10.0


# ---- which identities crawl, and with which browser state --------------------------------------


def crawl_identities(store: SessionStore) -> list[IdentitySession]:
    authenticated = store.authenticated()
    if authenticated:
        return authenticated
    return [s for s in store.all() if s.status == ANONYMOUS][:1]


def ensure_browser_session(runtime: Any, session: IdentitySession):
    """The identity's own guarded browser context, created on first use."""
    if session.browser_session is not None:
        return session.browser_session
    spec = session.spec
    storage_state = session.storage_state if spec.auth_method is AuthMethod.PREAUTH else None
    extra = {session.token_header[0]: session.token_header[1]} if spec.auth_method is AuthMethod.TOKEN and session.token_header else None
    session.browser_session = runtime.browser.new_session(spec, storage_state=storage_state, extra_headers=extra)
    if not session.start_url:
        session.start_url = runtime.target_url
    return session.browser_session


def _budgets(runtime: Any, crawlers: int) -> dict[str, Any]:
    eff = runtime.effective
    share = max(1, crawlers)
    return {
        "max_depth": int(eff.get("max_depth") or 3),
        "max_pages": max(1, int(eff.get("max_pages") or 30) // share),
        "max_runtime_minutes": max(0.5, float(eff.get("max_runtime_minutes") or DEFAULT_CRAWL_MINUTES) / share),
        "max_per_pattern": int(eff.get("max_per_pattern") or 3),
        "same_domain_mode": str(eff.get("same_domain_mode") or "exact"),
    }


def _fresh_crawl_state(base: GraphState, session: IdentitySession, page: Any, budgets: dict[str, Any]) -> dict[str, Any]:
    noise = [p.strip() for p in NOISE_QUERY_KEYS_DEFAULT.split(",") if p.strip()]
    return {
        "gateway": base["gateway"], "page": page, "browser": None, "verbose": base.get("verbose", True),
        # Carried through so visit_url() can namespace crawl screenshots under the scan's id
        # (state["runtime"].scan_id) — this sub-state is otherwise a fresh, narrow dict.
        "runtime": base.get("runtime"),
        "login_url": session.login_url if session.spec.auth_method is AuthMethod.FORM else "",
        "crawl_start_url": session.start_url or base["url"], "noise_params": noise,
        "visited": set(), "queue": [], "pattern_counts": {}, "pages_data": [], "skipped_duplicate_patterns": [],
        "api_calls": [], "failed_urls": [], "warnings": [], "crawl_stop_reason": "", "crawl_start_time": 0.0,
        "consecutive_low_value_visits": 0, "should_abort": base.get("should_abort"), "finished": False, **budgets,
    }


def _loss_checker(runtime: Any, identity_id: str, tracker: DenialTracker, cursor: dict[str, int]):
    """Feeds the identity's recorded responses to a `DenialTracker`; returns a reason once a run
    of refusals says the session is no longer accepted."""

    def check() -> str:
        reason, cursor[identity_id] = new_denials(runtime.traffic, identity_id, cursor.get(identity_id, 0), tracker)
        return reason

    return check


# ---- folding results into the inventory --------------------------------------------------------


def _form_endpoints(page_url: str, forms: list[dict], identity_id: str) -> list:
    out = []
    for form in forms or []:
        method = str(form.get("method") or "GET").upper()
        action = urljoin(page_url, str(form.get("action") or "")) or page_url
        location = Location.QUERY if method == "GET" else Location.BODY
        params = [
            Parameter(str(i["name"]), location, (str(i["value"]),) if i.get("value") else ())
            for i in form.get("inputs") or []
            if i.get("name")
        ]
        out.append(observed(method, action, identity_id=identity_id, parameters=params, kind="form"))
    return out


def fold_crawl_into_inventory(inventory: Inventory, sub: dict[str, Any], identity_id: str) -> None:
    for page in sub.get("pages_data") or []:
        url = page.get("url")
        if not url:
            continue
        inventory.add(observed("GET", url, identity_id=identity_id, kind="page", status=200, content_type="text/html"))
        for endpoint in _form_endpoints(url, page.get("forms") or [], identity_id):
            inventory.add(endpoint)
    for call in sub.get("api_calls") or []:
        inventory.add(
            observed(call.get("method") or "GET", call.get("url") or "", identity_id=identity_id, status=call.get("status_code"), content_type=call.get("content_type") or "", kind="api")
        )


def fold_traffic_into_inventory(inventory: Inventory, traffic: list) -> None:
    """Real request shapes from the recorder: bodies become samples, their fields become parameters."""
    for exchange in traffic:
        if exchange.asset:
            continue
        params = [Parameter(name, Location.BODY, (value,) if value else ()) for name, value in parameters_from_body(exchange.request_body, next((v for k, v in (exchange.request_headers or {}).items() if str(k).lower() == "content-type"), ""))]
        kind = "api" if exchange.resource_type in ("xhr", "fetch") else None
        inventory.add(
            observed(exchange.method, exchange.url, identity_id=exchange.identity_id or None, parameters=params, body_sample=exchange.request_body, status=exchange.status, content_type=exchange.content_type, kind=kind)
        )


def schema_endpoints_as_api_calls(inventory: Inventory) -> list[dict[str, Any]]:
    """Documented operations nothing observed, as targets for the API analysis stage (an API-only
    target would otherwise have none). Path placeholders get a neutral sample value."""
    calls = []
    for endpoint in inventory.only(EndpointSource.SCHEMA):
        if not endpoint.url or "#" in endpoint.path_template:
            continue
        import re

        url = re.sub(r"\{[^{}]*\}", "1", endpoint.url)
        calls.append({"method": endpoint.method, "url": url, "status_code": None, "content_type": "application/json", "source": "schema"})
    return calls


# ---- the node ---------------------------------------------------------------------------------


def _rule_check_enabled(runtime: Any, check_id: str):
    rule_set: EffectiveRuleSet | None = runtime.rule_set
    if rule_set is None:
        return None
    effective = rule_set.get(check_id)
    return effective.check if effective is not None and effective.enabled else None


def _fail(state: GraphState, message: str) -> GraphState:
    state["authentication_failed"] = message
    state["stop_reason"] = "authentication_failed"
    print(f"[4/4] FAILED: {message}")
    return state


def discover(state: GraphState) -> GraphState:
    runtime, store = state["runtime"], state["sessions"]
    fingerprint = Fingerprint(**{k: v for k, v in (state.get("fingerprint") or {}).items() if k in ("shape", "auth", "schema", "source", "schema_url")}) if state.get("fingerprint") else Fingerprint("mpa", "none", "none")
    plan = routing_plan(fingerprint, runtime.identities)
    if state.get("inventory") is None:
        state["inventory"] = Inventory()
    inventory: Inventory = state["inventory"]
    crawlers = crawl_identities(store)
    budgets = _budgets(runtime, len(crawlers))

    if plan["browser_crawl"] and runtime.browser is not None:
        print("### DAST: crawling")
        for session in crawlers:
            if runtime.cancelled():
                state["crawl_stop_reason"] = "cancelled"
                state["stop_reason"] = "cancelled"
                return state
            progress = state["crawl_progress"].get(session.spec.identity_id)
            if progress and progress.get("finished"):
                continue
            browser_session = ensure_browser_session(runtime, session)
            sub = progress or _fresh_crawl_state(state, session, browser_session.page, budgets)
            sub["page"] = browser_session.page  # a re-login hands the identity a new page
            tracker = DenialTracker()
            sub["session_lost_check"] = _loss_checker(runtime, session.spec.identity_id, tracker, state["traffic_cursor"])
            print(f"[4/4] Crawling as {session.label!r} ({session.spec.role_display}), up to {sub['max_pages']} pages...")
            crawl_node.crawl(sub)
            state["crawl_progress"][session.spec.identity_id] = sub
            stop = sub.get("crawl_stop_reason")
            if stop == "session_lost":
                identity_id = session.spec.identity_id
                reason = next((w["details"] for w in reversed(sub.get("warnings") or []) if w.get("event") == "session_lost"), "the session was lost")
                can_retry = session.spec.auth_method is AuthMethod.FORM and may_relogin(state["relogin_counts"], identity_id)
                if can_retry:
                    state["relogin_counts"][identity_id] = state["relogin_counts"].get(identity_id, 0) + 1
                    session.relogin_count = state["relogin_counts"][identity_id]
                    session.status = PENDING
                    state["relogin_requested"] = [identity_id]
                    sub["crawl_stop_reason"] = ""
                    print(f"[4/4] The session for {session.label!r} was lost ({reason}); signing in again once.")
                    return state
                why = "the session was lost again after signing in again" if session.relogin_count else ("its saved credentials cannot be refreshed" if session.spec.auth_method is not AuthMethod.FORM else "the session was lost")
                return _fail(state, f"Identity {session.label!r}: {why} ({reason}); the scan stopped rather than continue without it")
            sub["finished"] = True
            fold_crawl_into_inventory(inventory, sub, session.spec.identity_id)
            state["pages_data"].extend(dict(p, identity=session.label) for p in sub.get("pages_data") or [])
            seen = {(c["method"], c["url"]) for c in state["api_calls"]}
            state["api_calls"].extend(c for c in sub.get("api_calls") or [] if (c["method"], c["url"]) not in seen)
            state["failed_urls"].extend(sub.get("failed_urls") or [])
            state["warnings"].extend(sub.get("warnings") or [])
            state["skipped_duplicate_patterns"].extend(sub.get("skipped_duplicate_patterns") or [])
            state["crawl_stop_reason"] = stop or state.get("crawl_stop_reason") or ""
            runtime.counters.set("pages", len(state["pages_data"]))
            runtime.counters.set("endpoints", len(inventory))
        fold_traffic_into_inventory(inventory, runtime.traffic)
    elif plan["browser_crawl"]:
        print("[4/4] No browser is available for this scan; skipping the crawl.")
    else:
        print("[4/4] The target looks like an API: skipping the browser crawl and reading its schema instead.")

    if state.get("stop_reason") == "cancelled" or runtime.cancelled():
        state["stop_reason"] = "cancelled"
        return state

    ingested = 0
    schema_wanted = plan["schema_ingestion"] or ingest_schemas.should_probe_graphql(state)
    if schema_wanted:
        print("### DAST: importing schemas")
        ingested += ingest_schemas.ingest_openapi(state)
        if ingest_schemas.should_probe_graphql(state) and not runtime.cancelled():
            ingested += ingest_schemas.ingest_graphql(state)
        if ingested == 0:
            print("    No API description could be read.")

    diff = compare_observed_vs_documented(inventory, schema_found=ingested > 0)
    state["inventory_diff"] = diff.to_dict()
    if diff.compared:
        print(f"    Inventory diff: {len(diff.undocumented)} undocumented endpoint(s), {len(diff.unexercised)} documented but never exercised.")
        check = _rule_check_enabled(runtime, CHECK_ID)
        if check is not None and diff.undocumented and runtime.findings_writer is not None:
            runtime.findings_writer("inventory", undocumented_findings(diff, check))
    else:
        print(f"    Inventory diff skipped: {diff.reason}.")

    seen = {(c["method"], c["url"]) for c in state["api_calls"]}
    state["api_calls"].extend(c for c in schema_endpoints_as_api_calls(inventory) if (c["method"], c["url"]) not in seen)
    state["identity_results"] = [s.public() for s in store.all()]
    runtime.counters.set("pages", len(state["pages_data"]))
    runtime.counters.set("endpoints", len(inventory))
    root = state.get("root_response")
    root_body = getattr(root, "body_excerpt", "") or ""
    try:
        run_forced_browse(state, runtime, state["url"], root_body)
    except Exception as exc:  # noqa: BLE001
        print(f"    Hidden-path probe skipped: {exc}")
    try:
        harvest_scripts(state, runtime)
    except Exception as exc:  # noqa: BLE001
        print(f"    Script harvest skipped: {exc}")
    runtime.counters.set("endpoints", len(inventory))
    print(f"[4/4] Discovery finished: {len(inventory)} endpoint(s) in the inventory.")
    return state


def route_after_discover(state: GraphState) -> str:
    """Back to `authenticate` once for an identity whose session was lost, else on to the analysis
    (or END when the scan has already failed or been cancelled)."""
    if state.get("relogin_requested"):
        return "authenticate"
    if state.get("authentication_failed") or state.get("stop_reason") == "cancelled":
        return "end"
    return "passive_analysis"

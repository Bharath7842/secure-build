"""NODE: browser_probe — type inert markers into the pages discovery already found.

Runs after the HTTP active tests and before authorization. It reuses each identity's guarded
browser context (the crawl already created it, with the recorder and the safety guard attached).
Stored-XSS submits go through the guard's marker window, which allows a POST only when the scan
opted in, the target is disposable, and the body is nothing but this scan's marker.

The verdict never comes from the model: a finding is confirmed only when the marker executes.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from ..browser_probe import PlaywrightProbeDriver, reflected_hits, run_probes, synthetic_checks
from ..domain.browser_probe import MarkerFactory, new_token
from ..input_gate import InputGate
from ..state import GraphState
from .discover import ensure_browser_session

DEFAULT_MAX_INPUTS = 4


def _checks(runtime: Any) -> dict[str, Any]:
    rule_set = getattr(runtime, "rule_set", None)
    if rule_set is None:
        return synthetic_checks()
    wanted = ("dast-xss-dom", "dast-xss", "dast-xss-stored")
    return {ec.check_id: ec for ec in rule_set.enabled_checks() if ec.check_id in wanted}


def _driver_for(runtime: Any, page: Any):
    factory = getattr(runtime, "probe_driver_factory", None)
    if factory is not None:
        return factory(page)
    return PlaywrightProbeDriver(page)


def browser_probe(state: GraphState) -> GraphState:
    state["browser_probe"] = {}
    runtime = state.get("runtime")
    if runtime is None:
        print("[browser] No scan runtime — skipping browser input probes.")
        return state
    if runtime.cancelled() or state.get("stop_reason") == "cancelled":
        state["stop_reason"] = "cancelled"
        return state
    effective = getattr(runtime, "effective", None) or {}
    if not bool(effective.get("browser_probe_enabled", True)):
        print("[browser] Browser input probing is off for this scan.")
        state["browser_probe"] = {"skipped": "disabled", "probes": 0, "findings": 0}
        return state
    if runtime.browser is None:
        print("[browser] No browser for this scan — skipping input probes.")
        state["browser_probe"] = {"skipped": "no browser", "probes": 0, "findings": 0}
        return state

    checks = _checks(runtime)
    store = state.get("sessions")
    pages = [p for p in (state.get("pages_data") or []) if p.get("url")]
    reflected = reflected_hits(state.get("api_analysis") or [])
    if not pages and not reflected:
        print("[browser] Nothing was crawled and no reflected XSS to confirm.")
        state["browser_probe"] = {"skipped": "nothing to probe", "probes": 0, "findings": 0}
        return state
    if not checks:
        print("[browser] No browser XSS check is enabled.")
        state["browser_probe"] = {"skipped": "no browser check is enabled", "probes": 0, "findings": 0}
        return report_state(state, {"skipped": "no browser check is enabled", "probes": 0, "findings": 0})

    identities = []
    if store is not None:
        identities = [s for s in store.usable() if s.browser_session is not None or pages]
    if not identities and store is not None:
        identities = store.usable()[:1]
    if not identities:
        print("[browser] No identity to probe as.")
        return report_state(state, {"skipped": "no identity", "probes": 0, "findings": 0})

    allow_stored = bool(effective.get("browser_marker_posts", False)) and "dast-xss-stored" in checks
    max_pages = int(effective.get("max_targets") or 15)
    max_inputs = int(effective.get("browser_probe_max_inputs") or DEFAULT_MAX_INPUTS)
    secrets = list(runtime.credentials.secrets()) if getattr(runtime, "credentials", None) is not None and hasattr(runtime.credentials, "secrets") else []
    allowed = {(urlsplit(runtime.target_url).hostname or "").lower()}
    gate = InputGate(safe_mode=True, allow_state_changing=False, allowed_hosts=allowed, log=print)
    factory = MarkerFactory(new_token())
    window = getattr(runtime, "marker_window", None) or (lambda token: _null())

    totals = {"probes": 0, "marker_submits": 0, "executed": 0, "findings": 0, "skipped": ""}
    writer = state.get("findings_writer") or runtime.findings_writer
    print(f"[browser] Probing up to {min(len(pages), max_pages)} page(s), {max_inputs} input(s) each"
          + (" (stored submits enabled)" if allow_stored else "") + "...")
    for session in identities:
        if runtime.cancelled():
            state["stop_reason"] = "cancelled"
            break
        try:
            browser_session = session.browser_session or ensure_browser_session(runtime, session)
        except Exception as exc:  # noqa: BLE001
            print(f"    [browser] could not open a browser for {session.label!r}: {exc}")
            continue
        page = getattr(browser_session, "page", None)
        if page is None:
            continue
        # One identity's pages: the crawl tags them, and an untagged page belongs to every identity
        # only for the first (anonymous) pass. Prefer this identity's own pages when tagged.
        own = [p for p in pages if not p.get("identity") or p.get("identity") == session.label]
        try:
            report = run_probes(
                pages=own or pages, reflected=reflected, driver=_driver_for(runtime, page), factory=factory,
                checks=checks, marker_window=window, allow_stored=allow_stored, gate=gate,
                max_pages=max_pages, max_inputs=max_inputs, secrets=secrets, cancelled=runtime.cancelled, log=print,
            )
        except Exception as exc:  # noqa: BLE001 - a probe failure must not discard the HTTP findings already stored
            print(f"    [browser] probing stopped: {exc}")
            continue
        for key in ("probes", "marker_submits", "executed", "findings"):
            totals[key] += int(report.summary.get(key) or 0)
        if report.rows and writer:
            try:
                writer(f"browser probe ({session.label})", report.rows)
            except Exception as exc:  # noqa: BLE001
                print(f"    [browser] could not persist findings: {exc}")
        reflected = []  # confirm each HTTP hit once, as the first identity
        if not any(p.get("identity") for p in pages):
            break  # untagged pages belong to a single pass
    runtime.counters.set("browser_inputs", totals["probes"])
    return report_state(state, totals)


def report_state(state: GraphState, summary: dict) -> GraphState:
    state["browser_probe"] = summary
    return state


class _null:
    def __enter__(self):
        return None

    def __exit__(self, *exc):
        return False

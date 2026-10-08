"""NODE 1: check_connection (the preflight stage, DAST-05-030): confirm the target is reachable
and in scope before anything else, with a specific reason when it is not.

With a runtime (every scan started through the API) the check is one request made through the
guarded executor, so it is scope-checked, rate-limited, cancel-checked and audited like every
other. A failure ends the scan: the graph routes to END and no further request is sent. Without a
runtime (only the legacy standalone entry points before they were migrated) the old browser
`page.goto` check still works.
"""

from ..connection_recon import run_connection_recon
from ..domain.preflight import evaluate_preflight
from ..llm_utils import print_snippet
from ..sessions import SessionStore, anonymous_id
from ..state import GraphState
from ..tls_probe import finding_rows as tls_finding_rows, run_tls_probe, tls_checks


def _run_tls_probe(state: GraphState, runtime, url: str) -> None:
    """A one-time TLS posture check at the target's own host (see `tls_probe.py` for why this is
    safe outside the guarded executor). Never affects `connection_ok`: a probe-only concern is
    reported as findings, not a reason to stop the scan."""
    try:
        outcome = run_tls_probe(url)
    except Exception as exc:  # noqa: BLE001 - this probe must never crash the scan
        print(f"    TLS check skipped: {exc}")
        return
    if not outcome.ran:
        return
    if outcome.probe_error:
        print(f"    TLS check: could not re-connect to inspect the certificate ({outcome.probe_error}); skipping.")
        state["tls"] = {"host": outcome.host, "port": outcome.port, "probe_error": outcome.probe_error}
        return
    state["tls"] = {
        "host": outcome.host, "port": outcome.port, "protocol": outcome.protocol, "cipher": outcome.cipher,
        "not_after": outcome.not_after, "issues": [f.signal for f in outcome.findings],
    }
    if not outcome.findings:
        print(f"    TLS check: {outcome.protocol or 'unknown protocol'}, no issues found.")
        return
    print(f"    TLS check: {len(outcome.findings)} issue(s) found ({', '.join(f.signal for f in outcome.findings)}).")
    checks = tls_checks(runtime.rule_set, runtime.skipped_degraded)
    secrets = (lambda: runtime.credentials.secrets()) if runtime.credentials is not None and hasattr(runtime.credentials, "secrets") else (lambda: [])
    rows = tls_finding_rows(outcome, checks, secrets())
    writer = state.get("findings_writer") or runtime.findings_writer
    if rows and writer:
        try:
            writer("tls probe", rows)
        except Exception as exc:  # noqa: BLE001 - a storage hiccup must not stop the scan
            print(f"    Could not persist TLS findings: {exc}")


def _preflight_with_executor(state: GraphState) -> GraphState:
    runtime = state["runtime"]
    store: SessionStore = state["sessions"]
    url = state["url"]
    print(f"[1/4] Checking connection to {url} ...")
    anon = anonymous_id(store)
    decision = store.send(runtime.executor, anon, "GET", url)
    response = decision.response
    location = ""
    if response is not None:
        location = next((v for k, v in (response.headers or {}).items() if str(k).lower() == "location"), "")
    result = evaluate_preflight(
        url,
        status=response.status if response is not None else None,
        error=decision.error,
        error_detail=decision.error_detail,
        deny_reason=decision.deny_reason,
        redirect_location=location,
    )
    state["root_response"] = response
    state["preflight"] = {"outcome": result.outcome, "message": result.message, "status": result.status, "note": result.note}
    if result.ok:
        state["connection_ok"] = True
        print(f"[1/4] OK ({result.message}{'; ' + result.note if result.note else ''})")
        if anon and response is not None:
            store.note_document(anon, getattr(response, "body_excerpt", "") or "")
        _run_tls_probe(state, runtime, url)
        try:
            run_connection_recon(state, runtime, url, response)
        except Exception as exc:  # noqa: BLE001 - recon must not fail an otherwise reachable target
            print(f"    Connection recon skipped: {exc}")
    else:
        state["connection_ok"] = False
        state["connection_error"] = result.message
        state["stop_reason"] = "cancelled" if result.outcome == "cancelled" else "connection_failed"
        print(f"[1/4] FAILED: {result.message}")
    return state


def _preflight_with_page(state: GraphState) -> GraphState:
    verbose = state.get("verbose", True)
    print(f"[1/4] Checking connection to {state['url']} ...")
    print(f"    Executing: page.goto('{state['url']}')")
    try:
        response = state["page"].goto(state["url"], timeout=10_000)
        status = response.status if response else None
        if response is not None and status < 400:
            title = state["page"].title()
            final_url = state["page"].url
            print(f"[1/4] OK (title: '{title}', status {status}, url: {final_url})")
            try:
                print_snippet("HTML received", state["page"].content(), verbose)
            except Exception:  # noqa: BLE001
                pass
            state["connection_ok"] = True
        else:
            state["connection_ok"] = False
            state["connection_error"] = f"HTTP status {status}"
            state["stop_reason"] = "connection_failed"
            print(f"[1/4] FAILED: received status {status}")
    except Exception as exc:  # noqa: BLE001
        state["connection_ok"] = False
        state["connection_error"] = str(exc)
        state["stop_reason"] = "connection_failed"
        print(f"[1/4] FAILED: {exc}")
    return state


def check_connection(state: GraphState) -> GraphState:
    if state.get("runtime") is not None:
        return _preflight_with_executor(state)
    return _preflight_with_page(state)

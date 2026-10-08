"""NODE 5: analyze_apis (the stage banner stays `### DAST: testing apis`) - active testing.

The stage shell for the construct -> validate -> baseline -> test -> detect -> rule -> roll-up loop
(`app/dast/active.py`): it picks the targets from the endpoint inventory, enforces the caps from the
scan's effective settings, writes findings as each target finishes, records what was tested, dropped
and left untested, and lists the assist-only checks as review items. Requests go through the guarded
executor as one identity; the model only proposes inputs and advises on verdicts.
"""

from __future__ import annotations

from ..active import DefaultSteps, analysis_record, finding_rows, loop_checks, run_stage, summarize
from ..assist import review_rows
from ..domain.entities import Endpoint
from ..domain.inventory import observed
from ..domain.session import DenialTracker, may_relogin
from ..input_gate import InputGate
from ..ssrf import run_ssrf, ssrf_check
from ..state import GraphState
from .authenticate import authenticate_identity

DEFAULT_MAX_TARGETS = 15
DEFAULT_MAX_TESTS_PER_TARGET = 12


def _endpoints(state: GraphState) -> list[Endpoint]:
    inventory = state.get("inventory")
    if inventory is not None:
        return inventory.endpoints()
    return [observed(c.get("method") or "GET", c.get("url") or "", status=c.get("status_code"), content_type=c.get("content_type") or "", kind="api") for c in state.get("api_calls") or [] if c.get("url")]


def analyze_apis(state: GraphState) -> GraphState:
    state.setdefault("api_analysis", [])
    state["active_testing"] = {}
    if not state.get("run_analysis", True):
        print("\n[5/5] API security analysis disabled — skipping.")
        return state
    runtime = state.get("runtime")
    if runtime is None:
        print("\n[5/5] No scan runtime — cannot run API security analysis.")
        return state
    if runtime.cancelled():
        state["stop_reason"] = "cancelled"
        return state

    effective = runtime.effective
    store = state["sessions"]
    usable = store.usable()
    if not usable:
        print("\n[5/5] No usable identity to test as — skipping the active tests.")
        return state
    checks = loop_checks(runtime.rule_set, runtime.skipped_degraded)
    max_targets = int(state.get("dast_max_apis") or effective.get("max_targets") or DEFAULT_MAX_TARGETS)
    max_tests = int(state.get("dast_max_tests_per_api") or effective.get("max_tests_per_target") or DEFAULT_MAX_TESTS_PER_TARGET)
    allow_state_changing = bool(effective.get("allow_state_changing", False))
    # `model_parallelism` (1-8, DastInput/presets-validated) is how many endpoints run at once;
    # each endpoint's own construct/baseline/test/rule sequence stays in order within its thread.
    # The guarded executor's own semaphore (`max_concurrent_requests`) still caps in-flight HTTP
    # sends underneath this, independent of how many endpoints are in flight here.
    workers = max(1, int(effective.get("model_parallelism") or 1))
    secrets = (lambda: runtime.credentials.secrets()) if runtime.credentials is not None and hasattr(runtime.credentials, "secrets") else (lambda: [])
    endpoints = _endpoints(state)
    writer = state.get("findings_writer") or runtime.findings_writer

    concurrency_note = f"up to {workers} at a time" if workers > 1 else "one at a time"
    print(f"\n[5/5] Testing up to {max_targets} endpoint(s) ({concurrency_note}), up to {max_tests} test(s) each, {len(checks)} check(s) enabled...")
    if not checks:
        print("    No active check is enabled for this scan; nothing to test.")
    from urllib.parse import urlsplit

    # An input may name the target or the configured out-of-band host, and nothing else.
    allowed_hosts = {(urlsplit(runtime.target_url).hostname or "").lower()}
    if getattr(runtime, "oast", None) is not None and getattr(runtime.oast, "host", ""):
        allowed_hosts.add(runtime.oast.host)
    steps = DefaultSteps(
        gateway=state["gateway"], executor=runtime.executor, store=store, identity_id=usable[0].spec.identity_id,
        gate=InputGate(safe_mode=not allow_state_changing, allow_state_changing=allow_state_changing, allowed_hosts=allowed_hosts, log=print),
        checks=checks, allow_state_changing=allow_state_changing, secrets=secrets,
        opt_in_ceiling=int(effective.get("opt_in_request_ceiling") or 30),
    )
    records: list[dict] = []
    identity_id = usable[0].spec.identity_id
    denial_tracker = DenialTracker()
    session_lost_reason = {"v": ""}

    def note_exchange(exchange) -> None:
        # Fed from the active loop's own responses, not `runtime.traffic` (which only the browser
        # crawl populates) - the HTTP-only active-testing stage has no other way to see this.
        if exchange is not None and exchange.status is not None and denial_tracker.observe(exchange.status):
            session_lost_reason["v"] = session_lost_reason["v"] or "the server keeps refusing this identity's requests (401/403)"

    def session_lost() -> str:
        return session_lost_reason["v"]

    def on_outcome(outcome) -> None:
        for record in outcome.records:
            note_exchange(record.baseline)
            note_exchange(record.result)
        if outcome.error:
            state.setdefault("warnings", []).append({"event": "api_analysis_failed", "details": f"{outcome.label}: {outcome.error}"})
        runtime.counters.add("tests", outcome.tests_sent)
        record = analysis_record(outcome, checks, secrets())
        if record is not None:
            records.append(record)
            state.setdefault("api_analysis", []).append(record)
            counts = record["counts"]
            print(f"    {outcome.label}: overall {record['overall_verdict']} ({counts['fail']} fail, {counts['pass']} pass)")
            publish = getattr(runtime, "publish_discovery", None)
            if callable(publish):
                try:
                    publish(state)
                except Exception as exc:  # noqa: BLE001 - live UI must not stop the scan
                    print(f"    Could not publish live results for {outcome.label}: {exc}")
        elif outcome.skipped and outcome.skipped != "cancelled":
            print(f"    {outcome.label}: {outcome.skipped}")
        if runtime.training_capture is not None:
            try:
                runtime.training_capture(outcome, checks)
            except Exception as exc:  # noqa: BLE001 - capture must never affect the scan
                print(f"    Training-data capture skipped for {outcome.label}: {type(exc).__name__}")
        rows = finding_rows(outcome, checks, secrets())
        if rows and writer:
            try:
                writer(outcome.label, rows)
            except Exception as exc:  # noqa: BLE001 - a storage hiccup must not stop the scan
                print(f"    Could not persist findings for {outcome.label}: {exc}")

    # Up to `workers` endpoints at once (from `model_parallelism`); `on_outcome` still runs only
    # on the calling thread, in target order, regardless of how many workers are running.
    def run_once(target_endpoints):
        return run_stage(
            target_endpoints, steps, max_targets=max_targets, max_tests=max_tests, cancelled=runtime.cancelled, log=print,
            workers=workers, task_log=runtime.task_log, on_outcome=on_outcome, session_lost=session_lost,
        )

    result = run_once(endpoints)
    if result.session_lost_reason:
        identity_spec = usable[0].spec
        label = identity_spec.label
        if not may_relogin(state["relogin_counts"], identity_id):
            print(f"    Session for {label!r} was lost; already retried once this scan, not retrying again.")
        else:
            secret = runtime.credentials.read(identity_id) if runtime.credentials is not None else None
            state["relogin_counts"][identity_id] = state["relogin_counts"].get(identity_id, 0) + 1
            if secret is None:
                print(f"    Session for {label!r} was lost and its credentials are no longer available to retry.")
            else:
                ok, reason = authenticate_identity(state, identity_spec, dict(secret))
                if not ok:
                    print(f"    Session for {label!r} was lost and could not be re-established: {reason}.")
                else:
                    store.mark_authenticated(identity_id)
                    untested = [o.endpoint for o in result.outcomes if o.skipped == "not tested: session lost mid-scan"]
                    result.outcomes = [o for o in result.outcomes if o.skipped != "not tested: session lost mid-scan"]
                    denial_tracker.reset()
                    session_lost_reason["v"] = ""
                    print(f"    Session for {label!r} was lost; signed in again and resuming {len(untested)} untested endpoint(s).")
                    resumed = run_once(untested)
                    result.outcomes.extend(resumed.outcomes)
                    result.session_lost_reason = resumed.session_lost_reason
    summary = summarize(result, records)
    state["active_testing"] = summary

    items = review_rows(endpoints, runtime.rule_set, runtime.skipped_degraded)
    if items:
        print(f"    {len(items)} item(s) listed for human review (assist-only checks; nothing was tested).")
        summary["review_items"] = len(items)
        if writer:
            try:
                writer("review items", items)
            except Exception as exc:  # noqa: BLE001
                print(f"    Could not persist the review items: {exc}")

    ssrf = ssrf_check(runtime.rule_set, runtime.skipped_degraded)
    if ssrf is not None and getattr(runtime, "oast", None) is not None and not result.cancelled:
        print("    SSRF: sending unique out-of-band callback addresses to URL-accepting parameters...")
        run = run_ssrf(
            endpoints, oast=runtime.oast, check=ssrf, steps=steps, max_tests=max_tests, wait_s=float(effective.get("oast_wait_s") or 5.0),
            secrets=secrets(), cancelled=runtime.cancelled, log=print,
        )
        summary["ssrf"] = {"tests": run.tests, "confirmed": run.confirmed}
        summary["tests_sent"] += run.tests
        if run.rows and writer:
            try:
                writer("ssrf", run.rows)
            except Exception as exc:  # noqa: BLE001
                print(f"    Could not persist the SSRF findings: {exc}")
        result.cancelled = result.cancelled or run.cancelled
    elif getattr(runtime, "oast", None) is None and runtime.rule_set is not None and (ec := runtime.rule_set.get("dast-ssrf")) is not None and ec.enabled:
        summary["ssrf"] = {"tests": 0, "confirmed": 0, "reason": "no OAST address is configured; SSRF is assist-only"}
    if result.cancelled:
        state["stop_reason"] = "cancelled"
    total_fail = sum(r["counts"]["fail"] for r in records)
    total_pass = sum(r["counts"]["pass"] for r in records)
    print(
        f"\n[5/5] API security analysis finished: {len(records)} endpoint(s) tested, {summary['tests_sent']} test(s) sent, "
        f"{total_fail} failing check(s), {total_pass} passed."
    )
    return state

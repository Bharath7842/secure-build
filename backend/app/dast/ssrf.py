"""SSRF with out-of-band confirmation (DAST-09-060).

For every URL-accepting parameter of a target, send the target a unique callback address and wait,
a bounded time, for the collaborator to see it called. A callback is the only proof this check
accepts: no callback, no finding. With no collaborator configured the check never runs a test (the
scan setup already marked it `assist-only`, and `assist.py` lists the parameters for review).

The request carrying the address is validated like any other test input and sent through the guarded
executor as the scan's primary identity; polling the collaborator is the one thing that bypasses the
scope check (see `app/services/oast.py`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Sequence

from .assist import load_heuristics
from .domain.active import Exchange, TargetOutcome, TestRecord, build_request, order_targets, target_label
from .domain.catalog import standards_for
from .domain.entities import CheckVerdict, DetectorSignal, Endpoint, Location
from .domain.guardrail import apply_guardrail
from .domain.oast import SIGNAL, OastCollaborator, confirms
from .domain.ruleset import EffectiveCheck, EffectiveRuleSet

CHECK_ID = "dast-ssrf"
DEFAULT_WAIT_S = 5.0


def url_parameters(endpoint: Endpoint) -> list[tuple[str, str]]:
    """`(name, location)` of every parameter that looks like it takes a URL: a conventional name, or
    an observed value that is one."""
    names = {n.lower() for n in load_heuristics().get("url_parameter_names", ())}
    out = []
    for param in endpoint.parameters:
        if param.location in (Location.QUERY, Location.BODY) and (
            param.name.lower() in names or any(v.startswith(("http://", "https://")) for v in param.observed_values)
        ):
            out.append((param.name, param.location.value))
    return out


def ssrf_check(rule_set: EffectiveRuleSet | None, skipped: Iterable[dict[str, Any]] = ()) -> EffectiveCheck | None:
    """The SSRF check if it should run tests: enabled, automated, and not skipped or downgraded."""
    if rule_set is None:
        return None
    ec = rule_set.get(CHECK_ID)
    if ec is None or not ec.enabled or ec.mode.value == "assist-only":
        return None
    if any(s.get("check_id") == CHECK_ID and (s.get("status") == "skipped" or s.get("effective_mode") == "assist-only") for s in skipped):
        return None
    return ec


@dataclass
class SsrfRun:
    outcomes: list[TargetOutcome] = field(default_factory=list)
    rows: list[dict[str, Any]] = field(default_factory=list)
    tests: int = 0
    confirmed: int = 0
    cancelled: bool = False


def run_ssrf(
    endpoints: Iterable[Endpoint],
    *,
    oast: OastCollaborator,
    check: EffectiveCheck,
    steps: Any,  # an active.DefaultSteps: its gate, executor and session store send the test
    max_tests: int,
    wait_s: float = DEFAULT_WAIT_S,
    secrets: Sequence[str] = (),
    cancelled: Callable[[], bool] = lambda: False,
    log: Callable[[str], None] = print,
) -> SsrfRun:
    from .active import finding_rows  # local: active imports nothing from here

    run = SsrfRun()
    checks = {check.check_id: check}
    for endpoint in order_targets(endpoints):
        if endpoint.state_changing and not steps.allow_state_changing:
            continue
        for name, location in url_parameters(endpoint):
            if run.tests >= max_tests:
                log(f"    SSRF: reached the cap of {max_tests} test(s); remaining URL parameters were not tested.")
                return run
            if cancelled():
                run.cancelled = True
                return run
            token = oast.new_token(f"{target_label(endpoint)}|{name}")
            test = steps.gate.validate(method=endpoint.method, check_id=CHECK_ID, parameter=name, location=location, value=token.url, expected_signal="out-of-band callback")
            if test is None:
                continue
            run.tests += 1
            result = steps._send(build_request(endpoint, test), CHECK_ID)  # noqa: SLF001 - the same guarded send as every other test
            record = TestRecord(CHECK_ID, name, location, token.url, "out-of-band callback", result=result)
            outcome = TargetOutcome(target_label(endpoint), endpoint, [record])
            callbacks = confirms(token, oast.poll(token, wait_s=wait_s)) if result.sent else []
            signals = (DetectorSignal(SIGNAL, f"the target requested {token.url} ({callbacks[0].source or 'source unknown'})"),) if callbacks else ()
            record.signals = signals
            record.outcome = apply_guardrail(CheckVerdict.FAIL if callbacks else CheckVerdict.PASS, signals, check.check.detector_signals)
            outcome.verdict = record.outcome.verdict
            log(f"    SSRF {outcome.label} {name!r}: {'callback received' if callbacks else 'no callback'}")
            if callbacks:
                run.confirmed += 1
                run.rows.extend(finding_rows(outcome, checks, secrets))
            run.outcomes.append(outcome)
    return run

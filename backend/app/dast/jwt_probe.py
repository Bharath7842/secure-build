"""Deterministic JWT replays: one observed read, at most one probe per weakness/identity.

Only the selected JWT authenticates these isolated sessions. A denied anonymous control and a
successful real-token baseline are required; another cookie or a public page cannot prove a JWT
weakness. Never retain bodies, headers, tokens or key material in findings or prompts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Sequence

from .domain.active import target_label
from .domain.authz import replayable
from .domain.catalog import standards_for
from .domain.detectors import auth_boundary_crossed
from .domain.entities import CheckVerdict, Confidence, DetectorSignal, Endpoint, Evidence, Finding, Location
from .domain.guardrail import apply_guardrail
from .domain.jwt_check import decode_token, modified_token, weak_hmac_secret
from .domain.mapping import finding_to_row
from .domain.redaction import redact_text
from .sessions import SessionStore

CHECKS = {
    "dast-jwt-alg-none": ("alg-none", "jwt_alg_none_accepted"),
    "dast-jwt-weak-secret": ("weak-secret", "jwt_weak_secret_accepted"),
    "dast-jwt-missing-claims": ("missing-claims", "jwt_missing_claims_accepted"),
}


@dataclass
class JwtRun:
    rows: list[dict[str, Any]] = field(default_factory=list)
    tests: int = 0
    confirmed: int = 0
    cancelled: bool = False


def jwt_checks(rule_set, skipped=()):
    excluded = {s.get("check_id") for s in skipped if s.get("status") == "skipped" or s.get("effective_mode") == "assist-only"}
    return {ec.check_id: ec for ec in rule_set.enabled_checks()
            if ec.check_id in CHECKS and ec.check_id not in excluded and ec.mode.value != "assist-only"} if rule_set else {}


def _credential(session):
    if session.token_header:
        name, value = session.token_header
        prefix, _, raw = value.rpartition(" ")
        raw = raw or value
        if decode_token(raw) is not None:
            return raw, (name, prefix), None
    for cookie in session.cookies:
        raw = cookie.get("value", "")
        if decode_token(raw) is not None:
            return raw, None, cookie
    return None


def run_jwt(endpoints: Sequence[Endpoint], *, store: SessionStore, executor, credentials, checks,
            cancelled: Callable[[], bool] = lambda: False, log: Callable[[str], None] = print) -> JwtRun:
    run = JwtRun()
    if not checks or credentials is None:
        return run
    for session in store.authenticated():
        if cancelled():
            run.cancelled = True
            break
        selected = _credential(session)
        if selected is None:
            continue
        raw, header, cookie = selected
        decoded = decode_token(raw)
        if decoded is None:
            continue
        endpoint = next((e for e in endpoints if session.spec.identity_id in e.seen_as
                         and e.method.upper() == "GET" and e.last_status is not None and 200 <= e.last_status < 300
                         and replayable(e, allow_state_changing=False, anonymous_id=None)), None)
        if endpoint is None:
            continue
        identity_id = session.spec.identity_id
        original = dict(credentials.read(identity_id) or {})

        def send(token, check_id):
            if cancelled():
                return None
            # Register generated values before the audit/logger/executor can encounter them.
            if token:
                original[f"jwt_probe_{check_id}"] = token
                credentials.store(session.spec.to_identity(), original)
            isolated = SessionStore([session.spec])
            isolated.mark_authenticated(identity_id)
            if token and header:
                isolated.set_token(identity_id, header[0], header[1], token)
            elif token and cookie:
                isolated.update_cookies(identity_id, [{**cookie, "value": token}])
            return isolated.send(executor, identity_id, endpoint.method, endpoint.url, check_id=check_id)

        baseline_decision = send(raw, "jwt-baseline")
        if baseline_decision is None or not baseline_decision.allowed or baseline_decision.response is None:
            continue
        baseline = baseline_decision.response
        if baseline.status is None or not 200 <= baseline.status < 300 or not baseline.length:
            continue
        control = send(None, "jwt-control")
        # Require a real access denial, not just a different successful public response.
        if control is None or not control.allowed or control.response is None or control.response.status not in (401, 403):
            continue
        secret = weak_hmac_secret(*decoded.segments) if "dast-jwt-weak-secret" in checks else None
        for cid, ec in checks.items():
            if cancelled():
                run.cancelled = True
                break
            weakness, signal_name = CHECKS[cid]
            candidate = modified_token(decoded, weakness, secret=secret)
            if candidate is None:
                continue
            decision = send(candidate, cid)
            if decision is None:
                run.cancelled = True
                break
            run.tests += int(decision.allowed)
            response = decision.response
            if not decision.allowed or response is None or response.status != baseline.status or not auth_boundary_crossed(baseline, response):
                continue
            signal = DetectorSignal(signal_name, "modified JWT accepted with the authenticated response; anonymous control denied")
            outcome = apply_guardrail(CheckVerdict.FAIL, [signal], ec.check.detector_signals)
            if outcome.finding_verdict is None:
                continue
            secrets = credentials.secrets()
            target = redact_text(target_label(endpoint), secrets)
            label = redact_text(session.label, secrets)
            finding = Finding(
                check_id=cid, severity=ec.severity, confidence=Confidence.HIGH, verdict=outcome.finding_verdict,
                target=target, param=header[0] if header else "cookie", location=Location.HEADER,
                standards=tuple(standards_for(ec.check)), remediation_ref=ec.check.remediation_ref,
                evidence=Evidence(f"HTTP {baseline.status}, {baseline.length} bytes",
                                  f"HTTP {response.status}, {response.length} bytes", outcome.signals,
                                  str(decision.audit_seq) if decision.audit_seq is not None else ""), roles=(label,),
            )
            run.rows.append(finding_to_row(finding, title=f"{ec.check.title}: {target}", source=label,
                                           sink=redact_text(endpoint.url, secrets), verdict_reason=f"{signal.detail} ({finding.param})",
                                           snippet=f"{cid}: authenticated response matched; anonymous control denied."))
            run.confirmed += 1
            log(f"    JWT: {cid} confirmed for {label!r}.")
    run.cancelled = run.cancelled or cancelled()
    return run

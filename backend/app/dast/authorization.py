"""The cross-role replay engine and its findings (DAST-10-010 .. -030).

For each authenticated identity (the *owner*) the engine takes the requests it reached, replays each
one as every other identity and as Anonymous (the *actors*), and compares the actor's response with
the owner's using the `auth_boundary_crossed` detector. A refusal is a pass for that cell. A
successful, materially equivalent response is a crossing, classified by `domain.authz` into broken
authentication (anonymous), broken function-level authorization or broken object-level authorization,
and written as a finding carrying the role pair.

Every replay is sent through the guarded executor as the acting identity, so scope, the method gate
(read-only unless state-changing methods were opted in), the rate limit, cancellation and the audit
trail all apply; identical requests are never replayed twice; the total number of replays is capped;
pairs run in a fixed order and cancellation is honoured between replays.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Sequence

from .domain.active import Exchange, build_request, target_label
from .domain.catalog import standards_for
from .domain.detectors import run_detectors
from .domain.entities import CheckVerdict, Confidence, DetectorSignal, Endpoint, Evidence, Finding, FindingVerdict, Location, Severity
from .domain.guardrail import apply_guardrail
from .domain.identities import IdentitySpec
from .domain.mapping import finding_to_row
from .domain.authz import (
    AUTHN, BFLA, BOLA, Boundary, ReplaySummary, RolePair, alternate_object_value, classify_crossing,
    endpoint_with_object_value, owner_candidates, role_pairs,
)
from .domain.redaction import redact_text
from .domain.ruleset import EffectiveCheck, EffectiveRuleSet
from .domain.session import DenialTracker
from .sessions import SessionStore

AUTHZ_AUDIT_CHECK = "authz-replay"
EXCERPT_CHARS = 600
_LOGIN_FORM = ("type=\"password\"", "type='password'", "type=password")
# A crossing whose response body is this small or smaller carries little content to have been
# worth protecting in the first place (an empty JSON object, a bare boolean, ...); severity stays
# catalog-driven, but confidence in a *this specific instance* mattering is reduced for it.
TRIVIAL_BODY_BYTES = 32


@dataclass
class ReplayResult:
    summaries: list[ReplaySummary] = field(default_factory=list)
    rows: list[dict[str, Any]] = field(default_factory=list)
    replays: int = 0
    cap: int = 0
    cap_reached: bool = False
    cancelled: bool = False
    skipped_checks: list[str] = field(default_factory=list)  # a crossing whose check is not enabled


def authz_checks(rule_set: EffectiveRuleSet | None, skipped: Iterable[Mapping[str, Any]] = ()) -> dict[str, EffectiveCheck]:
    """The authorization checks that may produce findings: enabled, not skipped for a dependency.
    (`degraded` ones still run; they just run with less, e.g. the anonymous replay only.)"""
    if rule_set is None:
        return {}
    skipped_ids = {s.get("check_id") for s in skipped if s.get("status") == "skipped"}
    return {ec.check_id: ec for ec in rule_set.enabled_checks() if ec.check_id in (AUTHN, BFLA, BOLA) and ec.check_id not in skipped_ids}


def _key(identity_id: str, request) -> tuple:
    return (identity_id, request.method, request.url, json.dumps(request.body, sort_keys=True, default=str))


def _excerpt(label: str, exchange: Exchange, secrets: Sequence[str]) -> str:
    body = redact_text(exchange.body[:EXCERPT_CHARS], secrets)
    head = f"{label}: HTTP {exchange.status}, {exchange.length} bytes"
    return f"{head}\n{body}" if body else head


def _looks_like_login_wall(owner: Exchange, actor: Exchange) -> bool:
    """The actor was bounced to a login page (the executor follows redirects, so only the page is left)."""
    text = actor.body.lower()
    return any(m in text for m in _LOGIN_FORM) and not any(m in owner.body.lower() for m in _LOGIN_FORM)


def run_replays(
    endpoints: Sequence[Endpoint],
    specs: Sequence[IdentitySpec],
    store: SessionStore,
    executor: Any,
    checks: Mapping[str, EffectiveCheck],
    *,
    allow_state_changing: bool,
    max_replays: int,
    privilege: Mapping[str, int] | None = None,
    secrets: Sequence[str] = (),
    cancelled: Callable[[], bool] = lambda: False,
    log: Callable[[str], None] = print,
    on_rows: Callable[[list[dict[str, Any]]], None] | None = None,
    spa: bool = False,
) -> ReplayResult:
    result = ReplayResult(cap=max_replays)
    by_label = {s.label: s for s in specs}
    anonymous = next((s for s in specs if s.is_anonymous), None)
    pairs = role_pairs(specs)
    owners = list(dict.fromkeys(p.owner for p in pairs))
    actor_cache: dict[tuple, Exchange] = {}
    # One tracker per identity label, fed whenever that identity sends - as an owner (whose
    # candidates are being replayed) or as an actor (doing the replaying). A session dying either
    # way must stop results from being compared against a dead session, not just scored as usual.
    identity_trackers: dict[str, DenialTracker] = {}
    lost_identities: set[str] = set()

    def send(spec: IdentitySpec, request) -> Exchange:
        decision = store.send(executor, spec.identity_id, request.method, request.url, body=request.body, headers=dict(request.headers), check_id=AUTHZ_AUDIT_CHECK)
        if not decision.allowed:
            return Exchange(error=f"request not sent: {decision.deny_reason or 'denied'}", audit_seq=decision.audit_seq)
        response = decision.response
        if response is None:
            return Exchange(error=f"request failed: {decision.error or 'no response'}", audit_seq=decision.audit_seq)
        return Exchange(response.status, response.length, response.body_excerpt or "", dict(response.headers or {}), response.elapsed_ms, audit_seq=decision.audit_seq)

    for owner_label in owners:
        owner = by_label[owner_label]
        actors = [p for p in pairs if p.owner == owner_label]
        stats = {p.actor: {"replays": 0, "denied": 0, "crossed": 0, "owned": 0, "truncated": False, "session_lost": False} for p in actors}
        candidates = owner_candidates(endpoints, owner.identity_id, allow_state_changing=allow_state_changing, anonymous_id=anonymous.identity_id if anonymous else None, spa=spa)
        log(f"    {owner_label!r}: {len(candidates)} request(s) to replay as {', '.join(repr(p.actor) for p in actors)}.")
        for endpoint in candidates:
            if cancelled():
                result.cancelled = True
                break
            if owner_label in lost_identities:
                for pair in actors:
                    stats[pair.actor]["session_lost"] = True
                break
            request = build_request(endpoint)
            owner_response = send(owner, request)
            owner_tracker = identity_trackers.setdefault(owner_label, DenialTracker())  # the owner is never anonymous (role_pairs)
            if owner_response.status is not None and owner_tracker.observe(owner_response.status):
                lost_identities.add(owner_label)
                log(f"    {owner_label!r}'s session was lost mid-replay; its remaining candidates were skipped.")
                for pair in actors:
                    stats[pair.actor]["session_lost"] = True
                break
            if not owner_response.usable or not (200 <= (owner_response.status or 0) < 300):
                continue  # the owner did not reach it (refused, missing, or failed): nothing to compare against
            for pair in actors:
                s = stats[pair.actor]
                s["owned"] += 1
                if cancelled():
                    result.cancelled = True
                    break
                if pair.actor in lost_identities:
                    s["session_lost"] = True
                    continue  # this actor's own session already died; a comparison against it proves nothing
                if result.replays >= max_replays:
                    result.cap_reached = True
                    s["truncated"] = True
                    continue
                actor = by_label[pair.actor]
                key = _key(actor.identity_id, request)
                actor_response = actor_cache.get(key)
                if actor_response is None:  # an identical request is sent once, whoever owned it
                    actor_response = actor_cache[key] = send(actor, request)
                    result.replays += 1
                    # Anonymous has no session to lose - being refused is the expected, routine
                    # result for most of its replays, not a sign of a dying session.
                    if not actor.is_anonymous and actor_response.status is not None:
                        actor_tracker = identity_trackers.setdefault(pair.actor, DenialTracker())
                        if actor_tracker.observe(actor_response.status):
                            lost_identities.add(pair.actor)
                s["replays"] += 1  # a comparison for this pair, whether the response was fetched now or earlier
                if not actor_response.usable:
                    continue
                signals = run_detectors(owner_response.snapshot(), actor_response.snapshot(), None, ["auth_boundary_crossed"])
                classified_endpoint = endpoint
                if not signals or _looks_like_login_wall(owner_response, actor_response):
                    swapped = _object_swap(
                        endpoint, endpoints, actor, store, executor, result, max_replays, actor_cache, cancelled,
                    )
                    if swapped is None:
                        s["denied"] += 1
                        continue
                    signals, actor_response, classified_endpoint = swapped
                    s["replays"] += 1
                s["crossed"] += 1
                boundary = classify_crossing(pair, owner, actor, classified_endpoint, privilege=privilege)
                if boundary is None:
                    continue  # an expected access (a higher role reaching a lower role's page)
                row = _row(classified_endpoint, pair, boundary, owner_response, actor_response, signals, checks, secrets)
                if row is None:
                    result.skipped_checks.append(boundary.check_id)
                    continue
                result.rows.append(row)
                if on_rows:
                    on_rows([row])
        for pair in actors:
            s = stats[pair.actor]
            result.summaries.append(
                ReplaySummary(pair.owner, pair.actor, s["replays"], s["denied"], s["crossed"], s["owned"], s["truncated"], s["session_lost"])
            )
        if result.cap_reached:
            log(f"    The replay cap ({max_replays}) truncated the pairs for {owner_label!r}.")
        if result.cancelled:
            break
    # a pair that never ran (cancelled before its owner started) simply has no summary: its cell is untested
    return result


def _object_swap(endpoint, pool, actor, store, executor, result: ReplayResult, max_replays: int, cache: dict, cancelled: Callable[[], bool]):
    """One extra replay with another observed object id substituted. None when there is nothing to swap
    or the swapped request was not accepted."""
    if result.replays >= max_replays or cancelled():
        return None
    alternate = alternate_object_value(endpoint, pool)
    if alternate is None:
        return None
    name, location, value = alternate
    mutated = endpoint_with_object_value(endpoint, name, location, value)
    request = build_request(mutated)
    key = _key(actor.identity_id, request)
    response = cache.get(key)
    if response is None:
        decision = store.send(
            executor, actor.identity_id, request.method, request.url,
            body=request.body, headers=dict(request.headers), check_id=AUTHZ_AUDIT_CHECK,
        )
        result.replays += 1
        if not decision.allowed or decision.response is None:
            response = Exchange(error="request not sent" if not decision.allowed else "request failed", audit_seq=decision.audit_seq)
        else:
            snap = decision.response
            response = Exchange(snap.status, snap.length, snap.body_excerpt or "", dict(snap.headers or {}), snap.elapsed_ms, audit_seq=decision.audit_seq)
        cache[key] = response
    if not response.usable or not (200 <= (response.status or 0) < 300) or response.length == 0:
        return None
    if value not in (response.body or "") and response.length <= TRIVIAL_BODY_BYTES:
        return None
    return [DetectorSignal("auth_boundary_crossed", f"a different object id ({name}) was accepted")], response, mutated


def _row(endpoint, pair: RolePair, boundary: Boundary, owner_response: Exchange, actor_response: Exchange, signals, checks, secrets) -> dict[str, Any] | None:
    ec = checks.get(boundary.check_id)
    if ec is None:
        return None
    check = ec.check
    outcome = apply_guardrail(CheckVerdict.FAIL, signals, check.detector_signals)
    verdict = {
        "true_positive": FindingVerdict.TRUE_POSITIVE, "unverified": FindingVerdict.UNVERIFIED,
    }.get(boundary.verdict, FindingVerdict.FALSE_POSITIVE)
    target = target_label(endpoint)
    detail = signals[0].detail
    evidence = Evidence(
        _excerpt(pair.owner, owner_response, secrets), _excerpt(pair.actor, actor_response, secrets),
        # A false_positive means the crossing is expected (e.g. declared public): there is nothing
        # to show. Unverified still fired the signal; the evidence is exactly why it needs review.
        tuple(signals) if verdict is not FindingVerdict.FALSE_POSITIVE else (),
        str(actor_response.audit_seq) if actor_response.audit_seq is not None else "",
    )
    param = next((p.name for p in endpoint.parameters if p.location.value in ("path", "query") and "id" in p.name.lower()), None) if boundary.kind == "object" else None
    confidence = Confidence.LOW
    if verdict is FindingVerdict.TRUE_POSITIVE:
        confidence = Confidence.HIGH if actor_response.length > TRIVIAL_BODY_BYTES else Confidence.MEDIUM
    elif verdict is FindingVerdict.UNVERIFIED:
        # The empirical signal is real; only doc corroboration is missing, so this is worth more
        # than a bare LOW guess.
        confidence = Confidence.MEDIUM
    finding = Finding(
        check_id=check.check_id, severity=Severity(ec.severity.value), confidence=confidence,
        verdict=verdict, target=target, param=param, location=Location.RESPONSE, standards=tuple(standards_for(check)),
        remediation_ref=check.remediation_ref, evidence=evidence, roles=(pair.owner, pair.actor),
    )
    what = {"anonymous": "without any session", "function": f"as {pair.actor}, a lower-privileged role", "object": f"as {pair.actor}"}[boundary.kind]
    reason = f"{pair.actor} received a successful response {what} that matches what {pair.owner} received ({detail})."
    if boundary.reason:
        reason += f" {boundary.reason}."
    return finding_to_row(
        finding, title=f"{check.title}: {target} ({pair.owner} → {pair.actor})", source=f"{pair.owner} → {pair.actor}", sink=endpoint.url,
        verdict_reason=reason, snippet=f"Check: {check.title}\nRole pair: {pair.owner} → {pair.actor}\nTarget: {target}\nSignal: {signals[0].name}: {detail}",
    )

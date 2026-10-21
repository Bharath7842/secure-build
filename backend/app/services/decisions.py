"""The append-only machine decision history of a finding (SAST-00-050).

Every verdict the scanner gives an occurrence — the first one when the finding
is written, and each later change by group confirmation, the Joern confirm, the
reconcile sweep or the reachability confidence floor — is one `FindingDecision`
row. Nothing here updates or deletes: the module exposes inserts only (a test
holds it to that), and the model refuses UPDATE/DELETE through the ORM.

A row is written when the verdict or the confidence changes, never for a write
that leaves both as they were. Callers hold `scan_runner._DB_WRITE_LOCK` and
commit; this module only adds rows to the session.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Iterable, Mapping

from sqlalchemy.orm import Session

from app.models import Finding, FindingDecision, Scan, utcnow

STAGES = (
    "deep_scan",
    "triage_regex",
    "triage_llm",
    "group_confirm",
    "flow_verify",
    "reachability_floor",
    "joern_confirm",
    "reconcile",
    "sca_match",
    # EPIC-01: steps between the model's answer and the stored verdict.
    "validator",
    "dedupe",
    "publish_filter",
    "explanation_retry",
)
_STAGE_BY_KIND = {
    "regex": "triage_regex",
    "llm": "deep_scan",
    "flow": "flow_verify",
    "joern": "joern_confirm",
    "sca": "sca_match",
}
DEFAULT_CONFIRM_STAGE = "group_confirm"


def stage_for_new_finding(f: Mapping[str, Any]) -> str:
    """The stage that decided a finding at insert time: the engine's own
    `decision_stage` when it set one, else inferred from the finding's kind."""
    stamped = f.get("decision_stage")
    if stamped in STAGES:
        return stamped
    return _STAGE_BY_KIND.get(str(f.get("kind") or "").lower(), "deep_scan")


def evidence_version(scan: Scan | None, *, result_cache_hit: bool = False) -> dict[str, Any]:
    """The scan's recorded `versions` block, plus whether this answer was replayed
    from the cross-scan result cache rather than produced by the model now."""
    versions = dict(((scan.metadata_json or {}) if scan is not None else {}).get("versions") or {})
    versions["result_cache_hit"] = bool(result_cache_hit)
    return versions


def _decision(
    finding: Finding,
    *,
    stage: str,
    scan: Scan | None,
    result_cache_hit: bool,
    actor: str | None = None,
    detail: Mapping[str, Any] | None = None,
) -> FindingDecision:
    return FindingDecision(
        finding_id=finding.id,
        scan_id=finding.scan_id,
        occurrence_id=finding.occurrence_id,
        stage=stage if stage in STAGES else "deep_scan",
        verdict=finding.verdict,
        confidence=finding.confidence,
        unresolved_reason=finding.unresolved_reason,
        verdict_reason=finding.verdict_reason,
        evidence_version=evidence_version(scan, result_cache_hit=result_cache_hit),
        actor=actor,
        detail=dict(detail) if detail else None,
    )


def _step_decision(
    finding: Finding, step: Mapping[str, Any], *, scan: Scan | None, result_cache_hit: bool
) -> FindingDecision:
    """A decision the engine recorded on the finding dict (`decisions`), as it
    stood at that step: its own verdict/confidence/reason, not the final ones."""
    stage = step.get("stage")
    return FindingDecision(
        finding_id=finding.id,
        scan_id=finding.scan_id,
        occurrence_id=finding.occurrence_id,
        stage=stage if stage in STAGES else "deep_scan",
        verdict=step.get("verdict"),
        confidence=step.get("confidence"),
        unresolved_reason=step.get("unresolved_reason"),
        verdict_reason=step.get("verdict_reason"),
        evidence_version=evidence_version(scan, result_cache_hit=result_cache_hit),
        actor=step.get("actor"),
        detail=dict(step["detail"]) if step.get("detail") else None,
    )


def record_initial(
    db: Session, rows: Iterable[Finding], dicts: Iterable[Mapping[str, Any]], scan: Scan | None
) -> int:
    """The decisions of newly inserted findings (ids already assigned by a flush).

    A finding the engine altered after the model answered — a validator's proof,
    a dedupe that discarded a conflicting duplicate, a publish filter that held
    it back — carries those steps in `decisions`, oldest first. They are written
    before the final row, with timestamps a microsecond apart so the history
    orders them as they happened and the latest row still equals
    `Finding.verdict`."""
    added = 0
    for row, f in zip(rows, dicts):
        hit = bool(f.get("result_cache_hit"))
        steps = [s for s in (f.get("decisions") or []) if isinstance(s, Mapping)]
        base = utcnow()
        built = [_step_decision(row, s, scan=scan, result_cache_hit=hit) for s in steps]
        built.append(_decision(
            row, stage=stage_for_new_finding(f), scan=scan, result_cache_hit=hit,
            actor=f.get("decision_actor"),
            detail=f.get("decision_detail"),
        ))
        for offset, decision in enumerate(built):
            decision.at = base + timedelta(microseconds=offset)
            db.add(decision)
            added += 1
    return added


def record_change(
    db: Session,
    finding: Finding,
    *,
    before_verdict: str | None,
    before_confidence: float | None,
    stage: str,
    scan: Scan | None,
    result_cache_hit: bool = False,
    actor: str | None = None,
    detail: Mapping[str, Any] | None = None,
) -> bool:
    """Append a decision for `finding` (already updated) if its verdict or
    confidence differs from `before_*`. Returns whether a row was added."""
    if finding.verdict == before_verdict and finding.confidence == before_confidence:
        return False
    db.add(_decision(
        finding, stage=stage, scan=scan, result_cache_hit=result_cache_hit,
        actor=actor, detail=detail,
    ))
    return True

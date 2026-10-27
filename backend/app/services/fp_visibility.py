"""Leave out the false positives the scanner is all but sure of.

A SAST finding the scanner dismissed with at least `CONFIDENT_FP_THRESHOLD`
certainty is noise to anyone reading the results, so the findings list, every
export, the counts and review grouping read the scan without it. Read side only:
the row and its decision history stay in the database, and a different threshold
shows it again.

How sure the scanner was depends on who decided, because `confidence` is on two
scales:

* a validator's negative proof (`reason_tag`, no confidence) is deterministic: 1.0;
* the deep scan, flow verify and LLM triage prompts ask "how sure you are this is
  exploitable", so a dismissal's certainty is `1 - confidence`;
* grouped confirmation (also behind the Joern confirm and the reconcile sweep)
  asks "how sure you are of this verdict" since `RESULT_CACHE_VERSION` 5, so it is
  `confidence` — but only for a decision made under that version: before it the
  prompt did not say, and models answered on both scales (0.15 and 0.95 for one
  and the same dismissal).

Anything else — no decision row (scans older than the decision history), an older
group decision, no confidence — has no known certainty and stays visible. So does
any finding a reviewer has reviewed: their decision is shown, whatever it is.
"""

from __future__ import annotations

from collections.abc import Collection
from typing import Any

from sqlalchemy.orm import Session

from app.models import Finding, FindingDecision, Scan
from app.services.decision_diff import latest_decisions

CONFIDENT_FP_THRESHOLD = 0.9
FALSE_POSITIVE = "false_positive"

_EXPLOITABILITY_STAGES = frozenset({"deep_scan", "flow_verify", "triage_llm"})
_VERDICT_STAGES = frozenset({"group_confirm", "joern_confirm", "reconcile"})
_SCALE_STAGES = _EXPLOITABILITY_STAGES | _VERDICT_STAGES
# The first `RESULT_CACHE_VERSION` whose grouped-confirmation prompt defines confidence.
_VERDICT_SCALE_SINCE = 5


def _scanner_verdict(finding: Finding) -> str:
    return (getattr(finding, "llm_verdict", None) or finding.verdict or "").strip().lower()


def _verdict_scale_defined(evidence_version: dict[str, Any] | None) -> bool:
    try:
        return int((evidence_version or {}).get("result_cache_version")) >= _VERDICT_SCALE_SINCE
    except (TypeError, ValueError):
        return False


def fp_certainty(finding: Finding, decision: FindingDecision | None) -> float | None:
    """How sure the scanner was that `finding` is a false positive, 0..1, or None
    when that cannot be told. `decision` is the finding's latest decision by a stage
    whose confidence scale is known (see the module docstring)."""
    if _scanner_verdict(finding) != FALSE_POSITIVE:
        return None
    if finding.reason_tag:
        return 1.0
    if decision is None or decision.confidence is None or (decision.verdict or "") != FALSE_POSITIVE:
        return None
    confidence = max(0.0, min(1.0, float(decision.confidence)))
    if decision.stage in _EXPLOITABILITY_STAGES:
        return 1.0 - confidence
    if decision.stage in _VERDICT_STAGES and _verdict_scale_defined(decision.evidence_version):
        return confidence
    return None


def hide_confident_false_positives(
    db: Session, scan: Scan, findings: list[Finding], *, reviewed_ids: Collection[str] | None = None
) -> tuple[list[Finding], int]:
    """(visible findings in their order, how many were left out). Call after
    `apply_effective_verdicts`, which sets the `llm_verdict` and `review` read here —
    or, on raw rows, pass the ids of reviewed findings as `reviewed_ids`."""
    if (scan.scan_type or "sast").strip().lower() != "sast":
        return findings, 0

    def reviewed(finding: Finding) -> bool:
        if reviewed_ids is not None:
            return finding.id in reviewed_ids
        return getattr(finding, "review", None) is not None

    candidates = [f for f in findings if not reviewed(f) and _scanner_verdict(f) == FALSE_POSITIVE]
    if not candidates:
        return findings, 0
    latest = (
        latest_decisions(db, scan.id, stages=_SCALE_STAGES)
        if any(not f.reason_tag for f in candidates) else {}
    )
    hidden = set()
    for finding in candidates:
        certainty = fp_certainty(finding, latest.get(finding.id))
        if certainty is not None and certainty >= CONFIDENT_FP_THRESHOLD:
            hidden.add(finding.id)
    if not hidden:
        return findings, 0
    return [f for f in findings if f.id not in hidden], len(hidden)

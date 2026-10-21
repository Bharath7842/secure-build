"""Reviewer feedback on SAST findings.

A reviewer decides on an *issue group* (the same grouping the findings panel shows,
`scan_export._finding_group_key`). The decision is stored in `finding_reviews` with an
append-only `finding_review_events` history; `Finding` rows are never written, so the
original LLM result stays intact even though the engine's verdict writers UPDATE
`findings.verdict` in place.

Read paths that need counts/exports/gates to honour reviewers call
`apply_effective_verdicts`, which overlays the reviewer's verdict on loaded `Finding`
instances without marking them dirty.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
from datetime import date, datetime, time, timezone
from collections.abc import Collection
from typing import Any, Iterable

from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import set_committed_value

from app.models import Finding, FindingReview, FindingReviewEvent, Scan
from app.services.scan_export import _finding_group_key, group_findings_by_issue, issue_groups

# --- vocabulary -------------------------------------------------------------------------

DECISION_CONFIRMED = "confirmed_issue"
DECISION_FALSE_POSITIVE = "false_positive"
DECISION_NEEDS_INFO = "needs_more_info"
DECISION_RESOLVED = "resolved"
DECISION_ACCEPT_RISK = "accept_risk"

VERDICT_DECISIONS = (DECISION_CONFIRMED, DECISION_FALSE_POSITIVE, DECISION_NEEDS_INFO)
DECISIONS = VERDICT_DECISIONS + (DECISION_RESOLVED, DECISION_ACCEPT_RISK)

RESOLUTION_OPEN = "open"
RESOLUTION_RESOLVED = "resolved"
RESOLUTION_RISK_ACCEPTED = "risk_accepted"

LEARNING_PENDING = "pending_learning"
LEARNING_APPROVED = "approved_for_learning"
LEARNING_PROCESSED = "processed"
LEARNING_STATUSES = (LEARNING_PENDING, LEARNING_APPROVED, LEARNING_PROCESSED)

REVIEW_STATUSES = ("unreviewed", "needs_info", "reviewed")

# LLM verdict each reviewer verdict corresponds to; used to detect an override.
_LLM_EQUIVALENT = {DECISION_CONFIRMED: "true_positive", DECISION_FALSE_POSITIVE: "false_positive"}


class ReviewError(Exception):
    """A review request that breaks a rule. `status` is the HTTP status to answer with."""

    def __init__(self, message: str, status: int = 422):
        super().__init__(message)
        self.status = status


# --- keys and lookup --------------------------------------------------------------------


def _fingerprint(project_id: str | None, finding: Finding) -> str:
    key = _finding_group_key(finding)
    return hashlib.sha1(f"{project_id or ''}|{key!r}".encode("utf-8")).hexdigest()


def _members_of(db: Session, scan_id: str, finding: Finding) -> list[Finding]:
    rows = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    for members in issue_groups(rows):
        if any(row.id == finding.id for row in members):
            return members
    return [finding]


def _reviews_by_member(db: Session, scan_id: str) -> dict[str, FindingReview]:
    """finding id -> review, for every member of every reviewed group in the scan."""
    out: dict[str, FindingReview] = {}
    for review in db.query(FindingReview).filter(FindingReview.scan_id == scan_id).all():
        out[review.finding_id] = review
        for member_id in review.member_finding_ids or []:
            out[member_id] = review
    return out


def find_review(db: Session, scan_id: str, finding_id: str) -> FindingReview | None:
    return _reviews_by_member(db, scan_id).get(finding_id)


# --- derived state ----------------------------------------------------------------------


def _derive(review: FindingReview) -> None:
    """Recompute issue_status / is_closed from the reviewer verdict and resolution.

    Closed means a final answer: a dismissed false positive, or a confirmed issue that was
    resolved or explicitly risk-accepted. Anything else (unreviewed, needs more info, an
    unresolved confirmed issue) stays open."""
    verdict = review.reviewer_verdict
    if verdict == DECISION_FALSE_POSITIVE:
        review.resolution_status = RESOLUTION_OPEN
        review.issue_status, review.is_closed = "closed_false_positive", True
    elif verdict == DECISION_CONFIRMED and review.resolution_status == RESOLUTION_RESOLVED:
        review.issue_status, review.is_closed = "resolved", True
    elif verdict == DECISION_CONFIRMED and review.resolution_status == RESOLUTION_RISK_ACCEPTED:
        review.issue_status, review.is_closed = "risk_accepted", True
    elif verdict == DECISION_NEEDS_INFO:
        review.resolution_status = RESOLUTION_OPEN
        review.issue_status, review.is_closed = "needs_info", False
    else:
        review.issue_status, review.is_closed = "open", False


def review_status_of(review: FindingReview | None) -> str:
    verdict = review.reviewer_verdict if review else None
    if not verdict:
        return "unreviewed"
    return "needs_info" if verdict == DECISION_NEEDS_INFO else "reviewed"


def effective_verdict(llm_verdict: str | None, review: FindingReview | None) -> str | None:
    """Reviewer's verdict if it is a final one, else the LLM's. `needs_more_info` defers to the LLM."""
    if review is None:
        return llm_verdict
    if review.reviewer_verdict in _LLM_EQUIVALENT:
        return _LLM_EQUIVALENT[review.reviewer_verdict]
    return llm_verdict


REVIEW_STATES = ("pending", "agreed", "overridden", "resolved")


def review_state(review: FindingReview | None, scanner_verdict: str | None) -> str:
    """Where human review of a finding stands, apart from what the scanner decided:

    * `pending`    — no review yet (or only a "needs more info" note);
    * `agreed`     — the reviewer's verdict equals the scanner's;
    * `overridden` — the reviewer decided differently (`is_override`);
    * `resolved`   — someone closed the issue as fixed or accepted its risk.

    It is a workflow state and is never encoded in `verdict`: a finding the
    scanner dismissed with no reviewer yet is "Scanner: False Positive · Review:
    pending", not "Needs Review"."""
    if review is None:
        return "pending"
    if review.resolution_status in (RESOLUTION_RESOLVED, RESOLUTION_RISK_ACCEPTED):
        return "resolved"
    if review.is_override:
        return "overridden"
    if _LLM_EQUIVALENT.get(review.reviewer_verdict) == scanner_verdict:
        return "agreed"
    return "pending"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _clean(value: str | None) -> str:
    return (value or "").strip()


def _event(review: FindingReview, actor: str, action: str, **fields: Any) -> FindingReviewEvent:
    event = FindingReviewEvent(review_id=review.id, actor=actor, action=action, at=_utcnow(), **fields)
    review.events.append(event)
    return event


# --- submitting a decision --------------------------------------------------------------


def _snapshot(scan: Scan, finding: Finding, members: list[Finding]) -> FindingReview:
    return FindingReview(
        scan_id=scan.id,
        project_id=scan.project_id,
        finding_id=finding.id,
        fingerprint=_fingerprint(scan.project_id, finding),
        member_finding_ids=[m.id for m in members],
        occurrence_count=len(members),
        rule_id=finding.rule_id,
        cwe=finding.cwe,
        severity=finding.severity,
        confidence=finding.confidence,
        file_path=finding.file_path,
        line=finding.line,
        kind=finding.kind,
        title=finding.title,
        snippet=finding.snippet,
        matched_text=finding.matched_text,
        llm_verdict=finding.verdict,
        llm_explanation=finding.verdict_reason,
        llm_remediation=finding.ai_fix,
        resolution_status=RESOLUTION_OPEN,
        issue_status="open",
        is_closed=False,
    )


def submit_review(
    db: Session,
    scan: Scan,
    finding: Finding,
    *,
    decision: str,
    reviewer: str,
    comment: str | None = None,
    resolution_notes: str | None = None,
) -> FindingReview:
    """Apply one reviewer decision to the issue group `finding` belongs to. Commits."""
    reviewer = _clean(reviewer)
    comment = _clean(comment)
    resolution_notes = _clean(resolution_notes)
    if not reviewer:
        raise ReviewError("A reviewer name is required.")
    if decision not in DECISIONS:
        raise ReviewError(f"Unknown decision '{decision}'. Use one of: {', '.join(DECISIONS)}.")

    review = find_review(db, scan.id, finding.id)
    is_new = review is None
    if is_new:
        review = _snapshot(scan, finding, _members_of(db, scan.id, finding))
        db.add(review)
    now = _utcnow()
    previous_verdict, previous_resolution = review.reviewer_verdict, review.resolution_status

    if decision in VERDICT_DECISIONS:
        llm_verdict = (review.llm_verdict or "").lower()
        override = _LLM_EQUIVALENT.get(decision) is not None and llm_verdict in _LLM_EQUIVALENT.values() \
            and _LLM_EQUIVALENT[decision] != llm_verdict
        agrees_with_llm = decision == DECISION_CONFIRMED and llm_verdict == "true_positive"
        if not comment and not agrees_with_llm:
            why = "overriding the LLM verdict" if override else "this decision"
            raise ReviewError(f"A reason is required for {why}.")
        if previous_verdict and previous_verdict != decision and previous_resolution != RESOLUTION_OPEN:
            _event(review, reviewer, "reopened", from_resolution=previous_resolution,
                   to_resolution=RESOLUTION_OPEN, comment="Verdict changed after resolution")
            review.resolution_notes = None
            review.resolved_by = review.resolved_at = None
        review.resolution_status = RESOLUTION_OPEN if previous_verdict != decision else review.resolution_status
        review.reviewer_verdict = decision
        review.is_override = bool(override)
        review.reviewer_comment = comment or None
        review.reviewer = reviewer
        review.reviewed_at = review.reviewed_at or now
        review.last_reviewed_at = now
        if previous_verdict is None:
            action = "verdict_set"
        elif previous_verdict != decision:
            action = "verdict_changed"
        else:
            action = "verdict_reaffirmed"
        _event(review, reviewer, action, from_verdict=previous_verdict, to_verdict=decision,
               comment=comment or None, detail={"override": bool(override)})
        _update_learning(review, previous_verdict, reviewer)
    else:
        if review.reviewer_verdict != DECISION_CONFIRMED:
            raise ReviewError("Only a confirmed issue can be resolved or risk-accepted. Confirm it first.", 409)
        notes = resolution_notes or comment
        if not notes:
            label = "resolution notes" if decision == DECISION_RESOLVED else "a justification for accepting the risk"
            raise ReviewError(f"Please provide {label}.")
        review.resolution_status = RESOLUTION_RESOLVED if decision == DECISION_RESOLVED else RESOLUTION_RISK_ACCEPTED
        review.resolution_notes = notes
        review.resolved_by = reviewer
        review.resolved_at = now
        review.last_reviewed_at = now
        _event(review, reviewer, "resolved" if decision == DECISION_RESOLVED else "risk_accepted",
               from_resolution=previous_resolution, to_resolution=review.resolution_status, comment=notes)

    _derive(review)
    db.commit()
    db.refresh(review)
    _resync_scan_report(db, scan.id)
    return review


def _update_learning(review: FindingReview, previous_verdict: str | None, actor: str) -> None:
    """A final label becomes labelled data. A changed label after approval goes back to pending."""
    if review.reviewer_verdict not in _LLM_EQUIVALENT:
        if review.learning_status:
            _event(review, actor, "learning_reset", comment="Verdict is no longer a final label",
                   detail={"from": review.learning_status})
        review.learning_status = None
        return
    if review.learning_status is None:
        review.learning_status = LEARNING_PENDING
    elif previous_verdict != review.reviewer_verdict and review.learning_status != LEARNING_PENDING:
        _event(review, actor, "learning_reset", comment="Verdict changed after learning approval",
               detail={"from": review.learning_status})
        review.learning_status = LEARNING_PENDING
        review.learning_approved_by = review.learning_approved_at = review.learning_processed_at = None


def _resync_scan_report(db: Session, scan_id: str) -> None:
    """Refresh the cached TP/FP counts on the scan, which the results endpoint serves."""
    from app.services.scan_runner import sync_findings_report_to_metadata

    sync_findings_report_to_metadata(db, scan_id, force=True)


# --- learning lifecycle -----------------------------------------------------------------


def _move_learning(db: Session, review_ids: Iterable[str], actor: str, *, source: str, target: str,
                   action: str) -> dict[str, int]:
    actor = _clean(actor)
    if not actor:
        raise ReviewError("An actor name is required.")
    moved = skipped = 0
    now = _utcnow()
    for review in db.query(FindingReview).filter(FindingReview.id.in_(list(review_ids))).all():
        if review.learning_status != source:
            skipped += 1
            continue
        review.learning_status = target
        if target == LEARNING_APPROVED:
            review.learning_approved_by, review.learning_approved_at = actor, now
        else:
            review.learning_processed_at = now
        _event(review, actor, action, detail={"from": source, "to": target})
        moved += 1
    db.commit()
    return {"updated": moved, "skipped": skipped}


def approve_for_learning(db: Session, review_ids: Iterable[str], actor: str) -> dict[str, int]:
    return _move_learning(db, review_ids, actor, source=LEARNING_PENDING, target=LEARNING_APPROVED,
                          action="learning_approved")


def mark_processed(db: Session, review_ids: Iterable[str], actor: str) -> dict[str, int]:
    return _move_learning(db, review_ids, actor, source=LEARNING_APPROVED, target=LEARNING_PROCESSED,
                          action="learning_processed")


# --- serialisation ----------------------------------------------------------------------


def event_out(event: FindingReviewEvent) -> dict[str, Any]:
    return {
        "id": event.id, "at": event.at, "actor": event.actor, "action": event.action,
        "from_verdict": event.from_verdict, "to_verdict": event.to_verdict,
        "from_resolution": event.from_resolution, "to_resolution": event.to_resolution,
        "comment": event.comment, "detail": event.detail,
    }


def review_summary(review: FindingReview) -> dict[str, Any]:
    return {
        "review_id": review.id, "reviewer_verdict": review.reviewer_verdict,
        "is_override": bool(review.is_override), "reviewer": review.reviewer,
        "reviewed_at": review.reviewed_at, "comment": review.reviewer_comment,
        "resolution_status": review.resolution_status, "issue_status": review.issue_status,
        "is_closed": bool(review.is_closed), "learning_status": review.learning_status,
    }


def review_out(review: FindingReview, *, with_events: bool = True) -> dict[str, Any]:
    out = _row_from_review(review)
    if with_events:
        out["events"] = [event_out(e) for e in review.events]
    return out


def _row_from_review(review: FindingReview) -> dict[str, Any]:
    return {
        "review_id": review.id, "scan_id": review.scan_id, "project_id": review.project_id,
        "finding_id": review.finding_id, "rule_id": review.rule_id, "cwe": review.cwe,
        "severity": review.severity, "confidence": review.confidence, "file_path": review.file_path,
        "line": review.line, "title": review.title, "kind": review.kind, "snippet": review.snippet,
        "occurrence_count": review.occurrence_count,
        "llm_verdict": review.llm_verdict, "llm_explanation": review.llm_explanation,
        "llm_remediation": review.llm_remediation,
        "reviewer_verdict": review.reviewer_verdict, "is_override": bool(review.is_override),
        "reviewer_comment": review.reviewer_comment, "reviewer": review.reviewer,
        "reviewed_at": review.reviewed_at, "last_reviewed_at": review.last_reviewed_at,
        "review_status": review_status_of(review),
        "resolution_status": review.resolution_status, "resolution_notes": review.resolution_notes,
        "resolved_by": review.resolved_by, "resolved_at": review.resolved_at,
        "issue_status": review.issue_status, "is_closed": bool(review.is_closed),
        "learning_status": review.learning_status,
        "learning_approved_by": review.learning_approved_by,
        "learning_approved_at": review.learning_approved_at,
        "learning_processed_at": review.learning_processed_at,
    }


def _row_from_finding(scan: Scan, finding: Finding) -> dict[str, Any]:
    """An unreviewed group, described from its representative finding."""
    return {
        "review_id": None, "scan_id": scan.id, "project_id": scan.project_id,
        "finding_id": finding.id, "rule_id": finding.rule_id, "cwe": finding.cwe,
        "severity": finding.severity, "confidence": finding.confidence, "file_path": finding.file_path,
        "line": finding.line, "title": finding.title, "kind": finding.kind, "snippet": finding.snippet,
        "occurrence_count": getattr(finding, "occurrence_count", None) or 1,
        "llm_verdict": finding.verdict, "llm_explanation": finding.verdict_reason,
        "llm_remediation": finding.ai_fix,
        "reviewer_verdict": None, "is_override": False, "reviewer_comment": None, "reviewer": None,
        "reviewed_at": None, "last_reviewed_at": None, "review_status": "unreviewed",
        "resolution_status": RESOLUTION_OPEN, "resolution_notes": None, "resolved_by": None,
        "resolved_at": None, "issue_status": "open", "is_closed": False, "learning_status": None,
        "learning_approved_by": None, "learning_approved_at": None, "learning_processed_at": None,
    }


# --- the effective-verdict overlay ------------------------------------------------------


def apply_effective_verdicts(db: Session, scan: Scan, findings: list[Finding]) -> list[Finding]:
    """Overlay reviewer verdicts on loaded findings, in place, without dirtying them.

    `verdict` becomes the effective verdict, `llm_verdict` keeps the original, and `review`
    carries a summary. Uses `set_committed_value`, so nothing is flushed. Because grouping
    keys lead with the verdict, call this *before* `group_findings_by_issue`."""
    by_member = _reviews_by_member(db, scan.id)
    for finding in findings:
        review = by_member.get(finding.id)
        finding.llm_verdict = finding.verdict
        finding.review = review_summary(review) if review else None
        finding.review_state = review_state(review, finding.verdict)
        if review is not None:
            set_committed_value(finding, "verdict", effective_verdict(finding.verdict, review))
    return findings


def effective_verdicts_by_id(db: Session, scan_id: str, rows: list[Finding]) -> dict[str, str | None]:
    """Same mapping without touching the instances (for the report rollup, which shares a session)."""
    by_member = _reviews_by_member(db, scan_id)
    return {row.id: effective_verdict(row.verdict, by_member.get(row.id)) for row in rows}


def effective_scan_findings(db: Session, scan: Scan) -> list[Finding]:
    """The scan's findings with reviewer verdicts applied: what exports and gates should read."""
    return apply_effective_verdicts(db, scan, list(scan.findings or []))


# --- listing ----------------------------------------------------------------------------


def _parse_bound(value: str | None, *, end: bool) -> datetime | None:
    if not value:
        return None
    try:
        if len(value) <= 10:
            d = date.fromisoformat(value)
            return datetime.combine(d, time.max if end else time.min, tzinfo=timezone.utc)
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        raise ReviewError(f"Invalid date '{value}'. Use YYYY-MM-DD or an ISO timestamp.")


def _aware(value: datetime | None) -> datetime | None:
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _same(a: str | None, b: str | None) -> bool:
    return (a or "").strip().lower() == (b or "").strip().lower()


def _matches(row: dict[str, Any], f: dict[str, Any]) -> bool:
    if f.get("reviewer_verdict") and not _same(row["reviewer_verdict"], f["reviewer_verdict"]):
        return False
    if f.get("llm_verdict") and not _same(row["llm_verdict"], f["llm_verdict"]):
        return False
    if f.get("override") is not None and bool(row["is_override"]) != f["override"]:
        return False
    if f.get("severity") and not _same(row["severity"], f["severity"]):
        return False
    if f.get("rule_id") and not _same(row["rule_id"], f["rule_id"]):
        return False
    if f.get("cwe") and not _same(row["cwe"], f["cwe"]):
        return False
    if f.get("reviewer") and (f["reviewer"].strip().lower() not in (row["reviewer"] or "").lower()):
        return False
    if f.get("review_status") and row["review_status"] != f["review_status"]:
        return False
    if f.get("resolution_status") and row["resolution_status"] != f["resolution_status"]:
        return False
    if f.get("issue_status") and row["issue_status"] != f["issue_status"]:
        return False
    if f.get("closed") is not None and bool(row["is_closed"]) != f["closed"]:
        return False
    if f.get("learning_status") and row["learning_status"] != f["learning_status"]:
        return False
    start, end = f.get("reviewed_from"), f.get("reviewed_to")
    if start or end:
        at = _aware(row["reviewed_at"])
        if at is None or (start and at < start) or (end and at > end):
            return False
    q = (f.get("q") or "").strip().lower()
    if q:
        haystack = " ".join(str(row.get(k) or "") for k in ("title", "rule_id", "cwe", "file_path", "reviewer_comment"))
        if q not in haystack.lower():
            return False
    return True


def list_feedback(
    db: Session,
    *,
    scan_id: str | None = None,
    project_id: str | None = None,
    filters: dict[str, Any] | None = None,
    limit: int = 50,
    offset: int = 0,
    visible_scan_ids: Collection[str] | None = None,
) -> dict[str, Any]:
    """Grouped issues joined with their reviews.

    With `scan_id`: every issue group of that scan, reviewed or not. Without it: only
    reviewed items (across scans, optionally one project). Both pass the same filter.
    `visible_scan_ids` (None = all) limits the cross-scan list to scans the caller may see."""
    f = dict(filters or {})
    f["reviewed_from"] = _parse_bound(f.get("reviewed_from"), end=False)
    f["reviewed_to"] = _parse_bound(f.get("reviewed_to"), end=True)

    rows: list[dict[str, Any]] = []
    if scan_id:
        scan = db.get(Scan, scan_id)
        if scan is None:
            raise ReviewError("Scan not found", 404)
        with db.no_autoflush:  # grouping stamps affected_files on the ORM instances
            by_member = _reviews_by_member(db, scan_id)
            findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
            for group in group_findings_by_issue(findings):
                review = by_member.get(group.id)
                rows.append(_row_from_review(review) if review else _row_from_finding(scan, group))
            # A review whose members no longer match any group (verdict moved) still shows up.
            seen = {r["review_id"] for r in rows if r["review_id"]}
            for review in set(by_member.values()):
                if review.id not in seen:
                    rows.append(_row_from_review(review))
    else:
        query = db.query(FindingReview)
        if project_id:
            query = query.filter(FindingReview.project_id == project_id)
        if visible_scan_ids is not None:
            query = query.filter(FindingReview.scan_id.in_(list(visible_scan_ids)))
        rows = [_row_from_review(r) for r in query.all()]

    rows = [r for r in rows if _matches(r, f)]
    rows.sort(key=lambda r: (_aware(r["reviewed_at"]) or datetime.min.replace(tzinfo=timezone.utc)), reverse=True)
    if scan_id:
        # Unreviewed groups first-class: keep severity order inside the unreviewed block.
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        rows.sort(key=lambda r: (r["review_status"] != "unreviewed", order.get((r["severity"] or "").lower(), 4)))
    total = len(rows)
    return {"total": total, "limit": limit, "offset": offset, "items": rows[offset:offset + limit]}


# --- export -----------------------------------------------------------------------------

_EXPORT_FIELDS = (
    "review_id", "scan_id", "project_id", "finding_id", "rule_id", "cwe", "severity", "confidence",
    "file_path", "line", "kind", "title", "snippet", "matched_text", "label", "llm_verdict",
    "llm_explanation", "llm_remediation", "is_override", "reviewer_verdict", "reviewer_comment",
    "reviewer", "reviewed_at", "resolution_status", "resolution_notes", "learning_status",
)


def export_records(db: Session, *, learning_status: str | None = None, project_id: str | None = None) -> list[dict[str, Any]]:
    query = db.query(FindingReview).filter(FindingReview.learning_status.isnot(None))
    if learning_status:
        query = query.filter(FindingReview.learning_status == learning_status)
    if project_id:
        query = query.filter(FindingReview.project_id == project_id)
    records = []
    for review in query.order_by(FindingReview.reviewed_at).all():
        row = _row_from_review(review)
        row["matched_text"] = review.matched_text
        row["label"] = _LLM_EQUIVALENT.get(review.reviewer_verdict)
        row["_review"] = review
        records.append(row)
    return records


def render_export(records: list[dict[str, Any]], fmt: str) -> tuple[str, str]:
    """(body, media type). Records keep only the labelled-data fields."""
    def clean(record: dict[str, Any]) -> dict[str, Any]:
        out = {}
        for key in _EXPORT_FIELDS:
            value = record.get(key)
            out[key] = value.isoformat() if isinstance(value, datetime) else value
        return out

    cleaned = [clean(r) for r in records]
    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=_EXPORT_FIELDS)
        writer.writeheader()
        writer.writerows(cleaned)
        return buf.getvalue(), "text/csv"
    return "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in cleaned), "application/x-ndjson"

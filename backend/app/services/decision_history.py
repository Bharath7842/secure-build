"""One finding's decisions, machine and human, merged in time order (SAST-00-050).

The machine stream is `finding_decisions` (every verdict the scanner gave the
occurrence, append-only). The human stream is the reviewer events of the
`FindingReview` covering the finding. This is a read-side merge only: review
state still lives on `FindingReview`, never on `Finding` (see its docstring).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.models import Finding, FindingDecision
from app.services import feedback


def _aware(value: datetime | None) -> datetime:
    """SQLite hands datetimes back naive; they are stored as UTC."""
    if value is None:
        return datetime.min.replace(tzinfo=timezone.utc)
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def finding_history(db: Session, finding: Finding) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []

    previous_verdict: str | None = None
    machine = (
        db.query(FindingDecision)
        .filter(FindingDecision.finding_id == finding.id)
        .order_by(FindingDecision.at, FindingDecision.id)
        .all()
    )
    for row in machine:
        entries.append({
            "source": "machine",
            "actor": row.stage,
            "at": row.at,
            "from_verdict": previous_verdict,
            "to_verdict": row.verdict,
            "confidence": row.confidence,
            "unresolved_reason": row.unresolved_reason,
            "reason": row.verdict_reason,
            "evidence_version": row.evidence_version,
            "action": None,
        })
        previous_verdict = row.verdict

    review = feedback.find_review(db, finding.scan_id, finding.id)
    if review is not None:
        for event in review.events:
            entries.append({
                "source": "human",
                "actor": event.actor,
                "at": event.at,
                "from_verdict": event.from_verdict,
                "to_verdict": event.to_verdict,
                "confidence": None,
                "unresolved_reason": None,
                "reason": event.comment,
                "evidence_version": None,
                "action": event.action,
            })

    entries.sort(key=lambda entry: _aware(entry["at"]))
    return entries

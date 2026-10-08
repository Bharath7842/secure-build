"""Human triage on a finding: status, assignee, note, and an append-only event row."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models import Finding, FindingTriageEvent

STATUSES = frozenset({"open", "confirmed", "accepted_risk", "suppressed"})


class TriageError(ValueError):
    pass


def apply_triage(
    db: Session,
    finding: Finding,
    *,
    status: str | None = None,
    assignee: str | None = None,
    note: str | None = None,
    actor: str = "",
) -> Finding:
    changes = []
    if status is not None:
        cleaned = status.strip().lower()
        if cleaned not in STATUSES:
            raise TriageError(f"status must be one of: {', '.join(sorted(STATUSES))}")
        finding.triage_status = cleaned
        changes.append(f"status={cleaned}")
    if assignee is not None:
        finding.assignee = assignee.strip()[:120] or None
        changes.append(f"assignee={finding.assignee or ''}")
    if note is not None:
        finding.triage_note = note.strip()[:4000] or None
        changes.append("note")
    if not changes:
        raise TriageError("provide a status, an assignee, or a note")
    db.add(FindingTriageEvent(finding_id=finding.id, actor=(actor or "")[:120], action="update", detail="; ".join(changes)[:500]))
    db.commit()
    db.refresh(finding)
    return finding

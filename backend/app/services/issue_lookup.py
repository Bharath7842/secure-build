"""Find a project's issues by the short id a person types ("fix SB-7F3A9C21").

Read side only. The list is the same grouped view `GET /scans/{id}/findings` serves
(reviewer verdicts applied, confident false positives left out, one row per issue
group), taken from the project's latest finished SAST scan unless a scan is named.
An id matches a group when it is the short id of any occurrence the group stands for,
so an id taken from an older scan keeps resolving after the group's makeup shifts.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.auth.principal import Principal
from app.authz.scope import scope_scans
from app.models import Finding, Scan
from app.services.feedback import apply_effective_verdicts
from app.services.fp_visibility import hide_confident_false_positives
from app.services.occurrence import group_short_id, short_id
from app.services.scan_export import group_findings_by_issue


class IssueLookupError(Exception):
    """A lookup that cannot be answered; `status_code` is the HTTP status to use."""

    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def latest_finished_scan(db: Session, principal: Principal, project_id: str) -> Scan | None:
    """The newest successful SAST scan of the project the caller may see."""
    return (
        scope_scans(db.query(Scan), principal)
        .filter(
            Scan.project_id == project_id,
            Scan.status == "success",
            or_(Scan.scan_type == "sast", Scan.scan_type.is_(None)),
        )
        .order_by(Scan.created_at.desc())
        .first()
    )


def issue_groups(db: Session, scan: Scan) -> list[Finding]:
    """The scan's issue groups, most severe first (group_findings_by_issue's order)."""
    rows = db.query(Finding).filter(Finding.scan_id == scan.id).order_by(Finding.file_path, Finding.line).all()
    visible, _hidden = hide_confident_false_positives(db, scan, apply_effective_verdicts(db, scan, rows))
    return group_findings_by_issue(visible)


def member_short_ids(group: Finding) -> set[str]:
    """Every short id that names `group`: its own and each member's."""
    ids = {short_id(i) for i in (getattr(group, "member_occurrence_ids", None) or [])}
    ids.add(short_id(group.occurrence_id))
    ids.add(group_short_id(group.occurrence_id, getattr(group, "member_occurrence_ids", None)))
    ids.discard(None)
    return ids  # type: ignore[return-value]


def find_group(groups: list[Finding], wanted: str) -> Finding:
    """The one group `wanted` (a normalized `SB-XXXXXXXX`) names.

    Not found is a 404; two different groups sharing the prefix is a 409 listing them,
    because guessing which one a developer meant would fix the wrong code."""
    matches = [g for g in groups if wanted in member_short_ids(g)]
    if not matches:
        raise IssueLookupError(404, f"No issue {wanted} in this scan. It may be fixed already, or from another project.")
    if len(matches) > 1:
        listing = "; ".join(
            f"{group_short_id(g.occurrence_id, getattr(g, 'member_occurrence_ids', None))} {g.title} ({g.file_path}:{g.line})"
            for g in matches[:5]
        )
        raise IssueLookupError(409, f"{wanted} matches {len(matches)} issues: {listing}")
    return matches[0]


@dataclass(frozen=True)
class IssueFilter:
    verdict: str = "true_positive"  # a verdict, or "all"
    limit: int = 10


def filter_groups(groups: list[Finding], flt: IssueFilter) -> list[Finding]:
    if flt.verdict == "all":
        return list(groups)
    return [g for g in groups if g.verdict == flt.verdict]

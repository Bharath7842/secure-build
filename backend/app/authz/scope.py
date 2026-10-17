"""Which scans a caller may see and act on.

A scan outside the caller's scope answers 404, exactly like a scan that
doesn't exist, so scan ids can't be probed. A visible scan the caller may
not act on answers 403.
"""

from __future__ import annotations

from fastapi import HTTPException, status
from sqlalchemy import false
from sqlalchemy.orm import Query, Session

from app.auth.principal import Principal, forbidden
from app.models import Project, Scan


def can_see_project(principal: Principal, project: Project) -> bool:
    """Admins see every project; other users only the ones they created. The CI
    token is a pipeline, not a person, so it works on any project (the
    documented CI flow)."""
    if principal.kind == "service" or principal.can("projects.view_all"):
        return True
    return principal.user_id is not None and project.created_by_user_id == principal.user_id


def can_see_scan(principal: Principal, scan: Scan) -> bool:
    if principal.can("scans.view_all"):
        return True
    return (
        principal.can("scans.view_own")
        and principal.user_id is not None
        and scan.created_by_user_id == principal.user_id
    )


def can_stop_scan(principal: Principal, scan: Scan) -> bool:
    """Cancel, pause and resume."""
    if principal.can("scans.cancel_any"):
        return True
    return (
        principal.can("scans.cancel_own")
        and principal.user_id is not None
        and scan.created_by_user_id == principal.user_id
    )


def authorize_scan(db: Session, principal: Principal, scan_id: str, action: str | None = None) -> Scan:
    """The scan, if `principal` may see it (else 404) and, when given, holds
    `action` (else 403)."""
    scan = db.get(Scan, scan_id)
    if scan is None or not can_see_scan(principal, scan):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    if action and not principal.can(action):
        raise forbidden()
    return scan


def scope_scans(query: Query, principal: Principal) -> Query:
    """`query` (over Scan) narrowed to the scans `principal` may see."""
    if principal.can("scans.view_all"):
        return query
    if principal.can("scans.view_own") and principal.user_id:
        return query.filter(Scan.created_by_user_id == principal.user_id)
    return query.filter(false())

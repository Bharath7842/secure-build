"""The audit log, newest first."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.auth.principal import Principal, require
from app.db import get_db
from app.models import AuditEvent
from app.routers.admin_users import event_out

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/audit")
def list_audit_events(
    actor: str | None = Query(default=None, max_length=254, description="User id, or part of an email"),
    action: str | None = Query(default=None, max_length=64, description="Exact action, or a prefix ending in '.'"),
    outcome: str | None = Query(default=None),
    target_type: str | None = Query(default=None, max_length=32),
    target_id: str | None = Query(default=None, max_length=64),
    since: datetime | None = Query(default=None, alias="from"),
    until: datetime | None = Query(default=None, alias="to"),
    cursor: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    _: Principal = Depends(require("audit.view")),
    db: Session = Depends(get_db),
):
    query = db.query(AuditEvent)
    if actor:
        query = query.filter(or_(AuditEvent.actor_user_id == actor, AuditEvent.actor_label.ilike(f"%{actor}%")))
    if action:
        query = query.filter(AuditEvent.action.startswith(action) if action.endswith(".") else AuditEvent.action == action)
    if outcome:
        query = query.filter(AuditEvent.outcome == outcome)
    if target_type:
        query = query.filter(AuditEvent.target_type == target_type)
    if target_id:
        query = query.filter(AuditEvent.target_id == target_id)
    if since:
        query = query.filter(AuditEvent.at >= since)
    if until:
        query = query.filter(AuditEvent.at <= until)
    rows = query.order_by(AuditEvent.at.desc(), AuditEvent.id).offset(cursor).limit(limit + 1).all()
    return {
        "items": [event_out(e) for e in rows[:limit]],
        "next_cursor": cursor + limit if len(rows) > limit else None,
    }

"""Writing and pruning audit events.

`details` is for context such as old/new role or a permission diff. Keys that
look like secrets are dropped before anything is written, at any depth, so a
careless caller can't put a password or token in the log.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.config import settings
from app.models import AuditEvent

_SECRET_KEY_RE = re.compile(r"passw(or)?d|passphrase|secret|token|api[_-]?key|authori[sz]ation|cookie|session|credential", re.I)
_MAX_STRING = 500
_MAX_ITEMS = 50


def scrub(value: Any) -> Any:
    """`value` with secret-looking dict keys removed and sizes capped."""
    if isinstance(value, dict):
        return {
            str(k)[:64]: scrub(v)
            for k, v in list(value.items())[:_MAX_ITEMS]
            if not _SECRET_KEY_RE.search(str(k))
        }
    if isinstance(value, (list, tuple)):
        return [scrub(v) for v in list(value)[:_MAX_ITEMS]]
    if isinstance(value, str):
        return value[:_MAX_STRING]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:_MAX_STRING]


def record(
    db: Session,
    action: str,
    *,
    outcome: str = "success",
    actor_user_id: str | None = None,
    actor_label: str = "",
    target_type: str | None = None,
    target_id: str | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
    details: dict | None = None,
    commit: bool = True,
) -> AuditEvent:
    event = AuditEvent(
        action=action,
        outcome=outcome,
        actor_user_id=actor_user_id,
        actor_label=(actor_label or "")[:254],
        target_type=target_type,
        target_id=target_id,
        ip=(ip or None) and ip[:64],
        user_agent=(user_agent or None) and user_agent[:256],
        details=scrub(details or {}),
    )
    db.add(event)
    if commit:
        db.commit()
    return event


def purge_old_events(db: Session, now: datetime | None = None) -> int:
    """Delete events older than AUDIT_RETENTION_DAYS."""
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=settings.audit_retention_days)
    count = db.query(AuditEvent).filter(AuditEvent.at < cutoff).delete(synchronize_session=False)
    db.commit()
    return count

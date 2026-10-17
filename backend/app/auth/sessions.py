"""Server-side sessions and single-use account tokens (invites, resets).

The browser holds an opaque random token; the database holds only its
SHA-256, so revoking a session is a row update and a leaked database copy
contains no usable sessions. Every function takes an optional `now` so tests
can move the clock.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.config import settings
from app.models import User, UserSession, UserToken

# How stale last_seen_at may get before a request writes it again. Keeps a busy
# page (log polling every few seconds) from writing to SQLite on every call.
LAST_SEEN_WRITE_INTERVAL = timedelta(seconds=60)


def _now(now: datetime | None) -> datetime:
    return now or datetime.now(timezone.utc)


def as_utc(value: datetime | None) -> datetime | None:
    """SQLite hands timezone-aware columns back naive; they were stored as UTC."""
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=timezone.utc)


def new_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(
    db: Session,
    user: User,
    *,
    remember: bool = False,
    ip: str | None = None,
    user_agent: str | None = None,
    now: datetime | None = None,
) -> tuple[str, UserSession]:
    """Start a session for `user` and return (token for the cookie, row)."""
    now = _now(now)
    token = new_token()
    if remember:
        absolute = now + timedelta(days=settings.session_remember_days)
        idle = None
    else:
        absolute = now + timedelta(hours=settings.session_absolute_hours)
        idle = min(absolute, now + timedelta(minutes=settings.session_idle_minutes))
    row = UserSession(
        token_hash=hash_token(token),
        user_id=user.id,
        remember=remember,
        created_at=now,
        last_seen_at=now,
        idle_expires_at=idle,
        absolute_expires_at=absolute,
        ip=(ip or None) and ip[:64],
        user_agent=(user_agent or None) and user_agent[:256],
    )
    db.add(row)
    db.commit()
    return token, row


def _is_live(row: UserSession, now: datetime) -> bool:
    if row.revoked_at is not None:
        return False
    if as_utc(row.absolute_expires_at) <= now:
        return False
    idle = as_utc(row.idle_expires_at)
    return idle is None or idle > now


def resolve_session(db: Session, token: str | None, now: datetime | None = None) -> UserSession | None:
    """The live session for `token`, or None when it is unknown, revoked,
    expired, or belongs to a disabled user. Slides the idle expiry forward."""
    if not token:
        return None
    now = _now(now)
    row = db.query(UserSession).filter(UserSession.token_hash == hash_token(token)).one_or_none()
    if row is None or not _is_live(row, now) or not row.user.is_active:
        return None
    if now - as_utc(row.last_seen_at) >= LAST_SEEN_WRITE_INTERVAL:
        row.last_seen_at = now
        if row.idle_expires_at is not None:
            row.idle_expires_at = min(
                as_utc(row.absolute_expires_at), now + timedelta(minutes=settings.session_idle_minutes)
            )
        db.commit()
    return row


def revoke_session(db: Session, row: UserSession, reason: str, now: datetime | None = None) -> None:
    if row.revoked_at is None:
        row.revoked_at = _now(now)
        row.revoked_reason = reason
        db.commit()


def revoke_user_sessions(
    db: Session,
    user_id: str,
    reason: str,
    *,
    except_session_id: str | None = None,
    now: datetime | None = None,
) -> int:
    """Revoke every live session of a user (optionally keeping one). Returns
    how many were revoked."""
    query = db.query(UserSession).filter(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
    if except_session_id:
        query = query.filter(UserSession.id != except_session_id)
    count = query.update(
        {UserSession.revoked_at: _now(now), UserSession.revoked_reason: reason}, synchronize_session=False
    )
    db.commit()
    return count


def rotate_session(db: Session, row: UserSession) -> str:
    """Give an existing session a new token (after a password change) and
    return it; the old token stops working."""
    token = new_token()
    row.token_hash = hash_token(token)
    db.commit()
    return token


def purge_expired_sessions(db: Session, now: datetime | None = None) -> int:
    """Delete sessions past their absolute expiry or revoked over a day ago."""
    now = _now(now)
    count = (
        db.query(UserSession)
        .filter(
            (UserSession.absolute_expires_at <= now)
            | (UserSession.revoked_at <= now - timedelta(days=1))
        )
        .delete(synchronize_session=False)
    )
    db.commit()
    return count


def issue_user_token(
    db: Session,
    user: User,
    purpose: str,
    *,
    created_by_user_id: str | None = None,
    now: datetime | None = None,
) -> tuple[str, UserToken]:
    """Create an invite or reset token for `user`, retiring any unused one of
    the same purpose, and return (token for the link, row)."""
    if purpose not in ("invite", "reset"):
        raise ValueError(f"unknown token purpose {purpose!r}")
    now = _now(now)
    db.query(UserToken).filter(
        UserToken.user_id == user.id, UserToken.purpose == purpose, UserToken.used_at.is_(None)
    ).update({UserToken.used_at: now}, synchronize_session=False)
    hours = settings.invite_ttl_hours if purpose == "invite" else settings.reset_ttl_hours
    token = new_token()
    row = UserToken(
        token_hash=hash_token(token),
        user_id=user.id,
        purpose=purpose,
        expires_at=now + timedelta(hours=hours),
        created_at=now,
        created_by_user_id=created_by_user_id,
    )
    db.add(row)
    db.commit()
    return token, row


def peek_user_token(db: Session, token: str | None, now: datetime | None = None) -> UserToken | None:
    """The valid, unused, unexpired token row for `token`, left untouched; None otherwise."""
    if not token:
        return None
    row = db.query(UserToken).filter(UserToken.token_hash == hash_token(token)).one_or_none()
    if row is None or row.used_at is not None or as_utc(row.expires_at) <= _now(now):
        return None
    return row


def consume_user_token(db: Session, token: str | None, now: datetime | None = None) -> UserToken | None:
    """Mark a valid, unused, unexpired token as used and return it; None
    otherwise. The caller commits whatever it changes alongside."""
    if not token:
        return None
    now = _now(now)
    row = db.query(UserToken).filter(UserToken.token_hash == hash_token(token)).one_or_none()
    if row is None or row.used_at is not None or as_utc(row.expires_at) <= now:
        return None
    row.used_at = now
    return row

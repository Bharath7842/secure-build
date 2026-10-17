"""User management for admins: create (by invite link), edit, disable,
role and permission changes, and reset links. Every change is audited."""

from __future__ import annotations

import threading
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.auth import passwords, sessions
from app.auth.principal import ApiError, Principal, record, require
from app.auth.schemas import OneTimeLinkOut, PermissionsIn, UserCreateIn, UserOut, UserUpdateIn
from app.authz import catalog
from app.config import settings
from app.db import get_db
from app.models import AuditEvent, User, UserPermissionOverride

router = APIRouter(prefix="/admin", tags=["admin"])

_MANAGE = require("users.manage")

# Serializes role/status changes so the last-admin check can't race (one process).
_admin_change_lock = threading.Lock()


def _get_user(db: Session, user_id: str) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise ApiError(404, "not_found", "User not found")
    return user


def _link(token: str) -> str:
    return f"{settings.public_app_url.rstrip('/')}/account/setup#t={token}"


def _access(user: User) -> dict:
    overrides = user.overrides if user.role == catalog.USER else {}
    return {
        "overrides": overrides,
        "effective": sorted(catalog.effective_permissions(user.role, overrides)),
        "inactive": [
            {"key": k, "missing": missing}
            for k, missing in catalog.inactive_permissions(user.role, overrides).items()
        ],
    }


def _replace_overrides(db: Session, user: User, overrides: dict[str, str], actor_id: str | None) -> list[str]:
    """Validate, fill in requirements and store `overrides` for a regular user.
    Returns the requirement keys that were added."""
    try:
        catalog.validate_overrides(overrides)
    except ValueError as exc:
        raise ApiError(400, "invalid_permissions", str(exc)) from exc
    overrides, added = catalog.with_requirements(overrides)
    user.permission_overrides.clear()
    db.flush()
    for key, effect in sorted(overrides.items()):
        user.permission_overrides.append(
            UserPermissionOverride(permission_key=key, effect=effect, created_by_user_id=actor_id)
        )
    return added


def _other_active_admins(db: Session, user: User) -> int:
    return (
        db.query(User)
        .filter(User.role == catalog.ADMIN, User.is_active.is_(True), User.id != user.id)
        .count()
    )


@router.get("/permissions/catalog")
def permission_catalog(_: Principal = Depends(_MANAGE)):
    return {"permissions": catalog.catalog_entries(), "roles": list(catalog.ROLES)}


@router.get("/users")
def list_users(
    q: str | None = Query(default=None, max_length=200),
    role: str | None = Query(default=None),
    status: str | None = Query(default=None, description="active | invited | disabled"),
    cursor: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    _: Principal = Depends(_MANAGE),
    db: Session = Depends(get_db),
):
    query = db.query(User)
    if q and q.strip():
        like = f"%{q.strip().lower()}%"
        query = query.filter(or_(User.email_normalized.like(like), User.display_name.ilike(like)))
    if role:
        query = query.filter(User.role == role)
    if status == "disabled":
        query = query.filter(User.is_active.is_(False))
    elif status == "invited":
        query = query.filter(User.is_active.is_(True), User.password_hash.is_(None))
    elif status == "active":
        query = query.filter(User.is_active.is_(True), User.password_hash.is_not(None))
    rows = query.order_by(User.created_at, User.id).offset(cursor).limit(limit + 1).all()
    return {
        "items": [UserOut.model_validate(u).model_dump(mode="json") for u in rows[:limit]],
        "next_cursor": cursor + limit if len(rows) > limit else None,
    }


@router.post("/users", status_code=201)
def create_user(
    body: UserCreateIn,
    request: Request,
    principal: Principal = Depends(_MANAGE),
    db: Session = Depends(get_db),
):
    """Create an invited user (no password yet) and return their one-time
    invite link. The link is shown once; it isn't stored or logged."""
    email = passwords.normalize_email(body.email)
    if db.query(User.id).filter(User.email_normalized == email).first():
        raise ApiError(409, "email_taken", "A user with this email already exists.")
    user = User(
        email=body.email,
        email_normalized=email,
        display_name=body.display_name.strip(),
        role=body.role,
        created_by_user_id=principal.user_id,
    )
    db.add(user)
    db.flush()
    added: list[str] = []
    if body.role == catalog.USER and body.overrides:
        added = _replace_overrides(db, user, body.overrides, principal.user_id)
    db.commit()
    token, row = sessions.issue_user_token(db, user, "invite", created_by_user_id=principal.user_id)
    record(db, request, "user.created", principal, target_type="user", target_id=user.id,
           details={"email": user.email, "role": user.role, "overrides": user.overrides})
    return {
        "user": UserOut.model_validate(user).model_dump(mode="json"),
        **_access(user),
        "added_dependencies": added,
        "invite_url": _link(token),
        "invite_expires_at": sessions.as_utc(row.expires_at),
    }


@router.get("/users/{user_id}")
def get_user(user_id: str, _: Principal = Depends(_MANAGE), db: Session = Depends(get_db)):
    user = _get_user(db, user_id)
    activity = (
        db.query(AuditEvent)
        .filter(or_(AuditEvent.actor_user_id == user.id, (AuditEvent.target_type == "user") & (AuditEvent.target_id == user.id)))
        .order_by(AuditEvent.at.desc())
        .limit(20)
        .all()
    )
    return {
        "user": UserOut.model_validate(user).model_dump(mode="json"),
        **_access(user),
        "recent_activity": [event_out(e) for e in activity],
    }


@router.patch("/users/{user_id}")
def update_user(
    user_id: str,
    body: UserUpdateIn,
    request: Request,
    principal: Principal = Depends(_MANAGE),
    db: Session = Depends(get_db),
):
    with _admin_change_lock:
        # populate_existing: both rows may already sit in this session from
        # authentication; re-read them now that we hold the lock.
        user = db.get(User, user_id, populate_existing=True)
        if user is None:
            raise ApiError(404, "not_found", "User not found")
        demoting = body.role is not None and body.role != user.role and user.role == catalog.ADMIN
        disabling = body.is_active is False and user.is_active
        if demoting or disabling:
            # Two admins demoting each other at once must not both succeed: the
            # lock serializes the changes, and each re-reads who is still admin.
            actor = db.get(User, principal.user_id, populate_existing=True)
            if actor is None or actor.role != catalog.ADMIN or not actor.is_active:
                raise ApiError(403, "forbidden", "You no longer have permission to do this.")
        return _apply_user_update(db, request, principal, user, body, demoting, disabling)


def _apply_user_update(db, request, principal, user, body, demoting, disabling):
    changes: dict[str, dict] = {}
    if (body.role is not None and body.role != user.role) and user.id == principal.user_id:
        raise ApiError(409, "cannot_change_own_role", "You can't change your own role.")
    if disabling and user.id == principal.user_id:
        raise ApiError(409, "cannot_disable_self", "You can't disable your own account.")
    if (demoting or disabling) and user.role == catalog.ADMIN and user.is_active and _other_active_admins(db, user) == 0:
        raise ApiError(409, "last_admin", "This is the only active admin. Make someone else an admin first.")

    if body.display_name is not None and body.display_name.strip() != user.display_name:
        changes["display_name"] = {"from": user.display_name, "to": body.display_name.strip()}
        user.display_name = body.display_name.strip()
    if body.role is not None and body.role != user.role:
        changes["role"] = {"from": user.role, "to": body.role}
        user.role = body.role
    if body.is_active is not None and body.is_active != user.is_active:
        changes["is_active"] = {"from": user.is_active, "to": body.is_active}
        user.is_active = body.is_active
        if body.is_active:
            user.disabled_at = None
            user.disabled_by_user_id = None
        else:
            user.disabled_at = datetime.now(timezone.utc)
            user.disabled_by_user_id = principal.user_id
    db.commit()

    if disabling:
        sessions.revoke_user_sessions(db, user.id, "disabled")
    elif demoting:
        sessions.revoke_user_sessions(db, user.id, "role_changed")
    for field, change in changes.items():
        action = {"role": "user.role.changed", "is_active": "user.enabled" if user.is_active else "user.disabled"}.get(
            field, "user.updated"
        )
        record(db, request, action, principal, target_type="user", target_id=user.id,
               details={"field": field, **change})
    return {"user": UserOut.model_validate(user).model_dump(mode="json"), **_access(user)}


@router.put("/users/{user_id}/permissions")
def set_permissions(
    user_id: str,
    body: PermissionsIn,
    request: Request,
    principal: Principal = Depends(_MANAGE),
    db: Session = Depends(get_db),
):
    """Replace a regular user's overrides. Requirements of a granted key are
    granted too (listed in `added_dependencies`)."""
    user = _get_user(db, user_id)
    if user.role == catalog.ADMIN:
        raise ApiError(409, "admin_has_full_access", "Admins always have full access; overrides don't apply.")
    before = user.overrides
    added = _replace_overrides(db, user, body.overrides, principal.user_id)
    db.commit()
    after = user.overrides
    record(db, request, "user.permissions.changed", principal, target_type="user", target_id=user.id,
           details={
               "added": {k: v for k, v in after.items() if before.get(k) != v},
               "removed": sorted(set(before) - set(after)),
           })
    return {**_access(user), "added_dependencies": added}


@router.post("/users/{user_id}/invite-link", response_model=OneTimeLinkOut)
def new_invite_link(user_id: str, request: Request, principal: Principal = Depends(_MANAGE), db: Session = Depends(get_db)):
    """A fresh invite link for a user who hasn't set a password yet. The
    previous link stops working."""
    user = _get_user(db, user_id)
    if user.status != "invited":
        raise ApiError(409, "not_invited", "This user has already set a password. Send a reset link instead.")
    token, row = sessions.issue_user_token(db, user, "invite", created_by_user_id=principal.user_id)
    record(db, request, "user.invite.issued", principal, target_type="user", target_id=user.id)
    return OneTimeLinkOut(url=_link(token), expires_at=sessions.as_utc(row.expires_at))


@router.post("/users/{user_id}/reset-link", response_model=OneTimeLinkOut)
def new_reset_link(user_id: str, request: Request, principal: Principal = Depends(_MANAGE), db: Session = Depends(get_db)):
    """A one-time password reset link. The user's sessions end when they use it."""
    user = _get_user(db, user_id)
    if user.status != "active":
        raise ApiError(409, "not_active", "Only active users with a password can be sent a reset link.")
    token, row = sessions.issue_user_token(db, user, "reset", created_by_user_id=principal.user_id)
    record(db, request, "user.reset.issued", principal, target_type="user", target_id=user.id)
    return OneTimeLinkOut(url=_link(token), expires_at=sessions.as_utc(row.expires_at))


def event_out(e: AuditEvent) -> dict:
    return {
        "id": e.id,
        "at": sessions.as_utc(e.at),
        "actor_user_id": e.actor_user_id,
        "actor_label": e.actor_label,
        "action": e.action,
        "outcome": e.outcome,
        "target_type": e.target_type,
        "target_id": e.target_id,
        "ip": e.ip,
        "details": e.details or {},
    }

"""Sign-in, sign-out, the current user, password changes and invite/reset links.

Called by the Next.js server, which keeps the session token in an HttpOnly
cookie and forwards it as `Authorization: Session <token>`.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.auth import passwords, ratelimit, sessions
from app.auth.principal import ApiError, Principal, client_ip, public, record, require_user, user_agent
from app.auth.schemas import ChangePasswordIn, LoginIn, SessionOut, TokenIn, TokenPasswordIn, UserOut
from app.authz.catalog import BY_KEY, effective_permissions, landing_path
from app.db import get_db
from app.models import User, UserSession

router = APIRouter(prefix="/auth", tags=["auth"])

_INVALID_CREDENTIALS = ApiError(401, "invalid_credentials", "Invalid email or password")


def too_many_attempts(retry_after: int) -> ApiError:
    minutes = max(1, round(retry_after / 60))
    return ApiError(
        429,
        "too_many_attempts",
        f"Too many attempts. Try again in {minutes} minute{'s' if minutes != 1 else ''}.",
        headers={"Retry-After": str(retry_after)},
    )


def check_ip_limit(request: Request) -> None:
    """Count one attempt from this address, or refuse when it has used up its window."""
    key = client_ip(request) or "unknown"
    wait = ratelimit.attempts_by_ip.retry_after(key)
    if wait:
        raise too_many_attempts(wait)
    ratelimit.attempts_by_ip.hit(key)


def start_session(db: Session, request: Request, user: User, remember: bool) -> SessionOut:
    token, row = sessions.create_session(
        db, user, remember=remember, ip=client_ip(request), user_agent=user_agent(request)
    )
    held = effective_permissions(user.role, user.overrides)
    return SessionOut(
        token=token,
        expires_at=sessions.as_utc(row.absolute_expires_at),
        remember=remember,
        user=UserOut.model_validate(user),
        landing=landing_path(held),
        pages=sorted(k for k in held if BY_KEY[k].kind == "page"),
    )


def set_password(db: Session, user: User, password: str) -> None:
    problem = passwords.password_problem(password, user.email)
    if problem:
        raise ApiError(400, "weak_password", problem)
    user.password_hash = passwords.hash_password(password)
    user.password_changed_at = datetime.now(timezone.utc)
    user.failed_login_count = 0


@router.post("/login", response_model=SessionOut, dependencies=[Depends(public)])
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    check_ip_limit(request)
    email = passwords.normalize_email(body.email)
    wait = ratelimit.failures_by_email.retry_after(email)
    if wait:
        record(db, request, "auth.login.failed", outcome="denied", actor_label=email,
               details={"reason": "rate_limited"})
        raise too_many_attempts(wait)

    user = db.query(User).filter(User.email_normalized == email).one_or_none()
    ok, new_hash = passwords.verify_password(body.password, user.password_hash if user else None)
    if not ok or user is None or not user.is_active:
        ratelimit.failures_by_email.hit(email)
        reason = "unknown_email" if user is None else ("wrong_password" if not ok else "disabled")
        if user is not None:
            user.failed_login_count = (user.failed_login_count or 0) + 1
        record(db, request, "auth.login.failed", outcome="failure", actor_label=email,
               actor_user_id=user.id if user else None, target_type="user",
               target_id=user.id if user else None, details={"reason": reason})
        raise _INVALID_CREDENTIALS

    ratelimit.failures_by_email.reset(email)
    if new_hash:
        user.password_hash = new_hash
    user.failed_login_count = 0
    user.last_login_at = datetime.now(timezone.utc)
    out = start_session(db, request, user, body.remember)
    record(db, request, "auth.login.succeeded", actor_user_id=user.id, actor_label=user.email,
           target_type="user", target_id=user.id, details={"remember": body.remember})
    return out


@router.post("/logout", status_code=204)
def logout(request: Request, principal: Principal = Depends(require_user), db: Session = Depends(get_db)):
    row = db.get(UserSession, principal.session_id)
    if row is not None:
        sessions.revoke_session(db, row, "logout")
    record(db, request, "auth.logout", principal, target_type="user", target_id=principal.user_id)


@router.get("/me")
def me(principal: Principal = Depends(require_user), db: Session = Depends(get_db)):
    user = db.get(User, principal.user_id)
    held = sorted(principal.permissions)
    return {
        "user": UserOut.model_validate(user).model_dump(mode="json"),
        "permissions": [k for k in held if BY_KEY[k].kind == "action"],
        "pages": [k for k in held if BY_KEY[k].kind == "page"],
        "landing": landing_path(held),
    }


@router.post("/password")
def change_password(
    body: ChangePasswordIn,
    request: Request,
    principal: Principal = Depends(require_user),
    db: Session = Depends(get_db),
):
    """Change your own password. Signs out your other sessions and gives this
    one a new token, which the caller must store in place of the old one."""
    user = db.get(User, principal.user_id)
    if not passwords.verify_password(body.current_password, user.password_hash)[0]:
        record(db, request, "user.password.changed", principal, outcome="failure",
               target_type="user", target_id=user.id, details={"reason": "wrong_current_password"})
        raise ApiError(400, "wrong_current_password", "Your current password is incorrect.")
    set_password(db, user, body.new_password)
    db.commit()
    sessions.revoke_user_sessions(db, user.id, "password_changed", except_session_id=principal.session_id)
    row = db.get(UserSession, principal.session_id)
    token = sessions.rotate_session(db, row)
    record(db, request, "user.password.changed", principal, target_type="user", target_id=user.id)
    return {"token": token, "remember": row.remember, "expires_at": sessions.as_utc(row.absolute_expires_at)}


@router.post("/setup/preview", dependencies=[Depends(public)])
def preview_link(body: TokenIn, request: Request, db: Session = Depends(get_db)):
    """Whose account an invite or reset link is for, without using the link up.
    The token is the credential: only its holder learns the email."""
    check_ip_limit(request)
    row = sessions.peek_user_token(db, body.token)
    user = db.get(User, row.user_id) if row else None
    if row is None or user is None or not user.is_active:
        raise ApiError(400, "invalid_or_expired_token", "This link is invalid or has expired. Ask your administrator for a new one.")
    return {"email": user.email, "purpose": row.purpose}


@router.post("/setup", dependencies=[Depends(public)])
def accept_link(body: TokenPasswordIn, request: Request, db: Session = Depends(get_db)):
    """Set a password from an invite or reset link. Accepting a reset signs
    the user out everywhere."""
    check_ip_limit(request)
    row = sessions.consume_user_token(db, body.token)
    user = db.get(User, row.user_id) if row else None
    if row is None or user is None or not user.is_active:
        db.rollback()
        record(db, request, "user.link.rejected", outcome="failure")
        raise ApiError(400, "invalid_or_expired_token", "This link is invalid or has expired. Ask your administrator for a new one.")
    try:
        set_password(db, user, body.password)
    except ApiError:
        db.rollback()  # keep the link usable so the user can pick a stronger password
        raise
    db.commit()
    if row.purpose == "reset":
        sessions.revoke_user_sessions(db, user.id, "password_reset")
    action = "user.invite.accepted" if row.purpose == "invite" else "user.password.reset"
    record(db, request, action, actor_user_id=user.id, actor_label=user.email, target_type="user", target_id=user.id)
    return {"ok": True, "email": user.email}


@router.get("/sessions")
def list_sessions(principal: Principal = Depends(require_user), db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc)
    rows = (
        db.query(UserSession)
        .filter(UserSession.user_id == principal.user_id, UserSession.revoked_at.is_(None))
        .order_by(UserSession.last_seen_at.desc())
        .all()
    )
    return [
        {
            "id": r.id,
            "created_at": sessions.as_utc(r.created_at),
            "last_seen_at": sessions.as_utc(r.last_seen_at),
            "ip": r.ip,
            "user_agent": r.user_agent,
            "remember": r.remember,
            "current": r.id == principal.session_id,
        }
        for r in rows
        if sessions.as_utc(r.absolute_expires_at) > now
    ]


@router.post("/sessions/revoke-others")
def revoke_other_sessions(request: Request, principal: Principal = Depends(require_user), db: Session = Depends(get_db)):
    count = sessions.revoke_user_sessions(
        db, principal.user_id, "signed_out_elsewhere", except_session_id=principal.session_id
    )
    record(db, request, "auth.sessions.revoked", principal, target_type="user", target_id=principal.user_id,
           details={"count": count})
    return {"revoked": count}

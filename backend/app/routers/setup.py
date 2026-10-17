"""First-admin setup. Open only while there are no users at all, and only to
someone who knows SETUP_TOKEN from the server's .env. Closes for good as soon
as one user exists."""

from __future__ import annotations

import hmac
import threading

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.auth import passwords
from app.auth.principal import ApiError, public, record
from app.auth.schemas import SessionOut, SetupIn
from app.config import settings
from app.db import get_db
from app.models import User
from app.routers.auth import check_ip_limit, set_password, start_session

router = APIRouter(prefix="/setup", tags=["auth"], dependencies=[Depends(public)])

SETUP_TOKEN_MIN_LENGTH = 32

# Two submits racing on an empty database must not both create an admin.
_setup_lock = threading.Lock()


def _configured_token() -> str | None:
    token = settings.setup_token.get_secret_value() if settings.setup_token else ""
    return token if len(token) >= SETUP_TOKEN_MIN_LENGTH else None


def _has_users(db: Session) -> bool:
    return db.query(User.id).first() is not None


@router.get("/status")
def setup_status(db: Session = Depends(get_db)):
    """`open`: the setup form can be used now. `configured`: SETUP_TOKEN is
    set (and long enough) on the server."""
    has_users = _has_users(db)
    configured = _configured_token() is not None
    return {"open": not has_users and configured, "configured": configured, "has_users": has_users}


@router.post("", response_model=SessionOut, status_code=201)
def create_first_admin(body: SetupIn, request: Request, db: Session = Depends(get_db)):
    if _has_users(db):
        raise ApiError(404, "not_found", "Not found")
    expected = _configured_token()
    if expected is None:
        raise ApiError(
            503,
            "setup_not_configured",
            f"Set SETUP_TOKEN (at least {SETUP_TOKEN_MIN_LENGTH} characters) in the backend .env and restart.",
        )
    check_ip_limit(request)
    if not hmac.compare_digest(body.setup_token.encode(), expected.encode()):
        record(db, request, "admin.bootstrap", outcome="failure", actor_label=passwords.normalize_email(body.email),
               details={"reason": "invalid_setup_token"})
        raise ApiError(403, "invalid_setup_token", "The setup token is incorrect.")

    with _setup_lock:
        if _has_users(db):
            raise ApiError(404, "not_found", "Not found")
        user = User(
            email=body.email,
            email_normalized=passwords.normalize_email(body.email),
            display_name=body.display_name.strip(),
            role="admin",
        )
        set_password(db, user, body.password)
        db.add(user)
        db.commit()
    record(db, request, "admin.bootstrap", actor_user_id=user.id, actor_label=user.email,
           target_type="user", target_id=user.id)
    return start_session(db, request, user, remember=False)

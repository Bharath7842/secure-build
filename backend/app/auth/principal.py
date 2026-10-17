"""Who is calling, and what they may do.

Two kinds of caller:
- a signed-in user: `Authorization: Session <token>`, forwarded by the Next.js
  server from the browser's HttpOnly cookie;
- CI: `Authorization: Bearer <SAST_API_TOKEN>`, with the fixed
  `CI_SERVICE_PERMISSIONS` scope.

Permissions are worked out from the database on every request, so a role or
permission change applies on the user's next request without signing them out.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass

from fastapi import Depends, Header, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.auth import sessions
from app.authz.catalog import CI_SERVICE_PERMISSIONS, effective_permissions
from app.config import settings
from app.db import get_db
from app.services import audit


class ApiError(Exception):
    """An error answered as `{"detail": <message>, "code": <code>}`. `detail`
    stays a plain string, like FastAPI's own errors, so the frontend keeps
    reading it the same way."""

    def __init__(self, status_code: int, code: str, detail: str, headers: dict | None = None):
        super().__init__(detail)
        self.status_code = status_code
        self.code = code
        self.detail = detail
        self.headers = headers


async def api_error_handler(_request: Request, exc: ApiError) -> JSONResponse:
    return JSONResponse(
        {"detail": exc.detail, "code": exc.code}, status_code=exc.status_code, headers=exc.headers
    )


def unauthenticated() -> ApiError:
    return ApiError(401, "unauthenticated", "Authentication required")


def forbidden(detail: str = "You don't have permission to do this.") -> ApiError:
    return ApiError(403, "forbidden", detail)


@dataclass(frozen=True)
class Principal:
    kind: str  # "user" | "service"
    permissions: frozenset[str]
    user_id: str | None = None
    email: str = ""
    role: str | None = None
    session_id: str | None = None

    @property
    def label(self) -> str:
        return self.email if self.kind == "user" else "ci-token"

    def can(self, key: str) -> bool:
        return key in self.permissions


def client_ip(request: Request) -> str | None:
    """The browser's address. Behind the Next.js server every request comes
    from it, so its X-Client-IP is used, but only when it also proves itself
    with X-Frontend-Key."""
    secret = settings.frontend_proxy_secret
    forwarded = request.headers.get("x-client-ip")
    if secret and forwarded:
        key = request.headers.get("x-frontend-key") or ""
        if hmac.compare_digest(key.encode(), secret.get_secret_value().encode()):
            return forwarded.strip()[:64]
    return request.client.host if request.client else None


def user_agent(request: Request) -> str | None:
    return request.headers.get("user-agent")


def get_principal(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> Principal:
    scheme, _, credential = (authorization or "").partition(" ")
    credential = credential.strip()
    if scheme.lower() == "bearer" and credential:
        if hmac.compare_digest(credential.encode(), settings.sast_api_token.encode()):
            return Principal(kind="service", permissions=CI_SERVICE_PERMISSIONS)
    elif scheme.lower() == "session" and credential:
        row = sessions.resolve_session(db, credential)
        if row is not None:
            user = row.user
            return Principal(
                kind="user",
                permissions=effective_permissions(user.role, user.overrides),
                user_id=user.id,
                email=user.email,
                role=user.role,
                session_id=row.id,
            )
    raise unauthenticated()


def require(*keys: str):
    """Dependency: the caller must hold every key in `keys`."""

    def dependency(principal: Principal = Depends(get_principal)) -> Principal:
        if not all(principal.can(k) for k in keys):
            raise forbidden()
        return principal

    dependency.required_permissions = keys  # read by the route-coverage test
    return dependency


def require_user(principal: Principal = Depends(get_principal)) -> Principal:
    """Dependency: any signed-in user (not the CI token)."""
    if principal.kind != "user":
        raise forbidden("This needs a signed-in user.")
    return principal


def public() -> None:
    """Dependency marking a route as deliberately open to anyone."""


def record(
    db: Session,
    request: Request,
    action: str,
    principal: Principal | None = None,
    **kwargs,
):
    """audit.record with the caller and their address filled in."""
    if principal is not None:
        kwargs.setdefault("actor_user_id", principal.user_id)
        kwargs.setdefault("actor_label", principal.label)
    return audit.record(db, action, ip=client_ip(request), user_agent=user_agent(request), **kwargs)

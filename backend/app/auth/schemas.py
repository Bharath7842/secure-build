"""Request and response bodies shared by the setup, auth and admin routers."""

from __future__ import annotations

import re
from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.auth.passwords import MAX_LENGTH
from app.authz.catalog import ROLES

_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def _check_email(value: str) -> str:
    value = value.strip()
    if len(value) > 254 or not _EMAIL_RE.match(value):
        raise ValueError("Enter a valid email address.")
    return value


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    display_name: str
    role: str
    status: str
    last_login_at: datetime | None = None
    created_at: datetime | None = None

    @field_validator("last_login_at", "created_at")
    @classmethod
    def _utc(cls, value: datetime | None) -> datetime | None:
        # SQLite returns these naive; they were stored as UTC.
        return value.replace(tzinfo=timezone.utc) if value is not None and value.tzinfo is None else value


class LoginIn(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(max_length=MAX_LENGTH * 4)
    remember: bool = False


class SessionOut(BaseModel):
    """A new session. `token` goes into the HttpOnly cookie and nowhere else."""

    token: str
    expires_at: datetime
    remember: bool
    user: UserOut
    landing: str
    pages: list[str]


class SetupIn(BaseModel):
    setup_token: str = Field(max_length=512)
    email: str
    display_name: str = Field(default="", max_length=120)
    password: str = Field(max_length=MAX_LENGTH * 4)

    _email = field_validator("email")(_check_email)


class TokenPasswordIn(BaseModel):
    """Accepting an invite or a reset link."""

    token: str = Field(max_length=512)
    password: str = Field(max_length=MAX_LENGTH * 4)


class ChangePasswordIn(BaseModel):
    current_password: str = Field(max_length=MAX_LENGTH * 4)
    new_password: str = Field(max_length=MAX_LENGTH * 4)


class UserCreateIn(BaseModel):
    email: str
    display_name: str = Field(default="", max_length=120)
    role: str = "user"
    overrides: dict[str, str] = Field(default_factory=dict)

    _email = field_validator("email")(_check_email)

    @field_validator("role")
    @classmethod
    def _role(cls, value: str) -> str:
        if value not in ROLES:
            raise ValueError("Role must be 'admin' or 'user'.")
        return value


class UserUpdateIn(BaseModel):
    display_name: str | None = Field(default=None, max_length=120)
    role: str | None = None
    is_active: bool | None = None

    @field_validator("role")
    @classmethod
    def _role(cls, value: str | None) -> str | None:
        if value is not None and value not in ROLES:
            raise ValueError("Role must be 'admin' or 'user'.")
        return value


class PermissionsIn(BaseModel):
    overrides: dict[str, str]


class OneTimeLinkOut(BaseModel):
    url: str
    expires_at: datetime

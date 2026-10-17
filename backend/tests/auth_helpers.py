"""Signed-in callers for API tests.

`ADMIN_HEADERS` is a drop-in for the old `{"Authorization": "Bearer <token>"}`
constant: it signs in a test admin on whatever database the test set up with
`init_db(...)`, the first time the headers are read on that database. The CI
token's scope is narrower than an admin's; use `CI_HEADERS` to test CI calls.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping

from app import db as app_db
from app.auth import passwords, sessions
from app.config import settings
from app.models import User, UserPermissionOverride

CI_HEADERS = {"Authorization": f"Bearer {settings.sast_api_token}"}


def make_user(
    email: str = "user@test.local",
    role: str = "user",
    overrides: Mapping[str, str] | None = None,
) -> tuple[str, dict[str, str]]:
    """Create (or reuse) a user on the current test database and sign them
    in. Returns (user id, headers)."""
    with app_db.SessionLocal() as db:
        normalized = passwords.normalize_email(email)
        user = db.query(User).filter(User.email_normalized == normalized).one_or_none()
        if user is None:
            user = User(email=email, email_normalized=normalized, role=role, password_hash="x")
            db.add(user)
            db.flush()
            for key, effect in (overrides or {}).items():
                db.add(UserPermissionOverride(user_id=user.id, permission_key=key, effect=effect))
            db.commit()
        token, _ = sessions.create_session(db, user)
        return user.id, {"Authorization": f"Session {token}"}


class _AdminHeaders(Mapping):
    """Headers for a test admin on the database currently set up by init_db."""

    def __init__(self) -> None:
        self._cache: tuple[object, dict[str, str]] | None = None

    def _headers(self) -> dict[str, str]:
        current = app_db.SessionLocal
        if self._cache is None or self._cache[0] is not current:
            _, headers = make_user("admin@test.local", role="admin")
            self._cache = (current, headers)
        return self._cache[1]

    def __getitem__(self, key: str) -> str:
        return self._headers()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._headers())

    def __len__(self) -> int:
        return len(self._headers())


ADMIN_HEADERS = _AdminHeaders()

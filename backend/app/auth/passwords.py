"""Password hashing (Argon2id via pwdlib) and the password policy.

The policy follows NIST 800-63B: a length range and a short blocklist, no
composition rules. Callers show `password_problem`'s message as-is.
"""

from __future__ import annotations

import unicodedata

from pwdlib import PasswordHash

MIN_LENGTH = 12
MAX_LENGTH = 128

# Long enough to pass MIN_LENGTH, common enough to be guessed first.
_COMMON_PASSWORDS = frozenset(
    {
        "123456789012",
        "1234567890123",
        "12345678901234",
        "password1234",
        "password12345",
        "password123456",
        "passwordpassword",
        "qwertyuiop12",
        "qwertyuiop123",
        "qwerty123456",
        "iloveyou1234",
        "letmein12345",
        "welcome12345",
        "administrator",
        "administrator1",
        "changeme1234",
        "secretpassword",
        "securebuild123",
        "securebuild1234",
    }
)

_hasher = PasswordHash.recommended()
# Verified against when the account doesn't exist, so a login for an unknown
# email takes as long as one with a wrong password.
_DUMMY_HASH = _hasher.hash("not-a-real-password-just-timing")


def normalize_email(email: str) -> str:
    """The form emails are compared and stored uniquely in."""
    return unicodedata.normalize("NFKC", email).strip().lower()


def password_problem(password: str, email: str | None = None) -> str | None:
    """Why `password` is not acceptable, or None when it is."""
    if len(password) < MIN_LENGTH:
        return f"Use at least {MIN_LENGTH} characters."
    if len(password) > MAX_LENGTH:
        return f"Use at most {MAX_LENGTH} characters."
    lowered = password.lower()
    if lowered in _COMMON_PASSWORDS or len(set(password)) == 1:
        return "This password is too common. Choose a less predictable one."
    if email and lowered == normalize_email(email):
        return "Don't use your email address as your password."
    return None


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> tuple[bool, str | None]:
    """(matches, new hash to store or None). A missing hash never matches but
    still costs one hash verification."""
    if not password_hash:
        _hasher.verify(password, _DUMMY_HASH)
        return False, None
    return _hasher.verify_and_update(password, password_hash)

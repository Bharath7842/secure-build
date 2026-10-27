"""Bounded JWT checks. Tokens/signing material are memory-only and never evidence or prompts."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass, field
from typing import Any, Mapping

JWT_SIGNAL_NAMES = frozenset({"jwt_alg_none_accepted", "jwt_weak_secret_accepted", "jwt_missing_claims_accepted"})
REQUIRED_CLAIMS = ("exp", "iss", "aud")
# Fixed documentation/tutorial examples only. No external wordlist, expansion, or brute force.
PUBLIC_HMAC_SECRETS = (b"secret", b"your-256-bit-secret", b"your-secret-key", b"your_jwt_secret", b"jwt_secret")
_HASHES = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
MAX_TOKEN_CHARS = 16384


def _decode(segment: str) -> bytes:
    return base64.b64decode(segment + "=" * (-len(segment) % 4), altchars=b"-_", validate=True)


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _json_segment(value: Mapping[str, Any]) -> str:
    return _encode(json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode())


@dataclass(frozen=True, repr=False)
class DecodedJWT:
    header: Mapping[str, Any]
    payload: Mapping[str, Any]
    # Preserve exact original serialization when checking an HMAC signature.
    segments: tuple[str, str, str] = field(repr=False)


def decode_token(token: str) -> DecodedJWT | None:
    if not isinstance(token, str) or len(token) > MAX_TOKEN_CHARS:
        return None
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header, payload = json.loads(_decode(parts[0])), json.loads(_decode(parts[1]))
        _decode(parts[2])
        if not isinstance(header, dict) or not isinstance(payload, dict) or not isinstance(header.get("alg"), str):
            return None
        return DecodedJWT(header, payload, tuple(parts))
    except (ValueError, UnicodeError, RecursionError):
        return None


def alg_is_none(header: Mapping[str, Any]) -> bool:
    return str(header.get("alg", "")).lower() == "none"


def missing_required_claims(payload: Mapping[str, Any]) -> tuple[str, ...]:
    return tuple(claim for claim in REQUIRED_CLAIMS if claim not in payload)


def weak_hmac_secret(header: str, payload: str, signature: str) -> bytes | None:
    """Find a match in the five public examples, using the original encoded segments exactly."""
    decoded = decode_token(f"{header}.{payload}.{signature}")
    if decoded is None:
        return None
    digest = _HASHES.get(decoded.header.get("alg"))
    if digest is None:
        return None  # never confuse an RSA/EC public key with an HMAC secret
    actual = _decode(signature)
    message = f"{header}.{payload}".encode("ascii")
    for secret in PUBLIC_HMAC_SECRETS:
        if hmac.compare_digest(hmac.new(secret, message, digest).digest(), actual):
            return secret
    return None


def accepts_weak_hmac_secret(header: str, payload: str, signature: str) -> bool:
    return weak_hmac_secret(header, payload, signature) is not None


def modified_token(token: DecodedJWT, weakness: str, *, secret: bytes | None = None) -> str | None:
    """Keep identity/privilege claims. Change only verification fields and an inert marker.

    Without signing material the missing-claims probe may be rejected for its signature; that is
    not evidence of sound claim validation. Only acceptance produces a finding in the caller.
    """
    header, payload = dict(token.header), dict(token.payload)
    payload["dast_probe"] = "jwt-validation"
    if weakness == "alg-none":
        header["alg"] = "none"
    elif weakness == "missing-claims":
        for name in REQUIRED_CLAIMS:
            payload.pop(name, None)
    elif weakness != "weak-secret" or secret is None:
        return None
    head, body = _json_segment(header), _json_segment(payload)
    if alg_is_none(header):
        signature = ""
    elif secret is not None and header.get("alg") in _HASHES:
        signature = _encode(hmac.new(secret, f"{head}.{body}".encode(), _HASHES[header["alg"]]).digest())
    else:
        signature = token.segments[2]
    return f"{head}.{body}.{signature}"

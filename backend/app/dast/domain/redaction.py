"""Redaction of credential material before anything is stored or logged.

Pure and stdlib-only. DAST-06-010 registers the scan's actual secret values via
`secrets=`; until then headers are redacted by name and URLs by query-parameter name.
"""

from __future__ import annotations

import base64
import html
import json
import re
from typing import Any, Iterable, Mapping
from urllib.parse import parse_qsl, quote, quote_plus, urlencode, urlsplit, urlunsplit

REDACTED = "[REDACTED]"

SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
        "x-xsrf-token",
    }
)
_SENSITIVE_NAME = re.compile(r"(pass(word)?|pwd|secret|token|api[-_]?key|auth|session|sid|credential|cookie)", re.I)


def is_sensitive_name(name: str) -> bool:
    lowered = name.strip().lower()
    return lowered in SENSITIVE_HEADERS or bool(_SENSITIVE_NAME.search(lowered))


def _scrub(value: str, secrets: Iterable[str]) -> str:
    for secret in secrets:
        if secret and secret in value:
            value = value.replace(secret, REDACTED)
    return value


def redact_set_cookie(value: str, secrets: Iterable[str] = ()) -> str:
    """A `Set-Cookie` header (several cookies may be joined by newlines) with each cookie's
    *value* masked and its name and attributes (Path, HttpOnly, Secure, SameSite, ...) kept, so
    passive analysis can judge the flags without ever holding the session identifier."""
    secrets = tuple(s for s in secrets if s)
    lines: list[str] = []
    for line in str(value).splitlines() or [""]:
        head, sep, attrs = line.partition(";")
        name, eq, _cookie_value = head.partition("=")
        masked = f"{name.strip()}={REDACTED}" if eq else REDACTED
        lines.append(_scrub(masked + (sep + attrs if sep else ""), secrets))
    return "\n".join(lines)


def redact_headers(
    headers: Mapping[str, str] | None, secrets: Iterable[str] = (), *, keep_cookie_attributes: bool = False
) -> dict[str, str]:
    """Copy of `headers` with credential values replaced. Header names are kept (they
    show *that* a credential was sent); values of sensitive names, and any value
    containing a known secret, are masked. With `keep_cookie_attributes`, a `Set-Cookie`
    header keeps its cookie name and attributes (see `redact_set_cookie`)."""
    secrets = tuple(s for s in secrets if s)
    out: dict[str, str] = {}
    for name, value in (headers or {}).items():
        text = str(value)
        if keep_cookie_attributes and str(name).lower() == "set-cookie":
            out[str(name)] = redact_set_cookie(text, secrets)
        else:
            out[str(name)] = REDACTED if is_sensitive_name(str(name)) else _scrub(text, secrets)
    return out


def redact_url(url: str, secrets: Iterable[str] = ()) -> str:
    """URL with userinfo and sensitive query-parameter values masked."""
    secrets = tuple(s for s in secrets if s)
    try:
        parts = urlsplit(url)
    except ValueError:
        return _scrub(url, secrets)
    netloc = parts.netloc
    if "@" in netloc:
        netloc = f"{REDACTED}@{netloc.rsplit('@', 1)[1]}"
    query = parts.query
    if query:
        pairs = [
            (k, REDACTED if is_sensitive_name(k) else _scrub(v, secrets))
            for k, v in parse_qsl(query, keep_blank_values=True)
        ]
        query = urlencode(pairs, safe="[]")
    fragment = _scrub(parts.fragment, secrets)
    return _scrub(urlunsplit((parts.scheme, netloc, parts.path, query, fragment)), secrets)


_KEY_SHAPES = re.compile(
    r"(sk-[A-Za-z0-9_\-]{8,}|sk-ant-[A-Za-z0-9_\-]{8,}|AKIA[0-9A-Z]{12,}|ASIA[0-9A-Z]{12,}"
    r"|Bearer\s+[A-Za-z0-9._~+/=\-]{12,})"
)


def redact_text(text: str, secrets: Iterable[str] = ()) -> str:
    """Free text (an exception message, a log line) with known secret values and anything shaped
    like an API key or bearer token replaced. Provider error messages are the usual carrier: they
    quote the key the caller sent."""
    out = _scrub(str(text), tuple(s for s in secrets if s))
    return _KEY_SHAPES.sub(REDACTED, out)


# Derived spellings shorter than this are not registered: masking "ab" everywhere would turn the
# log into noise while hiding nothing a reader could reconstruct from the exact value.
MIN_DERIVED_LENGTH = 6


def secret_variants(secret: str, *, partner: str | None = None) -> list[str]:
    """Every spelling of `secret` that could show up in a log, URL, header or JSON body: the exact
    value, URL-encoded (path and query styles), HTML-escaped, JSON-escaped and base64. With
    `partner` (the username), also base64 of `partner:secret`, which is what HTTP Basic auth
    puts on the wire. Longest first, so masking a long spelling is not pre-empted by a short
    one that is a substring of it."""
    if not secret:
        return []
    candidates = [secret]
    derived = [
        quote(secret, safe=""),
        quote_plus(secret),
        html.escape(secret, quote=True),
        json.dumps(secret)[1:-1],
        base64.b64encode(secret.encode("utf-8")).decode("ascii"),
        base64.urlsafe_b64encode(secret.encode("utf-8")).decode("ascii"),
    ]
    if partner:
        pair = f"{partner}:{secret}".encode("utf-8")
        derived += [base64.b64encode(pair).decode("ascii"), f"{partner}:{secret}"]
    for value in derived:
        value = value.rstrip("=") if len(value.rstrip("=")) >= MIN_DERIVED_LENGTH else value
        if value != secret and len(value) >= MIN_DERIVED_LENGTH:
            candidates.append(value)
    seen: set[str] = set()
    unique = [c for c in candidates if not (c in seen or seen.add(c))]
    return sorted(unique, key=len, reverse=True)


def redact_json(value: Any, secrets: Iterable[str] = ()) -> Any:
    """`value` (nested dicts, lists, strings) with secrets masked in every string, key and
    value. Used on engine output before it is stored or narrated."""
    secrets = tuple(s for s in secrets if s)
    if not secrets:
        return value
    if isinstance(value, str):
        return redact_text(value, secrets)
    if isinstance(value, Mapping):
        return {redact_json(k, secrets) if isinstance(k, str) else k: redact_json(v, secrets) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_json(v, secrets) for v in value]
    return value

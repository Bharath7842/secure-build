"""Session decisions (DAST-06-030, -040, -050): pure rules about login success, expired
credentials and lost sessions. The engine gathers the facts (a response, a page's state); these
functions decide.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from .traffic import RecordedExchange

# A single weak signal (the URL changed) is not proof of login: an error page changes it too.
REQUIRED_LOGIN_SIGNALS = 2
LOGIN_SIGNALS = ("post_login_indicator", "url_changed", "credential_field_gone")

_LOGIN_PATH = re.compile(r"/(?:log[-_]?in|sign[-_]?in|signin|auth(?:enticate)?|sso|session/new|account/login)\b", re.IGNORECASE)
_UNSUPPORTED_REASONS = {
    "multi_step": "multi-step login",
    "oauth_sso": "OAuth/SSO login",
    "captcha": "CAPTCHA-protected login",
    "otp_2fa": "login with a one-time code (2FA)",
    "unknown": "an unrecognized login flow",
}


def login_verified(signals: Sequence[str]) -> bool:
    """Login counts as successful only with at least two distinct independent signals."""
    return len({s for s in signals if s in LOGIN_SIGNALS}) >= REQUIRED_LOGIN_SIGNALS


def unsupported_login_message(login_type: str, label: str) -> str:
    kind = _UNSUPPORTED_REASONS.get(login_type, _UNSUPPORTED_REASONS["unknown"])
    return (
        f"Identity {label!r}: this is a {kind}, which is not automated. "
        "Log in yourself, save the browser session, and supply it as a pre-authenticated identity."
    )


def looks_like_login_url(url: str) -> bool:
    """True for `/login` in the path or in a hash route (`#/login`), which SPAs like Juice Shop use."""
    parts = urlsplit(url or "")
    fragment = "/" + (parts.fragment or "").lstrip("#/")
    return bool(_LOGIN_PATH.search(parts.path) or _LOGIN_PATH.search(fragment))


@dataclass(frozen=True)
class SessionVerdict:
    ok: bool
    reason: str = ""  # human-readable, safe to show; empty when ok


def session_verdict(
    status: int | None,
    *,
    location: str = "",
    final_url: str = "",
    login_url: str = "",
    login_form_present: bool = False,
    post_login_indicator_missing: bool = False,
) -> SessionVerdict:
    """Is the session still valid, judging from one response or page?

    Lost when: the server answered 401/403; it redirected to a login-shaped URL (or the known
    login URL); the page now shows a login form; or the post-login indicator that was present
    after login has disappeared. A 404/5xx says nothing about the session either way."""
    if status in (401, 403):
        return SessionVerdict(False, f"the server answered {status}, so the session is no longer accepted")
    for url in (location, final_url):
        if not url:
            continue
        if looks_like_login_url(url) or (login_url and urlsplit(url).path == urlsplit(login_url).path and urlsplit(login_url).path not in ("", "/")):
            return SessionVerdict(False, "the target redirected to its login page")
    if login_form_present:
        return SessionVerdict(False, "the page is showing a login form")
    if post_login_indicator_missing:
        return SessionVerdict(False, "the signed-in indicator is gone")
    return SessionVerdict(True)


def probe_verdict(status: int | None, *, location: str = "", error: str = "", kind: str = "token") -> SessionVerdict:
    """Is a supplied token or saved session accepted by the target? Judged from one probe
    request made with it."""
    noun = "token" if kind == "token" else "saved session"
    if error:
        return SessionVerdict(False, f"the {noun} could not be checked: {error}")
    verdict = session_verdict(status, location=location)
    if not verdict.ok:
        return SessionVerdict(False, f"the {noun} is invalid or expired ({verdict.reason})")
    return SessionVerdict(True)


MAX_RELOGIN_ATTEMPTS = 1


def may_relogin(relogin_counts: Mapping[str, int], identity_id: str) -> bool:
    """One bounded re-login per identity (the single-identity limit, generalized)."""
    return relogin_counts.get(identity_id, 0) < MAX_RELOGIN_ATTEMPTS


class DenialTracker:
    """Session loss inferred from a run of refusals (401/403) with no success in between.

    One 403 is ordinary (a role may simply not be allowed that endpoint); `threshold` in a row,
    with no 2xx/3xx between them, is a session that stopped being accepted. A 401 is a stronger
    sign than a 403, so it counts double."""

    def __init__(self, threshold: int = 3) -> None:
        self.threshold = max(1, threshold)
        self._score = 0

    def observe(self, status: int | None) -> bool:
        """Feed one response status; True once the session should be treated as lost."""
        if status == 401:
            self._score += 2
        elif status == 403:
            self._score += 1
        elif status is not None and 200 <= status < 400:
            self._score = 0
        return self._score >= self.threshold

    def reset(self) -> None:
        self._score = 0


def new_denials(traffic: Sequence[RecordedExchange], identity_id: str, start: int, tracker: DenialTracker) -> tuple[str, int]:
    """Feed `traffic[start:]` belonging to `identity_id` (assets excluded) through `tracker`.

    Returns `(reason, next_start)`: `reason` is `""` unless a run of refusals says the identity's
    session is no longer accepted, and `next_start` is always `len(traffic)` so a caller can resume
    from there next time without re-scanning what was already seen."""
    for index in range(start, len(traffic)):
        exchange = traffic[index]
        if exchange.identity_id == identity_id and not exchange.asset and tracker.observe(exchange.status):
            return "the server keeps refusing this identity's requests (401/403)", len(traffic)
    return "", len(traffic)


# ---- fixation, lifetime, reuse, CSRF refresh -------------------------------------------------------

_SESSION_COOKIE = re.compile(r"session|sid|jsessionid|phpsessid|connect\.sid|auth", re.IGNORECASE)
_CSRF_META = re.compile(r"""<meta[^>]+name=["']csrf-token["'][^>]+content=["']([^"']+)["']""", re.IGNORECASE)
_CSRF_INPUT = re.compile(
    r"""name=["']([^"']*(?:csrf|xsrf|_token)[^"']*)["'][^>]*value=["']([^"']+)["']""",
    re.IGNORECASE,
)
SESSION_LIFETIME_LIMIT_S = 24 * 60 * 60


def _cookie_map(cookies: Sequence[Mapping[str, Any]]) -> dict[str, str]:
    out = {}
    for cookie in cookies or []:
        name = str(cookie.get("name") or "")
        if name:
            out[name] = str(cookie.get("value") or "")
    return out


def fixation_cookie_names(before: Sequence[Mapping[str, Any]], after: Sequence[Mapping[str, Any]]) -> tuple[str, ...]:
    """Session-looking cookies whose value was set before login and is unchanged after it."""
    prior = _cookie_map(before)
    names = []
    for name, value in _cookie_map(after).items():
        if not value or not _SESSION_COOKIE.search(name):
            continue
        if prior.get(name) and prior[name] == value:
            names.append(name)
    return tuple(names)


def excessive_cookie_lifetimes(
    cookies: Sequence[Mapping[str, Any]], *, now_s: float, limit_s: int = SESSION_LIFETIME_LIMIT_S
) -> tuple[tuple[str, int], ...]:
    """`(name, lifetime_seconds)` for cookies that will still be valid after `limit_s`.

    A session cookie (no `expires`, or `expires` < 0) is a browser session and is not reported:
    idle timeout on the server is not visible from the cookie alone. A far-future `expires`
    or `Max-Age` is."""
    found = []
    for cookie in cookies or []:
        name = str(cookie.get("name") or "")
        if not name or not _SESSION_COOKIE.search(name):
            continue
        expires = cookie.get("expires")
        max_age = cookie.get("max_age", cookie.get("maxAge"))
        lifetime = None
        if isinstance(max_age, (int, float)) and not isinstance(max_age, bool) and max_age > 0:
            lifetime = int(max_age)
        elif isinstance(expires, (int, float)) and not isinstance(expires, bool) and expires > 0:
            lifetime = int(expires - now_s)
        if lifetime is not None and lifetime > limit_s:
            found.append((name, lifetime))
    return tuple(found)


def reused_session_cookies(by_label: Mapping[str, Sequence[Mapping[str, Any]]]) -> tuple[tuple[str, str, str], ...]:
    """`(cookie name, label_a, label_b)` when two identities hold the same non-empty session cookie value."""
    seen: dict[tuple[str, str], str] = {}
    hits = []
    for label, cookies in by_label.items():
        for name, value in _cookie_map(cookies).items():
            if not value or not _SESSION_COOKIE.search(name):
                continue
            key = (name, value)
            other = seen.get(key)
            if other and other != label:
                hits.append((name, other, label))
            else:
                seen[key] = label
    return tuple(hits)


def csrf_from_html(html: str) -> tuple[str, str] | None:
    """`(header or field name, token)` from a CSRF meta tag or a hidden input, or None."""
    text = html or ""
    meta = _CSRF_META.search(text)
    if meta and meta.group(1).strip():
        return "X-CSRF-Token", meta.group(1).strip()
    field = _CSRF_INPUT.search(text)
    if field and field.group(2).strip():
        return field.group(1), field.group(2).strip()
    return None

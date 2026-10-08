"""Scope and method policy (DAST-01-010): a pure decision function.

`evaluate_request` takes a request description plus a `Scope` and `MethodPolicy`
and returns allow or deny with a reason. It never raises and does no I/O, so a
malformed or hostile URL is a denial, not an exception that could be swallowed
into a send.

Host comparison happens after normalization (case, trailing dot, IDN, IP
literal) and URLs that smuggle a different host past a naive parser are denied
outright: userinfo (`target.com@evil.com`), backslashes (browsers read `\\` as
`/`), whitespace/control characters, and non-http(s) schemes. Only the *host*
is compared; the port is validated but not part of scope.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, Callable, Literal
from urllib.parse import urljoin, urlsplit

from .browser_probe import is_destructive_destination, is_marker_body
from .introspection import is_introspection_request

SameDomainMode = Literal["exact", "root-domain"]

# Deny reasons. `cancelled` and `rate` are produced by the application-layer guard.
OFF_SCOPE = "off_scope"
METHOD_NOT_PERMITTED = "method_not_permitted"
CANCELLED = "cancelled"
DENY_REASONS = (OFF_SCOPE, METHOD_NOT_PERMITTED, CANCELLED)

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# The one documented exception to safe mode's "no state-changing methods": a GraphQL schema
# introspection query, which is a POST that only reads. It is allowed when the caller declares
# this intent AND the body is verified to be nothing but a schema query
# (`graphql.is_introspection_request`). It is an allow-list entry for that single request shape,
# not a general allowance for POST: any other POST in safe mode is still denied.
INTROSPECTION_INTENT = "graphql_introspection"

# The second documented exception: while an identity is signing in, a form POST (the login
# submit) must be possible even in safe mode, or no form login could ever work. The guard
# declares this intent itself, only inside `SafetyGuard.login_window()` (open for the duration of
# one login attempt), and only POST is covered: PUT/PATCH/DELETE stay refused. Scope still
# applies. Residual risk, accepted and documented: any other same-scope POST the page makes
# during that window (analytics, say) is allowed too; the window is short and fully audited.
AUTHENTICATION_INTENT = "authentication"

# The third documented exception: a browser POST that submits one of this scan's inert XSS markers
# and nothing else. The guard declares this intent only inside `SafetyGuard.marker_window()`, and
# only when the scan turned marker posts on for a disposable target. The body must be exactly the
# scan's marker templates (`browser_probe.is_marker_body`); any other POST, and any POST to a
# logout/delete/payment URL, stays refused. PUT/PATCH/DELETE stay refused. Scope still applies.
MARKER_SUBMIT_INTENT = "marker_submit"

_ALLOWED_SCHEMES = ("http", "https")


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str | None = None  # one of DENY_REASONS when denied
    detail: str = ""  # human-readable, safe to log


ALLOW = Decision(True)


def _deny(reason: str, detail: str) -> Decision:
    return Decision(False, reason, detail)


@dataclass(frozen=True)
class RequestDescription:
    method: str
    url: str
    intent: str = ""  # declared purpose; introspection, authentication and marker_submit change a decision
    body: Any = None  # inspected only to verify a declared intent
    marker_token: str = ""  # the scan's marker token; required to allow a marker submit


@dataclass(frozen=True)
class MethodPolicy:
    safe_mode: bool = True
    allow_state_changing: bool = False
    allow_marker_posts: bool = False  # inert marker submits; only for a disposable target


def resolve_method_policy(
    *,
    safe_mode: bool = True,
    allow_state_changing: bool = False,
    allow_marker_posts: bool = False,
    target_disposable: bool = False,
) -> MethodPolicy:
    """Safe mode is forced on for any target not marked disposable; a state-changing
    opt-in, and marker submits, are only honoured for a disposable target."""
    if not target_disposable:
        return MethodPolicy(safe_mode=True, allow_state_changing=False, allow_marker_posts=False)
    return MethodPolicy(
        safe_mode=safe_mode, allow_state_changing=allow_state_changing, allow_marker_posts=allow_marker_posts
    )


# ---- host normalization ---------------------------------------------------------------------


def normalize_host(host: str) -> str:
    """Lowercase, strip brackets and a trailing dot, punycode IDN labels and canonicalize IP
    literals. Returns "" when the host cannot be represented safely."""
    host = (host or "").strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host:
        return ""
    try:
        ip = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        ip = None
    if ip is not None:
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        return str(ip)
    host = host.rstrip(".").lower()
    if not host:
        return ""
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    return host.lower()


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


@dataclass(frozen=True)
class ParsedUrl:
    scheme: str
    host: str  # normalized
    port: int | None


def parse_url(url: str) -> ParsedUrl | None:
    """Parse a URL strictly. None means "do not trust this URL"."""
    if not isinstance(url, str) or not url:
        return None
    if "\\" in url or any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in url):
        return None
    try:
        parts = urlsplit(url)
        host_raw = parts.hostname
        port = parts.port  # raises ValueError on a bad port
    except ValueError:
        return None
    if parts.scheme.lower() not in _ALLOWED_SCHEMES:
        return None
    if "@" in parts.netloc:  # userinfo, however it is spelled
        return None
    host = normalize_host(host_raw or "")
    if not host:
        return None
    return ParsedUrl(parts.scheme.lower(), host, port)


# ---- scope ----------------------------------------------------------------------------------


def _default_registrable_domain(host: str) -> str:
    """Fallback when no public-suffix-aware function is supplied: the last two labels.
    Production wiring injects a tldextract-backed function (see `safety_guard`)."""
    labels = host.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


@dataclass(frozen=True)
class Scope:
    """The authorized host(s) of a scan. Build with `Scope.for_target`."""

    host: str  # normalized target host
    mode: SameDomainMode = "exact"
    registrable_domain: Callable[[str], str] = _default_registrable_domain

    @classmethod
    def for_target(
        cls,
        target_url: str,
        mode: SameDomainMode = "exact",
        registrable_domain: Callable[[str], str] | None = None,
    ) -> "Scope":
        parsed = parse_url(target_url)
        if parsed is None:
            raise ValueError(f"target address is not a usable http(s) URL: {target_url!r}")
        if mode not in ("exact", "root-domain"):
            raise ValueError(f"unknown same-domain mode: {mode!r}")
        return cls(parsed.host, mode, registrable_domain or _default_registrable_domain)

    def contains_host(self, host: str) -> bool:
        host = normalize_host(host)
        if not host:
            return False
        if host == self.host:
            return True
        if self.mode != "root-domain" or _is_ip(host) or _is_ip(self.host):
            return False
        root = self.registrable_domain(self.host)
        # A bare public suffix or single-label host has no registrable domain to share.
        if not root or "." not in root:
            return False
        return self.registrable_domain(host) == root


# ---- decisions ------------------------------------------------------------------------------


def evaluate_request(request: RequestDescription, scope: Scope, policy: MethodPolicy) -> Decision:
    """Allow or deny one request. Scope is checked before method so an off-scope
    request is always reported as such."""
    parsed = parse_url(request.url)
    if parsed is None:
        return _deny(OFF_SCOPE, "URL is malformed or uses a disallowed form (userinfo, backslash, scheme)")
    if not scope.contains_host(parsed.host):
        return _deny(OFF_SCOPE, f"host {parsed.host!r} is outside the authorized scope")

    method = (request.method or "").strip().upper()
    if method in SAFE_METHODS:
        return ALLOW
    if method in STATE_CHANGING_METHODS:
        if policy.safe_mode and not policy.allow_state_changing:
            if request.intent == AUTHENTICATION_INTENT and method == "POST":
                return ALLOW
            if request.intent == INTROSPECTION_INTENT and method == "POST":
                if is_introspection_request(request.body):
                    return ALLOW
                return _deny(METHOD_NOT_PERMITTED, "POST declared as a GraphQL introspection query, but the body is not a pure schema query")
            if request.intent == MARKER_SUBMIT_INTENT and method == "POST":
                if not policy.allow_marker_posts:
                    return _deny(METHOD_NOT_PERMITTED, "marker submits are not enabled for this scan")
                if is_destructive_destination(request.url):
                    return _deny(METHOD_NOT_PERMITTED, "a marker submit may not target a logout, delete or payment URL")
                if not is_marker_body(request.body, request.marker_token):
                    return _deny(METHOD_NOT_PERMITTED, "POST body is not one of this scan's marker payloads")
                return ALLOW
            return _deny(METHOD_NOT_PERMITTED, f"{method} is not permitted in safe mode")
        return ALLOW
    return _deny(METHOD_NOT_PERMITTED, f"method {method or '<empty>'!r} is not supported")


def evaluate_redirect(
    current_url: str, location: str, method: str, scope: Scope, policy: MethodPolicy,
    intent: str = "", body: Any = None,
) -> Decision:
    """Decide the next hop of a redirect. The Location header is resolved against the
    current URL; an off-scope hop is denied, never followed."""
    try:
        target = urljoin(current_url, (location or "").strip())
    except ValueError:
        return _deny(OFF_SCOPE, "redirect target is malformed")
    return evaluate_request(RequestDescription(method, target, intent, body), scope, policy)

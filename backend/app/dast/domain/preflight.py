"""Preflight outcomes (DAST-05-030): turn the result of the first request to the target into a
specific, human-readable decision. Pure.

Outcomes, each with its own message so an operator can tell a typo from an outage:

    reachable            the target answered (any status below 500)
    dns                  the host name did not resolve
    refused              the host is there but nothing accepts connections on that port
    timeout              no answer in time
    tls                  the TLS handshake or certificate failed
    redirect_off_scope   the first response redirected to a host outside the authorized scope
    server_error         the target answered with a 5xx
    unreachable          anything else that stopped the request
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from .redaction import redact_url

REACHABLE = "reachable"
FAILURES = ("dns", "refused", "timeout", "tls", "redirect_off_scope", "server_error", "unreachable", "cancelled")

_DNS = ("name or service not known", "nodename nor servname", "getaddrinfo", "temporary failure in name resolution", "no address associated", "name resolution", "gaierror")
_REFUSED = ("connection refused", "refused", "errno 111", "errno 61", "connect call failed", "no route to host", "network is unreachable")
_TLS = ("ssl", "tls", "certificate", "handshake")


@dataclass(frozen=True)
class PreflightResult:
    outcome: str
    message: str  # shown to the operator and stored as the scan's failure reason
    status: int | None = None
    note: str = ""  # reachable, but worth saying (e.g. "the root answered 404")

    @property
    def ok(self) -> bool:
        return self.outcome == REACHABLE


def classify_transport_error(kind: str, detail: str) -> str:
    text = f"{kind} {detail}".lower()
    if kind == "timeout" or "timeout" in text or "timed out" in text:
        return "timeout"
    if any(m in text for m in _DNS):
        return "dns"
    if any(m in text for m in _TLS):
        return "tls"
    if any(m in text for m in _REFUSED):
        return "refused"
    return "unreachable"


def evaluate_preflight(
    target_url: str,
    *,
    status: int | None = None,
    error: str | None = None,
    error_detail: str = "",
    deny_reason: str | None = None,
    redirect_location: str = "",
) -> PreflightResult:
    host = urlsplit(target_url).hostname or target_url
    if deny_reason == "cancelled":
        return PreflightResult("cancelled", "the scan was cancelled before the target was checked")
    if deny_reason == "off_scope":
        where = redact_url(redirect_location) if redirect_location else "another host"
        if redirect_location:
            return PreflightResult(
                "redirect_off_scope",
                f"the target redirects to {where}, which is outside the authorized scope; "
                "use the address it redirects to as the target, or allow the registrable domain (same-domain mode)",
                status,
            )
        return PreflightResult("unreachable", f"the target address {host!r} is outside the authorized scope or is not a usable http(s) URL")
    if deny_reason:
        return PreflightResult("unreachable", f"the request to the target was not permitted ({deny_reason})")
    if error:
        category = classify_transport_error(error, error_detail)
        messages = {
            "dns": f"the host name {host!r} does not resolve; check the address for typos and that DNS can reach it",
            "refused": f"{host!r} refused the connection; check the port and that the application is running",
            "timeout": f"{host!r} did not answer in time; the application may be down, slow or blocked by a firewall",
            "tls": f"the secure connection to {host!r} failed (TLS handshake or certificate error)",
            "unreachable": f"the connection to {host!r} failed ({error})",
        }
        return PreflightResult(category, messages[category])
    if status is None:
        return PreflightResult("unreachable", f"no response was received from {host!r}")
    if status >= 500:
        return PreflightResult("server_error", f"the target answered HTTP {status} (a server error), so it is not ready to be scanned", status)
    note = f"the root address answered HTTP {status}" if status >= 400 else ""
    return PreflightResult(REACHABLE, f"{host} is reachable (HTTP {status}).", status, note)

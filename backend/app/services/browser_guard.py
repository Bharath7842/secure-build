"""Browser traffic through the safety guard (DAST-01-040).

`install_browser_guard` hooks a browser context's route interception so that every
request the page makes (navigation, XHR/fetch, sub-resources) is decided by the
`SafetyGuard` *before* it leaves the browser. Allowed requests are audited and
continued; denied ones are audited and aborted, and the page keeps loading.

Infrastructure layer. It touches the context only through `.route(pattern, handler)`
and the route/request objects Playwright hands the handler, so tests drive it with
fakes and Playwright stays a lazy import.

Notes on behaviour:
* The guard's method policy applies as-is: with safe mode on, a browser POST (a form
  submit, an XHR write) is aborted like any other state-changing request.
* Browser requests are scope- and cancel-checked but not rate-limited or held to the
  concurrency cap (a browser cannot be made to wait on a slot); the crawl's own page
  budget paces it. The audit row is written when the request is intercepted, so a
  browser row has no `response_status`.
* Audit failure fails closed: a request that cannot be recorded is not sent.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Iterable
from urllib.parse import urlsplit

from app.dast.domain.redaction import redact_headers, redact_url
from app.services.request_audit import AuditRecord, AuditSink
from app.services.safety_guard import SafetyGuard

logger = logging.getLogger(__name__)

ABORT_REASON = "blockedbyclient"
# These schemes never reach the network, so there is nothing for the guard to decide.
_LOCAL_SCHEMES = frozenset({"data", "blob", "about"})


def install_browser_guard(
    context: Any,
    guard: SafetyGuard,
    audit: AuditSink,
    *,
    identity_label: str | None = None,
    on_denied: Callable[[str, str, bool], None] | None = None,
    secrets: Callable[[], Iterable[str]] | None = None,
) -> None:
    """Intercept every request on `context`.

    `on_denied(url, reason, is_navigation)` is called for each denial (URL already
    redacted); the scan log uses it to report a denied navigation without failing the crawl.
    """

    def _notify(url: str, reason: str, is_navigation: bool) -> None:
        if on_denied is None:
            return
        try:
            on_denied(url, reason, is_navigation)
        except Exception:  # noqa: BLE001 - logging must never break the page
            logger.debug("on_denied callback failed", exc_info=True)

    def _abort(route: Any) -> None:
        try:
            route.abort(ABORT_REASON)
        except Exception:  # noqa: BLE001 - the page may already be closed
            logger.debug("route.abort failed", exc_info=True)

    def handler(route: Any) -> None:
        request = route.request
        try:
            method, url = request.method, request.url
            if urlsplit(url).scheme.lower() in _LOCAL_SCHEMES:
                route.continue_()
                return
            is_navigation = bool(request.is_navigation_request())
            body = None
            if method.upper() == "POST":
                try:
                    body = request.post_data
                except Exception:  # noqa: BLE001 - a body we cannot read is not a marker submit
                    body = None
            decision = guard.decide(method, url, body=body)
            known_secrets = tuple(secrets()) if secrets else ()
            audit.record(
                AuditRecord(
                    method=method.upper(),
                    url=redact_url(url, known_secrets),
                    allowed=decision.allowed,
                    identity_label=identity_label,
                    deny_reason=decision.reason,
                    request_headers=redact_headers(request.headers, known_secrets),
                )
            )
        except Exception:  # noqa: BLE001 - fail closed: anything we cannot decide or record is not sent
            logger.exception("browser guard failed; aborting request")
            _abort(route)
            return

        if decision.allowed:
            route.continue_()
            return
        _abort(route)
        _notify(redact_url(url, known_secrets), decision.reason or "denied", is_navigation)

    context.route("**/*", handler)


def new_guarded_context(
    browser: Any,
    guard: SafetyGuard,
    audit: AuditSink,
    *,
    identity_label: str | None = None,
    on_denied: Callable[[str, str, bool], None] | None = None,
    secrets: Callable[[], Iterable[str]] | None = None,
    **context_kwargs: Any,
) -> Any:
    """`browser.new_context(...)` with the guard installed, so no context exists without it."""
    context = browser.new_context(**context_kwargs)
    install_browser_guard(context, guard, audit, identity_label=identity_label, on_denied=on_denied, secrets=secrets)
    return context

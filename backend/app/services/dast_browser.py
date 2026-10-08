"""The browser driver (DAST-01-040, DAST-07-020, -030): guarded, per-identity Playwright contexts
and the network recorder.

* Every context is created through `browser_guard.new_guarded_context`, so no page can send a
  request the safety guard has not decided on, and each identity gets its *own* context (cookies,
  storage and in-flight state are never shared between identities).
* Playwright is imported only when the first session is requested, and the browser is launched
  then. A scan that never needs one (an API-only target) launches nothing: `started` stays False.
* The recorder listens on each context and turns every response into a `RecordedExchange`
  (`domain.traffic.record_exchange` applies the redaction and size rules), appended to the shared
  `traffic` list. Static assets are kept by URL and status only.

This module needs a real browser to run end to end; the unit tests drive it with fakes, and the
`live` tests with a local fixture site.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Iterable

from app.dast.domain.identities import IdentitySpec
from app.dast.domain.traffic import DATA_RESOURCE_TYPES, record_exchange
from app.services.browser_guard import new_guarded_context
from app.services.request_audit import AuditSink
from app.services.safety_guard import SafetyGuard

logger = logging.getLogger(__name__)

_TEXTUAL = ("json", "text", "xml", "javascript", "html", "x-www-form-urlencoded")
MAX_BODY_READ = 256 * 1024  # larger response bodies are not read at all


def attach_recorder(context: Any, traffic: list, identity_id: str, secrets: Callable[[], Iterable[str]] | None = None) -> None:
    """Record every response on `context` into `traffic`. Best effort: a response the recorder
    cannot read is skipped, never an error for the page."""

    def on_response(response: Any) -> None:
        try:
            request = response.request
            resource_type = str(request.resource_type)
            headers = dict(response.headers)
            content_type = headers.get("content-type", "")
            body = None
            wanted = resource_type in DATA_RESOURCE_TYPES or resource_type == "document"
            if wanted and any(t in content_type.lower() for t in _TEXTUAL):
                try:
                    raw = response.body()
                    body = raw[:MAX_BODY_READ].decode("utf-8", errors="replace") if raw else ""
                except Exception:  # noqa: BLE001 - redirects and aborted responses have no body
                    body = None
            try:
                post_data = request.post_data
            except Exception:  # noqa: BLE001 - binary uploads
                post_data = None
            traffic.append(
                record_exchange(
                    method=request.method, url=response.url, resource_type=resource_type, status=response.status,
                    request_headers=dict(request.headers), request_body=post_data, response_headers=headers,
                    response_body=body, identity_id=identity_id, secrets=tuple(secrets()) if secrets else (),
                )
            )
        except Exception:  # noqa: BLE001
            logger.debug("traffic recorder skipped a response", exc_info=True)

    context.on("response", on_response)


class _Session:
    def __init__(self, context: Any, page: Any) -> None:
        self.context, self.page = context, page

    def cookies(self) -> list[dict]:
        try:
            return list(self.context.cookies())
        except Exception:  # noqa: BLE001
            return []

    def close(self) -> None:
        try:
            self.context.close()
        except Exception:  # noqa: BLE001 - already closed
            pass


class PlaywrightBrowserFactory:
    """Implements `app.dast.runtime.BrowserFactory`."""

    def __init__(
        self,
        guard: SafetyGuard,
        audit: AuditSink,
        *,
        traffic: list,
        headless: bool = True,
        secrets: Callable[[], Iterable[str]] | None = None,
        on_denied: Callable[[str, str, bool], None] | None = None,
        playwright_starter: Callable[[], Any] | None = None,
    ) -> None:
        self._guard, self._audit, self._traffic = guard, audit, traffic
        self._headless, self._secrets, self._on_denied = headless, secrets, on_denied
        self._starter = playwright_starter
        self._playwright: Any = None
        self._browser: Any = None
        self._sessions: list[_Session] = []

    @property
    def started(self) -> bool:
        return self._browser is not None

    def _start(self) -> Any:
        if self._browser is None:
            starter = self._starter
            if starter is None:
                from playwright.sync_api import sync_playwright  # lazy: never imported for an API-only scan

                starter = lambda: sync_playwright().start()  # noqa: E731
            self._playwright = starter()
            self._browser = self._playwright.chromium.launch(headless=self._headless)
        return self._browser

    def new_session(
        self, spec: IdentitySpec, *, storage_state: dict | None = None, extra_headers: dict[str, str] | None = None
    ) -> _Session:
        browser = self._start()
        kwargs: dict[str, Any] = {}
        if storage_state:
            kwargs["storage_state"] = storage_state
        if extra_headers:
            kwargs["extra_http_headers"] = dict(extra_headers)
        context = new_guarded_context(
            browser, self._guard, self._audit, identity_label=spec.label, on_denied=self._on_denied, secrets=self._secrets, **kwargs
        )
        attach_recorder(context, self._traffic, spec.identity_id, self._secrets)
        session = _Session(context, context.new_page())
        self._sessions.append(session)
        return session

    def close(self) -> None:
        for session in self._sessions:
            session.close()
        self._sessions.clear()
        for resource, method in ((self._browser, "close"), (self._playwright, "stop")):
            if resource is not None:
                try:
                    getattr(resource, method)()
                except Exception:  # noqa: BLE001
                    pass
        self._browser = self._playwright = None

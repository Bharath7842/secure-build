"""The guarded request executor (DAST-01-030): the only HTTP client the engine gets.

Every call goes guard decision -> send (only if allowed) -> audit row -> result. A
denial is a returned `GuardDecision(allowed=False, ...)`, never an exception, so no
caller can swallow its way into a send. Redirects are followed here, one hop at a time,
and each hop is guarded and audited like a fresh request: a redirect to an
out-of-scope host is denied, not followed.

`httpx` is confined to this module on purpose (a layering test forbids it in
`app/dast/nodes/`), and tests inject a fake target as the `transport`.
"""

from __future__ import annotations

import http.cookiejar
import json
import logging
import time
from dataclasses import dataclass, replace
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import urljoin, urlsplit

import httpx

from app.dast.domain.entities import ResponseSnapshot
from app.dast.domain.interfaces import GuardDecision, RequestSpec
from app.dast.domain.policy import OFF_SCOPE
from app.dast.domain.redaction import redact_headers, redact_text, redact_url
from app.services.request_audit import BODY_MAX, AuditRecord, AuditSink
from app.services.safety_guard import SafetyGuard

logger = logging.getLogger(__name__)

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_CREDENTIAL_HEADERS = frozenset({"authorization", "proxy-authorization", "cookie"})
_BODY_HEADERS = frozenset({"content-length", "content-type", "content-encoding", "transfer-encoding"})


def _redacted_body(body: Any, secrets: tuple) -> str | None:
    if body is None:
        return None
    if isinstance(body, (dict, list)):
        try:
            text = json.dumps(body)
        except (TypeError, ValueError):
            text = str(body)
    elif isinstance(body, bytes):
        text = body.decode("utf-8", errors="replace")
    else:
        text = str(body)
    text = redact_text(text, secrets)
    return text[:BODY_MAX] or None


class _NoCookies(http.cookiejar.CookiePolicy):
    """Never store or send cookies on the shared client. Identities are separate actors;
    a jar shared across them would let one session leak into another's requests. The caller
    passes the cookies it means to send in `RequestSpec.headers`."""

    netscape = True
    rfc2965 = False
    hide_cookie2 = False

    def set_ok(self, cookie, request):  # noqa: D102, ANN001
        return False

    def return_ok(self, cookie, request):  # noqa: D102, ANN001
        return False

    def domain_return_ok(self, domain, request):  # noqa: D102, ANN001
        return False

    def path_return_ok(self, path, request):  # noqa: D102, ANN001
        return False


@dataclass(frozen=True)
class _Hop:
    decision: GuardDecision
    status: int | None = None
    location: str | None = None


class GuardedExecutor:
    def __init__(
        self,
        guard: SafetyGuard,
        audit: AuditSink,
        *,
        transport: httpx.BaseTransport | None = None,
        max_body_bytes: int = 65536,
        timeout_s: float = 15.0,
        max_redirects: int = 5,
        secrets: Callable[[], Iterable[str]] | None = None,
    ) -> None:
        self._guard = guard
        self._audit = audit
        self._max_body = max(1, max_body_bytes)
        self._max_redirects = max(0, max_redirects)
        self._secrets = secrets or (lambda: ())
        self._client = httpx.Client(transport=transport, follow_redirects=False, timeout=timeout_s)
        self._client.cookies.jar.set_policy(_NoCookies())

    # ---- RequestExecutor ----------------------------------------------------------------

    def execute(self, request: RequestSpec) -> GuardDecision:
        spec = request
        previous: ResponseSnapshot | None = None
        for hop_number in range(self._max_redirects + 1):
            hop = self._send_once(spec)
            decision = hop.decision
            if not decision.allowed:
                # A denied redirect hop still reports the 3xx that pointed at it.
                return replace(decision, response=previous) if previous is not None else decision
            if hop.status not in _REDIRECT_STATUSES or not hop.location or decision.response is None:
                return decision
            previous = decision.response
            if hop_number == self._max_redirects:
                return decision
            next_spec = self._next_hop(spec, hop)
            if next_spec is None:
                seq = self._record(spec, allowed=False, deny_reason=OFF_SCOPE)
                return GuardDecision(False, response=previous, deny_reason=OFF_SCOPE, audit_seq=seq)
            spec = next_spec
        return decision  # pragma: no cover - loop always returns

    def close(self) -> None:
        self._client.close()
        self._audit.flush()

    def __enter__(self) -> "GuardedExecutor":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ---- internals ----------------------------------------------------------------------

    def _next_hop(self, spec: RequestSpec, hop: _Hop) -> RequestSpec | None:
        try:
            target = urljoin(spec.url, (hop.location or "").strip())
        except ValueError:
            return None
        method = spec.method.upper()
        body, headers = spec.body, dict(spec.headers or {})
        if hop.status == 303 and method != "HEAD" or hop.status in (301, 302) and method == "POST":
            method, body = "GET", None
            headers = {k: v for k, v in headers.items() if k.lower() not in _BODY_HEADERS}
        if urlsplit(target).hostname != urlsplit(spec.url).hostname:
            # Credentials were meant for the host the caller addressed, not wherever it redirects.
            headers = {k: v for k, v in headers.items() if k.lower() not in _CREDENTIAL_HEADERS}
        return replace(spec, method=method, url=target, body=body, headers=headers)

    def _record(
        self,
        spec: RequestSpec,
        *,
        allowed: bool,
        deny_reason: str | None = None,
        status: int | None = None,
        response_headers: Mapping[str, str] | None = None,
        response_body: str | None = None,
    ) -> int:
        secrets = tuple(self._secrets())
        record = AuditRecord(
            method=spec.method.upper(),
            url=redact_url(spec.url, secrets),
            allowed=allowed,
            identity_label=spec.identity_label or spec.identity_id,
            deny_reason=deny_reason,
            response_status=status,
            check_id=spec.check_id,
            request_headers=redact_headers(spec.headers, secrets) if spec.headers else None,
            response_headers=redact_headers(response_headers, secrets) if response_headers else None,
            request_body=_redacted_body(spec.body, secrets),
            response_body=_redacted_body(response_body, secrets),
        )
        return self._audit.record(record)

    def _send_once(self, spec: RequestSpec) -> _Hop:
        with self._guard.admit(spec.method, spec.url, intent=spec.intent or "", body=spec.body) as decision:
            if not decision.allowed:
                seq = self._record(spec, allowed=False, deny_reason=decision.reason)
                return _Hop(GuardDecision(False, deny_reason=decision.reason, audit_seq=seq))
            try:
                snapshot, response_headers, location = self._send(spec)
            except (httpx.HTTPError, httpx.InvalidURL, ValueError) as exc:
                # The request may or may not have reached the target, so it is audited as allowed.
                kind = "timeout" if isinstance(exc, httpx.TimeoutException) else type(exc).__name__
                logger.info("request to target failed (%s)", kind)
                seq = self._record(spec, allowed=True)
                detail = redact_text(f"{exc} {exc.__cause__ or ''} {exc.__context__ or ''}".strip(), tuple(self._secrets()))[:300]
                return _Hop(GuardDecision(True, error=kind, error_detail=detail, audit_seq=seq))
            seq = self._record(
                spec, allowed=True, status=snapshot.status, response_headers=response_headers,
                response_body=snapshot.body_excerpt,
            )
            return _Hop(GuardDecision(True, response=snapshot, audit_seq=seq), snapshot.status, location)

    def _send(self, spec: RequestSpec) -> tuple[ResponseSnapshot, dict[str, str], str | None]:
        max_body = max(1, spec.max_body_bytes) if spec.max_body_bytes else self._max_body
        kwargs: dict[str, Any] = {}
        body = spec.body
        if isinstance(body, (dict, list)):
            kwargs["json"] = body
        elif isinstance(body, (bytes, str)):
            kwargs["content"] = body
        request = self._client.build_request(spec.method.upper(), spec.url, headers=dict(spec.headers or {}), **kwargs)
        started = time.perf_counter()
        response = self._client.send(request, stream=True)
        try:
            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_bytes():
                room = max_body - total
                if room > 0:
                    chunks.append(chunk[:room])
                total += len(chunk)
                if total > max_body:
                    break  # the rest is dropped, not downloaded
            elapsed_ms = (time.perf_counter() - started) * 1000
            headers = {k: v for k, v in response.headers.items()}
            declared = response.headers.get("content-length", "")
            length = max(total, int(declared)) if declared.isdigit() else total
            try:
                excerpt = b"".join(chunks).decode(response.charset_encoding or "utf-8", errors="replace")
            except LookupError:  # a Content-Type naming a codec Python does not know
                excerpt = b"".join(chunks).decode("utf-8", errors="replace")
            location = response.headers.get("location")
            snapshot = ResponseSnapshot(
                status=response.status_code,
                length=length,
                body_excerpt=excerpt,
                headers=headers,
                elapsed_ms=elapsed_ms,
            )
        finally:
            response.close()
        return snapshot, headers, location

"""The HTTP OAST collaborator (DAST-09-060): one implementation of `domain.oast.OastCollaborator`.

Contract with the service (v1; swap the class to speak another service):

    callback address   <callback_url>/c/<token>          (the target is made to request it)
    poll               GET <poll_url>/poll?token=<token> -> {"callbacks": [{"token": ..., "remote": ..., "at": ...}]}

**Scope exception, on purpose.** The OAST service is not the target and is never one of the in-scope
hosts. Polling it therefore uses its own `httpx.Client`, configured explicitly, that is *not*
subject to the target scope check (`GuardedExecutor` would refuse it as off-scope, correctly). To
keep that exception reviewable, every poll is written to the request audit under its own category
(`check_id="oast-poll"`, identity label `oast`), with the token redacted from the URL.
"""

from __future__ import annotations

import secrets
import threading
import time
from typing import Callable
from urllib.parse import quote, urlsplit

import httpx

from app.dast.domain.oast import OastCallback, OastToken, make_token
from app.services.request_audit import AuditRecord, AuditSink

OAST_AUDIT_CHECK = "oast-poll"
OAST_AUDIT_IDENTITY = "oast"


class HttpOastCollaborator:
    def __init__(
        self,
        scan_id: str,
        callback_url: str,
        *,
        poll_url: str | None = None,
        audit: AuditSink | None = None,
        transport: httpx.BaseTransport | None = None,
        timeout_s: float = 10.0,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._scan_id = scan_id
        self.host = (urlsplit(callback_url).hostname or "").lower()  # the one other host an input may name
        self._callback = callback_url.rstrip("/")
        self._poll = (poll_url or callback_url).rstrip("/")
        self._audit = audit
        self._client = httpx.Client(transport=transport, timeout=timeout_s, follow_redirects=False)  # deliberately not the guarded executor
        self._nonce = secrets.token_hex(16)
        self._counter = 0
        self._lock = threading.Lock()
        self._sleep, self._clock = sleep, clock
        self.polls = 0

    def new_token(self, test_key: str) -> OastToken:
        with self._lock:
            self._counter += 1
            counter = self._counter
        token = make_token(self._scan_id, test_key, counter, self._nonce)
        return OastToken(token, f"{self._callback}/c/{quote(token)}", test_key)

    def _audit_poll(self, status: int | None) -> None:
        if self._audit is None:
            return
        try:
            self._audit.record(
                AuditRecord("GET", f"{self._poll}/poll?token=[REDACTED]", True, OAST_AUDIT_IDENTITY, None, status, OAST_AUDIT_CHECK)
            )
        except Exception:  # noqa: BLE001 - auditing must not break the scan
            pass

    def poll(self, token: OastToken, *, wait_s: float, interval_s: float = 1.0) -> list[OastCallback]:
        deadline = self._clock() + max(0.0, wait_s)
        while True:
            self.polls += 1
            status: int | None = None
            try:
                response = self._client.get(f"{self._poll}/poll", params={"token": token.token})
                status = response.status_code
                if response.status_code == 200:
                    items = response.json().get("callbacks") or []
                    found = [
                        OastCallback(str(i.get("token") or ""), str(i.get("remote") or ""), str(i.get("at") or ""))
                        for i in items
                        if isinstance(i, dict)
                    ]
                    found = [c for c in found if c.token == token.token]
                    if found:
                        self._audit_poll(status)
                        return found
            except (httpx.HTTPError, ValueError):
                status = None
            self._audit_poll(status)
            if self._clock() >= deadline:
                return []
            self._sleep(min(max(0.05, interval_s), max(0.0, deadline - self._clock())))

    def close(self) -> None:
        self._client.close()

"""The safety guard (DAST-01-010, -020): one decision point for every request a scan
sends to the target.

It composes the pure policy in `app.dast.domain.policy` (scope + method) with the
per-scan runtime controls that need state: cancellation, a request-rate limit and a
concurrency cap. Nothing here is process-global; each scan builds its own guard.

Typical use, via `GuardedExecutor` (the only HTTP client the engine receives):

    with guard.admit(method, url) as decision:
        if decision.allowed:
            send(...)          # holds a concurrency slot, rate token already taken

`decide` answers without waiting (scope, method, cancellation) and is what the
browser hook calls, because a browser request cannot be held open for a slot.
"""

from __future__ import annotations

import logging
import threading
import time
from contextlib import contextmanager
from typing import Any, Callable, Iterator, Mapping

import tldextract

from app.dast.domain.policy import (
    AUTHENTICATION_INTENT,
    CANCELLED,
    MARKER_SUBMIT_INTENT,
    METHOD_NOT_PERMITTED,
    OFF_SCOPE,
    Decision,
    MethodPolicy,
    RequestDescription,
    Scope,
    evaluate_redirect,
    evaluate_request,
    resolve_method_policy,
)
from app.dast.url_utils import normalize_url

logger = logging.getLogger(__name__)

# Offline on purpose: the bundled public-suffix snapshot is enough and a scope decision
# must never depend on a network fetch. Private suffixes are included (github.io, herokuapp.com,
# vercel.app, ...): they are shared hosting, where `bar.github.io` and `evil.github.io` are different
# owners. Without them, root-domain mode would treat every tenant of such a platform as in scope
# (found in the DAST-16-060 review).
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)


def registrable_domain(host: str) -> str:
    """The public-suffix-aware registrable domain of `host` ("" for IPs, single labels, bare suffixes)."""
    parts = _EXTRACT(host)
    if not parts.suffix or not parts.domain:
        return ""
    return f"{parts.domain}.{parts.suffix}"


class RateLimiter:
    """Spaces requests at least 1/rate seconds apart (a token bucket of capacity one, so
    no burst can push any one-second window above the configured rate). Thread-safe:
    each caller reserves its own slot under the lock and sleeps outside it."""

    def __init__(
        self,
        rate_per_sec: float,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if rate_per_sec <= 0:
            raise ValueError("rate_per_sec must be > 0")
        self._interval = 1.0 / rate_per_sec
        self._clock = clock
        self._sleep = sleep
        self._lock = threading.Lock()
        self._next_free: float | None = None

    def acquire(self) -> float:
        """Block until a request may be sent. Returns the seconds waited."""
        with self._lock:
            now = self._clock()
            start = now if self._next_free is None else max(now, self._next_free)
            self._next_free = start + self._interval
        wait = start - now
        if wait > 0:
            self._sleep(wait)
        return max(wait, 0.0)


class SafetyGuard:
    def __init__(
        self,
        scope: Scope,
        policy: MethodPolicy,
        *,
        rate_limit_per_sec: float,
        max_concurrent: int,
        is_cancelled: Callable[[], bool] | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        marker_post_ceiling: int = 30,
    ) -> None:
        if max_concurrent < 1:
            raise ValueError("max_concurrent must be >= 1")
        self.scope = scope
        self.policy = policy
        self._is_cancelled = is_cancelled or (lambda: False)
        self._login_windows = 0
        self._marker_windows = 0
        self.marker_token = ""
        self._marker_posts = 0
        self.marker_post_ceiling = max(0, int(marker_post_ceiling))
        self._window_lock = threading.Lock()
        self._limiter = RateLimiter(rate_limit_per_sec, clock=clock, sleep=sleep)
        self._slots = threading.BoundedSemaphore(max_concurrent)

    @classmethod
    def from_settings(
        cls,
        target_url: str,
        effective_settings: Mapping[str, object],
        *,
        target_disposable: bool = False,
        allow_state_changing: bool = False,
        is_cancelled: Callable[[], bool] | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> "SafetyGuard":
        """Build a guard from a scan's effective settings (`Settings.dast_effective_settings()`
        as snapshotted on the scan), so limits cannot drift from what the scan recorded."""
        scope = Scope.for_target(
            normalize_url(target_url, []),
            str(effective_settings.get("same_domain_mode", "exact")),  # type: ignore[arg-type]
            registrable_domain,
        )
        policy = resolve_method_policy(
            safe_mode=bool(effective_settings.get("safe_mode", True)),
            allow_state_changing=allow_state_changing,
            allow_marker_posts=bool(effective_settings.get("browser_marker_posts", False)),
            target_disposable=target_disposable,
        )
        return cls(
            scope,
            policy,
            rate_limit_per_sec=float(effective_settings["rate_limit_per_sec"]),  # type: ignore[arg-type]
            max_concurrent=int(effective_settings.get("max_concurrent_requests", 4)),  # type: ignore[arg-type]
            is_cancelled=is_cancelled,
            clock=clock,
            sleep=sleep,
            marker_post_ceiling=int(effective_settings.get("opt_in_request_ceiling") or 30),
        )

    # ---- the login window ---------------------------------------------------------------

    @contextmanager
    def login_window(self) -> Iterator[None]:
        """While open, a POST in scope is allowed even in safe mode (the login submit). Nests."""
        with self._window_lock:
            self._login_windows += 1
        try:
            yield
        finally:
            with self._window_lock:
                self._login_windows -= 1

    @property
    def login_window_open(self) -> bool:
        with self._window_lock:
            return self._login_windows > 0

    @contextmanager
    def marker_window(self, token: str) -> Iterator[None]:
        """While open, a POST in scope is allowed only when its body is this scan's marker payload.
        Nests. The policy still refuses the POST unless marker submits are enabled."""
        with self._window_lock:
            self._marker_windows += 1
            self.marker_token = token or ""
        try:
            yield
        finally:
            with self._window_lock:
                self._marker_windows -= 1
                if self._marker_windows == 0:
                    self.marker_token = ""

    @property
    def marker_window_open(self) -> bool:
        with self._window_lock:
            return self._marker_windows > 0

    def _take_marker_post(self) -> bool:
        with self._window_lock:
            if self._marker_posts >= self.marker_post_ceiling:
                return False
            self._marker_posts += 1
            return True

    # ---- decisions ----------------------------------------------------------------------

    def is_cancelled(self) -> bool:
        try:
            return bool(self._is_cancelled())
        except Exception:  # noqa: BLE001 - if cancellation cannot be read, assume it was requested
            logger.exception("cancel callback failed; treating the scan as cancelled")
            return True

    def decide(self, method: str, url: str, *, intent: str = "", body: Any = None) -> Decision:
        """Cancellation, scope, then method. Does not wait and holds nothing. Fails closed.
        `intent`/`body` matter only for the documented GraphQL-introspection exception."""
        if self.is_cancelled():
            return Decision(False, CANCELLED, "scan was cancelled")
        try:
            method_name = (method or "").strip().upper()
            token = ""
            if self.marker_window_open and method_name == "POST" and not intent:
                intent = MARKER_SUBMIT_INTENT
                token = self.marker_token
            elif not intent and self.login_window_open:
                intent = AUTHENTICATION_INTENT
            decision = evaluate_request(
                RequestDescription(method, url, intent, body, token), self.scope, self.policy
            )
            if decision.allowed and intent == MARKER_SUBMIT_INTENT and method_name == "POST" and not self._take_marker_post():
                return Decision(False, METHOD_NOT_PERMITTED, "the scan's marker-submit cap is spent")
            return decision
        except Exception:  # noqa: BLE001
            logger.exception("policy evaluation failed; denying")
            return Decision(False, OFF_SCOPE, "policy evaluation failed")

    def decide_redirect(self, current_url: str, location: str, method: str, *, intent: str = "", body: Any = None) -> Decision:
        if self.is_cancelled():
            return Decision(False, CANCELLED, "scan was cancelled")
        try:
            return evaluate_redirect(current_url, location, method, self.scope, self.policy, intent, body)
        except Exception:  # noqa: BLE001
            logger.exception("redirect evaluation failed; denying")
            return Decision(False, OFF_SCOPE, "redirect evaluation failed")

    @contextmanager
    def admit(self, method: str, url: str, *, intent: str = "", body: Any = None) -> Iterator[Decision]:
        """Decide, then (if allowed) hold a concurrency slot and spend a rate token for the
        duration of the `with` block. Cancellation is re-checked after any wait, so a scan
        cancelled while a caller was queued sends nothing."""
        decision = self.decide(method, url, intent=intent, body=body)
        if not decision.allowed:
            yield decision
            return
        with self._slots:
            self._limiter.acquire()
            if self.is_cancelled():
                yield Decision(False, CANCELLED, "scan was cancelled")
            else:
                yield decision

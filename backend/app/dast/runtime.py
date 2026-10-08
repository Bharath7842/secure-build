"""The per-scan collaborators the engine stages share (`state["runtime"]`).

Engine code never constructs infrastructure. The composition root
(`app/services/dast_runtime.build_runtime`, used by the API path and by the standalone CLI) builds
these once per scan and hands them in:

* `gateway`      the model gateway (the only way to reach a model)
* `executor`     the guarded request executor (the only HTTP client; every request is scope-checked,
                 rate-limited, cancel-checked and audited)
* `browser`      a browser driver whose contexts are guarded the same way; None for a scan that
                 never needs one (an API-only target), so no browser is even constructed
* `credentials`  the in-memory credential holder
* `identities`   who the scan acts as (no secrets)
* `effective`    the frozen effective settings
"""

from __future__ import annotations

import threading
from contextlib import nullcontext
from dataclasses import dataclass, field
from typing import Any, Callable, ContextManager, Protocol, Sequence

from .domain.identities import IdentitySpec


class BrowserSession(Protocol):
    """One identity's isolated browser state: its own context (cookies, storage) and page."""

    page: Any
    context: Any

    def cookies(self) -> list[dict]: ...

    def close(self) -> None: ...


class BrowserFactory(Protocol):
    def new_session(
        self, spec: IdentitySpec, *, storage_state: dict | None = None, extra_headers: dict[str, str] | None = None
    ) -> BrowserSession: ...

    def close(self) -> None: ...


class LiveCounters:
    """Thread-safe counters the stages bump while a scan runs (pages crawled, endpoints discovered,
    tests run, ...). Read by the live-summary endpoint every couple of seconds, so reading is a
    dictionary copy, never a query."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._values: dict[str, int] = {}

    def set(self, key: str, value: int) -> None:
        with self._lock:
            self._values[key] = int(value)

    def add(self, key: str, amount: int = 1) -> None:
        with self._lock:
            self._values[key] = self._values.get(key, 0) + int(amount)

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._values)


@dataclass
class ScanRuntime:
    gateway: Any
    executor: Any
    identities: Sequence[IdentitySpec]
    credentials: Any = None
    browser: BrowserFactory | None = None
    effective: dict[str, Any] = field(default_factory=dict)
    target_url: str = ""
    # Used only to namespace crawl screenshots on disk (data/dast_screenshots/{scan_id}/) —
    # nodes never use it to look anything up, consistent with everything else here arriving
    # as a collaborator rather than an id to query.
    scan_id: str = ""
    is_cancelled: Callable[[], bool] = lambda: False  # noqa: E731
    findings_writer: Callable[[str, list[dict]], None] | None = None
    # Optional: persist a live discovery snapshot after each finished endpoint so the UI can show
    # recorded traffic and results one API at a time. Signature: (graph_state) -> None.
    publish_discovery: Callable[[Any], None] | None = None
    log: Callable[[str], None] = print
    # The effective rule set (a `domain.ruleset.EffectiveRuleSet`) and the checks that cannot run
    # as designed; stages consult them to decide whether a check's findings should be written.
    rule_set: Any = None
    skipped_degraded: list[dict] = field(default_factory=list)
    # Everything the browser recorder captured (`domain.traffic.RecordedExchange`), shared with the
    # driver; feeds the inventory and, later, passive analysis.
    traffic: list = field(default_factory=list)
    # Wraps one task running in a worker thread so its log output stays together (see
    # `scan_log.buffered_capture`); a no-op by default. Takes a short label for the task.
    task_log: Callable[[str], ContextManager] = lambda label: nullcontext()  # noqa: E731
    # Opens the safety guard's login window (a form POST is allowed while an identity signs in).
    login_window: Callable[[], ContextManager] = nullcontext
    # Opens the marker-submit window for one inert XSS probe. Called with the scan's marker token.
    marker_window: Callable[[str], ContextManager] = lambda token: nullcontext()  # noqa: E731
    # Test hook: (page) -> ProbeDriver. Production leaves this None and uses Playwright.
    probe_driver_factory: Any = None
    # The out-of-band collaborator (`domain.oast.OastCollaborator`) when an OAST address is configured;
    # None otherwise, and the SSRF check then stays assist-only.
    oast: Any = None
    # Optional sink called with each finished active-testing target (`outcome, checks`); the training-data
    # capture hooks in here when a project has opted in. None otherwise.
    training_capture: Callable[[Any, Any], None] | None = None
    # Live counters for the progress summary (see `LiveCounters`).
    counters: LiveCounters = field(default_factory=LiveCounters)
    # Cleanup callables run (in order, errors ignored) by `close()` when the scan ends.
    closers: list = field(default_factory=list)

    def close(self) -> None:
        """Release what the composition root opened (the executor, which flushes the request
        audit, and the browser). Safe to call twice."""
        closers, self.closers = self.closers, []
        for closer in closers:
            try:
                closer()
            except Exception:  # noqa: BLE001 - one failed cleanup must not skip the rest
                pass

    def cancelled(self) -> bool:
        try:
            return bool(self.is_cancelled())
        except Exception:  # noqa: BLE001 - if it cannot be read, stop
            return True

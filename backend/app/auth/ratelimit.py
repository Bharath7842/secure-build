"""In-memory sliding-window limits for sign-in attempts.

Good for the single backend process this app runs as (scan threads already
require that). Counts are lost on restart, which only ever loosens a limit.
"""

from __future__ import annotations

import math
import threading
import time
from collections import defaultdict, deque


class SlidingWindow:
    def __init__(self, limit: int, window_seconds: float):
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _trim(self, key: str, now: float) -> deque[float]:
        hits = self._hits[key]
        while hits and hits[0] <= now - self.window:
            hits.popleft()
        return hits

    def retry_after(self, key: str, now: float | None = None) -> int:
        """Seconds until `key` may try again; 0 when it may try now."""
        now = time.monotonic() if now is None else now
        with self._lock:
            hits = self._trim(key, now)
            if len(hits) < self.limit:
                return 0
            return max(1, math.ceil(hits[0] + self.window - now))

    def hit(self, key: str, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        with self._lock:
            self._trim(key, now).append(now)

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._hits.clear()
            else:
                self._hits.pop(key, None)


WINDOW_SECONDS = 15 * 60
# Wrong passwords per account (normalized email) before it's paused.
failures_by_email = SlidingWindow(limit=5, window_seconds=WINDOW_SECONDS)
# All sign-in, setup and link attempts per client address.
attempts_by_ip = SlidingWindow(limit=30, window_seconds=WINDOW_SECONDS)


def reset_all() -> None:
    failures_by_email.reset()
    attempts_by_ip.reset()

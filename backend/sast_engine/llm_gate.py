"""One ordered gate in front of a local model server: at most `capacity` calls
are sent at a time, and waiting calls are served one whole scan before the next.

A local Ollama runs `OLLAMA_NUM_PARALLEL` generations at once (1 by default).
Calls sent past that wait inside the server, where they cannot be reordered or
cancelled and their request timeout is already running. Here they wait in this
process instead, and are only sent once the server can start them.

Order: the scan whose first gated call came first goes first, and within a scan
calls are served in arrival order. The gate is work-conserving, so a later
scan's call runs whenever the earlier scan has nothing waiting (its local regex
or call-graph work, say). Interleaving scans would not finish either sooner on
one slot, and would throw away the server's cached prompt prefix at every switch.

A separate module because `agent_bridge` reloads `llm_client` on every scan,
which would replace a gate defined there while calls are waiting on it.
"""

from __future__ import annotations

import itertools
import threading
from contextlib import contextmanager
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

# Usage-dict key holding the scan's place in the gate's order.
SCAN_ORDER_USAGE_KEY = "_gate_scan_order"
# How often a waiting call re-checks whether its scan was cancelled.
CANCEL_POLL_SECONDS = 1.0


class OrderedGate:
    def __init__(self) -> None:
        self._cond = threading.Condition()
        self._active = 0
        self._waiting: List[Tuple[int, int]] = []
        self._scan_order = itertools.count()
        self._ticket = itertools.count()

    def _order_for(self, usage: Optional[Dict[str, Any]]) -> int:
        """Caller holds the lock."""
        if usage is None:
            return next(self._scan_order)
        order = usage.get(SCAN_ORDER_USAGE_KEY)
        if order is None:
            order = next(self._scan_order)
            usage[SCAN_ORDER_USAGE_KEY] = order
        return order

    @contextmanager
    def slot(
        self,
        capacity: int,
        usage: Optional[Dict[str, Any]] = None,
        check_abort: Optional[Callable[[], None]] = None,
    ) -> Iterator[None]:
        """Hold one of `capacity` slots. `check_abort` is called while waiting
        and may raise (a cancelled scan); the call then leaves the queue."""
        capacity = max(1, int(capacity))
        with self._cond:
            entry = (self._order_for(usage), next(self._ticket))
            self._waiting.append(entry)
            try:
                while not (self._active < capacity and min(self._waiting) == entry):
                    self._cond.wait(timeout=CANCEL_POLL_SECONDS)
                    if check_abort is not None:
                        check_abort()
            except BaseException:
                self._waiting.remove(entry)
                self._cond.notify_all()
                raise
            self._waiting.remove(entry)
            self._active += 1
        try:
            yield
        finally:
            with self._cond:
                self._active -= 1
                self._cond.notify_all()

    def snapshot(self) -> Dict[str, int]:
        with self._cond:
            return {"active": self._active, "waiting": len(self._waiting)}


GATE = OrderedGate()

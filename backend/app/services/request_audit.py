"""Request-audit persistence (DAST-01-050).

Every request a DAST scan sent, or was refused permission to send, becomes one
`DastRequestAudit` row. Rows are batched (one commit per batch, not per request),
numbered 1.. per scan, and flushed on a short timer and at scan end so they survive
cancellation and failure.

Callers hand over already-redacted data (`GuardedExecutor` and the browser hook run
`app.dast.domain.redaction` first). Bodies are stored only after that redaction,
cut to `BODY_MAX` characters.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Mapping, Protocol

from sqlalchemy import func

from app import db as app_db
from app.models import DastRequestAudit

logger = logging.getLogger(__name__)

URL_MAX = 2000
BODY_MAX = 8192


@dataclass(frozen=True)
class AuditRecord:
    method: str
    url: str  # already redacted
    allowed: bool
    identity_label: str | None = None
    deny_reason: str | None = None
    response_status: int | None = None
    check_id: str | None = None
    request_headers: Mapping[str, str] | None = None  # already redacted
    response_headers: Mapping[str, str] | None = None  # already redacted
    request_body: str | None = None  # already redacted
    response_body: str | None = None  # already redacted
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class AuditSink(Protocol):
    def record(self, record: AuditRecord) -> int:
        """Persist (or buffer) the record and return its 1-based sequence number."""

    def flush(self) -> None: ...


class MemoryAuditSink:
    """In-memory sink for unit tests and for engines running without a database."""

    def __init__(self) -> None:
        self.records: list[AuditRecord] = []
        self._lock = threading.Lock()

    def record(self, record: AuditRecord) -> int:
        with self._lock:
            self.records.append(record)
            return len(self.records)

    def counts(self) -> dict[str, int]:
        with self._lock:
            return {"sent": sum(1 for r in self.records if r.allowed), "denied": sum(1 for r in self.records if not r.allowed)}

    def flush(self) -> None:
        return None


class DbAuditWriter:
    """Buffers audit rows for one scan and writes them in batches."""

    def __init__(
        self,
        scan_id: str,
        *,
        batch_size: int = 20,
        flush_interval_s: float = 2.0,
        session_factory: Callable[[], object] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.scan_id = scan_id
        self._batch_size = max(1, batch_size)
        self._flush_interval = flush_interval_s
        self._session_factory = session_factory
        self._clock = clock
        self._lock = threading.Lock()
        self._buffer: list[DastRequestAudit] = []
        self._next_seq: int | None = None
        self._last_flush = clock()
        self._sent = 0
        self._denied = 0

    def _session(self):
        # Resolved per call: `init_db` rebinds `app.db.SessionLocal`.
        return (self._session_factory or app_db.SessionLocal)()

    def _load_next_seq(self) -> int:
        with self._session() as session:
            current = session.query(func.max(DastRequestAudit.seq)).filter(DastRequestAudit.scan_id == self.scan_id).scalar()
        return (current or 0) + 1

    def record(self, record: AuditRecord) -> int:
        with self._lock:
            if self._next_seq is None:
                self._next_seq = self._load_next_seq()
            seq = self._next_seq
            self._next_seq += 1
            if record.allowed:
                self._sent += 1
            else:
                self._denied += 1
            self._buffer.append(
                DastRequestAudit(
                    scan_id=self.scan_id,
                    seq=seq,
                    method=record.method.upper()[:10],
                    url=record.url[:URL_MAX],
                    identity_label=(record.identity_label or None) and record.identity_label[:120],
                    allowed=record.allowed,
                    deny_reason=record.deny_reason,
                    response_status=record.response_status,
                    timestamp=record.timestamp,
                    check_id=record.check_id,
                    request_headers=dict(record.request_headers) if record.request_headers else None,
                    response_headers=dict(record.response_headers) if record.response_headers else None,
                    request_body=(record.request_body or None) and record.request_body[:BODY_MAX],
                    response_body=(record.response_body or None) and record.response_body[:BODY_MAX],
                )
            )
            due = len(self._buffer) >= self._batch_size or (self._clock() - self._last_flush) >= self._flush_interval
            if due:
                self._flush_locked()
            return seq

    def counts(self) -> dict[str, int]:
        """Requests sent and denied so far, kept in memory so polling it costs nothing."""
        with self._lock:
            return {"sent": self._sent, "denied": self._denied}

    def flush(self) -> None:
        with self._lock:
            self._flush_locked()

    def _flush_locked(self) -> None:
        if not self._buffer:
            self._last_flush = self._clock()
            return
        rows = list(self._buffer)
        try:
            with self._session() as session:
                session.add_all(rows)
                session.commit()
        except Exception:  # noqa: BLE001 - keep the rows and retry on the next flush; never break the scan
            logger.exception("request-audit flush failed for scan %s; %d rows kept for retry", self.scan_id, len(rows))
            return
        self._buffer.clear()
        self._last_flush = self._clock()

    def close(self) -> None:
        self.flush()

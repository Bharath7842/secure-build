"""Live counters and the progress summary of a DAST scan (DAST-12-030).

`GET /scans/{id}/summary` is polled every couple of seconds while a scan runs, so it must be cheap:

* what changes quickly (pages crawled, endpoints discovered, tests run, requests sent and denied,
  model calls and cost) is held in memory by the running scan (`LiveRegistry`) and read as a
  dictionary copy;
* findings by severity and verdict come from one `GROUP BY` over the indexed `findings.scan_id`;
* when the scan ends (finished, failed or cancelled) the final numbers are stored on the scan
  (`metadata_json["dast_summary"]`), so the same endpoint answers for a finished scan without
  touching the request-audit table, however large it is.

Running, finished and cancelled scans therefore return the same shape.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Callable

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models import UNVERIFIED_VERDICT, DastRequestAudit, Finding, Scan

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


@dataclass
class LiveScan:
    counters: Callable[[], dict[str, int]]
    audit_counts: Callable[[], dict[str, int]] = lambda: {"sent": 0, "denied": 0}  # noqa: E731
    usage: Callable[[], dict[str, Any]] = lambda: {}  # noqa: E731


class LiveRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._scans: dict[str, LiveScan] = {}

    def register(self, scan_id: str, live: LiveScan) -> None:
        with self._lock:
            self._scans[scan_id] = live

    def get(self, scan_id: str) -> LiveScan | None:
        with self._lock:
            return self._scans.get(scan_id)

    def unregister(self, scan_id: str) -> None:
        with self._lock:
            self._scans.pop(scan_id, None)


registry = LiveRegistry()


def _findings_counts(db: Session, scan_id: str) -> dict[str, Any]:
    rows = (
        db.query(Finding.severity, Finding.verdict, func.count())
        .filter(Finding.scan_id == scan_id, Finding.kind == "dast")
        .group_by(Finding.severity, Finding.verdict)
        .all()
    )
    by_severity = {sev: 0 for sev in SEVERITIES}  # confirmed only
    verdicts = {"true_positive": 0, UNVERIFIED_VERDICT: 0, "false_positive": 0}
    for severity, verdict, count in rows:
        verdicts[verdict or ""] = verdicts.get(verdict or "", 0) + count
        if verdict == "true_positive":
            key = (severity or "INFO").upper()
            by_severity[key if key in by_severity else "INFO"] += count
    return {"by_severity": by_severity, "by_verdict": verdicts, "total": sum(verdicts.values())}


def _persisted(scan: Scan) -> dict[str, Any]:
    return dict((scan.metadata_json or {}).get("dast_summary") or {})


def _from_discovery(scan: Scan) -> dict[str, Any]:
    """Counters rebuilt from the stored discovery, for a scan that has no live entry and no stored summary."""
    discovery = (scan.metadata_json or {}).get("discovery") or {}
    active = discovery.get("active_testing") or {}
    return {
        "pages": len(discovery.get("pages") or []),
        "endpoints": discovery.get("inventory_count") if discovery.get("inventory_count") is not None else len(discovery.get("api_calls") or []),
        "tests": int(active.get("tests_sent") or 0),
        "replays": int((discovery.get("authorization") or {}).get("total_replays") or 0),
        "browser_inputs": int((discovery.get("browser_probe") or {}).get("probes") or 0),
        "passive_findings": int((discovery.get("passive_analysis") or {}).get("findings") or 0),
    }


def _audit_counts_from_db(db: Session, scan_id: str) -> dict[str, int]:
    sent = db.query(func.count()).select_from(DastRequestAudit).filter(DastRequestAudit.scan_id == scan_id, DastRequestAudit.allowed.is_(True)).scalar() or 0
    denied = db.query(func.count()).select_from(DastRequestAudit).filter(DastRequestAudit.scan_id == scan_id, DastRequestAudit.allowed.is_(False)).scalar() or 0
    return {"sent": int(sent), "denied": int(denied)}


def build_summary(db: Session, scan: Scan) -> dict[str, Any]:
    meta = scan.metadata_json or {}
    live = registry.get(scan.id) if scan.status in ("queued", "running", "paused") else None
    stored = _persisted(scan)
    if live is not None:
        counters, audit, usage = live.counters(), live.audit_counts(), live.usage()
    elif stored:
        counters, audit, usage = stored.get("counters") or {}, stored.get("requests") or {}, stored.get("usage") or {}
    else:  # a scan from before summaries existed, or one the process lost: rebuild once
        counters = _from_discovery(scan)
        audit = _audit_counts_from_db(db, scan.id)
        usage = meta.get("usage_summary") or {}
    findings = _findings_counts(db, scan.id)
    skipped = meta.get("dast_skipped_degraded") or []
    return {
        "scan_id": scan.id,
        "status": scan.status,
        "running": scan.status in ("queued", "running", "paused"),
        "pages_crawled": int(counters.get("pages", 0)),
        "endpoints_discovered": int(counters.get("endpoints", 0)),
        "requests_sent": int(audit.get("sent", 0)),
        "requests_denied": int(audit.get("denied", 0)),
        "tests_run": int(counters.get("tests", 0)),
        "replays": int(counters.get("replays", 0)),
        "browser_inputs": int(counters.get("browser_inputs", 0)),
        "findings": findings,
        "skipped_checks": len(skipped),
        "model_calls": int(usage.get("call_count", 0) or 0),
        "model_cost_usd": float(usage.get("cost_usd", 0.0) or 0.0),
        "model_tokens": int(usage.get("total_tokens", 0) or 0),
    }


def finalize(db: Session, scan: Scan) -> None:
    """Store the scan's final numbers and drop its live entry. Called on every exit path."""
    live = registry.get(scan.id)
    meta = dict(scan.metadata_json or {})
    if live is not None:
        counters, usage = live.counters(), live.usage()
        requests = live.audit_counts()
    else:
        counters, usage, requests = _from_discovery(scan), meta.get("usage_summary") or {}, None
    if requests is None or not (requests.get("sent") or requests.get("denied")):
        requests = _audit_counts_from_db(db, scan.id)  # one count when the scan ends, never while it polls
    meta["dast_summary"] = {"counters": counters, "requests": requests, "usage": {k: usage.get(k) for k in ("call_count", "cost_usd", "total_tokens") if k in usage}}
    scan.metadata_json = meta
    db.commit()
    registry.unregister(scan.id)

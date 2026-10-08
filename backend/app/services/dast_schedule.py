"""Repeating DAST scans and named scan profiles.

A schedule stores a ScanCreate body with every secret removed. The scheduler thread
is off unless DAST_SCHEDULER_ENABLED is set, so the test suite never starts a scan.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.config import settings
from app.models import DastGlobalConfig, DastSchedule, Scan

logger = logging.getLogger(__name__)

PROFILES_KEY = "scan_profiles"
_SECRET_KEYS = frozenset(
    {"password", "token", "cookie", "authorization", "login_har", "secret", "access_token", "refresh_token"}
)
_thread: threading.Thread | None = None
_stop = threading.Event()


def strip_secrets(value):
    if isinstance(value, dict):
        return {k: strip_secrets(v) for k, v in value.items() if k.lower() not in _SECRET_KEYS}
    if isinstance(value, list):
        return [strip_secrets(v) for v in value]
    return value


def save_schedule(db: Session, *, project_id: str, name: str, interval_minutes: int, request: dict) -> DastSchedule:
    from app.schemas import ScanCreate

    cleaned = strip_secrets(request)
    ScanCreate.model_validate(cleaned)  # rejects a body the trigger endpoint would reject
    row = DastSchedule(
        project_id=project_id,
        name=(name or "Scheduled DAST")[:200],
        interval_minutes=max(15, int(interval_minutes)),
        request_json=cleaned,
        next_run_at=datetime.now(timezone.utc),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def queue_view(db: Session) -> dict:
    active = (
        db.query(Scan)
        .filter(Scan.status.in_(("queued", "running", "paused")))
        .order_by(Scan.created_at)
        .all()
    )
    schedules = db.query(DastSchedule).filter(DastSchedule.enabled.is_(True)).order_by(DastSchedule.next_run_at).all()
    return {
        "active": [
            {"scan_id": s.id, "project_id": s.project_id, "status": s.status, "scan_type": s.scan_type or "sast"}
            for s in active
        ],
        "schedules": [
            {
                "id": row.id,
                "project_id": row.project_id,
                "name": row.name,
                "interval_minutes": row.interval_minutes,
                "next_run_at": row.next_run_at.isoformat() if row.next_run_at else None,
                "last_scan_id": row.last_scan_id,
            }
            for row in schedules
        ],
    }


def list_profiles(db: Session) -> list[dict]:
    row = db.get(DastGlobalConfig, PROFILES_KEY)
    value = (row.value if row else None) or {}
    profiles = value.get("profiles") if isinstance(value, dict) else None
    return list(profiles or [])


def save_profiles(db: Session, profiles: list[dict]) -> list[dict]:
    cleaned = []
    for profile in profiles:
        name = str(profile.get("name") or "").strip()
        intensity = str(profile.get("intensity") or "standard").strip().lower()
        if not name or intensity not in ("light", "standard", "deep"):
            continue
        cleaned.append(
            {
                "name": name[:80],
                "intensity": intensity,
                "method_policy": profile.get("method_policy") if profile.get("method_policy") in ("safe", "opt_in_mutating") else "safe",
                "rule_packs": [str(p) for p in (profile.get("rule_packs") or [])][:12],
            }
        )
    row = db.get(DastGlobalConfig, PROFILES_KEY)
    if row is None:
        db.add(DastGlobalConfig(key=PROFILES_KEY, value={"profiles": cleaned}))
    else:
        row.value = {"profiles": cleaned}
    db.commit()
    return cleaned


def tick(db: Session) -> int:
    """Start every schedule that is due. Returns how many scans were started."""
    from app.routers.scans import trigger_scan
    from app.schemas import ScanCreate

    now = datetime.now(timezone.utc)
    due = (
        db.query(DastSchedule)
        .filter(DastSchedule.enabled.is_(True), DastSchedule.next_run_at <= now)
        .all()
    )
    started = 0
    for row in due:
        try:
            payload = ScanCreate.model_validate(strip_secrets(row.request_json or {}))
            out = trigger_scan(payload, db)
            row.last_scan_id = out.scan_id
            started += 1
        except Exception:  # noqa: BLE001 - one bad schedule must not stop the others
            logger.exception("scheduled DAST scan %s did not start", row.id)
        row.next_run_at = now + timedelta(minutes=max(15, int(row.interval_minutes or 1440)))
    if due:
        db.commit()
    return started


def _loop() -> None:
    from app.db import SessionLocal

    while not _stop.wait(30):
        db = SessionLocal()
        try:
            tick(db)
        except Exception:  # noqa: BLE001
            logger.exception("DAST scheduler tick failed")
        finally:
            db.close()


def start_scheduler() -> None:
    global _thread
    if not settings.dast_scheduler_enabled or _thread is not None:
        return
    _stop.clear()
    _thread = threading.Thread(target=_loop, name="dast-scheduler", daemon=True)
    _thread.start()

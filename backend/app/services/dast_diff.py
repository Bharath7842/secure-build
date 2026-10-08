"""Scan-to-scan comparison for DAST scans (DAST-11-020) and the `first_seen` / `last_seen` bookkeeping.

The previous comparable scan is the latest earlier *successful* DAST scan of the same project and
target; the caller may name a different earlier scan of the same project instead. What each scan
actually ran comes from its stored rule-set snapshot (and dependency skips), so a check that was off
in one of them is never reported as fixed.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.dast.domain.diff import DiffItem, compute_diff, item_key
from app.models import Finding, Scan


def normalize_target(url: str | None) -> str:
    parts = urlsplit((url or "").strip())
    path = parts.path.rstrip("/")
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}{path}"


def checks_run(scan: Scan) -> set[str] | None:
    """Check ids this scan ran as designed, from its rule-set snapshot; None when it has none
    (a scan from before snapshots existed, or the mock engine), which the diff reads as unknown."""
    meta = scan.metadata_json or {}
    snapshot = meta.get("dast_rule_set") or {}
    checks = snapshot.get("checks")
    if not checks:
        return None
    skipped = {
        s.get("check_id")
        for s in (meta.get("dast_skipped_degraded") or [])
        if s.get("status") == "skipped" or s.get("effective_mode") == "assist-only"
    }
    return {c["id"] for c in checks if c.get("enabled") and c["id"] not in skipped}


def previous_comparable_scan(db: Session, scan: Scan, against: str | None = None) -> Scan | None:
    if against:
        other = db.get(Scan, against)
        if other is None or (other.scan_type or "sast") != "dast" or other.project_id != scan.project_id or other.id == scan.id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Choose an earlier DAST scan of the same project to compare with.")
        return other
    target = normalize_target(scan.git_url)
    candidates = (
        db.query(Scan)
        .filter(Scan.project_id == scan.project_id, Scan.scan_type == "dast", Scan.status == "success", Scan.id != scan.id, Scan.version < scan.version)
        .order_by(Scan.version.desc())
        .all()
    )
    return next((c for c in candidates if normalize_target(c.git_url) == target), None)


def _items(db: Session, scan: Scan) -> list[DiffItem]:
    rows = db.query(Finding).filter(Finding.scan_id == scan.id, Finding.kind == "dast").order_by(Finding.rule_id, Finding.target, Finding.param, Finding.id).all()
    return [
        DiffItem(r.rule_id or "", r.target or r.file_path or "", r.param, (r.severity or "").upper(), r.verdict or "", tuple(r.roles or ()), r.id, r.title or "")
        for r in rows
    ]


def build_diff(db: Session, scan: Scan, against: str | None = None) -> dict[str, Any]:
    previous = previous_comparable_scan(db, scan, against)
    result = compute_diff(
        _items(db, scan), _items(db, previous) if previous is not None else None,
        current_checks_run=checks_run(scan), previous_checks_run=checks_run(previous) if previous is not None else None,
    )
    notes: list[str] = []
    if not result.baseline:
        notes.append("No baseline: there is no earlier successful scan of this target, so every finding is new.")
    if result.checks_not_run_current:
        notes.append("Not run in this scan (their earlier findings are not reported as fixed): " + ", ".join(result.checks_not_run_current))
    if result.checks_not_run_previous:
        notes.append("Not run in the earlier scan (their findings here are new by definition): " + ", ".join(result.checks_not_run_previous))
    return {
        "scan_id": scan.id,
        "previous_scan_id": previous.id if previous is not None else None,
        "previous_version": previous.version if previous is not None else None,
        "baseline": result.baseline,
        "entries": [
            {
                "check_id": e.item.check_id if e.item else e.key[0], "target": e.item.target if e.item else e.key[1], "param": e.item.param if e.item else None,
                "status": e.status.value, "severity": e.item.severity if e.item else "", "verdict": e.item.verdict if e.item else "",
                "roles": list(e.item.roles) if e.item else [], "finding_id": e.item.finding_id if e.item else "", "title": e.item.title if e.item else "", "note": e.note,
            }
            for e in result.entries
        ],
        "counts": result.counts(),
        "not_comparable": [
            {"check_id": n.item.check_id, "target": n.item.target, "param": n.item.param, "severity": n.item.severity, "reason": n.reason} for n in result.not_comparable
        ],
        "notes": notes,
        "checks_not_run_current": result.checks_not_run_current,
        "checks_not_run_previous": result.checks_not_run_previous,
    }


def refresh_seen(db: Session, scan: Scan) -> int:
    """Maintain `first_seen_scan_id` / `last_seen_scan_id` on `scan`'s findings: a finding also open
    in the previous comparable scan inherits that finding's first sighting. Idempotent; returns how
    many findings carry an earlier first sighting."""
    previous = previous_comparable_scan(db, scan)
    earlier: dict[Any, Finding] = {}
    if previous is not None:
        for row in db.query(Finding).filter(Finding.scan_id == previous.id, Finding.kind == "dast"):
            earlier.setdefault(item_key(DiffItem(row.rule_id or "", row.target or row.file_path or "", row.param, roles=tuple(row.roles or ()))), row)
    inherited = 0
    for row in db.query(Finding).filter(Finding.scan_id == scan.id, Finding.kind == "dast"):
        row.last_seen_scan_id = scan.id
        match = earlier.get(item_key(DiffItem(row.rule_id or "", row.target or row.file_path or "", row.param, roles=tuple(row.roles or ()))))
        row.first_seen_scan_id = (match.first_seen_scan_id or match.scan_id) if match is not None else scan.id
        inherited += 1 if match is not None else 0
    db.commit()
    return inherited

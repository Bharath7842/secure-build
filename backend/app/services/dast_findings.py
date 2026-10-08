"""The DAST findings writer (DAST-04-050): persists findings and their evidence as each
stage emits them, deduplicated within the scan.

Dedupe key: `(rule_id, path_template, param)` from `app.dast.domain.dedupe`. The first
occurrence becomes the finding; a later occurrence of the same issue on another endpoint
(`/users/1` then `/users/2`) adds its target to the finding's `affected_files` instead of
creating a second row. A retry of a stage re-emits findings with the *same* target, which is
recognized and ignored, so writing is idempotent per `(scan_id, rule_id, path_template, param)`.

If the later occurrence is a stronger result than the stored one (a confirmed `true_positive`
where an `unverified` is stored) the stored finding is upgraded in place: verdict, severity,
reason and evidence move to the stronger result, the locations are kept.

The writer signature `write(label, rows)` is the same `findings_writer` the engine stages
already call; one instance serves one scan and is safe to call from several threads.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Callable, Mapping, Sequence

from app import db as db_module
from app.dast.domain.dedupe import DedupeKey, key_for, merge_locations
from app.models import UNVERIFIED_VERDICT, DastEvidence, Finding
from app.services import scan_log
from app.services.finding_rows import build_evidence_row, build_finding_row

logger = logging.getLogger(__name__)

_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _roles_part(roles) -> str:
    return ">".join(roles or ())


def _key_of_row(row: Mapping[str, Any]) -> DedupeKey:
    """`(rule, path template, param)` plus the role pair for an authorization finding, so the same
    endpoint exposed to two different role pairs stays two findings (each is a matrix cell)."""
    base = key_for(row.get("rule_id") or "", row.get("target") or row.get("file_path") or "", row.get("param"))
    roles = _roles_part(row.get("roles"))
    return (*base, roles) if roles else base  # type: ignore[return-value]


def _stronger(new: Mapping[str, Any], stored_verdict: str | None) -> bool:
    return new.get("verdict") == "true_positive" and stored_verdict == UNVERIFIED_VERDICT


def _browser_confirmed(row: Mapping[str, Any]) -> bool:
    """A later row that proves the marker ran in the browser. Used to attach that proof to the
    reflected-XSS finding the HTTP stage already stored."""
    signals = (row.get("evidence") or {}).get("signals") or []
    return any(isinstance(s, Mapping) and s.get("name") == "marker_executed_in_browser" for s in signals)


def _already_executed(session, finding_id: str) -> bool:
    from app.models import DastEvidence

    for evidence in session.query(DastEvidence).filter(DastEvidence.finding_id == finding_id):
        if any(isinstance(s, Mapping) and s.get("name") == "marker_executed_in_browser" for s in (evidence.signals or [])):
            return True
    return False


class DastFindingsWriter:
    def __init__(self, scan_id: str, *, session_factory: Callable[[], Any] | None = None) -> None:
        self.scan_id = scan_id
        self._session_factory = session_factory
        self._lock = threading.Lock()
        self._index: dict[DedupeKey, str] | None = None  # key -> finding id, loaded lazily

    def _session(self):
        return (self._session_factory or db_module.SessionLocal)()

    def _load_index(self, session) -> dict[DedupeKey, str]:
        index: dict[DedupeKey, str] = {}
        for row in session.query(Finding).filter(Finding.scan_id == self.scan_id, Finding.kind == "dast"):
            base = key_for(row.rule_id or "", row.target or row.file_path or "", row.param)
            roles = _roles_part(row.roles)
            index[(*base, roles) if roles else base] = row.id  # type: ignore[index]
        return index

    def __call__(self, label: str, rows: Sequence[Mapping[str, Any]]) -> None:
        self.write(label, rows)

    def write(self, label: str, rows: Sequence[Mapping[str, Any]]) -> dict[str, int]:
        """Persist `rows`. Returns counts: `created`, `merged` (added a location or upgraded),
        `duplicate` (already stored, ignored)."""
        counts = {"created": 0, "merged": 0, "duplicate": 0}
        if not rows:
            return counts
        with self._lock:
            session = self._session()
            try:
                if self._index is None:
                    self._index = self._load_index(session)
                for row in rows:
                    outcome = self._write_one(session, label, row)
                    counts[outcome] += 1
                session.commit()
            except Exception:
                session.rollback()
                self._index = None  # re-read on the next call; never trust a half-applied cache
                raise
            finally:
                session.close()
        scan_log.log(
            self.scan_id,
            f"  Saved findings for {label}: {counts['created']} new, {counts['merged']} merged, "
            f"{counts['duplicate']} already recorded.",
        )
        return counts

    def _write_one(self, session, label: str, row: Mapping[str, Any]) -> str:
        key = _key_of_row(row)
        existing_id = (self._index or {}).get(key)
        if existing_id is None:
            finding = build_finding_row(self.scan_id, row, label)
            session.add(finding)
            session.flush()
            if row.get("evidence"):
                session.add(build_evidence_row(finding.id, row["evidence"]))
            assert self._index is not None
            self._index[key] = finding.id
            return "created"

        existing = session.get(Finding, existing_id)
        target = row.get("target") or row.get("file_path") or label
        outcome = "duplicate"
        known = list(existing.affected_files or [])
        if not known and existing.target:
            known = [existing.target]
        if target and target not in known:
            existing.affected_files = merge_locations(known, target)
            outcome = "merged"
        if _browser_confirmed(row) and not _already_executed(session, existing.id):
            self._upgrade(session, existing, row)
            if row.get("verdict") == "true_positive":
                existing.verdict = "true_positive"
            outcome = "merged"
        elif _stronger(row, existing.verdict):
            self._upgrade(session, existing, row)
            outcome = "merged"
        return outcome

    @staticmethod
    def _upgrade(session, existing: Finding, row: Mapping[str, Any]) -> None:
        existing.verdict = row.get("verdict")
        existing.verdict_reason = row.get("verdict_reason") or existing.verdict_reason
        existing.confidence = row.get("confidence", existing.confidence)
        existing.confidence_label = row.get("confidence_label") or existing.confidence_label
        new_sev = row.get("severity")
        if new_sev and _SEVERITY_RANK.get(new_sev, 9) < _SEVERITY_RANK.get(existing.severity, 9):
            existing.severity = new_sev
        if row.get("evidence"):
            for old in session.query(DastEvidence).filter(DastEvidence.finding_id == existing.id):
                session.delete(old)
            session.flush()
            session.add(build_evidence_row(existing.id, row["evidence"]))

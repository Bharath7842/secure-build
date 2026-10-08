"""Read side of DAST findings (DAST-04-060): grouping, filtering and enrichment for
`GET /scans/{id}/findings` on a DAST scan.

Filters (all optional, combinable): `severity`, `verdict`, `role`, `check`. Each accepts a comma
separated list. `unverified` findings are never hidden by default; a caller removes them only by
asking for a verdict that excludes them. `role` matches a role label involved in the finding,
and `a:b` matches a role pair (both involved).
"""

from __future__ import annotations

from typing import Iterable

from sqlalchemy.orm import Session

from app.models import UNVERIFIED_VERDICT, DastEvidence, Finding, Scan
from app.schemas import DastEvidenceOut, DastFindingOut, DastScanFindingsOut, DastTrafficOut
from app.services.dast_catalog import default_catalog, remediation_text
from app.services.dast_traffic import audits_by_seq, seq_from_ref, traffic_for
from app.services.scan_export import SEVERITY_ORDER, group_findings_by_issue


def _csv(value: str | None) -> list[str]:
    return [v.strip() for v in (value or "").split(",") if v.strip()]


def _matches_role(finding: Finding, wanted: list[str]) -> bool:
    roles = {r.lower() for r in (finding.roles or [])}
    for item in wanted:
        parts = {p.strip().lower() for p in item.split(":") if p.strip()}
        if parts and parts <= roles:
            return True
    return False


def _sort_key(finding: Finding) -> tuple:
    sev = (finding.severity or "").lower()
    rank = SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else len(SEVERITY_ORDER)
    return (rank, finding.target or "", finding.rule_id or "", finding.param or "")


def build_dast_findings(
    db: Session,
    scan: Scan,
    *,
    severity: str | None = None,
    verdict: str | None = None,
    role: str | None = None,
    check: str | None = None,
) -> DastScanFindingsOut:
    rows: list[Finding] = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    catalog = default_catalog()

    severities = {s.upper() for s in _csv(severity)}
    verdicts = {v.lower() for v in _csv(verdict)}
    roles = _csv(role)
    checks = {catalog.resolve_id(c) for c in _csv(check)}

    def keep(row: Finding) -> bool:
        if severities and (row.severity or "").upper() not in severities:
            return False
        if verdicts and (row.verdict or "").lower() not in verdicts:
            return False
        if roles and not _matches_role(row, roles):
            return False
        if checks and catalog.resolve_id(row.rule_id or "") not in checks:
            return False
        return True

    filtered = [r for r in rows if keep(r)]
    grouped = sorted(group_findings_by_issue(filtered), key=_sort_key)
    evidence_by_finding = _evidence_for(db, [g.id for g in grouped])
    audits = audits_by_seq(db, scan.id, (evidence_by_finding[g.id].audit_ref for g in grouped if g.id in evidence_by_finding))

    out: list[DastFindingOut] = []
    for finding in grouped:
        item = DastFindingOut.model_validate(finding)
        item.remediation = remediation_text(finding.remediation_ref or "")
        item.standards = list(finding.standards or [])
        item.roles = list(finding.roles or [])
        stored = evidence_by_finding.get(finding.id)
        if stored is None:
            item.evidence = DastEvidenceOut(request=DastTrafficOut.model_validate(traffic_for(finding)))
        else:
            item.evidence = DastEvidenceOut.model_validate(stored)
            seq = seq_from_ref(stored.audit_ref)
            item.evidence.request = DastTrafficOut.model_validate(
                traffic_for(finding, audit=audits.get(seq) if seq is not None else None, audit_ref=stored.audit_ref)
            )
        out.append(item)

    return DastScanFindingsOut(
        scan_id=scan.id,
        tp_count=sum(1 for r in rows if r.verdict == "true_positive"),
        fp_count=sum(1 for r in rows if r.verdict == "false_positive"),
        unverified_count=sum(1 for r in rows if r.verdict == UNVERIFIED_VERDICT),
        files_scanned=len({r.file_path for r in rows if r.file_path}),
        total_count=len(rows),
        findings=out,
    )


def _evidence_for(db: Session, finding_ids: Iterable[str]) -> dict[str, DastEvidence]:
    ids = list(finding_ids)
    if not ids:
        return {}
    return {e.finding_id: e for e in db.query(DastEvidence).filter(DastEvidence.finding_id.in_(ids))}

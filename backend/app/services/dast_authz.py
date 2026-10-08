"""The authorization matrix for a DAST scan (DAST-10-040).

Derived, never stored: it is recomputed on every request from what the scan stored (the identities
it ran as, the replay summaries its authorization stage wrote, and the findings, whose `roles` name
the pair) so it cannot drift from the findings. Works for a scan in progress: before the stage has
run every cell is `untested` ("has not run yet"), and a failing cell appears as soon as its
finding is written.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.dast.domain.authz import FindingRef, derive_matrix, matrix_notes
from app.dast.domain.identities import build_identities, spec_from_public
from app.models import Finding, Scan
from app.schemas import DastAuthzCellOut, DastAuthzIdentityOut, DastAuthzMatrixOut, DastRoleOut

AUTHZ_CHECKS = ("dast-authn", "dast-bfla", "dast-bola")


def build_authz_matrix(db: Session, scan: Scan) -> DastAuthzMatrixOut:
    meta = scan.metadata_json or {}
    stored = list((meta.get("dast_input") or {}).get("identities") or [])
    specs = [spec_from_public(i) for i in stored] if stored else build_identities([])
    authorization = (meta.get("discovery") or {}).get("authorization") or {}
    ran = bool(authorization.get("ran")) or scan.status == "success" and bool(authorization.get("replays"))
    refs = [
        FindingRef(f.id, f"{f.rule_id}|{f.target}", tuple(f.roles or ()), f.verdict or "")
        for f in db.query(Finding).filter(Finding.scan_id == scan.id, Finding.kind == "dast", Finding.rule_id.in_(AUTHZ_CHECKS)).order_by(Finding.rule_id, Finding.target, Finding.id)
        if f.roles
    ]
    # An in-progress scan has findings but no stored summary yet: failing cells still show.
    cells = derive_matrix(specs, authorization.get("replays") or [], refs, ran=ran)
    notes = matrix_notes(specs)
    anonymous = next((s for s in specs if s.is_anonymous), None)
    return DastAuthzMatrixOut(
        scan_id=scan.id,
        ran=ran,
        identities=[
            DastAuthzIdentityOut(identity_id=s.identity_id, label=s.label, role=DastRoleOut(name=s.role.name.value, label=s.role.label))
            for s in specs
            if not s.is_anonymous
        ],
        baseline_identity=anonymous.label if anonymous else "anonymous",
        replays=int(authorization.get("total_replays") or 0),
        degraded=notes["degraded"],
        degraded_reason=notes["degraded_reason"],
        cells=[DastAuthzCellOut(**c.to_dict()) for c in cells],
    )

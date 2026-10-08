"""The DAST report data set (DAST-11-010): everything the report view, the PDF and the XLSX show,
built once from what the scan stored.

Honest by construction:

* severity counts are *confirmed* findings only (`true_positive`); `unverified` findings (an
  inconclusive check, a review item for a check a scan cannot test) are listed separately and never
  added to the severity totals;
* counts are taken from the stored finding rows (the same grouped list `GET /scans/{id}/findings`
  returns), not recomputed from anything else, so the report cannot disagree with the findings view;
* skipped and degraded checks, the rule packs and their versions, and the scan's settings are part
  of the report, so a reader can tell what was and was not tested.

A DAST branch next to the SAST one: SAST/SCA/SBOM reports are untouched.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.models import UNVERIFIED_VERDICT, Project, Scan
from app.services.dast_catalog import default_catalog
from app.services.dast_diff import build_diff
from app.services.dast_findings_query import build_dast_findings
from app.services.dast_traffic import format_request

SEVERITIES = ("critical", "high", "medium", "low", "info")
REVIEW_SOURCE = "assist-only review"


def severity_bucket(value: str | None) -> str:
    key = (value or "info").strip().lower()
    return key if key in SEVERITIES else "info"


def _finding(f: Any) -> dict[str, Any]:
    evidence = f.evidence
    request = None
    if evidence is not None and getattr(evidence, "request", None) is not None:
        request = evidence.request.model_dump() if hasattr(evidence.request, "model_dump") else dict(evidence.request)
    return {
        "id": f.id,
        "check_id": f.rule_id,
        "title": f.title,
        "severity": (f.severity or "").upper(),
        "verdict": f.verdict,
        "confidence": f.confidence_label or "",
        "target": f.target or f.file_path or "",
        "param": f.param,
        "location": f.location,
        "standards": list(f.standards or []),
        "remediation": f.remediation or "",
        "remediation_ref": f.remediation_ref,
        "reason": f.verdict_reason or "",
        "source": f.source or "",
        "roles": list(f.roles or []),
        "affected": list(f.affected_files or []),
        "review_item": (f.source or "") == REVIEW_SOURCE,
        "evidence": (
            {
                "baseline": evidence.baseline_excerpt or "",
                "test": evidence.test_excerpt or "",
                "signals": list(evidence.signals or []),
                "audit_ref": evidence.audit_ref or "",
                "request": request,
                "request_text": format_request(request, fallback_target=f.target or f.file_path or ""),
            }
            if evidence is not None
            else None
        ),
    }


def _pack_summary(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    catalog = default_catalog()
    out = []
    for pack_id in snapshot.get("packs") or []:
        pack = catalog.pack(pack_id)
        out.append({"id": pack_id, "title": pack.title if pack else pack_id})
    return out


def _settings_summary(effective: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "intensity", "safe_mode", "method_policy", "target_disposable", "rate_limit_per_sec", "max_targets", "max_tests_per_target",
        "max_depth", "max_pages", "max_runtime_minutes", "same_domain_mode", "oast_configured", "rule_checks_enabled", "rule_checks_total",
    )
    summary = {k: effective[k] for k in keys if k in effective}
    summary["identities"] = [
        {"label": i.get("label"), "role": i.get("role_label") or i.get("role"), "auth_method": i.get("auth_method")} for i in effective.get("identities") or [] if i.get("role") != "anonymous"
    ]
    summary["model_routing"] = effective.get("model_routing") or {}
    return summary


def coverage_narrative(discovery: dict[str, Any]) -> dict[str, Any]:
    """One ledger over fields every stage already writes into `discovery`: whether this run's
    results reflect full coverage, and if not, why - so a reader sees "partial coverage" instead
    of a confident verdict built on a run that stopped early, lost a session, or hit a cap.
    Additive only: nothing here is computed from anything the report did not already have."""
    reasons: list[str] = []
    stop_reason = discovery.get("stop_reason") or ""
    if stop_reason == "cancelled":
        reasons.append("the scan was cancelled before it finished")
    elif stop_reason:
        reasons.append(f"the scan stopped early ({stop_reason})")
    if discovery.get("credentials_lost"):
        reasons.append("credentials were lost mid-scan and could not be refreshed")
    if discovery.get("authentication_failed"):
        reasons.append(f"an identity failed to authenticate ({discovery['authentication_failed']})")
    active = discovery.get("active_testing") or {}
    if active.get("targets_capped"):
        reasons.append(f"{active['targets_capped']} endpoint(s) were left untested by the target cap")
    if active.get("session_lost_reason"):
        reasons.append(f"the active-testing session was lost mid-scan ({active['session_lost_reason']})")
    authorization = discovery.get("authorization") or {}
    if authorization.get("degraded"):
        reasons.append(authorization.get("degraded_reason") or "the authorization checks ran degraded")
    if authorization.get("cap_reached"):
        reasons.append("the authorization replay cap was reached before every candidate was tried")
    return {"complete": not reasons, "reasons": reasons}


def build_dast_report(db: Session, scan: Scan, project: Project | None = None, against: str | None = None) -> dict[str, Any]:
    meta = scan.metadata_json or {}
    discovery = meta.get("discovery") or {}
    result = build_dast_findings(db, scan)
    findings = [_finding(f) for f in result.findings]
    confirmed = [f for f in findings if f["verdict"] == "true_positive"]
    unverified = [f for f in findings if f["verdict"] == UNVERIFIED_VERDICT]
    dismissed = [f for f in findings if f["verdict"] == "false_positive"]
    counts = {sev: 0 for sev in SEVERITIES}
    for f in confirmed:
        counts[severity_bucket(f["severity"])] += 1
    rule_set = meta.get("dast_rule_set") or {}
    diff = build_diff(db, scan, against)
    by_key = {(e["check_id"], e["target"], e["param"]): e["status"] for e in diff["entries"]}
    for f in findings:
        f["diff_status"] = by_key.get((f["check_id"], f["target"], f["param"]), "")
    return {
        "scan": {
            "id": scan.id, "version": scan.version, "status": scan.status, "target": (meta.get("dast_input") or {}).get("target_url") or scan.git_url,
            "project": project.name if project is not None else "", "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "finished_at": scan.updated_at.isoformat() if scan.updated_at else None, "message": scan.message or "",
        },
        "summary": {
            "severity_counts": counts,
            "confirmed": len(confirmed),
            "unverified": len(unverified),
            "review_items": sum(1 for f in unverified if f["review_item"]),
            "dismissed": len(dismissed),
            "total": len(findings),
        },
        "confirmed": confirmed,
        "unverified": unverified,
        "dismissed": dismissed,
        "rule_packs": _pack_summary(rule_set),
        "catalog_version": rule_set.get("catalog_version") or "",
        "custom_rules": list(rule_set.get("custom_rules") or []),
        "skipped_degraded": list(meta.get("dast_skipped_degraded") or []),
        "settings": _settings_summary(meta.get("dast_effective") or meta.get("dast_settings") or {}),
        "coverage": {
            "pages": len(discovery.get("pages") or []),
            "endpoints": discovery.get("inventory_count") if discovery.get("inventory_count") is not None else len(discovery.get("api_calls") or []),
            "passive": discovery.get("passive_analysis") or {},
            "active": discovery.get("active_testing") or {},
            "authorization": {
                k: v
                for k, v in (discovery.get("authorization") or {}).items()
                if k in ("ran", "total_replays", "findings", "degraded", "degraded_reason", "cap_reached")
            },
            **coverage_narrative(discovery),
        },
        "usage": meta.get("usage_summary") or {},
        "diff": diff,
    }

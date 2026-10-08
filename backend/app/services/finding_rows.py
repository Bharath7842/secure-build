"""Builds `Finding` / `DastEvidence` ORM rows from the finding dicts the engines emit.

One place for the dict -> column mapping, shared by the generic findings writer in
`scan_runner` (SAST/SCA/DAST rows written file by file) and the deduping DAST writer
(`dast_findings`). A key an engine does not set maps to None, so SAST rows leave every DAST
column empty.
"""

from __future__ import annotations

from typing import Any, Mapping

from app.models import DastEvidence, Finding

# Evidence excerpts are proof, not a response archive: cap what is stored per exchange.
EVIDENCE_EXCERPT_CAP = 2000


def cap_excerpt(text: str | None, limit: int = EVIDENCE_EXCERPT_CAP) -> str | None:
    if text is None:
        return None
    return text if len(text) <= limit else text[: limit - 15] + "…[truncated]"


def build_finding_row(scan_id: str, f: Mapping[str, Any], file_path: str) -> Finding:
    is_dast = bool(f.get("target"))
    return Finding(
        scan_id=scan_id,
        severity=f.get("severity") or "MEDIUM",
        cwe=f.get("cwe"),
        cvss=f.get("cvss"),
        owasp_category=f.get("owasp_category"),
        owasp_ref=f.get("owasp_ref"),
        rule_id=f.get("rule_id"),
        title=f.get("title") or "Untitled finding",
        file_path=f.get("file_path") or file_path,
        line=f.get("line"),
        snippet=f.get("snippet"),
        ai_fix=f.get("ai_fix"),
        kind=f.get("kind") or "llm",
        verdict=f.get("verdict"),
        confidence=f.get("confidence"),
        source=f.get("source"),
        sink=f.get("sink"),
        data_flow=f.get("data_flow"),
        verdict_reason=f.get("verdict_reason"),
        matched_text=f.get("matched_text"),
        group_by_rule=f.get("group_by_rule"),
        flow_path=f.get("flow_path"),
        affected_files=f.get("affected_files"),
        # DAST fields: absent (None) on SAST/SCA/SBOM finding dicts.
        target=f.get("target"),
        param=f.get("param"),
        location=f.get("location"),
        confidence_label=f.get("confidence_label"),
        remediation_ref=f.get("remediation_ref"),
        standards=f.get("standards"),
        roles=f.get("roles") or None,
        first_seen_scan_id=scan_id if is_dast else None,
        last_seen_scan_id=scan_id if is_dast else None,
    )


def build_evidence_row(finding_id: str, evidence: Mapping[str, Any]) -> DastEvidence:
    return DastEvidence(
        finding_id=finding_id,
        baseline_excerpt=cap_excerpt(evidence.get("baseline_excerpt")),
        test_excerpt=cap_excerpt(evidence.get("test_excerpt")),
        signals=evidence.get("signals"),
        audit_ref=evidence.get("audit_ref"),
    )

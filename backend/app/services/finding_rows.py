"""Builds `Finding` / `DastEvidence` ORM rows from the finding dicts the engines emit.

One place for the dict -> column mapping, shared by the generic findings writer in
`scan_runner` (SAST/SCA/DAST rows written file by file) and the deduping DAST writer
(`dast_findings`). A key an engine does not set maps to None, so SAST rows leave every DAST
column empty.
"""

from __future__ import annotations

import logging
from typing import Any, Mapping

from app.models import UNVERIFIED_VERDICT, DastEvidence, Finding
from app.services.occurrence import occurrence_id, occurrence_parts

logger = logging.getLogger(__name__)

# Evidence excerpts are proof, not a response archive: cap what is stored per exchange.
EVIDENCE_EXCERPT_CAP = 2000


def cap_excerpt(text: str | None, limit: int = EVIDENCE_EXCERPT_CAP) -> str | None:
    if text is None:
        return None
    return text if len(text) <= limit else text[: limit - 15] + "…[truncated]"


def build_finding_row(
    scan_id: str, f: Mapping[str, Any], file_path: str, project_id: str | None = None
) -> Finding:
    """`project_id`, when given, stamps the row's `occurrence_id`; DAST rows
    never get one (their own dedupe keys them)."""
    is_dast = bool(f.get("target"))
    verdict = f.get("verdict")
    unresolved_reason = f.get("unresolved_reason")
    if verdict == UNVERIFIED_VERDICT and not unresolved_reason:
        # Every writer that stores `unverified` should say why; a missing
        # reason is a bug in that writer, not something to leave undecided.
        logger.warning(
            "unverified finding without unresolved_reason (rule=%s file=%s)",
            f.get("rule_id"),
            f.get("file_path") or file_path,
        )
        unresolved_reason = "evidence_missing"
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
        verdict=verdict,
        confidence=f.get("confidence"),
        source=f.get("source"),
        sink=f.get("sink"),
        data_flow=f.get("data_flow"),
        verdict_reason=f.get("verdict_reason"),
        matched_text=f.get("matched_text"),
        group_by_rule=f.get("group_by_rule"),
        occurrence_id=(
            occurrence_id(project_id, f, file_path) if project_id and not is_dast else None
        ),
        identity_quality=(
            occurrence_parts(f, file_path)["identity_quality"] if project_id and not is_dast else None
        ),
        issue_class=f.get("issue_class"),
        unresolved_reason=unresolved_reason if verdict == UNVERIFIED_VERDICT else None,
        facts=f.get("facts") or None,
        reason_tag=f.get("reason_tag"),
        review_coverage=f.get("review_coverage"),
        flow_path=f.get("flow_path"),
        reachability=f.get("reachability"),
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
        reproduction=cap_excerpt(evidence.get("reproduction"), 2000),
        severity_source=evidence.get("severity_source"),
    )

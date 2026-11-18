"""Finding normalizer.

Inputs: InternalQueryResult, TrivyResult, OPAResult, and future scanner results.
Output: canonical Finding dictionaries.

Severity precedence:
    Explicit policy severity > scanner severity > query default severity
"""

from __future__ import annotations

import hashlib
import logging
from uuid import uuid4

from app.services.iac_app.domain.enums import normalize_severity

logger = logging.getLogger(__name__)


def normalize_file_path(path: str) -> str:
    """Normalize a file path for consistent fingerprinting.

    Strips leading slashes, removes ``../`` prefixes, strips common leading
    directory components (like ``src/``) that differ between scanners, and
    always uses forward slashes so that ``/terraform/aws/rds.tf``,
    ``../../src/terraform/aws/rds.tf`` and ``terraform/aws/rds.tf`` all
    resolve to the same canonical form.
    """
    p = (path or "").replace("\\", "/")
    # strip leading slashes
    while p.startswith("/"):
        p = p[1:]
    # strip all ../ prefixes
    while p.startswith("../"):
        p = p[3:]
    # strip leading src/ component (kics uses ../../src/ prefix)
    if p.startswith("src/"):
        p = p[4:]
    return p


def normalize_resource(resource: str | None) -> str:
    """Normalize a resource identifier for fingerprinting.

    Takes the last dot-segment so that module-qualified references like
    ``openshift.aws_instance.bastion`` and plain ``bastion`` (or
    ``aws_instance.bastion``) all reduce to the same token ``bastion``.
    """
    r = (resource or "").strip()
    if "." in r:
        r = r.rsplit(".", 1)[-1]
    return r


def generate_fingerprint(
    rule_id: str,
    file_path: str,
    resource: str | None,
    line_start: int | None,
) -> str:
    """Deterministic SHA-256 fingerprint as specified by the platform contract."""
    parts = [
        str(rule_id or ""),
        normalize_file_path(file_path),
        normalize_resource(resource),
        str(line_start if line_start is not None else ""),
    ]
    return hashlib.sha256(":".join(parts).encode("utf-8")).hexdigest()


def normalize_findings(
    scanner_results: dict[str, list[dict]],
    scan_id: str,
    classified_files: dict | None = None,
    policy_severity: dict[str, str] | None = None,
) -> list[dict]:
    all_findings = []
    policy_severity = policy_severity or {}

    for scanner_name, findings in (scanner_results or {}).items():
        for finding in findings:
            normalized = _normalize_finding(finding, scanner_name, scan_id, policy_severity)
            if normalized:
                all_findings.append(normalized)

    return all_findings


def _normalize_finding(
    finding: dict,
    scanner: str,
    scan_id: str,
    policy_severity: dict[str, str],
) -> dict | None:
    try:
        rule_id = finding.get("rule_id", "")
        title = finding.get("title", "")
        description = finding.get("description", "")
        scanner_severity = finding.get("severity", "INFO")
        explicit = policy_severity.get(rule_id)
        severity = normalize_severity(explicit or scanner_severity)
        category = finding.get("category", "OTHER")
        iac_type = finding.get("iac_type", "unknown")
        file_path = finding.get("file_path", "")
        line_start = finding.get("line_start")
        line_end = finding.get("line_end")
        resource = finding.get("resource", "")
        evidence = finding.get("evidence", "")
        remediation = finding.get("remediation", "")
        references = finding.get("references") or []
        compliance = finding.get("compliance") or []
        cwe = finding.get("cwe")
        owasp_category = finding.get("owasp_category")
        detected_by = finding.get("detected_by") or [scanner]
        fingerprint = finding.get("fingerprint") or generate_fingerprint(
            rule_id, file_path, resource, line_start
        )
        norm_file = normalize_file_path(file_path)
        norm_resource = normalize_resource(resource) if resource else None

        return {
            "id": finding.get("id") or str(uuid4()),
            "scan_id": scan_id,
            "fingerprint": fingerprint,
            "rule_id": rule_id,
            "scanner": scanner,
            "detected_by": detected_by,
            "scanners": detected_by,
            "title": title,
            "description": description,
            "severity": severity,
            "category": category,
            "finding_type": finding.get("finding_type") or "MISCONFIGURATION",
            "iac_type": iac_type,
            "provider": finding.get("provider"),
            "resource": norm_resource,
            "resource_type": finding.get("resource_type"),
            "file_path": norm_file,
            "line_start": line_start,
            "line_end": line_end,
            "evidence": evidence if evidence else None,
            "remediation": remediation if remediation else None,
            "references": references if references else [],
            "compliance": compliance,
            "status": finding.get("status") or "OPEN",
            "cwe": cwe,
            "owasp_category": owasp_category,
            "policy_id": finding.get("policy_id") or rule_id,
            "policy_version": finding.get("policy_version") or "1.0.0",
        }
    except Exception as exc:
        logger.warning("Error normalizing finding: %s", exc)
        return None


def _generate_fingerprint(
    iac_type: str,
    file_path: str,
    resource: str,
    rule_id: str,
    line: int | None,
) -> str:
    # Kept for callers that still pass the old signature via tests.
    return generate_fingerprint(rule_id, file_path, resource, line)


def _normalize_severity(severity: str) -> str:
    return normalize_severity(severity)

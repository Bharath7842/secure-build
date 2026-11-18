"""Canonical finding model used by every scanner and reporter."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.services.iac_app.domain.enums import FindingStatus, FindingType, Severity, normalize_severity


@dataclass
class Finding:
    id: str
    scan_id: str
    rule_id: str
    title: str
    description: str = ""
    severity: str = Severity.MEDIUM.value
    category: str = "OTHER"
    finding_type: str = FindingType.MISCONFIGURATION.value
    iac_type: str = "unknown"
    provider: str | None = None
    resource: str | None = None
    resource_type: str | None = None
    scanner: str = "internal"
    detected_by: list[str] = field(default_factory=list)
    file_path: str = ""
    line_start: int | None = None
    line_end: int | None = None
    evidence: str | None = None
    remediation: str | None = None
    references: list[str] = field(default_factory=list)
    compliance: list[dict[str, str]] = field(default_factory=list)
    fingerprint: str = ""
    status: str = FindingStatus.OPEN.value
    suppression_reason: str | None = None
    risk_score: float = 0.0
    risk_level: str | None = None
    risk_factors: list[str] = field(default_factory=list)
    policy_id: str | None = None
    policy_version: str | None = None
    cwe: str | None = None
    owasp_category: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        self.severity = normalize_severity(self.severity)
        if not self.detected_by:
            self.detected_by = [self.scanner] if self.scanner else []

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "category": self.category,
            "finding_type": self.finding_type,
            "iac_type": self.iac_type,
            "provider": self.provider,
            "resource": self.resource,
            "resource_type": self.resource_type,
            "scanner": self.scanner,
            "detected_by": self.detected_by,
            "scanners": self.detected_by,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": self.references,
            "compliance": self.compliance,
            "fingerprint": self.fingerprint,
            "status": self.status,
            "suppression_reason": self.suppression_reason,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "risk_factors": self.risk_factors,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "cwe": self.cwe,
            "owasp_category": self.owasp_category,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

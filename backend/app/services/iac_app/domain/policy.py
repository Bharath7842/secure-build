"""Policy and query metadata domain objects."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class QueryMetadata:
    id: str
    name: str
    description: str
    severity: str
    category: str
    finding_type: str = "MISCONFIGURATION"
    iac_type: str = "terraform"
    provider: str | None = None
    enabled: bool = True
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    compliance: list[dict[str, str]] = field(default_factory=list)
    version: str = "1.0.0"
    engine: str = "internal"
    path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "category": self.category,
            "finding_type": self.finding_type,
            "iac_type": self.iac_type,
            "provider": self.provider,
            "enabled": self.enabled,
            "remediation": self.remediation,
            "references": self.references,
            "compliance": self.compliance,
            "version": self.version,
            "engine": self.engine,
            "path": self.path,
        }


@dataclass
class PolicyPack:
    id: str
    name: str
    version: str
    description: str = ""
    iac_types: list[str] = field(default_factory=list)
    query_ids: list[str] = field(default_factory=list)
    enabled: bool = True

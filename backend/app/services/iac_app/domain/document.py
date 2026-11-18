"""Normalized intermediate representation for parsed IaC."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Location:
    line_start: int | None = None
    line_end: int | None = None
    file_path: str | None = None


@dataclass
class DetectedFile:
    path: str
    iac_type: str
    confidence: float
    reason: str
    absolute_path: str = ""
    size: int = 0
    extension: str = ""


@dataclass
class ParsedDocument:
    file_path: str
    iac_type: str
    raw: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


@dataclass
class NormalizedResource:
    id: str
    type: str
    provider: str
    name: str
    attributes: dict[str, Any] = field(default_factory=dict)
    location: Location = field(default_factory=Location)
    raw: Any = None
    relationships: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "provider": self.provider,
            "name": self.name,
            "attributes": self.attributes,
            "location": {
                "line_start": self.location.line_start,
                "line_end": self.location.line_end,
                "file_path": self.location.file_path,
            },
            "raw": self.raw,
            "relationships": self.relationships,
        }


@dataclass
class NormalizedDocument:
    file: str
    iac_type: str
    provider: str | None = None
    resources: list[NormalizedResource] = field(default_factory=list)
    raw_evidence: dict[str, Any] = field(default_factory=dict)
    variables: dict[str, Any] | None = None
    locals: dict[str, Any] | None = None
    data_sources: list[NormalizedResource] | None = None
    resolved_context: dict[str, Any] | None = None
    resource_relationships: dict[str, list[str]] | None = None

    def to_dict(self) -> dict[str, Any]:
        result = {
            "document": {
                "file": self.file,
                "iac_type": self.iac_type,
                "provider": self.provider,
            },
            "resources": [r.to_dict() for r in self.resources],
            "raw_evidence": self.raw_evidence,
        }
        if self.variables is not None:
            result["variables"] = self.variables
        if self.locals is not None:
            result["locals"] = self.locals
        if self.data_sources is not None:
            result["data_sources"] = [r.to_dict() for r in self.data_sources]
        if self.resolved_context is not None:
            result["resolved_context"] = self.resolved_context
        if self.resource_relationships is not None:
            result["resource_relationships"] = self.resource_relationships
        return result

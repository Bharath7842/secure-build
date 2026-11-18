"""Pulumi program parser.

Parses Pulumi YAML programs into ParsedDocument objects.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from app.services.iac_app.domain.document import ParsedDocument
from app.services.iac_app.scanner.parsers.base import ParserAdapter


class PulumiParser(ParserAdapter):
    """Parse Pulumi YAML programs."""

    def supports(self, file: str) -> bool:
        path = Path(file)
        if path.suffix.lower() in (".yaml", ".yml"):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    head = f.read(2000)
                return "pulumi:" in head.lower()
            except Exception:
                return False
        return False

    def parse(self, file: str) -> ParsedDocument:
        path = Path(file)
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if not isinstance(data, dict):
                return ParsedDocument(file_path=str(path), iac_type="pulumi", raw={})
            return ParsedDocument(file_path=str(path), iac_type="pulumi", raw=self._normalize(data))
        except Exception as exc:
            return ParsedDocument(
                file_path=str(path),
                iac_type="pulumi",
                raw={},
                errors=[f"Failed to parse Pulumi YAML: {exc}"],
            )

    def _normalize(self, data: dict) -> dict[str, Any]:
        resources = {}
        config = data.get("config", {})
        outputs = data.get("outputs", {})
        variables = data.get("variables", {})

        for name, resource_def in data.get("resources", {}).items():
            if isinstance(resource_def, dict):
                resource_type = resource_def.get("type", "")
                properties = {k: v for k, v in resource_def.items() if k != "type"}
                resources[name] = {
                    "logical_id": name,
                    "type": resource_type,
                    "properties": properties,
                    "depends_on": resource_def.get("dependsOn", []),
                }

        return {
            "file_path": "",
            "resources": resources,
            "config": config,
            "outputs": outputs,
            "variables": variables,
            "name": data.get("name", ""),
            "runtime": data.get("runtime", "yaml"),
        }

"""OpenAPI specification parser.

Parses OpenAPI 2.0 (Swagger) and 3.0 specifications for security scanning.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from app.services.iac_app.domain.document import ParsedDocument
from app.services.iac_app.scanner.parsers.base import ParserAdapter


class OpenAPIParser(ParserAdapter):
    """Parse OpenAPI specifications."""

    def supports(self, file: str) -> bool:
        path = Path(file)
        if path.suffix.lower() in (".yaml", ".yml", ".json"):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    head = f.read(2000)
                return ("swagger:" in head.lower() or "openapi:" in head.lower() or
                        '"swagger"' in head or '"openapi"' in head)
            except Exception:
                return False
        return False

    def parse(self, file: str) -> ParsedDocument:
        path = Path(file)
        try:
            with open(path, "r", encoding="utf-8") as f:
                if path.suffix.lower() == ".json":
                    import json
                    data = json.load(f)
                else:
                    data = yaml.safe_load(f)
            if not isinstance(data, dict):
                return ParsedDocument(file_path=str(path), iac_type="openapi", raw={})
            return ParsedDocument(file_path=str(path), iac_type="openapi", raw=self._normalize(data))
        except Exception as exc:
            return ParsedDocument(
                file_path=str(path),
                iac_type="openapi",
                raw={},
                errors=[f"Failed to parse OpenAPI spec: {exc}"],
            )

    def _normalize(self, data: dict) -> dict[str, Any]:
        spec_version = data.get("openapi") or data.get("swagger") or ""
        info = data.get("info", {})
        paths = data.get("paths", {})
        definitions = data.get("definitions") or data.get("components", {}).get("schemas", {})
        security = data.get("security") or []
        security_definitions = data.get("securityDefinitions") or data.get("components", {}).get("securitySchemes", {})

        operations = []
        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            for method in ("get", "post", "put", "patch", "delete", "options", "head"):
                operation = path_item.get(method)
                if not isinstance(operation, dict):
                    continue
                operations.append({
                    "path": path,
                    "method": method,
                    "operation_id": operation.get("operationId", ""),
                    "summary": operation.get("summary", ""),
                    "description": operation.get("description", ""),
                    "tags": operation.get("tags", []),
                    "security": operation.get("security", []),
                    "deprecated": operation.get("deprecated", False),
                    "parameters": operation.get("parameters", []),
                    "responses": operation.get("responses", {}),
                })

        return {
            "spec_version": spec_version,
            "info": info,
            "paths": paths,
            "operations": operations,
            "definitions": definitions,
            "security": security,
            "security_definitions": security_definitions,
            "servers": data.get("servers", []),
            "tags": data.get("tags", []),
        }

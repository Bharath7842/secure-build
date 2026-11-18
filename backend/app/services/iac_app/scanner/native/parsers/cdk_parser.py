"""AWS CDK template parser.

Parses AWS CDK-synthesized CloudFormation templates into ParsedDocument.
CDK templates are CloudFormation with additional metadata, transforms, and constructs.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import yaml

from app.services.iac_app.domain.document import ParsedDocument
from app.services.iac_app.scanner.parsers.base import ParserAdapter
from app.services.iac_app.scanner.native.parsers.cloudformation_resolver import CloudFormationResolver
from app.services.iac_app.scanner.native.parsers.cloudformation_parser import _CloudFormationLoader

logger = logging.getLogger(__name__)


class CDKParser(ParserAdapter):
    """Parse AWS CDK-synthesized CloudFormation templates."""

    EXTENSIONS = (".yaml", ".yml", ".json")

    def supports(self, file: str) -> bool:
        path = Path(file)
        if path.suffix.lower() not in self.EXTENSIONS:
            return False
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(4000)
            if "CDKMetadata" in content or "aws-cdk" in content.lower():
                return True
            if "AWSTemplateFormatVersion" in content:
                if "CDKMetadata" in content or "aws:cdk" in content.lower():
                    return True
            return False
        except OSError:
            return False

    def parse(self, file: str) -> ParsedDocument:
        path = Path(file)
        raw = self._parse_file(path)
        if raw is None:
            return ParsedDocument(
                file_path=str(path),
                iac_type="cdk",
                raw={},
                errors=[f"Failed to parse CDK template: {path}"],
            )
        return ParsedDocument(file_path=str(path), iac_type="cdk", raw=raw)

    def _parse_file(self, file_path: Path) -> dict[str, Any] | None:
        try:
            suffix = file_path.suffix.lower()
            with open(file_path, "r", encoding="utf-8") as f:
                if suffix == ".json":
                    data = json.load(f)
                else:
                    data = yaml.load(f, Loader=_CloudFormationLoader)
            if not isinstance(data, dict):
                return None
            return self._normalize(data)
        except Exception as exc:
            logger.warning("Failed to parse CDK template %s: %s", file_path, exc)
            return None

    def _normalize(self, data: dict) -> dict[str, Any]:
        resolver = CloudFormationResolver(
            parameters=data.get("Parameters", {}),
            mappings=data.get("Mappings", {}),
            conditions=data.get("Conditions", {}),
        )

        resources: dict[str, Any] = {}
        cdk_metadata = {}

        for logical_id, resource_def in data.get("Resources", {}).items():
            if not isinstance(resource_def, dict):
                continue
            resource_type = resource_def.get("Type", "")

            if resource_type == "AWS::CDK::Metadata":
                cdk_metadata = resource_def.get("Properties", {})
                continue

            properties = dict(resource_def.get("Properties", {}))
            resolved = resolver.resolve_all(properties)

            cdk_info = self._extract_cdk_construct_info(resource_def)

            resources[logical_id] = {
                "logical_id": logical_id,
                "type": resource_type,
                "properties": resolved,
                "condition": resource_def.get("Condition"),
                "depends_on": resource_def.get("DependsOn", []),
                "metadata": resource_def.get("Metadata", {}),
                "update_replace_policy": resource_def.get("UpdateReplacePolicy"),
                "deletion_policy": resource_def.get("DeletionPolicy"),
                "cdk_construct": cdk_info,
            }

        return {
            "file_path": "",
            "awstemplate_format_version": data.get("AWSTemplateFormatVersion", "2010-09-09"),
            "transform": data.get("Transform", []),
            "description": data.get("Description", ""),
            "parameters": data.get("Parameters", {}),
            "mappings": data.get("Mappings", {}),
            "conditions": data.get("Conditions", {}),
            "resources": resources,
            "outputs": data.get("Outputs", {}),
            "rules": data.get("Rules", {}),
            "metadata": data.get("Metadata", {}),
            "cdk_metadata": cdk_metadata,
            "cdk_version": self._extract_cdk_version(cdk_metadata),
            "stack_name": data.get("Description", ""),
        }

    def _extract_cdk_construct_info(self, resource_def: dict) -> dict:
        metadata = resource_def.get("Metadata", {})
        cdk_info = {}

        cdk_path = metadata.get("aws:cdk:path", "")
        if cdk_path:
            cdk_info["path"] = cdk_path
            parts = cdk_path.split("/")
            if len(parts) >= 2:
                cdk_info["construct"] = parts[-1]
                cdk_info["stack"] = parts[0] if len(parts) > 1 else ""

        cdk_artifact = metadata.get("aws:asset:path", "")
        if cdk_artifact:
            cdk_info["artifact_path"] = cdk_artifact

        return cdk_info

    def _extract_cdk_version(self, cdk_metadata: dict) -> str:
        properties = cdk_metadata if "Properties" not in cdk_metadata else cdk_metadata.get("Properties", {})
        return properties.get("CDKMetadata", {}).get("Version", "unknown")

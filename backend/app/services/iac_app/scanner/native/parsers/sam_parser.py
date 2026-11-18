"""AWS SAM template parser.

Parses AWS SAM templates (CloudFormation + SAM Transform) into ParsedDocument.
SAM is a superset of CloudFormation with additional resource types:
  AWS::Serverless::Function, AWS::Serverless::Api, AWS::Serverless::SimpleTable, etc.
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

SAM_RESOURCE_TYPES = {
    "AWS::Serverless::Function",
    "AWS::Serverless::Api",
    "AWS::Serverless::SimpleTable",
    "AWS::Serverless::HttpApi",
    "AWS::Serverless::StateMachine",
    "AWS::Serverless::LayerVersion",
    "AWS::Serverless::Application",
    "AWS::Serverless::Connector",
    "AWS::Serverless::Popover",
    "AWS::Serverless::Api V2",
    "AWS::Serverless::Connection",
    "AWS::Serverless::SimpleTable V2",
}


class SAMParser(ParserAdapter):
    """Parse AWS SAM templates."""

    EXTENSIONS = (".yaml", ".yml", ".json")

    def supports(self, file: str) -> bool:
        path = Path(file)
        if path.suffix.lower() not in self.EXTENSIONS:
            return False
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(4000)
            if "Transform" in content and "AWS::Serverless" in content:
                return True
            if "AWSTemplateFormatVersion" in content:
                for sam_type in SAM_RESOURCE_TYPES:
                    if sam_type in content:
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
                iac_type="sam",
                raw={},
                errors=[f"Failed to parse SAM template: {path}"],
            )
        return ParsedDocument(file_path=str(path), iac_type="sam", raw=raw)

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
            logger.warning("Failed to parse SAM template %s: %s", file_path, exc)
            return None

    def _normalize(self, data: dict) -> dict[str, Any]:
        resolver = CloudFormationResolver(
            parameters=data.get("Parameters", {}),
            mappings=data.get("Mappings", {}),
            conditions=data.get("Conditions", {}),
        )

        globals_section = data.get("Globals", {})
        resources: dict[str, Any] = {}

        for logical_id, resource_def in data.get("Resources", {}).items():
            if not isinstance(resource_def, dict):
                continue
            resource_type = resource_def.get("Type", "")
            properties = dict(resource_def.get("Properties", {}))

            if resource_type in SAM_RESOURCE_TYPES:
                properties = self._apply_globals(resource_type, properties, globals_section)

            resolved = resolver.resolve_all(properties)

            resources[logical_id] = {
                "logical_id": logical_id,
                "type": resource_type,
                "properties": resolved,
                "condition": resource_def.get("Condition"),
                "depends_on": resource_def.get("DependsOn", []),
                "metadata": resource_def.get("Metadata", {}),
                "update_replace_policy": resource_def.get("UpdateReplacePolicy"),
                "deletion_policy": resource_def.get("DeletionPolicy"),
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
            "globals": globals_section,
            "sam_version": self._extract_sam_version(data),
        }

    def _apply_globals(self, resource_type: str, properties: dict, globals_section: dict) -> dict:
        if resource_type == "AWS::Serverless::Function":
            fn_globals = globals_section.get("Function", {})
            for key, value in fn_globals.items():
                if key not in properties:
                    properties[key] = value
        elif resource_type == "AWS::Serverless::Api":
            api_globals = globals_section.get("Api", {})
            for key, value in api_globals.items():
                if key not in properties:
                    properties[key] = value
        elif resource_type == "AWS::Serverless::HttpApi":
            http_globals = globals_section.get("HttpApi", {})
            for key, value in http_globals.items():
                if key not in properties:
                    properties[key] = value
        return properties

    def _extract_sam_version(self, data: dict) -> str:
        transform = data.get("Transform", "")
        if isinstance(transform, list):
            for t in transform:
                if "AWS::Serverless" in str(t):
                    return str(t)
        elif isinstance(transform, str) and "AWS::Serverless" in transform:
            return transform
        return "AWS::Serverless-2016-10-31"

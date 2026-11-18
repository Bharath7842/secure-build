"""CloudFormation template parser — converts YAML/JSON CFN templates to ParsedDocument.

Supports CloudFormation intrinsic function resolution via CloudFormationResolver.
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

logger = logging.getLogger(__name__)


class _CloudFormationLoader(yaml.SafeLoader):
    """YAML loader that supports CloudFormation intrinsic functions."""
    pass


def _cfn_tag_constructor(tag_suffix):
    def constructor(loader, node):
        if isinstance(node, yaml.ScalarNode):
            value = loader.construct_scalar(node)
        elif isinstance(node, yaml.SequenceNode):
            value = loader.construct_sequence(node, deep=True)
        elif isinstance(node, yaml.MappingNode):
            value = loader.construct_mapping(node, deep=True)
        else:
            value = None
        return {tag_suffix: value}
    return constructor


for tag in ["!Ref", "!Sub", "!Join", "!Select", "!Split", "!GetAtt", "!FindInMap",
            "!Base64", "!Cidr", "!GetAZs", "!ImportValue", "!If", "!Not", "!And",
            "!Or", "!Equals", "!Condition", "!Transform"]:
    _CloudFormationLoader.add_constructor(tag, _cfn_tag_constructor(tag))


class CloudFormationParser(ParserAdapter):
    EXTENSIONS = (".yaml", ".yml", ".json")

    def supports(self, file: str) -> bool:
        path = Path(file)
        if path.suffix.lower() not in self.EXTENSIONS:
            return False
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                content = handle.read(4000)
            return "AWSTemplateFormatVersion" in content or "Resources" in content
        except OSError:
            return False

    def parse(self, file: str) -> ParsedDocument:
        path = Path(file)
        raw = self.parse_file(path)
        if raw is None:
            return ParsedDocument(
                file_path=str(path),
                iac_type="cloudformation",
                raw={},
                errors=[f"Failed to parse CloudFormation template: {path}"],
            )
        return ParsedDocument(file_path=str(path), iac_type="cloudformation", raw=raw)

    def parse_file(self, file_path: Path) -> dict[str, Any] | None:
        try:
            suffix = file_path.suffix.lower()
            if suffix == ".json":
                return self._parse_json(file_path)
            return self._parse_yaml(file_path)
        except Exception as exc:
            logger.debug("Failed to parse CloudFormation template %s: %s", file_path, exc)
            return None

    def parse_directory(self, dir_path: Path) -> list[dict[str, Any]]:
        results = []
        for ext in ("*.yaml", "*.yml", "*.json"):
            for path in sorted(Path(dir_path).rglob(ext)):
                parsed = self.parse_file(path)
                if parsed:
                    results.append(parsed)
        return results

    def _parse_yaml(self, file_path: Path) -> dict[str, Any] | None:
        try:
            with open(file_path, "r", encoding="utf-8") as handle:
                data = yaml.load(handle, Loader=_CloudFormationLoader)
            if not isinstance(data, dict):
                return None
            if not self._is_cloudformation(data):
                return None
            return self._normalize(data, str(file_path))
        except Exception as exc:
            logger.debug("YAML parse error in %s: %s", file_path, exc)
            return None

    def _parse_json(self, file_path: Path) -> dict[str, Any] | None:
        try:
            with open(file_path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            if not isinstance(data, dict):
                return None
            if not self._is_cloudformation(data):
                return None
            return self._normalize(data, str(file_path))
        except Exception as exc:
            logger.debug("JSON parse error in %s: %s", file_path, exc)
            return None

    def _is_cloudformation(self, data: dict) -> bool:
        resources = data.get("Resources", {})
        return (
            "AWSTemplateFormatVersion" in data
            or "AWS::CloudFormation" in str(resources)
            or any(str(k).startswith("AWS::") for k in resources.keys())
            or any(
                isinstance(v, dict) and str(v.get("Type", "")).startswith("AWS::")
                for v in resources.values()
            )
        )

    def _normalize(self, data: dict, file_path: str) -> dict[str, Any]:
        resources = {}
        parameters = data.get("Parameters", {})
        outputs = data.get("Outputs", {})
        conditions = data.get("Conditions", {})
        mappings = data.get("Mappings", {})

        resolver = CloudFormationResolver(
            parameters=parameters,
            mappings=mappings,
            conditions=conditions,
        )

        for logical_id, resource_def in data.get("Resources", {}).items():
            if isinstance(resource_def, dict):
                resource_type = resource_def.get("Type", "")
                properties = resource_def.get("Properties", {})
                resolved_properties = resolver.resolve(properties) if properties else {}

                resources[logical_id] = {
                    "logical_id": logical_id,
                    "type": resource_type,
                    "properties": properties or {},
                    "resolved_properties": resolved_properties,
                    "depends_on": resource_def.get("DependsOn", []),
                    "condition": resource_def.get("Condition", ""),
                    "creation_policy": resource_def.get("CreationPolicy"),
                    "deletion_policy": resource_def.get("DeletionPolicy", "Delete"),
                    "update_policy": resource_def.get("UpdatePolicy"),
                    "update_replace_policy": resource_def.get("UpdateReplacePolicy", "Delete"),
                    "metadata": resource_def.get("Metadata", {}),
                    "tags": properties.get("Tags", []) if isinstance(properties, dict) else [],
                }

        return {
            "file_path": file_path,
            "resources": resources,
            "parameters": parameters,
            "outputs": outputs,
            "conditions": conditions,
            "mappings": mappings,
            "transform": data.get("Transform"),
            "description": data.get("Description", ""),
            "metadata": data.get("Metadata", {}),
            "rules": data.get("Rules", {}),
            "analysis": data.get("Analysis", {}),
        }

    def get_resources_by_type(self, parsed: dict, resource_type: str) -> list[dict]:
        results = []
        for logical_id, resource in parsed.get("resources", {}).items():
            if resource["type"] == resource_type:
                resource["logical_id"] = logical_id
                results.append(resource)
        return results

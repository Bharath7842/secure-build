"""CloudFormation intrinsic function resolver.

Resolves CloudFormation intrinsic functions like Ref, Fn::Sub, Fn::Join, etc.
"""

from __future__ import annotations

import re
from typing import Any


class CloudFormationResolver:
    """Resolve CloudFormation intrinsic functions."""

    def __init__(
        self,
        parameters: dict | None = None,
        mappings: dict | None = None,
        conditions: dict | None = None,
        resources: dict | None = None,
        pseudo_params: dict | None = None,
    ) -> None:
        self._parameters = parameters or {}
        self._mappings = mappings or {}
        self._conditions = conditions or {}
        self._resources = resources or {}
        self._pseudo_params = pseudo_params or {
            "AWS::AccountId": "123456789012",
            "AWS::NotificationARNs": [],
            "AWS::NoValue": {"Ref": "AWS::NoValue"},
            "AWS::Region": "us-east-1",
            "AWS::StackId": "arn:aws:cloudformation:us-east-1:123456789012:stack/stack/guid",
            "AWS::StackName": "stack",
            "AWS::URLSuffix": "amazonaws.com",
            "AWS::Partition": "aws",
        }

    def resolve(self, value: Any) -> Any:
        """Recursively resolve intrinsic functions in a value."""
        if isinstance(value, dict):
            if len(value) == 1:
                key = list(value.keys())[0]
                if key == "Ref":
                    return self._resolve_ref(value[key])
                if key == "Fn::If":
                    return self._resolve_fn_if(value[key])
                if key.startswith("Fn::"):
                    return self._resolve_fn(key, value[key])
                if key == "Condition":
                    return self._resolve_condition(value[key])
            return {k: self.resolve(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.resolve(item) for item in value]
        return value

    def resolve_resource_properties(self, properties: dict) -> dict:
        """Resolve all intrinsic functions in a resource's properties."""
        return self.resolve(properties)

    def resolve_all(self, properties: dict) -> dict:
        """Resolve all intrinsic functions in properties (alias for resolve)."""
        return self.resolve(properties)

    def _resolve_ref(self, ref_value: str) -> Any:
        """Resolve a Ref intrinsic function."""
        if ref_value in self._pseudo_params:
            return self._pseudo_params[ref_value]
        if ref_value in self._parameters:
            param = self._parameters[ref_value]
            if isinstance(param, dict):
                return param.get("Default", "")
            return param
        if ref_value in self._resources:
            resource = self._resources[ref_value]
            if isinstance(resource, dict):
                return resource.get("physical_resource_id", ref_value)
        return ref_value

    def _resolve_fn_if(self, value: Any) -> Any:
        """Resolve Fn::If intrinsic function."""
        if not isinstance(value, list) or len(value) != 3:
            return value
        condition_name, true_value, false_value = value
        if self._evaluate_condition(condition_name):
            return self.resolve(true_value)
        return self.resolve(false_value)

    def _resolve_fn(self, fn_name: str, value: Any) -> Any:
        """Resolve Fn::* intrinsic functions."""
        resolvers = {
            "Fn::Sub": self._resolve_fn_sub,
            "Fn::Join": self._resolve_fn_join,
            "Fn::Select": self._resolve_fn_select,
            "Fn::Split": self._resolve_fn_split,
            "Fn::GetAtt": self._resolve_fn_get_att,
            "Fn::FindInMap": self._resolve_fn_find_in_map,
            "Fn::Base64": self._resolve_fn_base64,
            "Fn::Cidr": self._resolve_fn_cidr,
            "Fn::GetAZs": self._resolve_fn_get_azs,
            "Fn::ImportValue": self._resolve_fn_import_value,
            "Fn::Transform": self._resolve_fn_transform,
            "Fn::ToJsonString": self._resolve_fn_to_json_string,
            "Fn::Length": self._resolve_fn_length,
        }
        resolver = resolvers.get(fn_name)
        if resolver:
            return resolver(value)
        return {fn_name: value}

    def _resolve_fn_sub(self, value: Any) -> str:
        """Resolve Fn::Sub."""
        if isinstance(value, str):
            return self._interpolate(value)
        if isinstance(value, list) and len(value) == 2:
            template, mapping = value
            result = self._interpolate(template, mapping)
            return result
        return value

    def _interpolate(self, template: str, mapping: dict | None = None) -> str:
        """Interpolate ${Var} references in a string."""
        def replace_var(match: re.Match) -> str:
            var_name = match.group(1)
            if mapping and var_name in mapping:
                return str(self.resolve(mapping[var_name]))
            if var_name in self._pseudo_params:
                return str(self._pseudo_params[var_name])
            if var_name in self._parameters:
                param = self._parameters[var_name]
                if isinstance(param, dict):
                    return str(param.get("Default", ""))
                return str(param)
            if "." in var_name:
                parts = var_name.split(".", 1)
                resource_id = parts[0]
                attr = parts[1] if len(parts) > 1 else "PhysicalResourceId"
                if resource_id in self._resources:
                    resource = self._resources[resource_id]
                    if isinstance(resource, dict):
                        return str(resource.get("physical_resource_id", resource_id))
            return f"${{{var_name}}}"

        return re.sub(r'\$\{([^}]+)\}', replace_var, template)

    def _resolve_fn_join(self, value: Any) -> str:
        """Resolve Fn::Join."""
        if not isinstance(value, list) or len(value) != 2:
            return str(value)
        delimiter, items = value
        resolved_items = [str(self.resolve(item)) for item in items]
        return delimiter.join(resolved_items)

    def _resolve_fn_select(self, value: Any) -> Any:
        """Resolve Fn::Select."""
        if not isinstance(value, list) or len(value) != 2:
            return value
        index, list_value = value
        resolved_list = self.resolve(list_value)
        if isinstance(resolved_list, list) and isinstance(index, int):
            return resolved_list[index] if 0 <= index < len(resolved_list) else ""
        return value

    def _resolve_fn_split(self, value: Any) -> list[str]:
        """Resolve Fn::Split."""
        if not isinstance(value, list) or len(value) != 2:
            return [str(value)]
        delimiter, string_to_split = value
        resolved = self.resolve(string_to_split)
        return str(resolved).split(delimiter)

    def _resolve_fn_get_att(self, value: Any) -> Any:
        """Resolve Fn::GetAtt."""
        if isinstance(value, list) and len(value) == 2:
            resource_id, attribute = value
            if resource_id in self._resources:
                resource = self._resources[resource_id]
                if isinstance(resource, dict):
                    return resource.get("physical_resource_id", resource_id)
            return f"{resource_id}.{attribute}"
        if isinstance(value, str):
            return value
        return value

    def _resolve_fn_find_in_map(self, value: Any) -> Any:
        """Resolve Fn::FindInMap."""
        if not isinstance(value, list) or len(value) != 3:
            return value
        map_name, first_key, second_key = value
        resolved_first = self.resolve(first_key)
        resolved_second = self.resolve(second_key)
        if map_name in self._mappings:
            mapping = self._mappings[map_name]
            if isinstance(mapping, dict):
                first_level = mapping.get(resolved_first, {})
                if isinstance(first_level, dict):
                    return first_level.get(resolved_second, "")
        return ""

    def _resolve_fn_base64(self, value: Any) -> str:
        """Resolve Fn::Base64."""
        resolved = self.resolve(value)
        import base64
        return base64.b64encode(str(resolved).encode()).decode()

    def _resolve_fn_cidr(self, value: Any) -> list[str]:
        """Resolve Fn::Cidr."""
        if not isinstance(value, list) or len(value) < 2:
            return [str(value)]
        ip_block, count = value[0], value[1]
        resolved_ip = self.resolve(ip_block)
        resolved_count = self.resolve(count)
        return [f"{resolved_ip}/{i}" for i in range(int(resolved_count) if isinstance(resolved_count, int) else 1)]

    def _resolve_fn_get_azs(self, value: Any) -> list[str]:
        """Resolve Fn::GetAZs."""
        region = self.resolve(value) if value else self._pseudo_params.get("AWS::Region", "us-east-1")
        return [f"{region}a", f"{region}b", f"{region}c"]

    def _resolve_fn_import_value(self, value: Any) -> str:
        """Resolve Fn::ImportValue."""
        return str(self.resolve(value))

    def _resolve_fn_transform(self, value: Any) -> Any:
        """Resolve Fn::Transform."""
        return value

    def _resolve_fn_to_json_string(self, value: Any) -> str:
        """Resolve Fn::ToJsonString."""
        import json
        resolved = self.resolve(value)
        return json.dumps(resolved)

    def _resolve_fn_length(self, value: Any) -> int:
        """Resolve Fn::Length."""
        resolved = self.resolve(value)
        if isinstance(resolved, (list, dict, str)):
            return len(resolved)
        return 0

    def _evaluate_condition(self, condition_name: str) -> bool:
        """Evaluate a CloudFormation condition."""
        if condition_name not in self._conditions:
            return True
        condition = self._conditions[condition_name]
        if not isinstance(condition, dict):
            return bool(condition)
        for fn_name, fn_value in condition.items():
            if fn_name == "Fn::Equals":
                if isinstance(fn_value, list) and len(fn_value) == 2:
                    left = self.resolve(fn_value[0])
                    right = self.resolve(fn_value[1])
                    return str(left) == str(right)
            if fn_name == "Fn::Not":
                if isinstance(fn_value, list) and len(fn_value) == 1:
                    return not self._evaluate_condition(fn_value[0])
            if fn_name == "Fn::And":
                if isinstance(fn_value, list):
                    return all(self._evaluate_condition(c) for c in fn_value)
            if fn_name == "Fn::Or":
                if isinstance(fn_value, list):
                    return any(self._evaluate_condition(c) for c in fn_value)
        return True

"""Parse Terraform plan JSON (and convert binary .tfplan when possible).

Full support for Terraform Plan JSON format including:
- planned_values
- resource_changes (create/update/delete/replace)
- configuration
- prior_state
- terraform_version
- module calls and child modules
- moved blocks
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from app.services.iac_app.domain.document import ParsedDocument
from app.services.iac_app.scanner.parsers.base import ParserAdapter

logger = logging.getLogger(__name__)

PLAN_JSON_NAMES = {"tfplan.json", "plan.json", "terraform.tfplan.json"}


class TerraformPlanParser(ParserAdapter):
    def supports(self, file: str) -> bool:
        path = Path(file)
        name = path.name.lower()
        if path.suffix.lower() == ".tfplan":
            return True
        if name in PLAN_JSON_NAMES or name.endswith(".tfplan.json"):
            return True
        if path.suffix.lower() == ".json":
            return _looks_like_plan_json(path)
        return False

    def parse(self, file: str) -> ParsedDocument:
        path = Path(file)
        errors: list[str] = []
        try:
            payload = self._load_plan(path)
            raw = self._normalize_plan(payload, str(path))
            return ParsedDocument(file_path=str(path), iac_type="terraform", raw=raw, errors=errors)
        except Exception as exc:
            logger.warning("Terraform plan parse failed for %s: %s", path, exc)
            return ParsedDocument(
                file_path=str(path),
                iac_type="terraform",
                raw={},
                errors=[f"Failed to parse Terraform plan: {exc}"],
            )

    def _load_plan(self, path: Path) -> dict[str, Any]:
        if path.suffix.lower() == ".tfplan":
            try:
                from app.services.iac_app.scanner.collector.tfplan_converter import convert_tfplan_to_json
                return convert_tfplan_to_json(path)
            except Exception:
                try:
                    return json.loads(path.read_text(encoding="utf-8"))
                except Exception:
                    raise
        return json.loads(path.read_text(encoding="utf-8"))

    def _normalize_plan(self, payload: dict[str, Any], file_path: str) -> dict[str, Any]:
        resources: dict[str, Any] = {}
        data_sources: dict[str, Any] = {}

        planned = (payload.get("planned_values") or {}).get("root_module") or {}
        self._walk_module(planned, resources, data_sources)

        for change in payload.get("resource_changes") or []:
            address = change.get("address") or ""
            after = ((change.get("change") or {}).get("after")) or {}
            actions = (change.get("change") or {}).get("actions") or []
            if not address or change.get("mode") == "data":
                continue

            if address not in resources:
                resources[address] = {
                    "type": change.get("type") or "",
                    "name": change.get("name") or address,
                    "config": after if isinstance(after, dict) else {},
                    "source": "resource_changes",
                    "actions": actions,
                    "action": actions[0] if actions else "no-op",
                    "module": change.get("module_address", ""),
                    "provider": change.get("provider_name", ""),
                }
            else:
                merged = dict(resources[address].get("config") or {})
                if isinstance(after, dict):
                    merged.update({k: v for k, v in after.items() if v is not None})
                resources[address]["config"] = merged
                resources[address]["actions"] = actions
                resources[address]["action"] = actions[0] if actions else "no-op"

        prior_state = (payload.get("prior_state") or {}).get("root_module") or {}
        self._walk_module(prior_state, {}, data_sources, prefix="data.")

        configuration = (payload.get("configuration") or {}).get("root_module") or {}
        self._walk_configuration(configuration, resources)

        return {
            "file_path": file_path,
            "iac_type": "terraform",
            "resources": resources,
            "data_sources": data_sources,
            "variables": self._extract_variables(payload),
            "plan_format_version": payload.get("format_version"),
            "terraform_version": payload.get("terraform_version"),
            "prior_state": payload.get("prior_state"),
            "configuration": configuration,
            "moved": payload.get("moved"),
            "replaced_by": payload.get("replaced_by"),
            "summary": self._extract_summary(payload),
        }

    def _walk_module(
        self,
        module: dict[str, Any],
        resources: dict,
        data_sources: dict,
        prefix: str = "",
    ) -> None:
        for resource in module.get("resources") or []:
            address = resource.get("address") or f"{resource.get('type')}.{resource.get('name')}"
            entry = {
                "type": resource.get("type") or "",
                "name": resource.get("name") or address,
                "config": resource.get("values") or {},
                "source": "planned_values",
                "actions": ["create"],
                "action": "create",
                "module": prefix,
                "provider": resource.get("provider_name", ""),
            }
            if resource.get("mode") == "data":
                data_sources[address] = entry
            else:
                resources[address] = entry
        for child in module.get("child_modules") or []:
            child_prefix = prefix + (child.get("address", "").split(".")[-1] + ".") if child.get("address") else prefix
            self._walk_module(child, resources, data_sources, prefix=child_prefix)

    def _walk_configuration(self, module: dict[str, Any], resources: dict) -> None:
        """Extract configuration details for resources."""
        for expr in module.get("resources") or []:
            address = expr.get("address") or ""
            if address in resources:
                resources[address]["config_expressions"] = expr.get("expressions") or {}
                resources[address]["config_mode"] = expr.get("mode", "managed")
                resources[address]["config_provider"] = expr.get("provider_config_key", "")
                resources[address]["config_provisioners"] = expr.get("provisioners") or []

        for child in module.get("module_calls") or []:
            child_module = child.get("module") or {}
            self._walk_configuration(child_module, resources)

    def _extract_variables(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Extract variables from the plan."""
        variables = payload.get("variables") or {}
        if not isinstance(variables, dict):
            return {}
        result = {}
        for name, var_data in variables.items():
            if isinstance(var_data, dict):
                result[name] = {
                    "value": var_data.get("value"),
                    "type": var_data.get("type"),
                    "description": var_data.get("description"),
                }
            else:
                result[name] = {"value": var_data}
        return result

    def _extract_summary(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Extract summary statistics from the plan."""
        changes = payload.get("resource_changes") or []
        summary = {
            "add": 0,
            "change": 0,
            "destroy": 0,
            "total": len(changes),
        }
        for change in changes:
            actions = (change.get("change") or {}).get("actions") or []
            if "create" in actions:
                summary["add"] += 1
            if "update" in actions:
                summary["change"] += 1
            if "delete" in actions:
                summary["destroy"] += 1
        return summary


def _looks_like_plan_json(path: Path) -> bool:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            head = handle.read(4000)
        return '"format_version"' in head and (
            '"planned_values"' in head or '"resource_changes"' in head
        )
    except OSError:
        return False

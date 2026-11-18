"""Terraform HCL2 parser — converts .tf / .tf.json files to ParsedDocument."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from app.services.iac_app.domain.document import ParsedDocument
from app.services.iac_app.scanner.parsers.base import ParserAdapter

logger = logging.getLogger(__name__)


def _as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def flatten_hcl(obj: Any) -> Any:
    """Unwrap python-hcl2's single-element lists so queries see scalar values."""
    if isinstance(obj, list):
        if len(obj) == 1 and not isinstance(obj[0], (dict, list)):
            return flatten_hcl(obj[0])
        return [flatten_hcl(item) for item in obj]
    if isinstance(obj, dict):
        return { _clean_hcl_key(key): flatten_hcl(value) for key, value in obj.items() if key != "__is_block__" }
    if isinstance(obj, str):
        return _clean_hcl_key(obj)
    return obj


def _clean_hcl_key(value: str) -> str:
    text = str(value).strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
        return text[1:-1]
    return text


def iter_hcl_resources(block_body: Any):
    """Yield (resource_type, resource_name, config) from HCL resource blocks."""
    for item in _as_list(block_body):
        if not isinstance(item, dict):
            continue
        for resource_type, resource_defs in item.items():
            for resource_def in _as_list(resource_defs):
                if not isinstance(resource_def, dict):
                    continue
                for resource_name, resource_config in resource_def.items():
                    config = resource_config
                    if isinstance(config, list) and config:
                        config = config[0]
                    if not isinstance(config, dict):
                        config = {}
                    yield _clean_hcl_key(str(resource_type)), _clean_hcl_key(str(resource_name)), flatten_hcl(config)


class TerraformParser(ParserAdapter):
    EXTENSIONS = (".tf", ".tfvars", ".tf.json")

    def supports(self, file: str) -> bool:
        path = Path(file)
        name = path.name.lower()
        if name.endswith(".tf.json"):
            return True
        return path.suffix.lower() in {".tf", ".tfvars"}

    def parse(self, file: str) -> ParsedDocument:
        path = Path(file)
        try:
            name = path.name.lower()
            if name.endswith(".tf.json") or path.suffix.lower() == ".json":
                raw = self._parse_tf_json(path)
            else:
                raw = self._parse_hcl(path)
            if raw is None:
                return ParsedDocument(
                    file_path=str(path),
                    iac_type="terraform",
                    raw={},
                    errors=[f"Failed to parse Terraform file: {path}"],
                )
            return ParsedDocument(file_path=str(path), iac_type="terraform", raw=raw)
        except Exception as exc:
            logger.debug("Failed to parse %s: %s", path, exc)
            return ParsedDocument(
                file_path=str(path),
                iac_type="terraform",
                raw={},
                errors=[str(exc)],
            )

    def parse_file(self, file_path: Path) -> dict[str, Any] | None:
        document = self.parse(str(file_path))
        if document.errors and not document.raw:
            return None
        return document.raw

    def parse_directory(self, dir_path: Path) -> list[dict[str, Any]]:
        results = []
        for tf_file in sorted(Path(dir_path).rglob("*.tf")):
            parsed = self.parse_file(tf_file)
            if parsed:
                results.append(parsed)
        for tf_file in sorted(Path(dir_path).rglob("*.tf.json")):
            parsed = self.parse_file(tf_file)
            if parsed:
                results.append(parsed)
        return results

    def _parse_hcl(self, file_path: Path) -> dict[str, Any] | None:
        try:
            import hcl2

            with open(file_path, "r", encoding="utf-8") as handle:
                data = hcl2.load(handle)
            if not isinstance(data, dict):
                return None
            return self._normalize(data, str(file_path))
        except ImportError:
            logger.warning("python-hcl2 not installed")
            return None
        except Exception as exc:
            logger.debug("HCL parse error in %s: %s", file_path, exc)
            return None

    def _parse_tf_json(self, file_path: Path) -> dict[str, Any] | None:
        try:
            with open(file_path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            if not isinstance(data, dict):
                return None
            return self._normalize(data, str(file_path))
        except Exception as exc:
            logger.debug("TF JSON parse error in %s: %s", file_path, exc)
            return None

    def _normalize(self, data: dict, file_path: str) -> dict[str, Any]:
        resources: dict[str, Any] = {}
        variables: dict[str, Any] = {}
        outputs: dict[str, Any] = {}
        locals_block: dict[str, Any] = {}
        data_sources: dict[str, Any] = {}
        providers: dict[str, Any] = {}
        modules: dict[str, Any] = {}
        moved: list[dict[str, Any]] = []
        import_blocks: list[dict[str, Any]] = []
        terraform_block: dict[str, Any] = {}

        for block_type, block_body in data.items():
            if block_type == "resource":
                for resource_type, resource_name, resource_config in iter_hcl_resources(block_body):
                    resources[f"{resource_type}.{resource_name}"] = {
                        "type": resource_type,
                        "name": resource_name,
                        "config": resource_config or {},
                        "file": file_path,
                    }
            elif block_type == "variable":
                for item in _as_list(block_body):
                    if isinstance(item, dict):
                        for var_name, var_config in item.items():
                            clean_name = _clean_hcl_key(str(var_name))
                            config = var_config[0] if isinstance(var_config, list) and var_config else var_config
                            variables[clean_name] = flatten_hcl(config or {})
            elif block_type == "output":
                for item in _as_list(block_body):
                    if isinstance(item, dict):
                        for out_name, out_config in item.items():
                            clean_name = _clean_hcl_key(str(out_name))
                            config = out_config[0] if isinstance(out_config, list) and out_config else out_config
                            outputs[clean_name] = flatten_hcl(config or {})
            elif block_type == "locals":
                for item in _as_list(block_body):
                    if isinstance(item, dict):
                        locals_block.update(flatten_hcl(item))
            elif block_type == "data":
                for data_type, data_name, data_config in iter_hcl_resources(block_body):
                    data_sources[f"{data_type}.{data_name}"] = {
                        "type": data_type,
                        "name": data_name,
                        "config": data_config or {},
                    }
            elif block_type == "provider":
                for item in _as_list(block_body):
                    if isinstance(item, dict):
                        for provider_name, provider_config in item.items():
                            clean_name = _clean_hcl_key(str(provider_name))
                            config = provider_config[0] if isinstance(provider_config, list) and provider_config else provider_config
                            providers[clean_name] = flatten_hcl(config or {})
            elif block_type == "module":
                for item in _as_list(block_body):
                    if isinstance(item, dict):
                        for module_name, module_config in item.items():
                            clean_name = _clean_hcl_key(str(module_name))
                            config = module_config[0] if isinstance(module_config, list) and module_config else module_config
                            modules[clean_name] = flatten_hcl(config or {})
            elif block_type == "moved":
                for item in _as_list(block_body):
                    if isinstance(item, dict):
                        moved.append(flatten_hcl({
                            "from": _clean_hcl_key(str(item.get("from", ""))),
                            "to": _clean_hcl_key(str(item.get("to", ""))),
                        }))
            elif block_type == "import":
                for item in _as_list(block_body):
                    if isinstance(item, dict):
                        import_blocks.append(flatten_hcl({
                            "to": _clean_hcl_key(str(item.get("to", ""))),
                            "id": _clean_hcl_key(str(item.get("id", ""))),
                        }))
            elif block_type == "terraform":
                for item in _as_list(block_body):
                    if isinstance(item, dict):
                        terraform_block.update(flatten_hcl(item))

        return {
            "file_path": file_path,
            "resources": resources,
            "variables": variables,
            "outputs": outputs,
            "locals": locals_block,
            "data_sources": data_sources,
            "providers": providers,
            "modules": modules,
            "moved": moved,
            "import": import_blocks,
            "terraform": terraform_block,
        }

    def get_resource(self, parsed: dict, resource_type: str, resource_name: str | None = None) -> list[dict]:
        results = []
        for resource in parsed.get("resources", {}).values():
            if resource["type"] == resource_type:
                if resource_name is None or resource["name"] == resource_name:
                    results.append(resource)
        return results

    def get_resources_by_type(self, parsed: dict, resource_type: str) -> list[dict]:
        return self.get_resource(parsed, resource_type)

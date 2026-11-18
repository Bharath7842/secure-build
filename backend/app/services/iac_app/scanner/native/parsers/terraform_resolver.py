"""Terraform resolver — resolves variable references, locals, modules, and data sources.

This closes the gap between our internal engine and KICS/Trivy by:
- Resolving var.x -> default value, local.x -> computed value
- Evaluating ternary expressions, built-in functions, splat
- Reading terraform.tfvars and *.auto.tfvars for overrides
- Merging module resources into the parent scope
- Expanding count/for_each for literal and complex values
- Expanding dynamic blocks
- Exposing data sources in the query context
- Tracking moved blocks, import blocks, lifecycle configurations
- Resolving terraform.workspace references
- Supporting provider aliases
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from app.services.iac_app.scanner.native.parsers.terraform_expressions import evaluate_expression
from app.services.iac_app.scanner.native.parsers.relationship_builder import analyze_relationships

logger = logging.getLogger(__name__)

_VAR_PREFIX = "var."
_LOCAL_PREFIX = "local."
_DATA_PREFIX = "data."
_MODULE_PREFIX = "module."
_DATA_PATTERN = re.compile(r"^data\.([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+)")
_BRACE_VAR_PATTERN = re.compile(r"^\$\{var\.([a-zA-Z0-9_]+)\}$")
_BRACE_LOCAL_PATTERN = re.compile(r"^\$\{local\.([a-zA-Z0-9_]+)\}$")
_BRACE_DATA_PATTERN = re.compile(r"^\$\{data\.([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+)\}")


class TerraformResolver:
    def __init__(self, parsed_docs: list[dict[str, Any]], target_path: str | Path = "") -> None:
        self.parsed_docs = parsed_docs
        self.target_path = Path(target_path) if target_path else Path("")
        self.variables: dict[str, dict[str, Any]] = {}
        self.locals: dict[str, Any] = {}
        self.data_sources: dict[str, dict[str, Any]] = {}
        self.resources: dict[str, dict[str, Any]] = {}
        self.modules: dict[str, dict[str, Any]] = {}
        self.moved_blocks: list[dict[str, Any]] = []
        self.import_blocks: list[dict[str, Any]] = []
        self.terraform_settings: dict[str, Any] = {}
        self.providers: dict[str, dict[str, Any]] = {}
        self._resolving_locals: set[str] = set()
        self._resolving_vars: set[str] = set()
        self.workspace: str = "default"

    def resolve_all(self) -> dict[str, Any]:
        import time as _time
        resolved_resources = []
        steps = [
            ("_collect_variables", self._collect_variables),
            ("_read_tfvars", self._read_tfvars),
            ("_collect_terraform_settings", self._collect_terraform_settings),
            ("_collect_providers", self._collect_providers),
            ("_collect_data_sources", self._collect_data_sources),
            ("_collect_modules", self._collect_modules),
            ("_collect_resources", self._collect_resources),
            ("_collect_moved_blocks", self._collect_moved_blocks),
            ("_collect_import_blocks", self._collect_import_blocks),
            ("_compute_locals", self._compute_locals),
            ("_apply_moved_blocks", self._apply_moved_blocks),
            ("_expand_dynamic_blocks", self._expand_dynamic_blocks),
            ("_expand_count_foreach", self._expand_count_foreach),
            ("_expand_complex_foreach", self._expand_complex_foreach),
        ]
        for name, fn in steps:
            t = _time.time()
            fn()
            elapsed = _time.time() - t
            if elapsed > 1:
                logger.warning("TerraformResolver step %s took %.1fs", name, elapsed)
            if elapsed > 30:
                logger.error("TerraformResolver step %s timed out after %.1fs, aborting", name, elapsed)
                break
        else:
            t = _time.time()
            resolved_resources = self._resolve_all_resources()
            elapsed = _time.time() - t
            if elapsed > 1:
                logger.warning("TerraformResolver step _resolve_all_resources took %.1fs", elapsed)
        relationships = analyze_relationships(resolved_resources)
        relationships = analyze_relationships(resolved_resources)
        return {
            "resources": resolved_resources,
            "variables": {k: v.get("default") for k, v in self.variables.items()},
            "locals": dict(self.locals),
            "data_sources": self._resolve_data_sources(),
            "modules": {k: {"source": v.get("source"), "version": v.get("config", {}).get("version"), "resolved": v.get("_resolved", False)} for k, v in self.modules.items()},
            "resource_relationships": relationships,
            "moved_blocks": self.moved_blocks,
            "import_blocks": self.import_blocks,
            "terraform_settings": self.terraform_settings,
            "providers": self.providers,
            "workspace": self.workspace,
        }

    def _collect_variables(self) -> None:
        for doc in self.parsed_docs:
            raw = doc.get("raw") or doc
            for var_name, var_config in (raw.get("variables") or {}).items():
                if isinstance(var_config, dict) and var_name not in self.variables:
                    default = var_config.get("default")
                    self.variables[var_name] = {
                        "default": default,
                        "type": var_config.get("type"),
                        "description": var_config.get("description"),
                    }

    def _read_tfvars(self) -> None:
        if not self.target_path.exists():
            return
        for tfvars_file in self.target_path.glob("*.tfvars"):
            if tfvars_file.name == "terraform.tfvars" or tfvars_file.name.endswith(".auto.tfvars"):
                try:
                    import hcl2
                    from app.services.iac_app.scanner.native.parsers.terraform_parser import _clean_hcl_key, flatten_hcl
                    with open(tfvars_file, "r", encoding="utf-8") as handle:
                        data = hcl2.load(handle)
                    if not isinstance(data, dict):
                        continue
                    if "variable" in data:
                        block_body = data["variable"]
                        if isinstance(block_body, list):
                            for item in block_body:
                                if isinstance(item, dict):
                                    for var_name, value in item.items():
                                        clean_name = _clean_hcl_key(str(var_name))
                                        if clean_name in self.variables:
                                            if isinstance(value, list) and len(value) == 1:
                                                actual = flatten_hcl(value[0])
                                            else:
                                                actual = flatten_hcl(value)
                                            self.variables[clean_name]["default"] = actual
                    else:
                        for var_name, value in data.items():
                            clean_name = _clean_hcl_key(str(var_name))
                            if clean_name in self.variables:
                                if isinstance(value, list) and len(value) == 1:
                                    actual = flatten_hcl(value[0])
                                elif isinstance(value, str):
                                    actual = flatten_hcl(value)
                                else:
                                    actual = flatten_hcl(value)
                                self.variables[clean_name]["default"] = actual
                except Exception as exc:
                    logger.debug("Failed to read tfvars %s: %s", tfvars_file, exc)

    def _collect_terraform_settings(self) -> None:
        for doc in self.parsed_docs:
            raw = doc.get("raw") or doc
            terraform_block = raw.get("terraform") or {}
            if isinstance(terraform_block, dict):
                self.terraform_settings.update(terraform_block)
                backend = terraform_block.get("backend", {})
                if isinstance(backend, dict):
                    self.terraform_settings["backend"] = backend
                required_providers = terraform_block.get("required_providers", {})
                if isinstance(required_providers, dict):
                    self.terraform_settings["required_providers"] = required_providers
                required_version = terraform_block.get("required_version")
                if required_version:
                    self.terraform_settings["required_version"] = required_version

    def _collect_providers(self) -> None:
        for doc in self.parsed_docs:
            raw = doc.get("raw") or doc
            for provider_name, provider_config in (raw.get("providers") or {}).items():
                if isinstance(provider_config, dict):
                    clean_name = str(provider_name).strip().strip('"')
                    if "." in clean_name:
                        base, alias = clean_name.split(".", 1)
                        if base not in self.providers:
                            self.providers[base] = {}
                        self.providers[base][alias] = provider_config
                    else:
                        if clean_name not in self.providers:
                            self.providers[clean_name] = {}
                        self.providers[clean_name]["default"] = provider_config

    def _collect_moved_blocks(self) -> None:
        for doc in self.parsed_docs:
            raw = doc.get("raw") or doc
            for moved in (raw.get("moved") or []):
                if isinstance(moved, dict):
                    self.moved_blocks.append({
                        "from": moved.get("from", ""),
                        "to": moved.get("to", ""),
                    })

    def _collect_import_blocks(self) -> None:
        for doc in self.parsed_docs:
            raw = doc.get("raw") or doc
            for imp in (raw.get("import") or []):
                if isinstance(imp, dict):
                    self.import_blocks.append({
                        "to": imp.get("to", ""),
                        "id": imp.get("id", ""),
                    })

    def _apply_moved_blocks(self) -> None:
        if not self.moved_blocks:
            return
        move_map = {m["from"]: m["to"] for m in self.moved_blocks}
        new_resources: dict[str, dict[str, Any]] = {}
        for res_id, res_config in self.resources.items():
            if res_id in move_map:
                new_id = move_map[res_id]
                res_config = dict(res_config)
                res_config["moved_from"] = res_id
                new_resources[new_id] = res_config
            else:
                new_resources[res_id] = res_config
        self.resources = new_resources

    def _collect_data_sources(self) -> None:
        for doc in self.parsed_docs:
            raw = doc.get("raw") or doc
            for ds_id, ds_config in (raw.get("data_sources") or {}).items():
                if isinstance(ds_config, dict):
                    self.data_sources[ds_id] = ds_config

    def _collect_modules(self) -> None:
        for doc in self.parsed_docs:
            raw = doc.get("raw") or doc
            file_path = doc.get("file_path") or ""
            for module_name, module_config in (raw.get("modules") or {}).items():
                if isinstance(module_config, dict):
                    self.modules[module_name] = {
                        "source": module_config.get("source", ""),
                        "config": module_config,
                        "file_path": file_path,
                        "_resolved": False,
                    }

    def _collect_resources(self) -> None:
        for doc in self.parsed_docs:
            raw = doc.get("raw") or doc
            file_path = doc.get("file_path") or ""
            for res_id, res_config in (raw.get("resources") or {}).items():
                if isinstance(res_config, dict):
                    entry = dict(res_config)
                    entry["file"] = file_path
                    self.resources[res_id] = entry

    def _compute_locals(self) -> None:
        for doc in self.parsed_docs:
            raw = doc.get("raw") or doc
            for local_name, local_value in (raw.get("locals") or {}).items():
                if local_name not in self.locals:
                    self.locals[local_name] = self._resolve_value(local_value)

    def _resolve_value(self, value: Any, depth: int = 0) -> Any:
        if depth > 10:
            return value
        if isinstance(value, str):
            if value == "terraform.workspace":
                return self.workspace
            if value.startswith("terraform.") and "." not in value[len("terraform."):]:
                attr = value[len("terraform."):]
                if attr == "workspace":
                    return self.workspace
                return value
            if value.startswith(_VAR_PREFIX) and "." not in value[len(_VAR_PREFIX):]:
                var_name = value[len(_VAR_PREFIX):]
                if var_name not in self._resolving_vars:
                    self._resolving_vars.add(var_name)
                    try:
                        default = self.variables.get(var_name, {}).get("default")
                        if default is not None:
                            return self._resolve_value(default, depth + 1)
                        return value
                    finally:
                        self._resolving_vars.discard(var_name)
                return value
            if value.startswith(_LOCAL_PREFIX) and "." not in value[len(_LOCAL_PREFIX):]:
                local_name = value[len(_LOCAL_PREFIX):]
                if local_name not in self._resolving_locals:
                    self._resolving_locals.add(local_name)
                    try:
                        computed = self.locals.get(local_name)
                        if computed is not None:
                            return self._resolve_value(computed, depth + 1)
                        return value
                    finally:
                        self._resolving_locals.discard(local_name)
                return value
            m = _BRACE_VAR_PATTERN.match(value)
            if m:
                var_name = m.group(1)
                if var_name not in self._resolving_vars:
                    self._resolving_vars.add(var_name)
                    try:
                        default = self.variables.get(var_name, {}).get("default")
                        if default is not None:
                            return self._resolve_value(default, depth + 1)
                        return value
                    finally:
                        self._resolving_vars.discard(var_name)
                return value
            m = _BRACE_LOCAL_PATTERN.match(value)
            if m:
                local_name = m.group(1)
                if local_name not in self._resolving_locals:
                    self._resolving_locals.add(local_name)
                    try:
                        computed = self.locals.get(local_name)
                        if computed is not None:
                            return self._resolve_value(computed, depth + 1)
                        return value
                    finally:
                        self._resolving_locals.discard(local_name)
                return value
            m = _DATA_PATTERN.match(value) or _BRACE_DATA_PATTERN.match(value)
            if m:
                ds_type, ds_name = m.group(1), m.group(2)
                ds_id = f"{ds_type}.{ds_name}"
                if ds_id in self.data_sources:
                    return self.data_sources[ds_id].get("config", value)
                return value
            if "${" in value or "[*]" in value:
                context = self._build_eval_context()
                if hasattr(self, '_resolved'):
                    context.update(self._resolved)
                try:
                    expr = value if value.startswith("${") else f"${{{value}}}"
                    result = evaluate_expression(expr, context)
                    if result != value and not (isinstance(result, str) and result.startswith("${")):
                        return self._resolve_value(result, depth + 1)
                except Exception:
                    pass
            return value
        if isinstance(value, list):
            return [self._resolve_value(item, depth + 1) for item in value]
        if isinstance(value, dict):
            return {k: self._resolve_value(v, depth + 1) for k, v in value.items()}
        return value

    def _build_eval_context(self) -> dict[str, Any]:
        ctx: dict[str, Any] = {}
        var_dict = {}
        for var_name, var_config in self.variables.items():
            default = var_config.get("default")
            ctx[f"var.{var_name}"] = default
            ctx[var_name] = default
            var_dict[var_name] = default
        ctx["var"] = var_dict
        ctx["local"] = {}
        for local_name, local_value in self.locals.items():
            ctx[f"local.{local_name}"] = local_value
            ctx["local"][local_name] = local_value
        for ds_id, ds_config in self.data_sources.items():
            ctx[f"data.{ds_id}"] = ds_config.get("config") if isinstance(ds_config, dict) else ds_config
        for res_id, res_config in self.resources.items():
            res_type = res_config.get("type", "")
            res_name = res_config.get("name", "")
            if res_type and res_name:
                if res_type not in ctx:
                    ctx[res_type] = {}
                ctx[res_type][res_name] = res_config.get("config", {})
        ctx["terraform"] = {
            "workspace": self.workspace,
            "current_path": str(self.target_path),
        }
        for provider_name, aliases in self.providers.items():
            ctx[provider_name] = {}
            for alias, config in aliases.items():
                ctx[provider_name][alias] = config
        return ctx

    def _expand_dynamic_blocks(self) -> None:
        expanded: dict[str, dict[str, Any]] = {}
        for res_id, res_config in list(self.resources.items()):
            config = res_config.get("config") or {}
            dynamic_blocks = config.get("dynamic")
            if not dynamic_blocks or not isinstance(dynamic_blocks, (list, dict)):
                expanded[res_id] = res_config
                continue
            blocks = dynamic_blocks if isinstance(dynamic_blocks, list) else [dynamic_blocks]
            new_config = dict(config)
            new_config.pop("dynamic", None)
            for block_wrapper in blocks:
                if not isinstance(block_wrapper, dict):
                    continue
                for block_name, block_def in block_wrapper.items():
                    if not isinstance(block_def, dict):
                        continue
                    for_each_val = block_def.get("for_each")
                    content_list = block_def.get("content") or []
                    content = content_list[0] if isinstance(content_list, list) and content_list else content_list
                    if not isinstance(content, dict):
                        continue
                    items = self._resolve_foreach_value(for_each_val)
                    if items is None:
                        continue
                    generated = []
                    for item in items:
                        block_instance = {}
                        if isinstance(item, dict):
                            for k, v in content.items():
                                block_instance[k] = self._resolve_foreach_content(v, item)
                        else:
                            for k, v in content.items():
                                block_instance[k] = self._resolve_foreach_content(v, {"value": item, "key": item})
                        generated.append(block_instance)
                    if block_name in new_config:
                        existing = new_config[block_name]
                        if isinstance(existing, list):
                            existing.extend(generated)
                        else:
                            new_config[block_name] = generated
                    else:
                        new_config[block_name] = generated
            expanded[res_id] = {
                "type": res_config.get("type"),
                "name": res_config.get("name"),
                "config": new_config,
                "file": res_config.get("file"),
            }
        self.resources = expanded

    def _resolve_foreach_value(self, for_each_val: Any) -> list[Any] | None:
        if for_each_val is None:
            return None
        if isinstance(for_each_val, list):
            return for_each_val
        if isinstance(for_each_val, dict):
            return list(for_each_val.values())
        if isinstance(for_each_val, str):
            context = self._build_eval_context()
            if "${" in for_each_val:
                try:
                    result = evaluate_expression(for_each_val, context)
                    if isinstance(result, (list, dict)):
                        return list(result.values()) if isinstance(result, dict) else result
                except Exception:
                    pass
            if for_each_val.startswith("var."):
                var_name = for_each_val[len("var."):]
                default = self.variables.get(var_name, {}).get("default")
                if isinstance(default, (list, dict)):
                    return list(default.values()) if isinstance(default, dict) else default
            if for_each_val.startswith("local."):
                local_name = for_each_val[len("local."):]
                computed = self.locals.get(local_name)
                if isinstance(computed, (list, dict)):
                    return list(computed.values()) if isinstance(computed, dict) else computed
        return None

    def _resolve_foreach_content(self, value: Any, item: dict[str, Any]) -> Any:
        if isinstance(value, str):
            if value.startswith("${") and value.endswith("}"):
                inner = value[2:-1].strip()
                if inner == "each.value":
                    return item.get("value", item)
                if inner == "each.key":
                    return item.get("key", item)
                if inner.startswith("each.value."):
                    attr = inner[len("each.value."):]
                    return item.get("value", item).get(attr) if isinstance(item.get("value"), dict) else item.get(attr)
                context = self._build_eval_context()
                context["each"] = {"value": item.get("value", item), "key": item.get("key", item)}
                try:
                    return evaluate_expression(value, context)
                except Exception:
                    pass
            if value == "each.value":
                return item.get("value", item)
            if value == "each.key":
                return item.get("key", item)
        return value

    def _expand_complex_foreach(self) -> None:
        expanded: dict[str, dict[str, Any]] = {}
        for res_id, res_config in list(self.resources.items()):
            config = res_config.get("config") or {}
            foreach_val = config.get("for_each")
            if foreach_val is not None and isinstance(foreach_val, str):
                items = self._resolve_foreach_value(foreach_val)
                if items:
                    new_config = dict(config)
                    new_config.pop("for_each", None)
                    for item in items:
                        key = item if isinstance(item, str) else str(item)
                        new_id = f"{res_id}[{key}]"
                        expanded[new_id] = {
                            "type": res_config.get("type"),
                            "name": res_config.get("name"),
                            "config": new_config,
                            "file": res_config.get("file"),
                            "for_each_key": key,
                        }
                    continue
            expanded[res_id] = res_config
        self.resources = expanded

    def _expand_count_foreach(self) -> None:
        expanded: dict[str, dict[str, Any]] = {}
        for res_id, res_config in list(self.resources.items()):
            config = res_config.get("config") or {}
            count_val = config.get("count")
            if count_val is not None:
                try:
                    n = int(count_val) if not isinstance(count_val, int) else count_val
                    for i in range(n):
                        new_id = f"{res_id}[{i}]" if n > 1 else res_id
                        new_config = dict(config)
                        new_config.pop("count", None)
                        expanded[new_id] = {
                            "type": res_config.get("type"),
                            "name": res_config.get("name"),
                            "config": new_config,
                            "file": res_config.get("file"),
                            "count_index": i,
                        }
                    continue
                except (ValueError, TypeError):
                    pass
            foreach_val = config.get("for_each")
            if foreach_val is not None and isinstance(foreach_val, (list, dict)):
                items = list(foreach_val) if isinstance(foreach_val, list) else list(foreach_val.keys())
                for idx, key in enumerate(items):
                    new_id = f"{res_id}[{key}]"
                    new_config = dict(config)
                    new_config.pop("for_each", None)
                    expanded[new_id] = {
                        "type": res_config.get("type"),
                        "name": res_config.get("name"),
                        "config": new_config,
                        "file": res_config.get("file"),
                        "for_each_key": str(key),
                    }
                continue
            expanded[res_id] = res_config
        self.resources = expanded

    def _resolve_all_resources(self) -> list[dict[str, Any]]:
        resolved = []
        for res_id, res_config in self.resources.items():
            config = res_config.get("config") or {}
            lifecycle = config.pop("lifecycle", None)
            resolved_config = self._resolve_value(config)
            entry = {
                "id": res_id,
                "type": res_config.get("type", ""),
                "name": res_config.get("name", ""),
                "config": resolved_config,
                "file": res_config.get("file", ""),
                "count_index": res_config.get("count_index"),
                "for_each_key": res_config.get("for_each_key"),
                "module": res_config.get("module"),
            }
            if lifecycle:
                entry["lifecycle"] = lifecycle
            if res_config.get("moved_from"):
                entry["moved_from"] = res_config["moved_from"]
            resolved.append(entry)
        for module_name, module_info in self.modules.items():
            for res in self._resolve_module_resources(module_name, module_info):
                resolved.append(res)
        return resolved

    def _resolve_module_resources(self, module_name: str, module_info: dict[str, Any]) -> list[dict[str, Any]]:
        source = module_info.get("source", "")
        version = module_info.get("config", {}).get("version")
        caller_file = module_info.get("file_path", "")

        from app.services.iac_app.scanner.native.parsers.module_downloader import resolve_module_path, classify_source
        source_type = classify_source(source)

        if source_type == "local":
            module_path = Path(caller_file).parent / source if caller_file else Path(source)
            if not module_path.exists() or not module_path.is_dir():
                return []
        else:
            module_path = resolve_module_path(source, caller_file, version, skip_remote=True)
            if module_path is None:
                return []
        from app.services.iac_app.scanner.native.parsers.terraform_parser import TerraformParser
        parser = TerraformParser()
        module_docs = []
        for tf_file in module_path.glob("*.tf"):
            parsed = parser.parse_file(tf_file)
            if parsed:
                module_docs.append(parsed)
        if not module_docs:
            return []
        module_info["_resolved"] = True
        module_inputs = {}
        config = module_info.get("config") or {}
        for key, value in config.items():
            if key != "source" and not key.startswith("_"):
                module_inputs[key] = value
        module_resolver = TerraformResolver(module_docs, str(module_path))
        for var_name, value in module_inputs.items():
            module_resolver.variables[var_name] = {"default": value}
        resolved_ctx = module_resolver.resolve_all()
        result = []
        for res in resolved_ctx.get("resources", []):
            res["id"] = f"module.{module_name}.{res['id']}"
            res["module"] = module_name
            result.append(res)
        if resolved_ctx.get("moved_blocks"):
            self.moved_blocks.extend(resolved_ctx["moved_blocks"])
        if resolved_ctx.get("import_blocks"):
            self.import_blocks.extend(resolved_ctx["import_blocks"])
        return result

    def _resolve_data_sources(self) -> dict[str, Any]:
        resolved = {}
        for ds_id, ds_config in self.data_sources.items():
            config = ds_config.get("config") or ds_config
            resolved[ds_id] = self._resolve_value(config)
        return resolved

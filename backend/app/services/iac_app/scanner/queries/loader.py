"""Load query metadata.yaml + rule.py modules from the queries directory."""

from __future__ import annotations

import importlib.util
import logging
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Callable

import yaml

from app.services.iac_app.domain.policy import QueryMetadata

logger = logging.getLogger(__name__)

EvaluateFn = Callable[[dict[str, Any]], list[dict[str, Any]]]


def _default_queries_dir() -> Path:
    # After porting: iac_app/scanner/queries/loader.py -> parents[2] = iac_app/
    return Path(__file__).resolve().parents[2] / "queries_pack"


class LoadedQuery:
    def __init__(self, metadata: QueryMetadata, evaluate: EvaluateFn, module_path: Path) -> None:
        self.metadata = metadata
        self.evaluate = evaluate
        self.module_path = module_path


class QueryLoader:
    def __init__(self, queries_dir: str | Path | None = None) -> None:
        self.queries_dir = Path(queries_dir) if queries_dir else _default_queries_dir()

    def load(self) -> list[LoadedQuery]:
        if not self.queries_dir.exists():
            logger.warning("Queries directory does not exist: %s", self.queries_dir)
            return []

        queries_str = str(self.queries_dir.resolve())
        if queries_str not in sys.path:
            sys.path.insert(0, queries_str)

        loaded: list[LoadedQuery] = []
        for metadata_path in sorted(self.queries_dir.rglob("metadata.yaml")):
            query_dir = metadata_path.parent
            rule_path = query_dir / "rule.py"
            if not rule_path.exists():
                logger.warning("Query %s is missing rule.py", query_dir)
                continue
            try:
                metadata = self._load_metadata(metadata_path)
                module = self._load_module(rule_path)
                evaluate = getattr(module, "evaluate", None)
                if not callable(evaluate):
                    logger.warning("Query %s rule.py has no evaluate()", query_dir)
                    continue
                loaded.append(LoadedQuery(metadata=metadata, evaluate=evaluate, module_path=rule_path))
            except Exception as exc:
                logger.error("Failed to load query from %s: %s", query_dir, exc)
        logger.info("Loaded %s internal queries from %s", len(loaded), self.queries_dir)
        return loaded

    def _load_metadata(self, path: Path) -> QueryMetadata:
        with open(path, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}

        compliance_raw = data.get("compliance") or []
        compliance: list[dict[str, str]] = []
        for item in compliance_raw:
            if isinstance(item, str):
                compliance.append({"framework": item, "control": ""})
            elif isinstance(item, dict):
                compliance.append(
                    {
                        "framework": str(item.get("framework") or item.get("id") or ""),
                        "control": str(item.get("control") or item.get("id") or ""),
                    }
                )

        references = data.get("references") or []
        if isinstance(references, str):
            references = [references]

        return QueryMetadata(
            id=str(data.get("id") or path.parent.name),
            name=str(data.get("name") or path.parent.name),
            description=str(data.get("description") or ""),
            severity=str(data.get("severity") or "MEDIUM").upper(),
            category=str(data.get("category") or "OTHER"),
            finding_type=str(data.get("finding_type") or "MISCONFIGURATION"),
            iac_type=str(data.get("iac_type") or "unknown").lower(),
            provider=(str(data["provider"]).lower() if data.get("provider") else None),
            enabled=bool(data.get("enabled", True)),
            remediation=str(data.get("remediation") or "").strip(),
            references=[str(r) for r in references if r],
            compliance=compliance,
            version=str(data.get("version") or "1.0.0"),
            engine="internal",
            path=str(path.parent),
        )

    def _load_module(self, rule_path: Path) -> ModuleType:
        module_name = f"iac_query_{'_'.join(rule_path.parent.parts[-4:])}"
        spec = importlib.util.spec_from_file_location(module_name, rule_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot import {rule_path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module

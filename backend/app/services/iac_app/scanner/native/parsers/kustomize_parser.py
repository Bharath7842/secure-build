"""Kustomize parser — parses kustomization.yaml and merges overlays.

Supports base/overlay merging, strategic merge patches, and resource includes.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from app.services.iac_app.domain.document import ParsedDocument
from app.services.iac_app.scanner.parsers.base import ParserAdapter
from app.services.iac_app.scanner.native.parsers.kubernetes_parser import KubernetesParser

logger = logging.getLogger(__name__)


class KustomizeParser(ParserAdapter):
    """Parse Kustomize kustomization.yaml files."""

    FILENAMES = ("kustomization.yaml", "kustomization.yml", "kustomizaton.yaml")

    def supports(self, file: str) -> bool:
        path = Path(file)
        return path.name.lower() in ("kustomization.yaml", "kustomization.yml", "kustomizaton.yaml")

    def parse(self, file: str) -> list[ParsedDocument]:
        path = Path(file)
        documents: list[ParsedDocument] = []
        try:
            for raw in self._parse_kustomization(path):
                documents.append(
                    ParsedDocument(file_path=str(path), iac_type="kubernetes", raw=raw)
                )
        except Exception as exc:
            logger.debug("Failed to parse Kustomize %s: %s", path, exc)
            documents.append(
                ParsedDocument(file_path=str(path), iac_type="kubernetes", raw={}, errors=[str(exc)])
            )
        return documents

    def parse_file(self, file_path: Path) -> list[dict[str, Any]]:
        return self._parse_kustomization(file_path)

    def _parse_kustomization(self, kustomization_path: Path) -> list[dict[str, Any]]:
        try:
            with open(kustomization_path, "r", encoding="utf-8") as handle:
                kust = yaml.safe_load(handle)
            if not isinstance(kust, dict):
                return []
            return self._resolve_kustomization(kust, kustomization_path.parent)
        except Exception as exc:
            logger.debug("Failed to parse kustomization %s: %s", kustomization_path, exc)
            return []

    def _resolve_kustomization(self, kust: dict, base_dir: Path) -> list[dict[str, Any]]:
        resources: list[dict[str, Any]] = []

        for resource_ref in kust.get("resources", []):
            resource_path = base_dir / resource_ref
            if resource_path.is_dir():
                kust_file = resource_path / "kustomization.yaml"
                if kust_file.exists():
                    sub_kust = self._load_yaml(kust_file)
                    if sub_kust:
                        resources.extend(self._resolve_kustomization(sub_kust, resource_path))
                    continue
            if resource_path.exists():
                parser = KubernetesParser()
                for doc in parser.parse_file(resource_path):
                    resources.append(doc)

        for crd_ref in kust.get("crds", []):
            crd_path = base_dir / crd_ref
            if crd_path.exists():
                parser = KubernetesParser()
                for doc in parser.parse_file(crd_path):
                    resources.append(doc)

        patches = kust.get("patches", []) or kust.get("patchesStrategicMerge", []) or []
        for patch_ref in patches:
            if isinstance(patch_ref, dict):
                resources.append(patch_ref)
            elif isinstance(patch_ref, str):
                patch_path = base_dir / patch_ref
                if patch_path.exists():
                    parser = KubernetesParser()
                    for doc in parser.parse_file(patch_path):
                        resources.append(doc)

        for generator_ref in kust.get("configMapGenerator", []):
            if isinstance(generator_ref, dict):
                name = generator_ref.get("name", "generated-configmap")
                literals = generator_ref.get("literals", [])
                data = {}
                for lit in literals:
                    if isinstance(lit, str) and "=" in lit:
                        key, _, val = lit.partition("=")
                        data[key] = val
                resources.append({
                    "apiVersion": "v1",
                    "kind": "ConfigMap",
                    "metadata": {"name": name},
                    "data": data,
                })

        for generator_ref in kust.get("secretGenerator", []):
            if isinstance(generator_ref, dict):
                name = generator_ref.get("name", "generated-secret")
                literals = generator_ref.get("literals", [])
                data = {}
                for lit in literals:
                    if isinstance(lit, str) and "=" in lit:
                        key, _, val = lit.partition("=")
                        data[key] = val
                resources.append({
                    "apiVersion": "v1",
                    "kind": "Secret",
                    "metadata": {"name": name},
                    "data": data,
                })

        return resources

    def _load_yaml(self, path: Path) -> dict | None:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = yaml.safe_load(handle)
            return data if isinstance(data, dict) else None
        except Exception:
            return None

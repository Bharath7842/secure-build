"""Helm chart parser and template renderer.

Processes Helm charts by reading Chart.yaml, values.yaml, and templates/
to produce rendered Kubernetes manifests.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from app.services.iac_app.domain.document import ParsedDocument
from app.services.iac_app.scanner.parsers.base import ParserAdapter


class HelmParser(ParserAdapter):
    """Parse Helm charts into normalized documents."""

    def supports(self, file: str) -> bool:
        p = Path(file)
        if p.is_dir():
            return (p / "Chart.yaml").exists()
        return False

    def parse(self, file: str) -> ParsedDocument | list[ParsedDocument]:
        chart_dir = Path(file)
        if not chart_dir.is_dir():
            chart_dir = chart_dir.parent

        chart_metadata = self._load_chart_yaml(chart_dir)
        values = self._load_values(chart_dir)
        templates = self._load_templates(chart_dir, values)

        all_resources = []
        for tpl_name, rendered in templates.items():
            docs = self._split_yaml_docs(rendered)
            for doc in docs:
                if not doc:
                    continue
                resource = self._doc_to_resource(doc, tpl_name, chart_metadata)
                if resource:
                    all_resources.append(resource)

        raw = {
            "chart": chart_metadata,
            "values": values,
            "resources": all_resources,
        }

        return ParsedDocument(
            file_path=str(chart_dir / "Chart.yaml"),
            iac_type="helm",
            raw=raw,
        )

    def _load_chart_yaml(self, chart_dir: Path) -> dict:
        chart_file = chart_dir / "Chart.yaml"
        if not chart_file.exists():
            return {}
        try:
            return yaml.safe_load(chart_file.read_text(encoding="utf-8")) or {}
        except Exception:
            return {}

    def _load_values(self, chart_dir: Path) -> dict:
        values_file = chart_dir / "values.yaml"
        if not values_file.exists():
            return {}
        try:
            return yaml.safe_load(values_file.read_text(encoding="utf-8")) or {}
        except Exception:
            return {}

    def _load_templates(self, chart_dir: Path, values: dict) -> dict[str, str]:
        templates_dir = chart_dir / "templates"
        if not templates_dir.is_dir():
            return {}

        rendered = {}
        for tpl_file in sorted(templates_dir.glob("*.yaml")):
            content = tpl_file.read_text(encoding="utf-8")
            rendered[tpl_file.name] = self._render_template(content, values)

        for tpl_file in sorted(templates_dir.glob("*.yml")):
            content = tpl_file.read_text(encoding="utf-8")
            rendered[tpl_file.name] = self._render_template(content, values)

        for tpl_file in sorted(templates_dir.glob("*.tpl")):
            content = tpl_file.read_text(encoding="utf-8")
            rendered[tpl_file.name] = self._render_template(content, values)

        return rendered

    def _render_template(self, content: str, values: dict) -> str:
        """Render Helm template expressions with basic substitution."""
        result = content

        def replace_value(match: re.Match) -> str:
            path = match.group(1).strip()
            parts = path.split(".")
            current = values
            for part in parts:
                if isinstance(current, dict):
                    current = current.get(part)
                else:
                    return match.group(0)
            if current is None:
                return ""
            if isinstance(current, bool):
                return "true" if current else "false"
            return str(current)

        result = re.sub(r'\{\{\s*\.Values\.([\w.]+)\s*\}\}', replace_value, result)
        result = re.sub(r'\{\{\s*\.Release\.Name\s*\}\}', "RELEASE", result)
        result = re.sub(r'\{\{\s*\.Release\.Namespace\s*\}\}', "default", result)
        result = re.sub(r'\{\{\s*\.Chart\.Name\s*\}\}', values.get("_chartName", "chart"), result)

        result = re.sub(r'\{\{-?\s*if\s+\.Values\.([\w.]+)\s*-?\}\}', r'<!-- if \1 -->', result)
        result = re.sub(r'\{\{-?\s*else\s*-?\}\}', '<!-- else -->', result)
        result = re.sub(r'\{\{-?\s*end\s*-?\}\}', '<!-- end -->', result)
        result = re.sub(r'\{\{-?\s*range\s+\.Values\.([\w.]+)\s*-?\}\}', r'<!-- range \1 -->', result)

        result = re.sub(r'\{\{\s*include\s+"([^"]+)"\s*\.\s*\}\}', r'<!-- include \1 -->', result)
        result = re.sub(r'\{\{\s*tpl\s+"([^"]+)"\s*\.\s*\}\}', r'<!-- tpl \1 -->', result)

        return result

    def _split_yaml_docs(self, content: str) -> list[dict]:
        """Split multi-document YAML content."""
        docs = []
        try:
            for doc in yaml.safe_load_all(content):
                if isinstance(doc, dict):
                    docs.append(doc)
        except Exception:
            pass
        return docs

    def _doc_to_resource(
        self, doc: dict, template_name: str, chart_metadata: dict
    ) -> dict | None:
        """Convert a YAML document to a resource dict."""
        kind = doc.get("kind", "")
        metadata = doc.get("metadata", {})
        name = metadata.get("name", "")
        api_version = doc.get("apiVersion", "")

        if not kind or not name:
            return None

        resource_type = f"helm/{kind.lower()}"

        return {
            "id": f"{kind}/{name}",
            "type": resource_type,
            "provider": "kubernetes",
            "name": name,
            "attributes": {
                "apiVersion": api_version,
                "kind": kind,
                "metadata": metadata,
                "spec": doc.get("spec", {}),
                "data": doc.get("data"),
                "helm_template": template_name,
                "chart_name": chart_metadata.get("name", ""),
                "chart_version": chart_metadata.get("version", ""),
            },
            "location": {
                "file": f"templates/{template_name}",
                "line_start": 1,
                "line_end": 1,
            },
        }

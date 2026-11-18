"""Parse Docker Compose YAML into a normalized document."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from app.services.iac_app.domain.document import ParsedDocument
from app.services.iac_app.scanner.parsers.base import ParserAdapter

logger = logging.getLogger(__name__)

COMPOSE_NAMES = {
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
}


class DockerComposeParser(ParserAdapter):
    def supports(self, file: str) -> bool:
        path = Path(file)
        name = path.name.lower()
        if name in COMPOSE_NAMES:
            return True
        if name.startswith("docker-compose") and path.suffix.lower() in {".yml", ".yaml"}:
            return True
        return False

    def parse(self, file: str) -> ParsedDocument:
        path = Path(file)
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8", errors="ignore")) or {}
        except Exception as exc:
            return ParsedDocument(
                file_path=str(path),
                iac_type="docker_compose",
                raw={},
                errors=[f"Failed to parse Docker Compose file: {exc}"],
            )
        if not isinstance(data, dict):
            data = {}
        services = data.get("services") or {}
        if not isinstance(services, dict):
            services = {}
        raw = {
            "file_path": str(path),
            "iac_type": "docker_compose",
            "version": data.get("version"),
            "services": services,
            "networks": data.get("networks") or {},
            "volumes": data.get("volumes") or {},
            "secrets": data.get("secrets") or {},
        }
        return ParsedDocument(file_path=str(path), iac_type="docker_compose", raw=raw)

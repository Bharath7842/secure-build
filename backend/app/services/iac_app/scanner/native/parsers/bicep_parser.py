"""Lightweight Azure Bicep parser (resource extraction without az CLI)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from app.services.iac_app.domain.document import ParsedDocument
from app.services.iac_app.scanner.parsers.base import ParserAdapter

RESOURCE_RE = re.compile(
    r"resource\s+(\w+)\s+'([^']+)'\s*=\s*\{",
    re.MULTILINE,
)


class BicepParser(ParserAdapter):
    def supports(self, file: str) -> bool:
        return Path(file).suffix.lower() == ".bicep"

    def parse(self, file: str) -> ParsedDocument:
        path = Path(file)
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            return ParsedDocument(file_path=str(path), iac_type="bicep", raw={}, errors=[str(exc)])

        resources: dict[str, Any] = {}
        for match in RESOURCE_RE.finditer(text):
            name, type_ver = match.group(1), match.group(2)
            resource_type = type_ver.split("@", 1)[0]
            block = _extract_block(text, match.end() - 1)
            resources[name] = {
                "type": resource_type,
                "name": name,
                "api_version": type_ver.split("@", 1)[1] if "@" in type_ver else "",
                "properties": _simple_properties(block),
                "raw": block,
            }
        return ParsedDocument(
            file_path=str(path),
            iac_type="bicep",
            raw={"file_path": str(path), "iac_type": "bicep", "resources": resources},
        )


def _extract_block(text: str, start: int) -> str:
    depth = 0
    for index, char in enumerate(text[start:], start=start):
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    return text[start:]


def _simple_properties(block: str) -> dict[str, Any]:
    props: dict[str, Any] = {}
    for line in block.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip().rstrip(",").strip("'\"")
        if key and not key.startswith("//"):
            if value.lower() in {"true", "false"}:
                props[key] = value.lower() == "true"
            else:
                props[key] = value
    return props

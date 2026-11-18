"""gRPC/Protobuf parser.

Parses .proto files and gRPC service definitions for security scanning.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from app.services.iac_app.domain.document import ParsedDocument
from app.services.iac_app.scanner.parsers.base import ParserAdapter


class GRPCParser(ParserAdapter):
    """Parse gRPC/Protobuf definitions."""

    def supports(self, file: str) -> bool:
        return Path(file).suffix.lower() == ".proto"

    def parse(self, file: str) -> ParsedDocument:
        path = Path(file)
        try:
            content = path.read_text(encoding="utf-8")
            return ParsedDocument(
                file_path=str(path),
                iac_type="grpc",
                raw=self._parse_proto(content),
            )
        except Exception as exc:
            return ParsedDocument(
                file_path=str(path),
                iac_type="grpc",
                raw={},
                errors=[f"Failed to parse proto file: {exc}"],
            )

    def _parse_proto(self, content: str) -> dict[str, Any]:
        syntax = ""
        package = ""
        services = []
        messages = []
        enums = []
        imports = []

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            if line.startswith("syntax"):
                m = re.match(r'syntax\s*=\s*"([^"]+)"', line)
                if m:
                    syntax = m.group(1)
            elif line.startswith("package"):
                m = re.match(r'package\s+([^;]+);', line)
                if m:
                    package = m.group(1).strip()
            elif line.startswith("import"):
                m = re.match(r'import\s+(?:public\s+|weak\s+)?"([^"]+)"', line)
                if m:
                    imports.append(m.group(1))
            elif line.startswith("service"):
                m = re.match(r'service\s+(\w+)\s*\{', line)
                if m:
                    services.append({"name": m.group(1), "methods": []})
            elif line.startswith("message"):
                m = re.match(r'message\s+(\w+)\s*\{', line)
                if m:
                    messages.append({"name": m.group(1), "fields": []})
            elif line.startswith("enum"):
                m = re.match(r'enum\s+(\w+)\s*\{', line)
                if m:
                    enums.append({"name": m.group(1), "values": []})
            elif "rpc " in line:
                m = re.match(r'rpc\s+(\w+)\s*\(([^)]+)\)\s*returns\s*\(([^)]+)\)', line)
                if m and services:
                    services[-1]["methods"].append({
                        "name": m.group(1),
                        "input": m.group(2).strip(),
                        "output": m.group(3).strip(),
                    })

        return {
            "syntax": syntax,
            "package": package,
            "services": services,
            "messages": messages,
            "enums": enums,
            "imports": imports,
        }

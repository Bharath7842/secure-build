"""Dockerfile parser — converts Dockerfiles to ParsedDocument.

Supports multi-stage build tracking, ARG/ENV scoping, and .dockerignore.
"""

from __future__ import annotations

import fnmatch
import logging
import re
from pathlib import Path
from typing import Any

from app.services.iac_app.domain.document import ParsedDocument
from app.services.iac_app.scanner.parsers.base import ParserAdapter

logger = logging.getLogger(__name__)

try:
    from dockerfile_parse import DockerfileParser as _LibDockerfileParser

    HAS_DOCKERFILE_PARSE = True
except ImportError:
    HAS_DOCKERFILE_PARSE = False
    logger.debug("dockerfile-parse not installed; Dockerfile parsing uses the builtin parser")


class DockerfileParser(ParserAdapter):
    FILENAMES = ("Dockerfile", "Dockerfile.*", "*.dockerfile")

    def supports(self, file: str) -> bool:
        return self._is_dockerfile(Path(file))

    def parse(self, file: str) -> ParsedDocument:
        path = Path(file)
        raw = self.parse_file(path)
        if raw is None:
            return ParsedDocument(
                file_path=str(path),
                iac_type="docker",
                raw={},
                errors=[f"Failed to parse Dockerfile: {path}"],
            )
        return ParsedDocument(file_path=str(path), iac_type="docker", raw=raw)

    def parse_file(self, file_path: Path) -> dict[str, Any] | None:
        if not self._is_dockerfile(file_path):
            return None
        if HAS_DOCKERFILE_PARSE:
            parsed = self._parse_with_library(file_path)
            if parsed:
                return parsed
        return self._parse_basic(file_path)

    def _is_dockerfile(self, file_path: Path) -> bool:
        name = file_path.name.lower()
        if name == "dockerfile":
            return True
        if name.startswith("dockerfile."):
            return True
        if name.endswith(".dockerfile"):
            return True
        return False

    def _parse_with_library(self, file_path: Path) -> dict[str, Any] | None:
        try:
            with open(file_path, "r", encoding="utf-8") as handle:
                dfp = _LibDockerfileParser(fileobj=handle)
                instructions = dfp.structure
                base_image = dfp.baseimage
                labels = dfp.labels
                envs = dfp.envs

            parsed_instructions = []
            for inst in instructions:
                parsed_instructions.append(
                    {
                        "instruction": inst.get("instruction", "").upper(),
                        "value": inst.get("value", ""),
                        "startline": inst.get("startline"),
                        "endline": inst.get("endline"),
                    }
                )

            stages = self._build_stages(parsed_instructions)
            dockerignore = self._read_dockerignore(file_path)

            return {
                "file_path": str(file_path),
                "base_image": base_image,
                "labels": labels,
                "envs": envs,
                "instructions": parsed_instructions,
                "stages": stages,
                "final_stage": stages[-1] if stages else {},
                "exposed_ports": self._extract_exposed_ports(parsed_instructions),
                "volumes": self._extract_volumes(parsed_instructions),
                "user": self._extract_user(parsed_instructions),
                "healthcheck": self._extract_healthcheck(parsed_instructions),
                "workdir": self._extract_workdir(parsed_instructions),
                "has_secrets_in_env": self._has_secrets_in_env(parsed_instructions),
                "dockerignore": dockerignore,
                "arg_scoping": self._analyze_arg_scoping(parsed_instructions),
            }
        except Exception as exc:
            logger.debug("Dockerfile parse error in %s: %s", file_path, exc)
            return None

    def _parse_basic(self, file_path: Path) -> dict[str, Any] | None:
        try:
            content = file_path.read_text(encoding="utf-8")
            instructions = []
            for index, raw_line in enumerate(content.splitlines(), start=1):
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if len(parts) < 2:
                    continue
                instructions.append(
                    {
                        "instruction": parts[0].upper(),
                        "value": parts[1],
                        "startline": index,
                        "endline": index,
                    }
                )

            base_image = ""
            for inst in instructions:
                if inst["instruction"] == "FROM":
                    base_image = inst["value"].split(" AS ")[0].split(" as ")[0].strip()
                    break

            stages = self._build_stages(instructions)
            dockerignore = self._read_dockerignore(file_path)

            return {
                "file_path": str(file_path),
                "base_image": base_image,
                "labels": {},
                "envs": {},
                "instructions": instructions,
                "stages": stages,
                "final_stage": stages[-1] if stages else {},
                "exposed_ports": self._extract_exposed_ports(instructions),
                "volumes": self._extract_volumes(instructions),
                "user": self._extract_user(instructions),
                "healthcheck": self._extract_healthcheck(instructions),
                "workdir": self._extract_workdir(instructions),
                "has_secrets_in_env": self._has_secrets_in_env(instructions),
                "dockerignore": dockerignore,
                "arg_scoping": self._analyze_arg_scoping(instructions),
            }
        except Exception as exc:
            logger.debug("Basic Dockerfile parse error in %s: %s", file_path, exc)
            return None

    def _build_stages(self, instructions: list[dict]) -> list[dict[str, Any]]:
        stages = []
        current_stage: dict[str, Any] = {
            "name": "",
            "base_image": "",
            "alias": "",
            "instructions": [],
            "args": {},
            "envs": {},
            "user": "",
            "workdir": "",
            "has_user": False,
            "line_start": 0,
        }

        for inst in instructions:
            if inst["instruction"] == "FROM":
                if current_stage["base_image"]:
                    stages.append(current_stage)
                value = inst["value"]
                parts = re.split(r"\s+[Aa][Ss]\s+", value, maxsplit=1)
                base = parts[0].strip()
                alias = parts[1].strip() if len(parts) > 1 else ""
                current_stage = {
                    "name": alias or base.split("/")[-1].split(":")[0],
                    "base_image": base,
                    "alias": alias,
                    "instructions": [],
                    "args": {},
                    "envs": {},
                    "user": "",
                    "workdir": "",
                    "has_user": False,
                    "line_start": inst.get("startline", 0),
                }
            elif inst["instruction"] == "ARG":
                key, _, val = inst["value"].partition("=")
                key = key.strip()
                if "=" in inst["value"]:
                    current_stage["args"][key] = val.strip()
            elif inst["instruction"] == "ENV":
                key, _, val = inst["value"].partition("=")
                key = key.strip()
                current_stage["envs"][key] = val.strip()
            elif inst["instruction"] == "USER":
                current_stage["user"] = inst["value"].strip()
                current_stage["has_user"] = True
            elif inst["instruction"] == "WORKDIR":
                current_stage["workdir"] = inst["value"].strip()
            current_stage["instructions"].append(inst)

        if current_stage["base_image"]:
            stages.append(current_stage)

        return stages

    def _analyze_arg_scoping(self, instructions: list[dict]) -> dict[str, Any]:
        global_args = {}
        stage_args: list[dict[str, dict[str, str]]] = []
        current_stage_args: dict[str, str] = {}
        in_stage = False

        for inst in instructions:
            if inst["instruction"] == "FROM":
                if in_stage:
                    stage_args.append(dict(current_stage_args))
                in_stage = True
                current_stage_args = {}
            elif inst["instruction"] == "ARG":
                key, _, val = inst["value"].partition("=")
                key = key.strip()
                if "=" in inst["value"]:
                    if not in_stage:
                        global_args[key] = val.strip()
                    else:
                        current_stage_args[key] = val.strip()

        if in_stage:
            stage_args.append(dict(current_stage_args))

        return {
            "global_args": global_args,
            "per_stage_args": stage_args,
        }

    def _read_dockerignore(self, dockerfile_path: Path) -> list[str]:
        dockerignore_path = dockerfile_path.parent / ".dockerignore"
        if not dockerignore_path.exists():
            return []
        try:
            content = dockerignore_path.read_text(encoding="utf-8")
            patterns = []
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    patterns.append(line)
            return patterns
        except (OSError, UnicodeDecodeError):
            return []

    def _extract_exposed_ports(self, instructions: list[dict]) -> list[str]:
        ports = []
        for inst in instructions:
            if inst["instruction"] == "EXPOSE":
                for part in inst["value"].split():
                    port = part.split("/")[0]
                    if port.isdigit():
                        ports.append(port)
        return ports

    def _extract_volumes(self, instructions: list[dict]) -> list[str]:
        volumes = []
        for inst in instructions:
            if inst["instruction"] == "VOLUME":
                for vol in inst["value"].split():
                    volumes.append(vol.strip('"').strip("'"))
        return volumes

    def _extract_user(self, instructions: list[dict]) -> str:
        for inst in reversed(instructions):
            if inst["instruction"] == "USER":
                return inst["value"].strip()
        return ""

    def _extract_healthcheck(self, instructions: list[dict]) -> dict | None:
        for inst in instructions:
            if inst["instruction"] == "HEALTHCHECK":
                if "NONE" in inst["value"].upper():
                    return None
                return {"command": inst["value"]}
        return None

    def _extract_workdir(self, instructions: list[dict]) -> str:
        for inst in reversed(instructions):
            if inst["instruction"] == "WORKDIR":
                return inst["value"].strip()
        return ""

    def _has_secrets_in_env(self, instructions: list[dict]) -> bool:
        secret_patterns = re.compile(
            r"(password|secret|token|api_key|apikey|access_key|private_key)\s*=",
            re.IGNORECASE,
        )
        for inst in instructions:
            if inst["instruction"] in ("ENV", "ARG"):
                if secret_patterns.search(inst["value"]):
                    return True
        return False


NativeDockerfileParser = DockerfileParser

"""Julia collector — static parsing of ``Manifest.toml`` and ``Project.toml``.

Static only: no ``Pkg`` invocation, no registry network access.
"""

import re
from pathlib import Path

from .base import DependencyCollector, link_dependencies, rel_posix


# Manifest.toml v1.2:  [[deps.Name]]
_MANIFEST_V1 = re.compile(r"\[\[deps\.(?P<name>[^\]]+)\]\]")
# Manifest.toml v2 / Project.toml:  [deps.Name]  or  [deps]
_SECTION = re.compile(r"^\s*\[(?P<section>[^\]]+)\]\s*$", re.M)
_VERSION_LINE = re.compile(r'^\s*version\s*=\s*"(?P<version>[^"]+)"', re.M)
_DEPS_TABLE = re.compile(r"^\s*\[deps\]\s*$", re.M)
_DEP_LINE = re.compile(r'^\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"(?P<uuid>[^"]+)"', re.M)
# A package's own dependency list:  deps = ["Dates", "Parsers"]
_DEP_LIST = re.compile(r'^\s*deps\s*=\s*\[(?P<body>[^\]]*)\]', re.M)


class JuliaCollector(DependencyCollector):

    def supported_files(self) -> list[str]:
        return ["Manifest.toml", "Project.toml"]

    def collect(self, project_path: Path) -> list[dict]:
        components: list[dict] = []
        seen: set[str] = set()

        # Names the project itself declares in Project.toml [deps] (§5.4).
        declared: set[str] = set()
        for project in sorted(project_path.rglob("Project.toml")):
            for comp in self._parse_project(project, project_path):
                declared.add(comp["name"])

        # Lockfile-equivalent wins: Manifest pins exact versions (§5.3).
        for manifest in sorted(project_path.rglob("Manifest.toml")):
            for comp in self._parse_manifest(manifest, project_path):
                if comp["name"] in seen:
                    continue
                seen.add(comp["name"])
                components.append(comp)

        for project in sorted(project_path.rglob("Project.toml")):
            for comp in self._parse_project(project, project_path):
                if comp["name"] in seen:
                    continue
                seen.add(comp["name"])
                components.append(comp)

        # The Manifest contains the whole graph; only Project.toml names are
        # *direct* dependencies of the project.
        if declared:
            for comp in components:
                if comp.get("source_file", "").endswith("Manifest.toml"):
                    comp["direct"] = comp["name"] in declared

        link_dependencies(components)
        return components

    def _parse_manifest(self, manifest_path: Path, root_path: Path) -> list[dict]:
        try:
            content = manifest_path.read_text(encoding="utf-8-sig")
        except OSError:
            return []

        results: list[dict] = []
        rel = rel_posix(manifest_path, root_path)

        for match in _MANIFEST_V1.finditer(content):
            # Take the slice up to the next package header for uuid/version.
            tail = content[match.end():]
            nxt = _MANIFEST_V1.search(tail)
            segment = tail[: nxt.start()] if nxt else tail
            results.append(self._build(match.group("name"), segment, rel, is_dep=True))

        if results:
            return results

        # Manifest v2 style: [deps.Name] sections with uuid/version lines.
        sections = list(_SECTION.finditer(content))
        for idx, sec in enumerate(sections):
            section_name = sec.group("section")
            if not section_name.startswith("deps."):
                continue
            start = sec.end()
            end = sections[idx + 1].start() if idx + 1 < len(sections) else len(content)
            segment = content[start:end]
            results.append(self._build(section_name[len("deps."):], segment, rel, is_dep=True))

        return results

    def _parse_project(self, project_path: Path, root_path: Path) -> list[dict]:
        try:
            content = project_path.read_text(encoding="utf-8-sig")
        except OSError:
            return []

        rel = rel_posix(project_path, root_path)
        results: list[dict] = []

        deps_match = _DEPS_TABLE.search(content)
        if deps_match:
            tail = content[deps_match.end():]
            next_section = _SECTION.search(tail)
            block = tail[: next_section.start()] if next_section else tail
            for line in _DEP_LINE.finditer(block):
                name = line.group("name")
                if name in ("name", "uuid", "version"):
                    continue
                results.append({
                    "name": name,
                    "group": "",
                    "version": "",
                    "ecosystem": "julia",
                    "scope": "runtime",
                    "direct": True,
                    "source_file": rel,
                    "hashes": [],
                    "depends_on": [],
                    "registry_url": f"https://github.com/JuliaRegistries/General/tree/master/{name}",
                })
        return results

    def _build(self, name: str, segment: str, rel: str, *, is_dep: bool) -> dict:
        version = _VERSION_LINE.search(segment)
        dep_list = _DEP_LIST.search(segment)
        dep_names = re.findall(r'"([^"]+)"', dep_list.group("body")) if dep_list else []
        return {
            "name": name,
            "group": "",
            "version": version.group("version") if version else "",
            "ecosystem": "julia",
            "scope": "runtime",
            "direct": is_dep,
            "source_file": rel,
            "hashes": [],
            "depends_on": [],
            "_dep_names": [n for n in dep_names if n != name],
            "registry_url": f"https://github.com/JuliaRegistries/General/tree/master/{name}",
        }

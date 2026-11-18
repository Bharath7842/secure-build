"""Clojure collector — static parsing of ``deps.edn`` and ``project.clj``.

Static only: no ``clojure -P``/``lein`` invocation and no lockfile exists for
these tools, so the evidence is declared direct dependencies only (§5).
``:local/root`` coordinates point at project code and are never recorded.
"""

import re
from pathlib import Path

from .base import DependencyCollector, path_ignored, read_text_safe, rel_posix

_MVN_COORD = re.compile(
    r'(?P<coord>[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+)\s+\{:mvn/version\s+"(?P<version>[^"]+)"'
)
# A git coordinate's keys live inside one map — usually across several lines:
# io.github.example/widget {:git/tag "v1.2.0"
#                           :git/sha "abc1234"
#                           :git/url "https://…"}
_GIT_BLOCK = re.compile(
    r'(?P<coord>[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+)\s+\{(?P<body>[^}]*)\}'
)
_GIT_KEY = re.compile(r':git/(?P<key>tag|sha|url|branch)\s+"(?P<value>[^"]+)"')
_LEIN_DEP = re.compile(
    r'\[\s*"?(?P<coord>[A-Za-z0-9_.\-]+(?:/[A-Za-z0-9_.\-]+)?)"?\s+"(?P<version>[^"]+)"'
)


def _brace_blocks(text: str, key: str) -> list[tuple[int, int]]:
    """Spans of ``key {…}`` blocks with balanced braces."""
    spans: list[tuple[int, int]] = []
    for match in re.finditer(re.escape(key) + r"\s*\{", text):
        depth = 0
        for i in range(match.end() - 1, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    spans.append((match.start(), i + 1))
                    break
    return spans


def _vector_blocks(text: str, key: str) -> list[tuple[int, int]]:
    """Spans of ``key […]`` blocks with balanced brackets."""
    spans: list[tuple[int, int]] = []
    for match in re.finditer(re.escape(key) + r"\s*\[", text):
        depth = 0
        for i in range(match.end() - 1, len(text)):
            if text[i] == "[":
                depth += 1
            elif text[i] == "]":
                depth -= 1
                if depth == 0:
                    spans.append((match.start(), i + 1))
                    break
    return spans


class ClojureCollector(DependencyCollector):

    def supported_files(self) -> list[str]:
        return ["deps.edn", "project.clj"]

    def collect(self, project_path: Path) -> list[dict]:
        components: list[dict] = []
        seen: set[str] = set()

        for path in sorted(project_path.rglob("deps.edn")):
            if path_ignored(path.relative_to(project_path)):
                continue
            for comp in self._parse_deps_edn(path, project_path):
                if comp["name"] in seen:
                    continue
                seen.add(comp["name"])
                components.append(comp)

        for path in sorted(project_path.rglob("project.clj")):
            if path_ignored(path.relative_to(project_path)):
                continue
            for comp in self._parse_project_clj(path, project_path):
                if comp["name"] in seen:
                    continue
                seen.add(comp["name"])
                components.append(comp)

        return components

    def _parse_deps_edn(self, path: Path, root_path: Path) -> list[dict]:
        try:
            content = read_text_safe(path)
        except (OSError, UnicodeDecodeError):
            return []
        source = rel_posix(path, root_path)
        dev_spans = _brace_blocks(content, ":extra-deps")

        def scope_at(pos: int) -> str:
            return "dev" if any(start <= pos < end for start, end in dev_spans) else "compile"

        git_info: dict[str, dict[str, str]] = {}
        for match in _GIT_BLOCK.finditer(content):
            info = {m.group("key"): m.group("value")
                    for m in _GIT_KEY.finditer(match.group("body"))}
            if info:
                git_info.setdefault(match.group("coord"), {}).update(info)

        results: list[dict] = []
        recorded: set[str] = set()

        for match in _MVN_COORD.finditer(content):
            coord = match.group("coord")
            if coord in recorded:
                continue
            recorded.add(coord)
            results.append(self._component(
                coord, match.group("version"), scope_at(match.start()), source,
                git_url=git_info.get(coord, {}).get("url", ""),
            ))

        for coord, info in git_info.items():
            if coord in recorded:
                continue
            version = info.get("tag") or info.get("sha") or ""
            if not version:
                continue
            recorded.add(coord)
            results.append(self._component(
                coord, version, "compile", source, git_url=info.get("url", ""),
            ))
        return results

    def _parse_project_clj(self, path: Path, root_path: Path) -> list[dict]:
        try:
            content = read_text_safe(path)
        except (OSError, UnicodeDecodeError):
            return []
        source = rel_posix(path, root_path)
        profiles_at = content.find(":profiles")
        results: list[dict] = []
        seen: set[str] = set()
        for start, end in _vector_blocks(content, ":dependencies"):
            scope = "dev" if profiles_at != -1 and start > profiles_at else "compile"
            for match in _LEIN_DEP.finditer(content[start:end]):
                coord = match.group("coord")
                if coord in seen:
                    continue
                seen.add(coord)
                results.append(self._component(
                    coord, match.group("version"), scope, source,
                ))
        return results

    @staticmethod
    def _component(coord: str, version: str, scope: str, source: str,
                   *, git_url: str = "") -> dict:
        group, sep, name = coord.partition("/")
        if not sep:
            # Leiningen allows a bare artifact name; no group is invented (§4).
            name, group = group, ""
        return {
            "name": name,
            "group": group,
            "version": version,
            "ecosystem": "clojure",
            "scope": scope,
            "direct": True,
            "source_file": source,
            "hashes": [],
            "depends_on": [],
            "registry_url": git_url or (
                f"https://central.sonatype.com/artifact/{group}/{name}/{version}"
                if group else ""
            ),
        }

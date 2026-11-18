"""Elixir / Hex collector — static parsing of ``mix.exs`` and ``mix.lock``.

Static only: no ``mix deps.get`` invocation, no network access.
"""

import re
from pathlib import Path

from .base import DependencyCollector, link_dependencies, rel_posix


_DEP_LINE = re.compile(
    r"""\{\s*:(?P<name>[a-zA-Z0-9_]+)\s*,\s*"""
    r"""(?:"(?P<req>[^"]+)"|github:\s*"(?P<github>[^"]+)"|git:\s*"(?P<git>[^"]+)")""",
)
_LOCK_ENTRY = re.compile(
    r"""["'](?P<name>[a-zA-Z0-9_]+)["']\s*:\s*\{:hex,\s*:?(?P<pkg>[a-zA-Z0-9_]+),\s*"""
    r"""["'](?P<version>[^"']+)["']""",
)
# A dependency tuple inside a lock entry: {:name, "requirement", [hex: ...]}
# or {:name, git: "...", ...}. The entry header ({:hex, :pkg, "ver") is never
# inside the searched segment, so it cannot match.
_LOCK_DEP = re.compile(
    r"""\{:(?P<name>[a-zA-Z0-9_]+)\s*,\s*(?:"|git\s*:|github\s*:|path\s*:)"""
)


class HexCollector(DependencyCollector):

    def supported_files(self) -> list[str]:
        return ["mix.exs", "mix.lock"]

    def collect(self, project_path: Path) -> list[dict]:
        components: list[dict] = []
        seen: set[str] = set()

        # Lockfile wins (§5.3): exact resolved versions before manifest ranges.
        for lock in sorted(project_path.rglob("mix.lock")):
            for comp in self._parse_lock(lock, project_path):
                if comp["name"] in seen:
                    continue
                seen.add(comp["name"])
                components.append(comp)

        manifest_names: set[str] = set()
        for manifest in sorted(project_path.rglob("mix.exs")):
            for comp in self._parse_manifest(manifest, project_path):
                manifest_names.add(comp["name"])
                if comp["name"] in seen:
                    continue
                seen.add(comp["name"])
                components.append(comp)

        # mix.lock pins the whole graph; only packages declared in mix.exs are
        # *direct* dependencies (§5.4).
        if manifest_names:
            for comp in components:
                if comp.get("source_file", "").endswith("mix.lock"):
                    comp["direct"] = comp["name"] in manifest_names

        link_dependencies(components)
        return components

    def _parse_lock(self, lock_path: Path, root_path: Path) -> list[dict]:
        try:
            content = lock_path.read_text(encoding="utf-8-sig")
        except OSError:
            return []

        results = []
        matches = list(_LOCK_ENTRY.finditer(content))
        for index, match in enumerate(matches):
            name = match.group("pkg")
            segment = content[match.end(): matches[index + 1].start()
                              if index + 1 < len(matches) else len(content)]
            dep_names = [dep.group("name") for dep in _LOCK_DEP.finditer(segment)]
            results.append({
                "name": name,
                "group": "hexpm",
                "version": match.group("version"),
                "ecosystem": "hex",
                "scope": "runtime",
                "direct": True,
                "source_file": rel_posix(lock_path, root_path),
                "hashes": [],
                "depends_on": [],
                "_dep_names": [d for d in dep_names if d != name],
                "registry_url": f"https://hex.pm/packages/{name}",
            })
        return results

    def _parse_manifest(self, manifest_path: Path, root_path: Path) -> list[dict]:
        try:
            content = manifest_path.read_text(encoding="utf-8-sig")
        except OSError:
            return []

        # Only inspect the deps block when one exists to avoid config noise.
        deps_block = content
        block = re.search(r"defp?\s+deps\s+do(.*?)\n\s*end", content, re.S)
        if block:
            deps_block = block.group(1)

        results = []
        for match in _DEP_LINE.finditer(deps_block):
            name = match.group("name")
            requirement = match.group("req") or match.group("github") or match.group("git") or ""
            version = requirement
            results.append({
                "name": name,
                "group": "hexpm",
                "version": version,
                "ecosystem": "hex",
                "scope": "runtime",
                "direct": True,
                "source_file": rel_posix(manifest_path, root_path),
                "hashes": [],
                "depends_on": [],
                "registry_url": f"https://hex.pm/packages/{name}",
            })
        return results

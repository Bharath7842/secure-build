"""Perl collector — static parsing of ``cpanfile.snapshot``, ``cpanfile``
and ``META.json``.

Static only: no ``cpanm``/``carton`` invocation. The snapshot pins the
installed graph (with dist->dist requirement edges); the cpanfile declares
which pins are direct and their phase scope (§5).
"""

import json
import re
from pathlib import Path

from .base import (
    DependencyCollector,
    link_dependencies,
    path_ignored,
    read_text_safe,
    rel_posix,
)

_DIST_ID = re.compile(r"^(?P<name>.+)-(?P<version>\d[\d.]*)$")
_CPANFILE_REQ = re.compile(
    r"\b(?P<verb>requires|recommends|suggests)\s+'(?P<name>[^']+)'"
    r"(?:\s*=>\s*'(?P<version>[^']*)')?"
)
_CPANFILE_ON = re.compile(r"\bon\s+'(?P<phase>[^']+)'")

_SCOPE_ORDER = {"compile": 0, "dev": 1}


def _dist_split(dist_id: str) -> tuple[str, str] | None:
    match = _DIST_ID.match(dist_id)
    if not match:
        return None
    return match.group("name"), match.group("version")


def _scope_for(phase: str) -> str:
    return "dev" if phase in ("test", "develop") else "compile"


def _record(declared: dict[str, dict], name: str, scope: str,
            version: str = "") -> None:
    """Declare ``name``; compile outranks dev, first version wins."""
    entry = declared.get(name)
    if entry is None:
        declared[name] = {"scope": scope, "version": version}
        return
    if _SCOPE_ORDER[scope] < _SCOPE_ORDER[entry["scope"]]:
        entry["scope"] = scope
    if not entry["version"] and version:
        entry["version"] = version


class PerlCollector(DependencyCollector):

    def supported_files(self) -> list[str]:
        return ["cpanfile", "cpanfile.snapshot", "META.json"]

    def collect(self, project_path: Path) -> list[dict]:
        declared: dict[str, dict] = {}
        source = ""
        for cpanfile in sorted(project_path.rglob("cpanfile")):
            if path_ignored(cpanfile.relative_to(project_path)):
                continue
            parsed = self._parse_cpanfile(cpanfile)
            if parsed and not source:
                source = "cpanfile"
            for name, entry in parsed.items():
                _record(declared, name, entry["scope"], entry["version"])
        if not declared:
            for meta in sorted(project_path.rglob("META.json")):
                if path_ignored(meta.relative_to(project_path)):
                    continue
                parsed = self._parse_meta(meta)
                if parsed and not source:
                    source = "META.json"
                for name, entry in parsed.items():
                    _record(declared, name, entry["scope"], entry["version"])

        components: list[dict] = []
        provides: dict[str, list[str]] = {}
        for snapshot in sorted(project_path.rglob("cpanfile.snapshot")):
            if path_ignored(snapshot.relative_to(project_path)):
                continue
            snap_comps, snap_provides = self._parse_snapshot(snapshot, project_path)
            components.extend(snap_comps)
            provides.update(snap_provides)

        if components:
            # Requirement entries may be dist ids or module names (the
            # snapshot's `provides` maps them back to their dist); link only
            # identities that resolve to a collected dist (§13).
            dist_names = {c["name"] for c in components}
            module_dist: dict[str, str] = {}
            for dist, modules in provides.items():
                for module in modules:
                    module_dist.setdefault(module, dist)
            for comp in components:
                resolved: list[str] = []
                for dep in comp.pop("_dep_names", []) or []:
                    if not isinstance(dep, str):
                        continue
                    dist = dep if dep in dist_names else module_dist.get(dep)
                    if dist and dist != comp["name"] and dist not in resolved:
                        resolved.append(dist)
                comp["_dep_names"] = resolved

            for comp in components:
                # cpanfile/META declare module names; the snapshot indexes its
                # dists by the modules each dist provides.
                entry = declared.get(comp["name"])
                if entry is None:
                    for module in provides.get(comp["name"], []):
                        entry = declared.get(module)
                        if entry is not None:
                            break
                comp["direct"] = entry is not None
                comp["scope"] = entry["scope"] if entry else "compile"
            link_dependencies(components)
            return components

        # No snapshot: the declared set itself is the direct-only evidence (§5),
        # carrying the raw version constraints from the manifest.
        for name, entry in declared.items():
            components.append(self._component(
                name, entry["version"], source or "cpanfile", entry["scope"],
                registry=f"https://metacpan.org/pod/{name}",
            ))
        return components

    @staticmethod
    def _component(name: str, version: str, source: str, scope: str,
                   *, registry: str = "") -> dict:
        return {
            "name": name,
            "group": "",
            "version": version,
            "ecosystem": "perl",
            "scope": scope,
            "direct": True,
            "source_file": source,
            "hashes": [],
            "depends_on": [],
            "registry_url": registry or f"https://metacpan.org/dist/{name}",
        }

    def _parse_cpanfile(self, path: Path) -> dict[str, dict]:
        try:
            content = read_text_safe(path)
        except (OSError, UnicodeDecodeError):
            return {}
        declared: dict[str, dict] = {}
        phase = "runtime"
        for line in content.splitlines():
            block = _CPANFILE_ON.search(line)
            if block:
                phase = block.group("phase")
            end = line.find("};")
            scan = line if end == -1 else line[:end]
            match = _CPANFILE_REQ.search(scan)
            if match and match.group("name") != "perl":
                _record(declared, match.group("name"), _scope_for(phase),
                        match.group("version") or "")
            if end != -1:
                phase = "runtime"
        return declared

    def _parse_meta(self, path: Path) -> dict[str, dict]:
        try:
            data = json.loads(read_text_safe(path))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return {}
        if not isinstance(data, dict):
            return {}
        declared: dict[str, dict] = {}
        prereqs = data.get("prereqs")
        if isinstance(prereqs, dict):
            for phase, kinds in prereqs.items():
                if not isinstance(kinds, dict):
                    continue
                requires = kinds.get("requires")
                if not isinstance(requires, dict):
                    continue
                for name, version in requires.items():
                    if isinstance(name, str) and name != "perl":
                        _record(declared, name, _scope_for(str(phase)),
                                version if isinstance(version, str) else "")
        return declared

    def _parse_snapshot(
        self, path: Path, root_path: Path
    ) -> tuple[list[dict], dict[str, list[str]]]:
        try:
            content = read_text_safe(path)
        except (OSError, UnicodeDecodeError):
            return [], {}
        source = rel_posix(path, root_path)
        results: list[dict] = []
        provides: dict[str, list[str]] = {}
        current: dict | None = None
        section = ""

        for raw in content.splitlines():
            if not raw.strip() or raw.lstrip().startswith("#"):
                continue
            if not raw.startswith(" "):
                section = ""
                current = None
                continue
            indent = len(raw) - len(raw.lstrip())
            body = raw.strip()
            if indent == 2:
                split = _dist_split(body)
                current = None
                section = ""
                if split:
                    current = {"name": split[0], "version": split[1],
                               "requires": [], "provides": []}
                    comp = self._component(split[0], split[1], source, "compile")
                    comp["direct"] = False
                    comp["_dep_names"] = current["requires"]
                    results.append(comp)
                    provides.setdefault(split[0], [])
            elif indent == 4 and body.endswith(":"):
                section = body[:-1]
            elif indent >= 6 and current:
                parts = body.split()
                if section == "requirements":
                    child = parts[0] if parts else ""
                    if child and child != "perl" and child != current["name"]:
                        current["requires"].append(child)
                elif section == "provides" and parts:
                    provides[current["name"]].append(parts[0])
        return results, provides

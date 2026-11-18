"""Haskell collector — static parsing of ``cabal.project.freeze``,
``stack.yaml.lock``, ``*.cabal`` and ``package.yaml``.

Static only: no ``cabal``/``stack`` invocation. The freeze/lock files pin the
resolved set flat (no package-to-package edges); the cabal/hpack manifests
declare which pins are direct and their scope (§5).
"""

import re
from pathlib import Path

from .base import DependencyCollector, path_ignored, read_text_safe, rel_posix

try:
    import yaml
except ImportError:  # pragma: no cover - exercised only without PyYAML
    yaml = None

_FREEZE_CONSTRAINT = re.compile(
    r"^(?:any\.)?(?P<name>[A-Za-z][A-Za-z0-9'-]*)\s+==(?P<version>\d[\d.]*)"
)
_HACKAGE_ID = re.compile(r"^(?P<name>.+)-(?P<version>\d[\d.]*)$")
_NAME_ONLY = re.compile(r"^[A-Za-z][A-Za-z0-9-]*$")
_FIELD_LINE = re.compile(r"^[A-Za-z][A-Za-z0-9-]*\s*:")
_CONDITION_LINE = re.compile(r"^(if|else|elif|when|condition)\b")
_STANZA_HEAD = re.compile(r"^(library|executable|test-suite|benchmark|common|flag)\b")


def _requirement_name(entry) -> str:
    """Package name from a cabal/hpack requirement string."""
    if not isinstance(entry, str):
        return ""
    token = entry.split()[0] if entry.split() else ""
    return token if _NAME_ONLY.match(token) else ""


def _split_requirement(entry: str) -> tuple[str, str]:
    """``base >=4.14 && <5`` -> (``base``, ``>=4.14 && <5``)."""
    parts = entry.split(None, 1)
    if not parts:
        return "", ""
    return parts[0], parts[1] if len(parts) > 1 else ""


class HaskellCollector(DependencyCollector):

    def supported_files(self) -> list[str]:
        return ["cabal.project.freeze", "stack.yaml.lock", "*.cabal", "package.yaml"]

    def collect(self, project_path: Path) -> list[dict]:
        declared: dict[str, str] = {}
        declared_version: dict[str, str] = {}
        declared_source: dict[str, str] = {}
        manifests = sorted(set(project_path.rglob("*.cabal"))
                           | set(project_path.rglob("package.yaml")))
        for path in manifests:
            rel = path.relative_to(project_path)
            if path_ignored(rel):
                continue
            if path.suffix == ".cabal":
                entries = self._parse_cabal(path)
            else:
                entries = self._parse_package_yaml(path)
            source = rel_posix(path, project_path)
            for name, scope, version in entries:
                if name in declared and scope != "compile":
                    continue
                declared[name] = scope
                declared_version.setdefault(name, version)
                declared_source.setdefault(name, source)

        lock_comps = self._parse_freeze(project_path)
        if not lock_comps:
            lock_comps = self._parse_stack_lock(project_path)

        if lock_comps:
            for comp in lock_comps:
                scope = declared.get(comp["name"])
                comp["direct"] = scope is not None
                comp["scope"] = scope or "compile"
            return lock_comps

        # No freeze/lock evidence: declared constraints are direct-only (§5).
        components = []
        for name, scope in declared.items():
            components.append(self._component(
                name, declared_version.get(name, ""),
                declared_source.get(name, "cabal"), scope, direct=True,
            ))
        return components

    @staticmethod
    def _component(name: str, version: str, source: str, scope: str,
                   *, direct: bool) -> dict:
        # A fallback component can carry a raw constraint (">=4.14 && <5");
        # only a plain pinned version belongs in the hackage release URL.
        registry = (
            f"https://hackage.haskell.org/package/{name}-{version}"
            if re.fullmatch(r"\d[\d.]*", version)
            else f"https://hackage.haskell.org/package/{name}"
        )
        return {
            "name": name,
            "group": "",
            "version": version,
            "ecosystem": "haskell",
            "scope": scope,
            "direct": direct,
            "source_file": source,
            "hashes": [],
            "depends_on": [],
            "registry_url": registry,
        }

    def _parse_freeze(self, project_path: Path) -> list[dict]:
        components: list[dict] = []
        seen: set[str] = set()
        for path in sorted(project_path.rglob("cabal.project.freeze")):
            if path_ignored(path.relative_to(project_path)):
                continue
            try:
                content = read_text_safe(path)
            except (OSError, UnicodeDecodeError):
                continue
            source = rel_posix(path, project_path)
            for chunk in content.split(","):
                piece = chunk.strip()
                if piece.startswith("constraints:"):
                    piece = piece[len("constraints:"):].strip()
                match = _FREEZE_CONSTRAINT.match(piece)
                if not match or match.group("name") in seen:
                    continue
                seen.add(match.group("name"))
                components.append(self._component(
                    match.group("name"), match.group("version"),
                    source, "compile", direct=False,
                ))
        return components

    def _parse_stack_lock(self, project_path: Path) -> list[dict]:
        if yaml is None:
            return []
        components: list[dict] = []
        seen: set[str] = set()
        for path in sorted(project_path.rglob("stack.yaml.lock")):
            if path_ignored(path.relative_to(project_path)):
                continue
            try:
                data = yaml.safe_load(read_text_safe(path))
            except (OSError, UnicodeDecodeError, yaml.YAMLError):
                continue
            if not isinstance(data, dict):
                continue
            source = rel_posix(path, project_path)
            packages = data.get("packages")
            if not isinstance(packages, list):
                continue
            for pkg in packages:
                if not isinstance(pkg, dict):
                    continue
                hackage = None
                for key in ("completed", "original"):
                    block = pkg.get(key)
                    if isinstance(block, dict) and isinstance(block.get("hackage"), str):
                        hackage = block["hackage"]
                        break
                if not hackage:
                    continue
                split = _HACKAGE_ID.match(hackage.split("@", 1)[0])
                if not split or split.group("name") in seen:
                    continue
                seen.add(split.group("name"))
                components.append(self._component(
                    split.group("name"), split.group("version"),
                    source, "compile", direct=False,
                ))
        return components

    def _parse_cabal(self, path: Path) -> list[tuple[str, str, str]]:
        """``(name, scope, raw version)`` from every build-depends field."""
        try:
            content = read_text_safe(path)
        except (OSError, UnicodeDecodeError):
            return []
        entries: list[tuple[str, str, str]] = []
        stanza = "library"
        in_deps = False

        for raw in content.splitlines():
            line = raw.rstrip()
            stripped = line.strip()
            if not stripped or stripped.startswith("--"):
                in_deps = False
                continue
            if line and not line[0].isspace():
                in_deps = False
                head = stripped.split(":", 1)[0].split()[0]
                if _STANZA_HEAD.match(stripped):
                    stanza = head
                    continue
                if stripped.lower().startswith("build-depends"):
                    in_deps = True
                    _, _, rest = stripped.partition(":")
                    entries.extend(self._cabal_items(rest, stanza))
                continue
            if not in_deps:
                if stripped.lower().startswith("build-depends"):
                    in_deps = True
                    _, _, rest = stripped.partition(":")
                    entries.extend(self._cabal_items(rest, stanza))
                continue
            if (_FIELD_LINE.match(stripped) or _CONDITION_LINE.match(stripped)
                    or stripped.startswith("[")):
                in_deps = False
                if stripped.lower().startswith("build-depends"):
                    in_deps = True
                    _, _, rest = stripped.partition(":")
                    entries.extend(self._cabal_items(rest, stanza))
                continue
            entries.extend(self._cabal_items(stripped, stanza))
        return entries

    @staticmethod
    def _cabal_items(body: str, stanza: str) -> list[tuple[str, str, str]]:
        scope = "dev" if stanza in ("test-suite", "benchmark") else "compile"
        results = []
        for item in body.split(","):
            name, version = _split_requirement(item.strip())
            if _NAME_ONLY.match(name):
                results.append((name, scope, version))
        return results

    def _parse_package_yaml(self, path: Path) -> list[tuple[str, str, str]]:
        if yaml is None:
            return []
        try:
            data = yaml.safe_load(read_text_safe(path))
        except (OSError, UnicodeDecodeError, yaml.YAMLError):
            return []
        if not isinstance(data, dict):
            return []
        entries: list[tuple[str, str, str]] = []

        def add(items, scope: str) -> None:
            for item in items or []:
                raw = _requirement_name(item)
                if not raw:
                    continue
                _, _, version = _split_requirement(str(item))
                entries.append((raw, scope, version))

        add(data.get("dependencies"), "compile")
        for test in data.get("tests") or []:
            if isinstance(test, dict):
                add(test.get("dependencies"), "dev")
        for bench in data.get("benchmarks") or []:
            if isinstance(bench, dict):
                add(bench.get("dependencies"), "dev")
        return entries

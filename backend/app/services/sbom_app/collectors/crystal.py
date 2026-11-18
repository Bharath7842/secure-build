"""Crystal collector — static parsing of ``shard.lock`` and ``shard.yml``.

Static only: no ``shards install`` invocation. ``shard.lock`` pins the graph
flat (no inter-shard edges), so the project-root edge is synthesized
downstream (§9); ``shard.yml`` declares which pins are direct (§5).
"""

from pathlib import Path

from .base import DependencyCollector, path_ignored, read_text_safe, rel_posix

try:
    import yaml
except ImportError:  # pragma: no cover - exercised only without PyYAML
    yaml = None


def _declared(path: Path) -> dict[str, str]:
    """Shard name -> scope from shard.yml (development_dependencies are dev)."""
    if yaml is None:
        return {}
    try:
        data = yaml.load(read_text_safe(path), Loader=yaml.BaseLoader)
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        return {}
    if not isinstance(data, dict):
        return {}
    declared: dict[str, str] = {}
    for field, scope in (("dependencies", "compile"),
                         ("development_dependencies", "dev")):
        section = data.get(field)
        if isinstance(section, dict):
            for name in section:
                if isinstance(name, str):
                    declared.setdefault(name, scope)
    return declared


class CrystalCollector(DependencyCollector):

    def supported_files(self) -> list[str]:
        return ["shard.lock", "shard.yml"]

    def collect(self, project_path: Path) -> list[dict]:
        if yaml is None:
            return []
        declared: dict[str, str] = {}
        for shardfile in sorted(project_path.rglob("shard.yml")):
            if path_ignored(shardfile.relative_to(project_path)):
                continue
            for name, scope in _declared(shardfile).items():
                declared.setdefault(name, scope)

        components: list[dict] = []
        seen: set[str] = set()
        for lock in sorted(project_path.rglob("shard.lock")):
            if path_ignored(lock.relative_to(project_path)):
                continue
            for comp in self._parse_lock(lock, project_path, declared):
                if comp["name"] in seen:
                    continue
                seen.add(comp["name"])
                components.append(comp)

        if not components:
            # No lock yet: declared ranges from shard.yml are direct-only (§5).
            for shardfile in sorted(project_path.rglob("shard.yml")):
                if path_ignored(shardfile.relative_to(project_path)):
                    continue
                for comp in self._parse_manifest(shardfile, project_path):
                    if comp["name"] in seen:
                        continue
                    seen.add(comp["name"])
                    components.append(comp)
        return components

    def _parse_lock(
        self, lock: Path, root_path: Path, declared: dict[str, str]
    ) -> list[dict]:
        try:
            data = yaml.load(read_text_safe(lock), Loader=yaml.BaseLoader)
        except (OSError, UnicodeDecodeError, yaml.YAMLError):
            return []
        if not isinstance(data, dict):
            return []
        shards = data.get("shards")
        if not isinstance(shards, dict):
            return []
        source = rel_posix(lock, root_path)

        results: list[dict] = []
        for name, rec in shards.items():
            if not isinstance(name, str) or not isinstance(rec, dict):
                continue
            if "path" in rec:
                # path: shards point at project-local code (§4).
                continue
            version = str(rec.get("version") or rec.get("commit") or "")
            git = rec.get("git")
            github = rec.get("github")
            if isinstance(github, str):
                registry_url = f"https://github.com/{github}"
            elif isinstance(git, str):
                registry_url = git
            else:
                registry_url = ""
            scope = declared.get(name, "compile")
            results.append({
                "name": name,
                "group": "",
                "version": version,
                "ecosystem": "crystal",
                "scope": scope,
                "direct": name in declared,
                "source_file": source,
                "hashes": [],
                "depends_on": [],
                "registry_url": registry_url,
            })
        return results

    def _parse_manifest(self, path: Path, root_path: Path) -> list[dict]:
        if yaml is None:
            return []
        try:
            data = yaml.load(read_text_safe(path), Loader=yaml.BaseLoader)
        except (OSError, UnicodeDecodeError, yaml.YAMLError):
            return []
        if not isinstance(data, dict):
            return []
        source = rel_posix(path, root_path)
        results: list[dict] = []
        for field, scope in (("dependencies", "compile"),
                             ("development_dependencies", "dev")):
            section = data.get(field)
            if not isinstance(section, dict):
                continue
            for name, entry in section.items():
                if not isinstance(name, str):
                    continue
                version = ""
                registry_url = ""
                if isinstance(entry, dict):
                    raw = entry.get("version")
                    if isinstance(raw, str):
                        version = raw
                    elif "path" in entry:
                        continue
                    github = entry.get("github")
                    git = entry.get("git")
                    if isinstance(github, str):
                        registry_url = f"https://github.com/{github}"
                    elif isinstance(git, str):
                        registry_url = git
                results.append({
                    "name": name,
                    "group": "",
                    "version": version,
                    "ecosystem": "crystal",
                    "scope": scope,
                    "direct": True,
                    "source_file": source,
                    "hashes": [],
                    "depends_on": [],
                    "registry_url": registry_url,
                })
        return results

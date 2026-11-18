import re
from pathlib import Path

from .base import (
    DependencyCollector,
    link_dependencies,
    prefer_static_or_cli,
    rel_posix,
)


def _parse_dep_array(text: str) -> list[dict]:
    """Cargo.lock ``dependencies`` entries: ``"name"``, ``"name version"`` or
    ``"name version (source)"`` — quoted strings in a TOML array body."""
    specs: list[dict] = []
    for raw in re.findall(r'"([^"]+)"', text):
        parts = raw.split()
        name = parts[0]
        version = parts[1] if len(parts) > 1 and parts[1][:1].isdigit() else ""
        if name:
            specs.append({"name": name, "version": version})
    return specs


class CargoCollector(DependencyCollector):

    def supported_files(self) -> list[str]:
        return ["Cargo.toml", "Cargo.lock"]

    def collect(self, project_path: Path) -> list[dict]:
        """§5.3 pipeline: Cargo.lock → Cargo.toml → ``cargo metadata`` fallback.

        Cargo.lock carries exact pins, checksums, the dependency graph and
        workspace-root direct flags, so the CLI never preempts it.
        """
        # 1. Lockfile first (§5.3): exact versions, hashes and real edges.
        components: list[dict] = []
        seen: set[str] = set()
        for manifest in sorted(project_path.rglob("Cargo.toml")):
            if "target" in manifest.parts:
                continue
            lockfile = manifest.parent / "Cargo.lock"
            if not lockfile.exists():
                continue
            for comp in self._parse_lockfile(lockfile, project_path):
                key = f"{comp['name']}:{comp.get('version', '')}"
                if key in seen:
                    continue
                seen.add(key)
                components.append(comp)
        if components:
            return components

        # 2. Manifest: declared constraints — direct-only evidence.
        static_seen: set[str] = set()
        for manifest in sorted(project_path.rglob("Cargo.toml")):
            if "target" in manifest.parts:
                continue
            for comp in self._parse_manifest(manifest, project_path):
                if comp["name"] in static_seen:
                    continue
                static_seen.add(comp["name"])
                components.append(comp)

        # 3. CLI fallback (§5): only when static evidence has no depth to add.
        cli: list[dict] = []
        if self._command_exists("cargo"):
            cli = self._run_cargo_metadata(project_path)
        return prefer_static_or_cli(components, cli)

    def _run_cargo_metadata(self, project_path: Path) -> list[dict]:
        for manifest_dir in self._find_cargo_roots(project_path):
            data = self._run_cli_json(
                ["cargo", "metadata", "--format-version", "1"],
                cwd=manifest_dir,
                timeout=120,
            )
            if data:
                return self._parse_metadata(data, project_path)
        return []

    def _find_cargo_roots(self, project_path: Path) -> list[Path]:
        roots = []
        for manifest in project_path.rglob("Cargo.toml"):
            if "target" not in str(manifest):
                roots.append(manifest.parent)
        return roots[:5]

    def _parse_metadata(self, data: dict, root_path: Path) -> list[dict]:
        results: list[dict] = []
        seen: set[str] = set()

        for pkg in data.get("packages", []):
            name = pkg.get("name", "")
            version = pkg.get("version", "")
            dep_key = f"{name}:{version}"

            if dep_key in seen:
                continue
            seen.add(dep_key)

            homepage = pkg.get("homepage", "")
            repository = pkg.get("repository", "")

            results.append({
                "name": name,
                "group": "",
                "version": version,
                "ecosystem": "cargo",
                "scope": "compile",
                "optional": False,
                "direct": False,
                "source_file": "cargo metadata",
                "homepage": homepage,
                "repository": repository,
                "registry_url": f"https://crates.io/crates/{name}",
                "hashes": [],
                "depends_on": [],
            })

        self._apply_resolve_graph(data, results)
        link_dependencies(results)
        return results

    def _apply_resolve_graph(self, data: dict, results: list[dict]) -> None:
        """Turn ``cargo metadata``'s resolve graph into depends_on identities."""
        resolve = data.get("resolve") or {}
        nodes = resolve.get("nodes") or []
        if not nodes:
            return

        def identity(node_id: str) -> tuple[str, str]:
            if "#" not in node_id:
                return ("", "")
            name, _, version = node_id.rsplit("#", 1)[-1].partition("@")
            return (name, version)

        comp_index = {(c.get("name", ""), c.get("version", "")): c for c in results}
        root_id = resolve.get("root", "")

        for node in nodes:
            node_id = node.get("id", "")
            parent = comp_index.get(identity(node_id))
            is_root = bool(root_id) and node_id == root_id
            for dep in node.get("deps", []):
                child = comp_index.get(identity(dep.get("pkg", "")))
                if child is None or child is parent:
                    continue
                if is_root:
                    child["direct"] = True
                if parent is None:
                    continue
                spec = {"name": child.get("name", ""),
                        "version": child.get("version", "")}
                bucket = parent.setdefault("_dep_names", [])
                if spec not in bucket:
                    bucket.append(spec)

    def _parse_lockfile(self, lockfile: Path, root_path: Path) -> list[dict]:
        results: list[dict] = []
        seen: set[str] = set()

        try:
            content = lockfile.read_text(encoding="utf-8-sig")
        except Exception:
            return results

        in_package = False
        in_deps_array = False
        dep_buffer: list[str] = []
        current_pkg: dict = {}
        local_roots: list[dict] = []

        def flush() -> None:
            if current_pkg.get("name"):
                dep_key = f"{current_pkg['name']}:{current_pkg.get('version', '')}"
                if dep_key not in seen:
                    seen.add(dep_key)
                    comp = self._build_component(
                        current_pkg, root_path, lockfile
                    )
                    if not current_pkg.get("source"):
                        local_roots.append(comp)
                    results.append(comp)

        for line in content.splitlines():
            line = line.strip()

            if in_deps_array:
                if line == "]":
                    in_deps_array = False
                    current_pkg["dep_entries"] = _parse_dep_array(" ".join(dep_buffer))
                    dep_buffer = []
                else:
                    dep_buffer.append(line)
                continue

            if line == "[[package]]":
                flush()
                current_pkg = {}
                in_package = True
            elif in_package:
                if line.startswith("name = "):
                    current_pkg["name"] = line.split("=", 1)[1].strip().strip('"')
                elif line.startswith("version = "):
                    current_pkg["version"] = line.split("=", 1)[1].strip().strip('"')
                elif line.startswith("source = "):
                    current_pkg["source"] = line.split("=", 1)[1].strip().strip('"')
                elif line.startswith("checksum = "):
                    current_pkg["checksum"] = line.split("=", 1)[1].strip().strip('"')
                elif line.startswith("dependencies = ["):
                    inline = line[len("dependencies = ["):].strip()
                    if inline.endswith("]"):
                        current_pkg["dep_entries"] = _parse_dep_array(inline[:-1])
                    else:
                        in_deps_array = True
                        dep_buffer = []

        flush()

        # A package without `source` is a workspace member: its lockfile
        # dependencies are the project's *direct* dependencies (§5.4).
        index: dict[str, list[dict]] = {}
        for comp in results:
            index.setdefault(comp.get("name", ""), []).append(comp)
        for root in local_roots:
            for spec in root.get("_dep_names", []):
                for candidate in index.get(spec.get("name", ""), []):
                    if not spec.get("version") or candidate.get("version") == spec.get("version"):
                        candidate["direct"] = True
        link_dependencies(results)
        return results

    def _build_component(
        self, pkg: dict, root_path: Path, source_path: Path
    ) -> dict:
        name = pkg.get("name", "")
        version = pkg.get("version", "")
        checksum = pkg.get("checksum", "")

        hashes = []
        if checksum:
            if checksum.startswith("sha256:"):
                hashes.append({"alg": "SHA-256", "content": checksum[7:]})
            elif len(checksum) == 64:
                hashes.append({"alg": "SHA-256", "content": checksum})

        return {
            "name": name,
            "group": "",
            "version": version,
            "ecosystem": "cargo",
            "scope": "compile",
            "optional": False,
            "direct": False,
            "source_file": rel_posix(source_path, root_path),
            "registry_url": f"https://crates.io/crates/{name}",
            "hashes": hashes,
            "depends_on": [],
            "_dep_names": list(pkg.get("dep_entries") or []),
        }

    def _parse_manifest(self, manifest_path: Path, root_path: Path) -> list[dict]:
        results: list[dict] = []

        try:
            content = manifest_path.read_text(encoding="utf-8-sig")
        except Exception:
            return results

        in_deps = False
        for line in content.splitlines():
            line = line.strip()

            if line == "[dependencies]" or line.startswith("[dependencies."):
                in_deps = True
                continue
            elif line.startswith("[") and in_deps:
                in_deps = False
                continue

            if in_deps and "=" in line:
                parts = line.split("=", 1)
                name = parts[0].strip()
                version_spec = parts[1].strip().strip('"')

                if version_spec.startswith("{"):
                    ver_match = re.search(r'version\s*=\s*"([^"]+)"', version_spec)
                    if ver_match:
                        version_spec = ver_match.group(1)

                if name and version_spec and not version_spec.startswith("{"):
                    results.append({
                        "name": name,
                        "group": "",
                        "version": version_spec,
                        "ecosystem": "cargo",
                        "scope": "compile",
                        "optional": False,
                        "direct": True,
                        "source_file": rel_posix(manifest_path, root_path),
                        "registry_url": f"https://crates.io/crates/{name}",
                        "hashes": [],
                        "depends_on": [],
                    })

        return results

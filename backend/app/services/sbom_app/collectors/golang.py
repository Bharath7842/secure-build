import re
from pathlib import Path

from .base import (
    DependencyCollector,
    link_dependencies,
    prefer_static_or_cli,
    rel_posix,
)


class GoCollector(DependencyCollector):

    def supported_files(self) -> list[str]:
        return ["go.mod", "go.sum"]

    def collect(self, project_path: Path) -> list[dict]:
        """§5.3 pipeline: go.sum/go.mod static → Go CLI when static lacks depth.

        Static Go evidence carries no dependency graph (go.sum is a flat
        verified closure with hashes, go.mod the direct declarations), so
        ``go list -m all`` plus ``go mod graph`` is consulted — but only to
        replace static evidence when it actually adds transitive edges.
        """
        static = self._collect_static(project_path)
        cli: list[dict] = []
        if self._command_exists("go"):
            cli = self._run_go_list(project_path)
        return prefer_static_or_cli(static, cli)

    def _collect_static(self, project_path: Path) -> list[dict]:
        """go.sum closure enriched with go.mod's direct declarations (§5.4).

        The two files are complementary: go.sum pins every verified module
        version with its hash, go.mod says which of them the build requires
        directly. A module only go.sum knows about is reported as
        locked-transitive evidence — no static graph exists to attach it to.
        """
        components: list[dict] = []
        seen: set[str] = set()
        index: dict[str, dict] = {}

        for go_sum in sorted(project_path.rglob("go.sum")):
            if "vendor" in go_sum.parts:
                continue
            for comp in self._parse_go_sum(go_sum, project_path):
                key = self._module_key(comp)
                if key in seen:
                    continue
                seen.add(key)
                index[key] = comp
                components.append(comp)

        for gomod in sorted(project_path.rglob("go.mod")):
            if "vendor" in gomod.parts:
                continue
            for comp in self._parse_gomod(gomod, project_path):
                key = self._module_key(comp)
                existing = index.get(key)
                if existing is not None:
                    existing["direct"] = True
                    continue
                if key in seen:
                    continue
                seen.add(key)
                index[key] = comp
                components.append(comp)

        return components

    @staticmethod
    def _module_key(comp: dict) -> str:
        group, name, version = comp.get("group", ""), comp["name"], comp.get("version", "")
        path = f"{group}/{name}" if group else name
        return f"{path}@{version}"

    def _run_go_list(self, project_path: Path) -> list[dict]:
        results: list[dict] = []
        seen: set[str] = set()

        for go_dir in self._find_go_roots(project_path):
            import json
            output = self._run_cli(
                ["go", "list", "-m", "-json", "all"],
                cwd=go_dir,
                timeout=120,
            )
            if output:
                try:
                    modules = []
                    decoder = json.JSONDecoder()
                    idx = 0
                    while idx < len(output):
                        try:
                            obj, end_idx = decoder.raw_decode(output, idx)
                            modules.append(obj)
                            idx = end_idx
                        except json.JSONDecodeError:
                            idx += 1

                    go_sum_hashes = self._load_go_sum_hashes(project_path)

                    for module in modules:
                        path = module.get("Path", "")
                        version = module.get("Version", "")
                        main = module.get("Main", False)

                        if main or not path or not version:
                            continue

                        dep_key = f"{path}:{version}"
                        if dep_key in seen:
                            continue
                        seen.add(dep_key)

                        name = path.rsplit("/", 1)[-1]
                        group = path.rsplit("/", 1)[0] if "/" in path else ""

                        hashes = []
                        hash_val = go_sum_hashes.get(f"{path} {version}")
                        if hash_val:
                            hashes.append({"alg": "SHA-256", "content": hash_val})

                        results.append({
                            "name": name,
                            "group": group,
                            "version": version,
                            "ecosystem": "golang",
                            "scope": "compile",
                            "optional": False,
                            "direct": False,
                            "source_file": "go list -m all",
                            "hashes": hashes,
                            "registry_url": f"https://pkg.go.dev/{path}",
                        })
                except Exception:
                    pass

        if results:
            self._apply_go_mod_graph(results, project_path)
        return results

    def _apply_go_mod_graph(self, components: list[dict], project_path: Path) -> None:
        """Mark direct modules and link transitive edges from ``go mod graph``.

        ``go mod graph`` prints ``parent child`` pairs of ``path version``
        tokens; the main module appears as a bare path (no version) and is the
        implicit project root, so edges are only recorded between collected
        components (§5.6).
        """
        index: dict[tuple[str, str], dict] = {}
        for comp in components:
            path = f"{comp.get('group', '')}/{comp['name']}" if comp.get("group") else comp["name"]
            index[(path, comp.get("version", ""))] = comp

        direct_paths: set[str] = set()
        for go_dir in self._find_go_roots(project_path):
            direct_paths |= self._direct_module_paths(go_dir / "go.mod")
            graph = self._run_cli(["go", "mod", "graph"], cwd=go_dir, timeout=120)
            if not graph:
                continue
            for line in graph.splitlines():
                tokens = line.split()
                if len(tokens) == 4:
                    parent_path, parent_version, child_path, child_version = tokens
                elif len(tokens) == 3:
                    parent_path, child_path, child_version = tokens
                    parent_version = ""
                else:
                    continue
                if not parent_version:
                    continue  # main module: root edge, adopted by the graph node
                parent = index.get((parent_path, parent_version))
                child = index.get((child_path, child_version))
                if parent is None or child is None or parent is child:
                    continue
                spec = {"name": child["name"], "version": child.get("version", "")}
                bucket = parent.setdefault("_dep_names", [])
                if spec not in bucket:
                    bucket.append(spec)

        for comp in components:
            path = f"{comp.get('group', '')}/{comp['name']}" if comp.get("group") else comp["name"]
            if path in direct_paths:
                comp["direct"] = True
        link_dependencies(components)

    def _direct_module_paths(self, gomod: Path) -> set[str]:
        """Module paths listed in go.mod's require statements (§5.4)."""
        try:
            lines = gomod.read_text(encoding="utf-8-sig").splitlines()
        except OSError:
            return set()

        paths: set[str] = set()
        in_require = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("require ("):
                in_require = True
                continue
            if stripped == ")" and in_require:
                in_require = False
                continue
            if in_require or stripped.startswith("require "):
                dep_line = stripped.removeprefix("require ").strip()
                match = re.match(r"([\w./-]+)\s+v", dep_line)
                if match:
                    paths.add(match.group(1))
        return paths

    def _find_go_roots(self, project_path: Path) -> list[Path]:
        roots = []
        for gomod in project_path.rglob("go.mod"):
            if "vendor" not in str(gomod):
                roots.append(gomod.parent)
        return roots[:5]

    def _parse_go_sum(self, go_sum: Path, root_path: Path) -> list[dict]:
        results: list[dict] = []
        seen: set[str] = set()

        try:
            lines = go_sum.read_text(encoding="utf-8-sig").splitlines()
        except UnicodeDecodeError:
            return results

        hashes_by_module: dict[str, str] = {}
        for line in lines:
            parts = line.split()
            if len(parts) < 3:
                continue
            module_path = parts[0]
            version = parts[1]
            if not version.startswith("v"):
                continue
            if "/go.mod" in parts[-1]:
                continue
            hash_parts = parts[-1].split(":")
            if len(hash_parts) == 2:
                hashes_by_module[f"{module_path} {version}"] = hash_parts[1]

        for line in lines:
            parts = line.split()
            if len(parts) < 2:
                continue

            module_path = parts[0]
            version = parts[1]

            # ``v1.2.3/go.mod`` lines are go.mod hashes, not module pins.
            if not version.startswith("v") or version.endswith("/go.mod"):
                continue

            dep_key = f"{module_path}:{version}"
            if dep_key in seen:
                continue
            seen.add(dep_key)

            name = module_path.rsplit("/", 1)[-1]
            group = module_path.rsplit("/", 1)[0] if "/" in module_path else ""

            hashes = []
            hash_val = hashes_by_module.get(f"{module_path} {version}")
            if hash_val:
                hashes.append({"alg": "SHA-256", "content": hash_val})

            results.append({
                "name": name,
                "group": group,
                "version": version,
                "ecosystem": "golang",
                "scope": "compile",
                "optional": False,
                "direct": False,
                "source_file": rel_posix(go_sum, root_path),
                "hashes": hashes,
                "registry_url": f"https://pkg.go.dev/{module_path}",
            })

        return results

    def _load_go_sum_hashes(self, project_path: Path) -> dict[str, str]:
        hashes: dict[str, str] = {}
        for go_sum in project_path.rglob("go.sum"):
            try:
                lines = go_sum.read_text(encoding="utf-8-sig").splitlines()
            except UnicodeDecodeError:
                continue
            for line in lines:
                parts = line.split()
                if len(parts) < 3:
                    continue
                module_path = parts[0]
                version = parts[1]
                if not version.startswith("v"):
                    continue
                if "/go.mod" in parts[-1]:
                    continue
                hash_parts = parts[-1].split(":")
                if len(hash_parts) == 2:
                    hashes[f"{module_path} {version}"] = hash_parts[1]
        return hashes

    def _parse_gomod(self, gomod_path: Path, root_path: Path) -> list[dict]:
        results: list[dict] = []
        try:
            lines = gomod_path.read_text(encoding="utf-8-sig").splitlines()
        except UnicodeDecodeError:
            return results

        in_require = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("require ("):
                in_require = True
                continue
            if stripped == ")" and in_require:
                in_require = False
                continue

            if in_require or stripped.startswith("require "):
                dep_line = stripped.removeprefix("require ").strip()
                match = re.match(r"([\w./-]+)\s+(v[\d.]+\S*)", dep_line)
                if match:
                    module, version = match.groups()
                    name = module.rsplit("/", 1)[-1]
                    results.append({
                        "name": name,
                        "group": module.rsplit("/", 1)[0] if "/" in module else "",
                        "version": version,
                        "ecosystem": "golang",
                        "scope": "compile",
                        "optional": False,
                        "direct": True,
                        "source_file": rel_posix(gomod_path, root_path),
                        "registry_url": f"https://pkg.go.dev/{module}",
                    })

        return results

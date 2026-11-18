import re
import json
from pathlib import Path

from .base import (
    DependencyCollector,
    link_dependencies,
    prefer_static_or_cli,
    sri_hashes,
    rel_posix,
)


class NuGetCollector(DependencyCollector):

    def supported_files(self) -> list[str]:
        return ["*.csproj", "*.fsproj", "*.vbproj", "packages.config",
                "packages.lock.json", "project.assets.json"]

    def collect(self, project_path: Path) -> list[dict]:
        """§5.3 pipeline: packages.lock.json/project.assets.json → project
        files → ``dotnet list`` fallback.

        The lock/restore outputs carry exact pins, hashes, direct flags and
        the dependency graph, so the CLI never preempts them.
        """
        # 1. Lockfiles first (§5.3): exact versions, hashes and real edges.
        lockfile_components = self._parse_lockfiles(project_path)
        if lockfile_components:
            return lockfile_components

        # 2. Project files: declared versions (or central versions from
        #    Directory.Packages.props) — direct-only evidence.
        components: list[dict] = []
        seen: set[str] = set()

        def add(comps: list[dict]) -> None:
            for comp in comps:
                key = f"{comp['name']}:{comp.get('version', '')}"
                if key in seen:
                    continue
                seen.add(key)
                components.append(comp)

        for pattern in ("*.csproj", "*.fsproj", "*.vbproj"):
            for proj in sorted(project_path.rglob(pattern)):
                if "node_modules" in proj.parts:
                    continue
                add(self._parse_csproj(proj, project_path))
        for config in sorted(project_path.rglob("packages.config")):
            add(self._parse_packages_config(config, project_path))
        for props in sorted(project_path.rglob("Directory.Packages.props")):
            add(self._parse_directory_packages_props(props, project_path))

        # 3. CLI fallback (§5): only when static evidence has no depth to add.
        cli: list[dict] = []
        if self._command_exists("dotnet"):
            cli = self._run_dotnet_list(project_path)
        return prefer_static_or_cli(components, cli)

    def _parse_lockfiles(self, project_path: Path) -> list[dict]:
        components: list[dict] = []
        seen: set[str] = set()

        for lockfile in sorted(project_path.rglob("packages.lock.json")):
            components.extend(self._parse_packages_lock(lockfile, project_path, seen))
        for assets_file in sorted(project_path.rglob("project.assets.json")):
            components.extend(self._parse_project_assets(assets_file, project_path, seen))

        return components

    def _run_dotnet_list(self, project_path: Path) -> list[dict]:
        results: list[dict] = []
        seen: set[str] = set()

        for proj in project_path.rglob("*.csproj"):
            if "node_modules" in str(proj) or "Test" in proj.name:
                continue

            output = self._run_cli_json(
                ["dotnet", "list", str(proj), "package", "--include-transitive", "--json"],
                cwd=project_path,
                timeout=120,
            )
            if output:
                try:
                    for version_data in output.get("projects", []):
                        for version in version_data.get("version", []):
                            pkg = version.get("id", "")
                            ver = version.get("resolvedVersion", "")
                            transitive = version.get("transitive", [])

                            if not pkg or not ver:
                                continue

                            dep_key = f"{pkg}:{ver}"
                            if dep_key in seen:
                                continue
                            seen.add(dep_key)

                            results.append({
                                "name": pkg,
                                "group": "NuGet",
                                "version": ver,
                                "ecosystem": "nuget",
                                "scope": "compile",
                                "optional": False,
                                "direct": True,
                                "source_file": "dotnet list package --json",
                                "registry_url": f"https://www.nuget.org/packages/{pkg}",
                            })

                            for t in transitive:
                                t_pkg = t.get("id", "")
                                t_ver = t.get("resolvedVersion", "")
                                if not t_pkg or not t_ver:
                                    continue
                                t_key = f"{t_pkg}:{t_ver}"
                                if t_key in seen:
                                    continue
                                seen.add(t_key)
                                results.append({
                                    "name": t_pkg,
                                    "group": "NuGet",
                                    "version": t_ver,
                                    "ecosystem": "nuget",
                                    "scope": "compile",
                                    "optional": False,
                                    "direct": False,
                                    "source_file": "dotnet list package --json",
                                    "registry_url": f"https://www.nuget.org/packages/{t_pkg}",
                                })
                except Exception:
                    pass

        return results

    def _parse_packages_lock(self, lockfile_path: Path, root_path: Path, seen: set[str]) -> list[dict]:
        results: list[dict] = []
        by_key: dict[str, dict] = {}

        try:
            data = json.loads(lockfile_path.read_text(encoding="utf-8-sig"))
        except Exception:
            return results
        if not isinstance(data, dict):
            return results

        # packages.lock.json: {"dependencies": {"<tfm>": {"<id>": {...}}}}
        dependency_groups = data.get("dependencies")
        if not isinstance(dependency_groups, dict):
            return results

        for group in dependency_groups.values():
            if not isinstance(group, dict):
                continue
            for pkg_name, entry in group.items():
                if not isinstance(entry, dict):
                    continue
                version = entry.get("resolved") or ""
                if not version:
                    requested = str(entry.get("requested") or "").strip("[]()")
                    version = requested.split(",")[0].strip() or ""

                dep_key = f"{pkg_name}:{version}"
                child_names = [
                    child for child in (entry.get("dependencies") or {})
                    if isinstance(child, str)
                ]

                existing = by_key.get(dep_key)
                if existing is None:
                    if dep_key in seen:
                        continue
                    seen.add(dep_key)
                    existing = {
                        "name": pkg_name,
                        "group": "NuGet",
                        "version": version,
                        "ecosystem": "nuget",
                        "scope": "compile",
                        "optional": False,
                        "direct": str(entry.get("type", "")).lower() == "direct",
                        "source_file": rel_posix(lockfile_path, root_path),
                        "registry_url": f"https://www.nuget.org/packages/{pkg_name}",
                        "hashes": sri_hashes(f"sha512-{entry['contentHash']}")
                        if entry.get("contentHash") else [],
                        "depends_on": [],
                        "_dep_names": list(child_names),
                    }
                    by_key[dep_key] = existing
                    results.append(existing)
                else:
                    if str(entry.get("type", "")).lower() == "direct":
                        existing["direct"] = True
                    for child in child_names:
                        if child not in existing["_dep_names"]:
                            existing["_dep_names"].append(child)

        link_dependencies(results)
        return results

    def _parse_project_assets(self, assets_path: Path, root_path: Path, seen: set[str]) -> list[dict]:
        results: list[dict] = []

        try:
            data = json.loads(assets_path.read_text(encoding="utf-8-sig"))
        except Exception:
            return results
        if not isinstance(data, dict):
            return results

        libraries = data.get("libraries", {})

        # projectFileDependencyGroups lists the project's *direct* packages
        # as ``name >= version`` (restore output) or ``name/version``.
        direct_names: set[str] = set()
        for group in (data.get("projectFileDependencyGroups") or {}).values():
            for declared in group or []:
                if isinstance(declared, str) and declared:
                    direct_names.add(
                        declared.split("/", 1)[0].split(" ", 1)[0].strip()
                    )

        for lib_key, lib_data in libraries.items():
            parts = lib_key.split("/", 1)
            if len(parts) != 2:
                continue

            pkg_name, version = parts
            if not isinstance(lib_data, dict):
                lib_data = {}

            dep_key = f"{pkg_name}:{version}"
            if dep_key in seen:
                continue
            seen.add(dep_key)

            results.append({
                "name": pkg_name,
                "group": "NuGet",
                "version": version,
                "ecosystem": "nuget",
                "scope": "compile",
                "optional": False,
                "direct": pkg_name in direct_names,
                "source_file": rel_posix(assets_path, root_path),
                "registry_url": f"https://www.nuget.org/packages/{pkg_name}",
                "hashes": [],
                "depends_on": [],
                "_dep_names": [
                    child for child in (lib_data.get("dependencies") or {})
                    if isinstance(child, str)
                ],
            })

        link_dependencies(results)
        return results

    def _parse_directory_packages_props(
        self, props_path: Path, root_path: Path
    ) -> list[dict]:
        """Central Package Management: versions declared centrally (§5.2).

        With ``ManagePackageVersionsCentrally`` enabled, ``PackageReference``
        entries carry no version — ``Directory.Packages.props`` holds the
        ``PackageVersion`` entries the project actually depends on.
        """
        results: list[dict] = []

        try:
            content = props_path.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError:
            return results

        for tag in re.findall(r"<PackageVersion\b[^>]*>", content):
            include = re.search(r'Include="([^"]+)"', tag)
            version = re.search(r'Version="([^"]+)"', tag)
            if not include or not version:
                continue
            name = include.group(1)
            results.append({
                "name": name,
                "group": "NuGet",
                "version": version.group(1),
                "ecosystem": "nuget",
                "scope": "compile",
                "optional": False,
                "direct": True,
                "source_file": rel_posix(props_path, root_path),
                "registry_url": f"https://www.nuget.org/packages/{name}",
                "hashes": [],
                "depends_on": [],
            })

        return results

    def _parse_csproj(self, csproj_path: Path, root_path: Path) -> list[dict]:
        results: list[dict] = []

        try:
            content = csproj_path.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError:
            return results

        pattern = re.compile(r'<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"')
        for match in pattern.finditer(content):
            name = match.group(1)
            version = match.group(2)
            results.append({
                "name": name,
                "group": "NuGet",
                "version": version,
                "ecosystem": "nuget",
                "scope": "compile",
                "optional": False,
                "direct": True,
                "source_file": rel_posix(csproj_path, root_path),
                "registry_url": f"https://www.nuget.org/packages/{name}",
            })

        return results

    def _parse_packages_config(self, config_path: Path, root_path: Path) -> list[dict]:
        results: list[dict] = []

        try:
            content = config_path.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError:
            return results

        pattern = re.compile(r'<package\s+id="([^"]+)"\s+version="([^"]+)"')
        for match in pattern.finditer(content):
            name = match.group(1)
            version = match.group(2)
            results.append({
                "name": name,
                "group": "NuGet",
                "version": version,
                "ecosystem": "nuget",
                "scope": "compile",
                "optional": False,
                "direct": True,
                "source_file": rel_posix(config_path, root_path),
                "registry_url": f"https://www.nuget.org/packages/{name}",
            })

        return results

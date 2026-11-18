import json
from pathlib import Path

from .base import (
    DependencyCollector,
    jsonc_loads,
    read_text_safe,
    rel_posix,
    sri_hashes,
)

_jsonc_loads = jsonc_loads


class NpmCollector(DependencyCollector):

    def supported_files(self) -> list[str]:
        return [
            "package.json", "npm-shrinkwrap.json", "bun.lock",
            "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
        ]

    def collect(self, project_path: Path) -> tuple[list[dict], list[dict]]:
        """Lockfile first (§5.3): exact versions, hashes and real edges.

        ``npm ls`` is only consulted when no lockfile exists anywhere.
        """
        components: list[dict] = []
        edges: list[dict] = []
        seen_roots: set[Path] = set()
        lock_names: set[str] = set()
        manifest_only: list[Path] = []

        for pkg_dir in self._find_npm_roots(project_path):
            if pkg_dir in seen_roots:
                continue
            seen_roots.add(pkg_dir)

            # npm-shrinkwrap.json wins over package-lock.json (§5.3);
            # bun.lock only ever exists when bun is the active package manager.
            collected = False
            for lock_name, parser in (
                ("npm-shrinkwrap.json", self._parse_package_lock),
                ("bun.lock", self._parse_bun_lock),
                ("package-lock.json", self._parse_package_lock),
                ("yarn.lock", self._parse_yarn_lock),
                ("pnpm-lock.yaml", self._parse_pnpm_lock),
            ):
                lockfile = pkg_dir / lock_name
                if not lockfile.exists():
                    continue
                comps, lock_edges = parser(lockfile, pkg_dir, project_path)
                if comps:
                    components.extend(comps)
                    edges.extend(lock_edges)
                    for comp in comps:
                        group = comp.get("group") or ""
                        lock_names.add(
                            f"{group}/{comp['name']}" if group else comp["name"]
                        )
                    collected = True
                    break
            if not collected:
                manifest_only.append(pkg_dir)

        for pkg_dir in manifest_only:
            components.extend(
                self._parse_package_json_tree(
                    pkg_dir, project_path, skip_known=lock_names
                )
            )

        if not components and self._command_exists("npm"):
            for pkg_dir in self._find_npm_roots(project_path)[:1]:
                result, npm_edges = self._run_npm_ls(pkg_dir, project_path)
                if result:
                    components.extend(result)
                    edges.extend(npm_edges)
                    break

        return components, edges

    def _manifest_meta(self, pkg_dir: Path) -> tuple[str, str]:
        """Root package name/version from package.json (for root edges)."""
        pkg_path = pkg_dir / "package.json"
        if not pkg_path.exists():
            return "", ""
        try:
            data = json.loads(read_text_safe(pkg_path))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return "", ""
        name = data.get("name", "")
        version = data.get("version", "")
        return name if isinstance(name, str) else "", version if isinstance(version, str) else ""

    @staticmethod
    def _root_purl(name: str, version: str) -> str:
        if not name:
            return ""
        return f"pkg:npm/{name}@{version}" if version else f"pkg:npm/{name}"

    @staticmethod
    def _direct_names(data: dict) -> set[str]:
        names: set[str] = set()
        for field in ("dependencies", "devDependencies", "optionalDependencies"):
            deps = data.get(field)
            if isinstance(deps, dict):
                names.update(k for k in deps if isinstance(k, str))
        return names

    def _manifest_direct_names(self, pkg_dir: Path) -> set[str]:
        pkg_path = pkg_dir / "package.json"
        if not pkg_path.exists():
            return set()
        try:
            data = json.loads(read_text_safe(pkg_path))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return set()
        return self._direct_names(data)

    VENDORED_DIRS = frozenset({
        "node_modules", "vendor", "vendors", "third-party", "third_party",
        "assets",
    })

    def _find_npm_roots(self, project_path: Path) -> list[Path]:
        roots = []
        for pkg in project_path.rglob("package.json"):
            if self._is_vendored(pkg, project_path):
                continue
            roots.append(pkg.parent)
        return sorted(roots)[:25]

    def _is_vendored(self, pkg: Path, project_path: Path) -> bool:
        try:
            parts = pkg.relative_to(project_path).parts
        except ValueError:
            parts = pkg.parts
        return any(part.lower() in self.VENDORED_DIRS for part in parts)

    def _run_npm_ls(self, pkg_dir: Path, root_path: Path) -> tuple[list[dict], list[dict]]:
        data = self._run_cli_json(
            ["npm", "ls", "--json", "--all"],
            cwd=pkg_dir,
            timeout=120,
        )
        if not data:
            return [], []
        return self._parse_npm_ls(data, pkg_dir, root_path)

    def _parse_npm_ls(
        self, data: dict, pkg_dir: Path, root_path: Path
    ) -> tuple[list[dict], list[dict]]:
        results: list[dict] = []
        index: dict[str, int] = {}
        child_specs: dict[str, set[tuple[str, str]]] = {}
        direct_names = self._manifest_direct_names(pkg_dir)

        def walk_deps(deps: dict, path: frozenset[str]) -> None:
            for name, info in deps.items():
                if not isinstance(info, dict):
                    continue
                version = info.get("version", "")
                if not version or not isinstance(version, str):
                    continue
                dep_key = f"{name}:{version}"
                if dep_key not in index:
                    index[dep_key] = len(results)
                    child_specs[dep_key] = set()
                    results.append({
                        "name": name.split("/")[-1] if "/" in name else name,
                        "group": name.split("/")[0] if "/" in name else "",
                        "version": version,
                        "ecosystem": "npm",
                        "scope": "dev" if info.get("dev") else "compile",
                        "optional": bool(info.get("optional")),
                        "direct": name in direct_names,
                        "source_file": "npm ls",
                        "registry_url": f"https://www.npmjs.com/package/{name}",
                        "depends_on": [],
                    })
                children = info.get("dependencies") or {}
                for child_name, child_info in children.items():
                    if isinstance(child_info, dict) and isinstance(child_info.get("version"), str):
                        child_specs[dep_key].add((child_name, child_info["version"]))
                if dep_key in path:
                    continue
                if children:
                    walk_deps(children, path | {dep_key})

        walk_deps(data.get("dependencies") or {}, frozenset())

        purl_of: dict[str, str] = {
            key: f"pkg:npm/{key.split(':', 1)[0]}@{key.split(':', 1)[1]}"
            for key in index
        }
        for key, pos in index.items():
            depends_on: list[str] = []
            for child_name, child_version in sorted(child_specs[key]):
                child_purl = purl_of.get(f"{child_name}:{child_version}")
                if child_purl and child_purl != purl_of[key] and child_purl not in depends_on:
                    depends_on.append(child_purl)
            results[pos]["depends_on"] = depends_on

        edges: list[dict] = []
        root_purl = self._root_purl(*self._manifest_meta(pkg_dir))
        direct_purls = [purl_of[key] for key in index if results[index[key]]["direct"]]
        if root_purl and direct_purls:
            edges.append({"ref": root_purl, "dependsOn": sorted(set(direct_purls))})

        results.extend(self._parse_package_json_tree(
            pkg_dir, root_path,
            skip_known={key.split(":", 1)[0] for key in index},
        ))
        return results, edges

    @staticmethod
    def _display_name(key: str) -> str:
        parts = key.split("node_modules/")
        return parts[-1] if len(parts) > 1 else key

    @staticmethod
    def _resolve_key(packages: dict, from_key: str, dep_name: str) -> str | None:
        """npm resolution: walk up the install tree to the nearest node_modules."""
        prefix = from_key
        while True:
            candidate = f"{prefix}/node_modules/{dep_name}" if prefix else f"node_modules/{dep_name}"
            if candidate in packages:
                return candidate
            if not prefix:
                return None
            prefix = prefix.rsplit("/", 1)[0] if "/" in prefix else ""

    @staticmethod
    def _integrity_hashes(integrity: str) -> list[dict]:
        """SRI digests are base64; CycloneDX wants hex (§5.7/§13)."""
        return sri_hashes(integrity)

    def _parse_package_lock(
        self, lockfile: Path, pkg_dir: Path, root_path: Path
    ) -> tuple[list[dict], list[dict]]:
        try:
            data = json.loads(read_text_safe(lockfile))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return [], []

        packages = data.get("packages")
        if isinstance(packages, dict) and packages:
            return self._parse_lock_v3(data, packages, lockfile, pkg_dir, root_path)
        if isinstance(data.get("dependencies"), dict) and data["dependencies"]:
            return self._parse_lock_v1(data, lockfile, root_path)
        return [], []

    def _parse_lock_v3(
        self, data: dict, packages: dict, lockfile: Path, pkg_dir: Path, root_path: Path
    ) -> tuple[list[dict], list[dict]]:
        source = rel_posix(lockfile, root_path)
        root_entry = packages.get("", {}) or {}
        components: list[dict] = []

        key_to_purl: dict[str, str] = {}
        entry_by_key: dict[str, dict] = {}
        for key, val in packages.items():
            if not key or not isinstance(val, dict):
                continue
            version = val.get("version", "")
            if not version:
                continue
            display = self._display_name(key)
            purl = f"pkg:npm/{display}@{version}"
            key_to_purl[key] = purl
            entry_by_key[key] = val

        direct_names: set[str] = self._direct_names(root_entry)
        root_purl = ""
        root_name = root_entry.get("name") or data.get("name") or ""
        root_version = root_entry.get("version") or data.get("version") or ""
        if root_name:
            root_purl = f"pkg:npm/{root_name}@{root_version}" if root_version else f"pkg:npm/{root_name}"

        direct_purls: list[str] = []
        for key, val in entry_by_key.items():
            display = self._display_name(key)
            group = display.split("/")[0] if "/" in display else ""
            name = display.split("/")[-1] if "/" in display else display
            purl = key_to_purl[key]

            depends_on: list[str] = []
            child_names: list[str] = []
            seen_children: set[str] = set()
            normal_children: set[str] = set()
            for field in ("dependencies", "optionalDependencies", "peerDependencies", "requires"):
                section = val.get(field)
                if not isinstance(section, dict):
                    continue
                if field != "peerDependencies":
                    normal_children.update(section)
                for dep_name in section:
                    if dep_name not in seen_children:
                        seen_children.add(dep_name)
                        child_names.append(dep_name)
            resolved_of: dict[str, str] = {}
            for dep_name in child_names:
                child_key = self._resolve_key(packages, key, dep_name)
                child_purl = key_to_purl.get(child_key or "")
                if child_purl and child_purl != purl:
                    resolved_of[dep_name] = child_purl
                    if child_purl not in depends_on:
                        depends_on.append(child_purl)
            normal_purls = {resolved_of[n] for n in normal_children if n in resolved_of}
            peer_purls = {
                resolved_of[n] for n in child_names
                if n not in normal_children and n in resolved_of
            }
            peer_depends_on = [
                child_purl for child_purl in depends_on
                if child_purl in peer_purls and child_purl not in normal_purls
            ]

            is_direct = display in direct_names
            if is_direct:
                direct_purls.append(purl)

            component = {
                "name": name,
                "group": group,
                "version": val.get("version", ""),
                "ecosystem": "npm",
                "scope": "dev" if val.get("dev") else "compile",
                "optional": bool(val.get("optional")),
                "direct": is_direct,
                "source_file": source,
                "hashes": self._integrity_hashes(val.get("integrity", "")),
                "download_url": val.get("resolved", ""),
                "registry_url": f"https://www.npmjs.com/package/{display}",
                "license": val.get("license", ""),
                "depends_on": depends_on,
            }
            if peer_depends_on:
                component["peer_depends_on"] = peer_depends_on
            components.append(component)

        # Direct deps declared in package.json but absent from the lockfile.
        components.extend(self._parse_package_json_tree(pkg_dir, root_path, skip_known={self._display_name(k) for k in entry_by_key}))

        edges: list[dict] = []
        if root_purl and direct_purls:
            edges.append({"ref": root_purl, "dependsOn": sorted(set(direct_purls))})
        return components, edges

    def _parse_lock_v1(
        self, data: dict, lockfile: Path, root_path: Path
    ) -> tuple[list[dict], list[dict]]:
        """lockfileVersion 1: nested ``dependencies`` with ``requires`` maps."""
        source = rel_posix(lockfile, root_path)
        components: list[dict] = []
        edges: list[dict] = []

        def walk(node: dict, parent_purl: str | None) -> None:
            for name, val in (node.get("dependencies") or {}).items():
                if not isinstance(val, dict):
                    continue
                version = val.get("version", "")
                if not version:
                    continue
                purl = f"pkg:npm/{name}@{version}"
                display_group = name.split("/")[0] if "/" in name else ""
                display_name = name.split("/")[-1] if "/" in name else name
                children = [
                    f"pkg:npm/{child}@{(val.get('dependencies') or {}).get(child, {}).get('version', '')}"
                    for child in (val.get("requires") or {})
                    if (val.get("dependencies") or {}).get(child, {}).get("version")
                ]
                components.append({
                    "name": display_name,
                    "group": display_group,
                    "version": version,
                    "ecosystem": "npm",
                    "scope": "dev" if val.get("dev") else "compile",
                    "optional": bool(val.get("optional")),
                    "direct": parent_purl is None,
                    "source_file": source,
                    "hashes": self._integrity_hashes(val.get("integrity", "")),
                    "download_url": val.get("resolved", ""),
                    "registry_url": f"https://www.npmjs.com/package/{name}",
                    "license": val.get("license", ""),
                    "depends_on": children,
                })
                if parent_purl:
                    edges.append({"ref": parent_purl, "dependsOn": [purl]})
                walk(val, purl)

        walk(data, None)
        return components, edges

    def _parse_bun_lock(
        self, lockfile: Path, pkg_dir: Path, root_path: Path
    ) -> tuple[list[dict], list[dict]]:
        """bun.lock: resolved graph with SRI hashes (text lockfile, JSONC)."""
        try:
            data = _jsonc_loads(read_text_safe(lockfile))
        except (json.JSONDecodeError, UnicodeDecodeError, OSError):
            return [], []
        packages = data.get("packages")
        if not isinstance(packages, dict) or not packages:
            return [], []
        source = rel_posix(lockfile, root_path)

        # Declared direct names from every workspace; first declaration kind wins.
        direct_spec: dict[str, tuple[str, str]] = {}
        for ws in (data.get("workspaces") or {}).values():
            if not isinstance(ws, dict):
                continue
            for field, scope in (
                ("dependencies", "compile"),
                ("optionalDependencies", "compile"),
                ("devDependencies", "dev"),
                ("peerDependencies", "provided"),
            ):
                declared = ws.get(field)
                if isinstance(declared, dict):
                    for dep_name, dep_range in declared.items():
                        if isinstance(dep_name, str) and isinstance(dep_range, str):
                            direct_spec.setdefault(dep_name, (dep_range, scope))

        entries: list[dict] = []
        seen: set[str] = set()
        for val in packages.values():
            if not isinstance(val, list) or not val or not isinstance(val[0], str):
                continue
            resolution = val[0]
            at = resolution.rfind("@")
            if at <= 0:
                continue
            name, rest = resolution[:at], resolution[at + 1:]
            if not rest or not rest[0].isdigit():
                # workspace:/link:/file:/git+/github:/tarball:/root: — project
                # code or versionless, so no honest version to record (§4).
                continue
            key = f"{name}:{rest}"
            if key in seen:
                continue
            seen.add(key)
            info = val[2] if len(val) > 2 and isinstance(val[2], dict) else {}
            integrity = val[3] if len(val) > 3 and isinstance(val[3], str) else ""
            registry = val[1] if len(val) > 1 and isinstance(val[1], str) else ""
            entries.append({
                "name": name,
                "version": rest,
                "info": info,
                "hashes": sri_hashes(integrity),
                "registry": registry,
            })

        purl_of: dict[str, str] = {}
        name_index: dict[str, list[str]] = {}
        for entry in entries:
            purl = f"pkg:npm/{entry['name']}@{entry['version']}"
            purl_of[f"{entry['name']}:{entry['version']}"] = purl
            name_index.setdefault(entry["name"], []).append(purl)

        def resolve_child(child_name: str, spec: str) -> str | None:
            spec = spec.removeprefix("npm:")
            if self._is_exact_version(spec):
                return purl_of.get(f"{child_name}:{spec}")
            purls = name_index.get(child_name) or []
            return purls[0] if len(purls) == 1 else None

        direct_purls: dict[str, str] = {}
        for dep_name, (dep_range, scope) in direct_spec.items():
            target = resolve_child(dep_name, dep_range)
            if target:
                direct_purls.setdefault(target, scope)

        components: list[dict] = []
        for entry in entries:
            name = entry["name"]
            purl = purl_of[f"{name}:{entry['version']}"]
            info = entry["info"]
            depends_on: list[str] = []
            for field in ("dependencies", "optionalDependencies", "peerDependencies"):
                section = info.get(field)
                if not isinstance(section, dict):
                    continue
                for child_name, child_spec in section.items():
                    if not isinstance(child_name, str) or not isinstance(child_spec, str):
                        continue
                    target = resolve_child(child_name, child_spec)
                    if target and target != purl and target not in depends_on:
                        depends_on.append(target)
            normal_names: set[str] = set()
            normal_purls: set[str] = set()
            for field in ("dependencies", "optionalDependencies"):
                section = info.get(field)
                if not isinstance(section, dict):
                    continue
                normal_names.update(section)
                for child_name, child_spec in section.items():
                    if isinstance(child_name, str) and isinstance(child_spec, str):
                        target = resolve_child(child_name, child_spec)
                        if target and target != purl:
                            normal_purls.add(target)
            peer_purls: set[str] = set()
            peer_section = info.get("peerDependencies")
            if isinstance(peer_section, dict):
                for child_name, child_spec in peer_section.items():
                    if (isinstance(child_name, str) and isinstance(child_spec, str)
                            and child_name not in normal_names):
                        target = resolve_child(child_name, child_spec)
                        if target and target != purl:
                            peer_purls.add(target)
            peer_depends_on = [
                child for child in depends_on
                if child in peer_purls and child not in normal_purls
            ]
            is_direct = purl in direct_purls
            registry = entry["registry"]
            registry_url = (
                registry if registry and "npmjs" not in registry
                else f"https://www.npmjs.com/package/{name}"
            )
            component = {
                "name": name.split("/")[-1] if "/" in name else name,
                "group": name.split("/")[0] if "/" in name else "",
                "version": entry["version"],
                "ecosystem": "npm",
                "scope": direct_purls.get(purl, "compile") if is_direct else "compile",
                "optional": False,
                "direct": is_direct,
                "source_file": source,
                "hashes": entry["hashes"],
                "registry_url": registry_url,
                "depends_on": depends_on,
            }
            if peer_depends_on:
                component["peer_depends_on"] = peer_depends_on
            components.append(component)

        edges: list[dict] = []
        root_purl = self._root_purl(*self._manifest_meta(pkg_dir))
        if root_purl and direct_purls:
            edges.append({"ref": root_purl, "dependsOn": sorted(direct_purls)})
        components.extend(self._parse_package_json_tree(
            pkg_dir, root_path,
            skip_known={entry["name"] for entry in entries},
        ))
        return components, edges

    @staticmethod
    def _yarn_descriptors(header: str) -> list[str]:
        descriptors = []
        for piece in header.split(","):
            piece = piece.strip().strip('"').strip("'").strip()
            if piece:
                descriptors.append(piece)
        return descriptors

    @staticmethod
    def _descriptor_name(descriptor: str) -> tuple[str, str]:
        at = descriptor.find("@", 1) if descriptor.startswith("@") else descriptor.find("@")
        if at <= 0:
            return "", ""
        return descriptor[:at], descriptor[at + 1:]

    @staticmethod
    def _yarn_hashes(checksum: str) -> list[dict]:
        if not checksum:
            return []
        value = checksum.split("?", 1)[0]
        hashes = sri_hashes(value)
        if hashes:
            return hashes
        if value and all(c in "0123456789abcdefABCDEF" for c in value):
            for alg in ("md5", "sha1", "sha256", "sha384", "sha512"):
                hashes = sri_hashes(f"{alg}-{value}")
                if hashes:
                    return hashes
        return []

    @staticmethod
    def _is_exact_version(spec: str) -> bool:
        if not spec or not spec[0].isdigit():
            return False
        return not any(ch in spec for ch in "^~*<>=| ")

    def _parse_yarn_lock(
        self, lockfile: Path, pkg_dir: Path, root_path: Path
    ) -> tuple[list[dict], list[dict]]:
        source = rel_posix(lockfile, root_path)
        try:
            content = read_text_safe(lockfile)
        except (UnicodeDecodeError, OSError):
            return [], []

        berry = "__metadata:" in content
        entries: list[dict] = []
        seen: set[str] = set()

        for block in content.split("\n\n"):
            lines = block.strip().splitlines()
            if not lines:
                continue
            header = lines[0].strip()
            if header.startswith("#") or not header.endswith(":"):
                continue
            label = header[:-1].strip().strip('"').strip("'")
            if label == "__metadata":
                continue
            descriptors = self._yarn_descriptors(label)
            if not descriptors:
                continue

            version = ""
            resolution = ""
            integrity = ""
            resolved = ""
            deps: dict[str, str] = {}
            in_deps = False
            deps_indent = 0
            for line in lines[1:]:
                raw = line.rstrip()
                if not raw.strip() or raw.lstrip().startswith("#"):
                    continue
                indent = len(raw) - len(raw.lstrip())
                stripped = raw.strip()
                if in_deps and indent <= deps_indent:
                    in_deps = False
                if in_deps and indent > deps_indent:
                    dep_key, sep, dep_val = stripped.partition(":")
                    if sep:
                        key = dep_key.strip().strip('"').strip("'")
                        deps[key] = dep_val.strip().strip('"').strip("'")
                    continue
                if stripped.startswith("version:"):
                    version = stripped.split(":", 1)[1].strip().strip('"').strip("'")
                elif stripped.startswith("version "):
                    version = stripped.split(" ", 1)[1].strip().strip('"').strip("'")
                elif stripped.startswith("resolution:"):
                    resolution = stripped.split(":", 1)[1].strip().strip('"').strip("'")
                elif stripped.startswith("integrity "):
                    integrity = stripped.split(" ", 1)[1].strip().strip('"').strip("'")
                elif stripped.startswith("checksum:"):
                    integrity = stripped.split(":", 1)[1].strip().strip('"').strip("'")
                elif stripped.startswith("resolved "):
                    resolved = stripped.split(" ", 1)[1].strip().strip('"').strip("'")
                elif stripped in ("dependencies:", "optionalDependencies:"):
                    in_deps = True
                    deps_indent = indent

            entry_name = ""
            entry_version = version
            if berry:
                if "@npm:" in resolution:
                    entry_name, _, ver = resolution.partition("@npm:")
                    entry_version = ver.split("::", 1)[0] or version
                elif "@virtual:" in resolution:
                    left, _, rest = resolution.partition("@virtual:")
                    entry_name = left
                    if "#npm:" in rest:
                        entry_version = rest.split("#npm:", 1)[1].split("::", 1)[0]
                elif "@patch:" in resolution:
                    entry_name = resolution.split("@patch:", 1)[0]
                    entry_version = version
                elif any(f"@{proto}:" in resolution for proto in (
                    "workspace", "link", "portal", "file", "exec",
                    "http", "git", "github", "tarball",
                )):
                    continue
                else:
                    entry_name, _ = self._descriptor_name(descriptors[0])
            else:
                entry_name, _ = self._descriptor_name(descriptors[0])

            if not entry_name or not entry_version:
                continue
            dep_key = f"{entry_name}:{entry_version}"
            if dep_key in seen:
                continue
            seen.add(dep_key)
            entries.append({
                "name": entry_name,
                "version": entry_version,
                "descriptors": descriptors,
                "deps": deps,
                "hashes": self._yarn_hashes(integrity),
                "resolved": resolved,
            })

        purl_of: dict[str, str] = {}
        name_index: dict[str, list[str]] = {}
        desc_purl: dict[str, str] = {}
        for entry in entries:
            purl = f"pkg:npm/{entry['name']}@{entry['version']}"
            purl_of[f"{entry['name']}:{entry['version']}"] = purl
            name_index.setdefault(entry["name"], []).append(purl)
            for descriptor in entry["descriptors"]:
                desc_purl.setdefault(descriptor, purl)

        manifest_deps: dict[str, str] = {}
        manifest_path = pkg_dir / "package.json"
        if manifest_path.exists():
            try:
                manifest = json.loads(read_text_safe(manifest_path))
                for field in ("dependencies", "devDependencies", "optionalDependencies"):
                    declared = manifest.get(field)
                    if isinstance(declared, dict):
                        for dep_name, dep_range in declared.items():
                            if isinstance(dep_name, str) and isinstance(dep_range, str):
                                manifest_deps.setdefault(dep_name, dep_range)
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

        direct_purls: set[str] = set()
        for dep_name, dep_range in manifest_deps.items():
            hit = (desc_purl.get(f"{dep_name}@{dep_range}")
                   or desc_purl.get(f"{dep_name}@npm:{dep_range}"))
            if not hit:
                purls = name_index.get(dep_name) or []
                if len(purls) == 1:
                    hit = purls[0]
            if hit:
                direct_purls.add(hit)

        components: list[dict] = []
        for entry in entries:
            name = entry["name"]
            purl = purl_of[f"{name}:{entry['version']}"]
            depends_on: list[str] = []
            for dep_name, dep_spec in entry["deps"].items():
                spec = dep_spec.removeprefix("npm:")
                if self._is_exact_version(spec):
                    target = purl_of.get(f"{dep_name}:{spec}")
                else:
                    target = (desc_purl.get(f"{dep_name}@npm:{spec}")
                              or desc_purl.get(f"{dep_name}@{spec}"))
                    if not target:
                        purls = name_index.get(dep_name) or []
                        target = purls[0] if len(purls) == 1 else None
                if target and target != purl and target not in depends_on:
                    depends_on.append(target)
            components.append({
                "name": name.split("/")[-1] if "/" in name else name,
                "group": name.split("/")[0] if "/" in name else "",
                "version": entry["version"],
                "ecosystem": "npm",
                "scope": "compile",
                "optional": False,
                "direct": purl in direct_purls,
                "source_file": source,
                "hashes": entry["hashes"],
                "download_url": entry["resolved"]
                if entry["resolved"].startswith(("http://", "https://"))
                else "",
                "registry_url": f"https://www.npmjs.com/package/{name}",
                "depends_on": depends_on,
            })

        edges: list[dict] = []
        root_purl = self._root_purl(*self._manifest_meta(pkg_dir))
        if root_purl and direct_purls:
            edges.append({"ref": root_purl, "dependsOn": sorted(direct_purls)})
        components.extend(self._parse_package_json_tree(
            pkg_dir, root_path,
            skip_known={entry["name"] for entry in entries},
        ))
        return components, edges

    @staticmethod
    def _pnpm_key_name_version(key: str) -> tuple[str, str]:
        cleaned = key.split("(")[0].strip().strip('"').strip("'")
        cleaned = cleaned.removeprefix("/")
        if cleaned.startswith("@"):
            at = cleaned.find("@", 1)
            if at > 0:
                return cleaned[:at], cleaned[at + 1:]
        elif "@" in cleaned:
            at = cleaned.find("@")
            if at > 0:
                return cleaned[:at], cleaned[at + 1:]
        if "/" in cleaned:
            name, _, version = cleaned.rpartition("/")
            return name.strip('"').strip("'"), version
        return "", ""

    @staticmethod
    def _pnpm_dep_version(value: str) -> str:
        text = value.split("(")[0].strip().strip('"').strip("'")
        if not text:
            return ""
        if text.startswith("/"):
            inner = text[1:]
            if "@" in inner:
                return inner.rsplit("@", 1)[-1]
            if "/" in inner:
                return inner.rsplit("/", 1)[-1]
            return ""
        if text[0].isdigit():
            return text
        if "@" in text:
            tail = text.rsplit("@", 1)[-1]
            if tail[:1].isdigit():
                return tail
        return ""

    @staticmethod
    def _pnpm_resolution(value: str) -> tuple[str, str]:
        text = value.strip()
        if text.startswith("{") and text.endswith("}"):
            text = text[1:-1]
        integrity = ""
        tarball = ""
        for part in text.split(","):
            key, sep, val = part.partition(":")
            if not sep:
                continue
            key = key.strip().strip('"').strip("'")
            val = val.strip().strip('"').strip("'")
            if key == "integrity":
                integrity = val
            elif key == "tarball":
                tarball = val
        return integrity, tarball

    def _parse_pnpm_lock(
        self, lockfile: Path, pkg_dir: Path, root_path: Path
    ) -> tuple[list[dict], list[dict]]:
        source = rel_posix(lockfile, root_path)
        try:
            content = read_text_safe(lockfile)
        except (UnicodeDecodeError, OSError):
            return [], []

        records: dict[str, dict] = {}
        order: list[str] = []
        direct_specs: list[tuple[str, str, str]] = []

        section = ""
        entry_key = ""
        field = ""
        dep_key = ""
        current: dict | None = None

        def flush() -> None:
            nonlocal current
            if current and current["name"] and current["version"]:
                key = f'{current["name"]}:{current["version"]}'
                if key in records:
                    rec = records[key]
                    for child in current["deps"]:
                        if child not in rec["deps"]:
                            rec["deps"].append(child)
                    if not rec["integrity"]:
                        rec["integrity"] = current["integrity"]
                    if not rec["tarball"]:
                        rec["tarball"] = current["tarball"]
                    rec["dev"] = rec["dev"] or current["dev"]
                    rec["optional"] = rec["optional"] or current["optional"]
                else:
                    records[key] = current
                    order.append(key)
            current = None

        for raw in content.splitlines():
            if not raw.strip() or raw.lstrip().startswith("#"):
                continue
            indent = len(raw) - len(raw.lstrip())
            stripped = raw.strip()

            if indent == 0:
                flush()
                field = ""
                dep_key = ""
                if stripped.endswith(":"):
                    top = stripped[:-1].strip().strip('"').strip("'")
                    if top in ("packages", "snapshots", "importers",
                               "dependencies", "devDependencies", "optionalDependencies"):
                        section = top
                        entry_key = ""
                        continue
                section = ""
                continue

            if section in ("packages", "snapshots"):
                if indent == 2 and stripped.endswith((":", "{}")):
                    flush()
                    field = ""
                    dep_key = ""
                    entry_key = stripped.split(":", 1)[0].strip().strip('"').strip("'")
                    name, version = self._pnpm_key_name_version(entry_key)
                    current = {"name": name, "version": version, "deps": [],
                               "integrity": "", "tarball": "",
                               "dev": False, "optional": False}
                    continue
                if current is None:
                    continue
                if indent == 4:
                    key_part, sep, value_part = stripped.partition(":")
                    if sep and not value_part.strip() and stripped.endswith(":"):
                        fld = key_part.strip().strip('"').strip("'")
                        field = fld if fld in ("dependencies", "optionalDependencies") else ""
                        dep_key = ""
                        continue
                    if sep:
                        fld = key_part.strip().strip('"').strip("'")
                        val = value_part.strip()
                        if fld == "resolution":
                            integrity, tarball = self._pnpm_resolution(val)
                            if integrity:
                                current["integrity"] = integrity
                            if tarball:
                                current["tarball"] = tarball
                        elif fld == "integrity":
                            current["integrity"] = val.strip('"').strip("'")
                        elif fld == "tarball":
                            current["tarball"] = val.strip('"').strip("'")
                        elif fld == "dev":
                            current["dev"] = val.lower() == "true"
                        elif fld == "optional":
                            current["optional"] = val.lower() == "true"
                        continue
                if dep_key and indent == 8:
                    key_part, sep, value_part = stripped.partition(":")
                    if sep and key_part.strip() == "version":
                        current["deps"].append((dep_key, value_part.strip()))
                        dep_key = ""
                    continue
                if field and indent == 6:
                    key_part, sep, value_part = stripped.partition(":")
                    if not sep:
                        continue
                    child_name = key_part.strip().strip('"').strip("'")
                    if not value_part.strip():
                        dep_key = child_name
                        continue
                    current["deps"].append((child_name, value_part.strip()))
                    dep_key = ""
                    continue
                continue

            if section == "importers":
                if indent == 2 and stripped.endswith(":"):
                    entry_key = stripped[:-1].strip().strip('"').strip("'")
                    if entry_key in (".", "./", ""):
                        entry_key = "."
                    else:
                        entry_key = ""
                    field = ""
                    dep_key = ""
                    continue
                if not entry_key:
                    continue
                if indent == 4:
                    key_part, sep, value_part = stripped.partition(":")
                    if sep and not value_part.strip() and stripped.endswith(":"):
                        fld = key_part.strip().strip('"').strip("'")
                        field = fld if fld in (
                            "dependencies", "devDependencies", "optionalDependencies",
                        ) else ""
                        dep_key = ""
                        continue
                if field and indent == 6:
                    key_part, sep, value_part = stripped.partition(":")
                    if not sep:
                        continue
                    child_name = key_part.strip().strip('"').strip("'")
                    if not value_part.strip():
                        dep_key = child_name
                        continue
                    direct_specs.append((child_name, value_part.strip(), field))
                    dep_key = ""
                    continue
                if dep_key and indent == 8:
                    key_part, sep, value_part = stripped.partition(":")
                    if sep and key_part.strip() == "version":
                        direct_specs.append((dep_key, value_part.strip(), field))
                        dep_key = ""
                    continue
                continue

            if section in ("dependencies", "devDependencies", "optionalDependencies"):
                if indent == 2:
                    key_part, sep, value_part = stripped.partition(":")
                    if not sep:
                        continue
                    dep_name = key_part.strip().strip('"').strip("'")
                    if not value_part.strip():
                        dep_key = dep_name
                        continue
                    direct_specs.append((dep_name, value_part.strip(), section))
                    dep_key = ""
                    continue
                if dep_key and indent >= 4:
                    key_part, sep, value_part = stripped.partition(":")
                    if sep and key_part.strip() == "version":
                        direct_specs.append((dep_key, value_part.strip(), section))
                        dep_key = ""
                    continue

        flush()

        purl_of: dict[str, str] = {}
        name_index: dict[str, list[str]] = {}
        for key in order:
            rec = records[key]
            purl_of[key] = f"pkg:npm/{rec['name']}@{rec['version']}"
            name_index.setdefault(rec["name"], []).append(purl_of[key])

        def resolve_child(name: str, value: str) -> str | None:
            version = self._pnpm_dep_version(value)
            if version:
                return purl_of.get(f"{name}:{version}")
            purls = name_index.get(name) or []
            return purls[0] if len(purls) == 1 else None

        direct_purls: set[str] = set()
        dev_purls: set[str] = set()
        for dep_name, value, kind in direct_specs:
            purl = resolve_child(dep_name, value)
            if purl:
                direct_purls.add(purl)
                if kind == "devDependencies":
                    dev_purls.add(purl)

        components: list[dict] = []
        for key in order:
            rec = records[key]
            name = rec["name"]
            purl = purl_of[key]
            depends_on: list[str] = []
            for child_name, child_value in rec["deps"]:
                child = resolve_child(child_name, child_value)
                if child and child != purl and child not in depends_on:
                    depends_on.append(child)
            components.append({
                "name": name.split("/")[-1] if "/" in name else name,
                "group": name.split("/")[0] if "/" in name else "",
                "version": rec["version"],
                "ecosystem": "npm",
                "scope": "dev" if rec["dev"] or purl in dev_purls else "compile",
                "optional": bool(rec["optional"]),
                "direct": purl in direct_purls,
                "source_file": source,
                "hashes": sri_hashes(rec["integrity"]),
                "download_url": rec["tarball"]
                if rec["tarball"].startswith(("http://", "https://"))
                else "",
                "registry_url": f"https://www.npmjs.com/package/{name}",
                "depends_on": depends_on,
            })

        edges: list[dict] = []
        root_purl = self._root_purl(*self._manifest_meta(pkg_dir))
        if root_purl and direct_purls:
            edges.append({"ref": root_purl, "dependsOn": sorted(direct_purls)})
        components.extend(self._parse_package_json_tree(
            pkg_dir, root_path,
            skip_known={rec["name"] for rec in records.values()},
        ))
        return components, edges

    def _parse_package_json_tree(
        self, pkg_dir: Path, root_path: Path, skip_known: set[str] | None = None
    ) -> list[dict]:
        """Direct deps declared in package.json, filtered against what the lockfile already gave."""
        pkg_path = pkg_dir / "package.json"
        if not pkg_path.exists():
            return []
        results: list[dict] = []
        try:
            data = json.loads(read_text_safe(pkg_path))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return results

        lock_versions = self._load_lockfile(pkg_path)
        known = skip_known or set()

        for dep_type in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            deps = data.get(dep_type, {})
            if not isinstance(deps, dict):
                continue
            for name, version_spec in deps.items():
                if name in known:
                    continue
                if isinstance(version_spec, str):
                    version = lock_versions.get(name) or (
                        "" if version_spec in ("*", "latest") else version_spec
                    )
                else:
                    version = lock_versions.get(name) or ""
                scope = "dev" if dep_type == "devDependencies" else "compile"
                if dep_type == "peerDependencies":
                    scope = "provided"
                optional = dep_type == "optionalDependencies"

                results.append({
                    "name": name.split("/")[-1] if "/" in name else name,
                    "group": name.split("/")[0] if "/" in name else "",
                    "version": version,
                    "ecosystem": "npm",
                    "scope": scope,
                    "optional": optional,
                    "direct": True,
                    "source_file": rel_posix(pkg_path, root_path),
                    "registry_url": f"https://www.npmjs.com/package/{name}",
                    "depends_on": [],
                })

        return results

    def _load_lockfile(self, pkg_path: Path) -> dict[str, str]:
        """Pinned versions for manifest fallback — shrinkwrap first (§5.3)."""
        candidates = ("npm-shrinkwrap.json", "package-lock.json")
        lockfile = next(
            (pkg_path.parent / name for name in candidates
             if (pkg_path.parent / name).exists()),
            None,
        )
        if lockfile is None:
            return {}
        try:
            data = json.loads(lockfile.read_text(encoding="utf-8-sig"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

        versions: dict[str, str] = {}
        lock_deps = data.get("packages", data.get("dependencies", {}))
        for key, val in lock_deps.items():
            if not key or key == "":
                continue
            name = key.rsplit("/", 1)[-1] if "/" in key else key
            ver = val.get("version", "")
            if ver:
                versions[name] = ver
        return versions

import json
import re
from pathlib import Path

from .base import DependencyCollector, rel_posix


class SwiftCollector(DependencyCollector):

    def supported_files(self) -> list[str]:
        return ["Package.swift", "Package.resolved", "Podfile", "Podfile.lock"]

    def collect(self, project_path: Path) -> tuple[list[dict], list[dict]]:
        """CocoaPods and SwiftPM are independent package managers (§5.3).

        Podfile.lock carries the full pod graph. SwiftPM's static evidence
        (Package.resolved pins) has no graph, so the CLI is consulted for
        depth when available; otherwise the pins + declarations stand alone.
        """
        components: list[dict] = []
        edges: list[dict] = []

        pod_components, pod_edges = self._collect_cocoapods(project_path)
        components.extend(pod_components)
        edges.extend(pod_edges)

        if self._command_exists("swift"):
            cli_components, cli_edges = self._run_swift_show(project_path)
            if cli_components:
                components.extend(cli_components)
                edges.extend(cli_edges)
                return components, edges

        components.extend(self._parse_swiftpm_static(project_path))
        return components, edges

    # ── CocoaPods ──────────────────────────────────────────────────────────

    def _collect_cocoapods(self, project_path: Path) -> tuple[list[dict], list[dict]]:
        for lock in project_path.rglob("Podfile.lock"):
            if "Pods" in lock.parts:
                continue
            components, edges = self._parse_podfile_lock(lock, project_path)
            if components:
                return components, edges

        components: list[dict] = []
        for podfile in project_path.rglob("Podfile"):
            if "Pods" in podfile.parts:
                continue
            components.extend(self._parse_podfile(podfile, project_path))
        return components, []

    @staticmethod
    def _pod_purl(name: str, version: str) -> str:
        return f"pkg:cocoapods/{name}@{version}" if version else f"pkg:cocoapods/{name}"

    def _parse_podfile_lock(
        self, lockfile_path: Path, root_path: Path
    ) -> tuple[list[dict], list[dict]]:
        """Parse the PODS tree: indentation carries pod → dependency edges.

        A child line inside ``PODS`` may show a requirement (`~> 5.0`) instead
        of its locked version — the locked version from that pod's own entry
        wins, and a version that is never locked stays empty (§7).
        """
        try:
            lines = lockfile_path.read_text(encoding="utf-8-sig").splitlines()
        except OSError:
            return [], []

        raw_entries: list[tuple[int, str, str]] = []
        direct_names: set[str] = set()
        section = ""

        for line in lines:
            if line and line[0] not in " \t":
                section = line.strip()[:-1] if line.strip().endswith(":") else ""
                continue
            stripped = line.strip()
            if not stripped.startswith("- "):
                continue
            if section == "PODS":
                indent = len(line) - len(line.lstrip(" "))
                match = re.match(r"^(.+?)\s+\(([^)]+)\):?\s*$", stripped[2:])
                if match:
                    raw_entries.append((indent, *match.groups()))
            elif section == "DEPENDENCIES":
                direct_names.add(stripped[2:].split(" ")[0].strip())

        if not raw_entries:
            return [], []

        locked: dict[str, str] = {}
        for _indent, name, version in raw_entries:
            if name in locked:
                continue
            if version[:1].isdigit():
                locked[name] = version
            elif version.startswith("= "):
                locked[name] = version[2:].strip()

        if not direct_names:
            top_indent = min(indent for indent, _n, _v in raw_entries)
            direct_names = {
                name for indent, name, _v in raw_entries if indent == top_indent
            }

        components: list[dict] = []
        by_name: dict[str, dict] = {}
        stack: list[tuple[int, dict]] = []
        source = rel_posix(lockfile_path, root_path)

        for indent, name, _version in raw_entries:
            comp = by_name.get(name)
            if comp is None:
                version = locked.get(name, "")
                comp = {
                    "name": name,
                    "group": "",
                    "version": version,
                    "ecosystem": "swift",
                    "purl_type": "cocoapods",
                    "scope": "compile",
                    "optional": False,
                    "direct": name in direct_names,
                    "source_file": source,
                    "registry_url": f"https://cocoapods.org/pods/{name}",
                    "hashes": [],
                    "depends_on": [],
                }
                components.append(comp)
                by_name[name] = comp

            while stack and stack[-1][0] >= indent:
                stack.pop()
            if stack:
                parent = stack[-1][1]
                child_purl = self._pod_purl(comp["name"], comp["version"])
                if (child_purl != self._pod_purl(parent["name"], parent["version"])
                        and child_purl not in parent["depends_on"]):
                    parent["depends_on"].append(child_purl)
            stack.append((indent, comp))

        return components, []

    def _parse_podfile(self, podfile_path: Path, root_path: Path) -> list[dict]:
        results: list[dict] = []

        try:
            lines = podfile_path.read_text(encoding="utf-8-sig").splitlines()
        except OSError:
            return results

        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            match = re.match(r"""pod\s+['"]([^'"]+)['"](?:,\s*['"]([^'"]+)['"])?""", stripped)
            if match:
                name = match.group(1)
                version = match.group(2) or ""

                results.append({
                    "name": name,
                    "group": "",
                    "version": version,
                    "ecosystem": "swift",
                    "purl_type": "cocoapods",
                    "scope": "compile",
                    "optional": False,
                    "direct": True,
                    "source_file": rel_posix(podfile_path, root_path),
                    "registry_url": f"https://cocoapods.org/pods/{name}",
                    "hashes": [],
                    "depends_on": [],
                })

        return results

    # ── SwiftPM ────────────────────────────────────────────────────────────

    def _parse_swiftpm_static(self, project_path: Path) -> list[dict]:
        manifest_components: list[dict] = []
        for pkg_file in project_path.rglob("Package.swift"):
            manifest_components.extend(self._parse_package_swift(pkg_file, project_path))

        resolved_components: list[dict] = []
        for resolved in project_path.rglob("Package.resolved"):
            resolved_components.extend(self._parse_package_resolved(resolved, project_path))

        if resolved_components:
            # Exact pins win over declared ranges (§5.3); the declarations only
            # tell us which pins are the project's direct dependencies.
            declared = {c["name"].lower() for c in manifest_components}
            for comp in resolved_components:
                comp["direct"] = comp["name"].lower() in declared
            return resolved_components

        return manifest_components

    def _run_swift_show(self, project_path: Path) -> tuple[list[dict], list[dict]]:
        results: list[dict] = []
        edges: list[dict] = []
        seen: set[str] = set()
        by_key: dict[str, dict] = {}

        for pkg_dir in self._find_swift_roots(project_path):
            output = self._run_cli_json(
                ["swift", "package", "show-dependencies", "--json"],
                cwd=pkg_dir,
                timeout=120,
            )
            if not output:
                continue
            try:
                root_purl, children = self._walk_swift_deps(
                    output, results, seen, by_key, project_path, depth=0
                )
            except (AttributeError, TypeError):
                # Malformed `swift package show-dependencies` trees are
                # skipped rather than aborting the scan.
                continue
            if root_purl and children:
                edges.append({"ref": root_purl, "dependsOn": children})

        return results, edges

    def _walk_swift_deps(
        self,
        node: dict,
        results: list[dict],
        seen: set[str],
        by_key: dict[str, dict],
        root_path: Path,
        depth: int,
    ) -> tuple[str | None, list[str]]:
        """Register ``node`` and its subtree; return (its purl, child purls).

        The depth-0 node is the local package — an edge anchor, never a
        component of the SBOM.
        """
        name = node.get("name", "")
        url = node.get("url", "")
        version = node.get("version", "")

        if depth == 0:
            if not name:
                return None, []
            root_purl = f"pkg:swift/{name}@{version}" if version else f"pkg:swift/{name}"
            children: list[str] = []
            for child in node.get("dependencies", []) or []:
                child_purl, _grandchildren = self._walk_swift_deps(
                    child, results, seen, by_key, root_path, depth + 1
                )
                if child_purl:
                    children.append(child_purl)
            return root_purl, children

        if not name or not version:
            return None, []

        purl = f"pkg:swift/{name}@{version}"
        key = f"{name}:{version}"
        comp = by_key.get(key)
        if comp is None:
            repo_name = (
                url.rstrip("/").rsplit("/", 1)[-1].replace(".git", "") if url else name
            )
            comp = {
                "name": name,
                "group": repo_name,
                "version": version,
                "ecosystem": "swift",
                "scope": "compile",
                "optional": False,
                "direct": depth == 1,
                "source_file": "swift package show-dependencies --json",
                "homepage": url or f"https://github.com/{name}",
                "repository": url or f"https://github.com/{name}",
                "hashes": [],
                "depends_on": [],
            }
            results.append(comp)
            by_key[key] = comp
            seen.add(key)
        elif depth == 1:
            comp["direct"] = True

        children = []
        for child in node.get("dependencies", []) or []:
            child_purl, _grandchildren = self._walk_swift_deps(
                child, results, seen, by_key, root_path, depth + 1
            )
            if child_purl and child_purl != purl:
                children.append(child_purl)
        for child_purl in children:
            if child_purl not in comp["depends_on"]:
                comp["depends_on"].append(child_purl)

        return purl, children

    def _find_swift_roots(self, project_path: Path) -> list[Path]:
        roots = []
        for pkg in project_path.rglob("Package.swift"):
            roots.append(pkg.parent)
        return roots[:5]

    def _parse_package_swift(self, pkg_path: Path, root_path: Path) -> list[dict]:
        results: list[dict] = []

        try:
            content = pkg_path.read_text(encoding="utf-8-sig")
        except OSError:
            return results

        for line in content.splitlines():
            stripped = line.strip()
            if ".package(" in stripped and ("url:" in stripped or stripped.startswith(".package")):
                url_match = re.search(r'url:\s*"([^"]+)"', stripped)
                name_match = re.search(r'Name\("([^"]+)"\)', stripped)
                version_match = re.search(r'from:\s*"([^"]+)"', stripped)

                if url_match and version_match:
                    url = url_match.group(1)
                    version = version_match.group(1).lstrip("v")
                    name = name_match.group(1) if name_match else url.rstrip("/").rsplit("/", 1)[-1].replace(".git", "")

                    results.append({
                        "name": name,
                        "group": "",
                        "version": version,
                        "ecosystem": "swift",
                        "scope": "compile",
                        "optional": False,
                        "direct": True,
                        "source_file": rel_posix(pkg_path, root_path),
                        "homepage": url,
                        "repository": url,
                        "hashes": [],
                        "depends_on": [],
                    })

        return results

    def _parse_package_resolved(self, resolved_path: Path, root_path: Path) -> list[dict]:
        results: list[dict] = []

        try:
            data = json.loads(resolved_path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            return results

        pins = data.get("pins", [])
        if isinstance(pins, dict):
            pins = list(pins.values())

        for pin in pins:
            identity = pin.get("identity", "")
            location = pin.get("location", pin.get("repositoryURL", ""))
            version = pin.get("version", pin.get("state", {}).get("version", ""))

            if not identity or not version:
                continue

            results.append({
                "name": identity,
                "group": "",
                "version": version,
                "ecosystem": "swift",
                "scope": "compile",
                "optional": False,
                "direct": False,
                "source_file": rel_posix(resolved_path, root_path),
                "homepage": location or f"https://github.com/{identity}",
                "repository": location or f"https://github.com/{identity}",
                "hashes": [],
                "depends_on": [],
            })

        return results

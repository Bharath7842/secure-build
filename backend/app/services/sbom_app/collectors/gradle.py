import logging
import re
import subprocess
from pathlib import Path

from .base import DependencyCollector, prefer_static_or_cli, purl_for, rel_posix

logger = logging.getLogger("sbom.collectors")

_MARKER = re.compile(r"(?P<marker>\+---|\\---)\s+(?P<rest>\S.*)")
# gradle.lockfile: ``group:name:version=configurations`` (§5.3) or ``empty=<conf>``.
_LOCK_LINE = re.compile(r"^(?P<group>[^:=]+):(?P<name>[^:=]+):(?P<version>[^=]+)=(?P<config>.+)$")


class GradleCollector(DependencyCollector):

    def supported_files(self) -> list[str]:
        return ["build.gradle", "build.gradle.kts", "gradle.lockfile"]

    def collect(self, project_path: Path) -> list[dict]:
        """§5.3 pipeline: gradle.lockfile → build.gradle → ``gradle dependencies``.

        The lockfile pins the full resolved closure (direct flags derived
        from the sibling build scripts), so it is never preempted by the
        CLI; the CLI tree only replaces manifest evidence because it adds
        real transitive depth.
        """
        # 1. Lockfile first (§5.3): exact resolved versions.
        components = self._parse_gradle_lockfiles(project_path)
        if components:
            return components

        # 2. Manifest: declared coordinates and the version catalog.
        for gradle_file in sorted(project_path.rglob("build.gradle*")):
            if "buildSrc" in gradle_file.parts or ".gradle" in gradle_file.parts:
                continue
            if gradle_file.name in ("build.gradle", "build.gradle.kts"):
                components.extend(self._parse_gradle_file(gradle_file, project_path))

        # 3. CLI fallback (§5): only when static evidence has no depth to add.
        return prefer_static_or_cli(components, self._run_gradle_tree(project_path))

    def _parse_gradle_lockfiles(self, project_path: Path) -> list[dict]:
        """All ``gradle.lockfile`` files: pins for the resolved closure.

        The lockfile does not record which module pulled which, so only the
        sibling build scripts' declared coordinates are marked direct — the
        rest is reported as locked-but-transitive evidence (§4).
        """
        components: list[dict] = []
        seen: set[str] = set()

        for lockfile in sorted(project_path.rglob("gradle.lockfile")):
            if "buildSrc" in lockfile.parts or ".gradle" in lockfile.parts:
                continue
            declared = self._declared_coordinates(lockfile.parent, project_path)
            try:
                content = lockfile.read_text(encoding="utf-8-sig")
            except OSError:
                continue

            for raw in content.splitlines():
                stripped = raw.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                match = _LOCK_LINE.match(stripped)
                if not match:
                    continue
                group = match.group("group").strip()
                name = match.group("name").strip()
                version = match.group("version").strip()
                key = f"{group}:{name}:{version}"
                if not group or not name or not version or key in seen:
                    continue
                seen.add(key)
                components.append({
                    "name": name,
                    "group": group,
                    "version": version,
                    "ecosystem": "gradle",
                    "scope": "compile",
                    "optional": False,
                    "direct": (group, name) in declared,
                    "source_file": rel_posix(lockfile, project_path),
                    "registry_url": f"https://mvnrepository.com/artifact/{group}/{name}/{version}",
                    "hashes": [],
                    "depends_on": [],
                })

        return components

    def _declared_coordinates(self, gradle_dir: Path, root_path: Path) -> set[tuple[str, str]]:
        """``(group, name)`` pairs declared by the build scripts in one dir."""
        declared: set[tuple[str, str]] = set()
        for name in ("build.gradle", "build.gradle.kts"):
            path = gradle_dir / name
            if not path.exists():
                continue
            for comp in self._parse_gradle_file(path, root_path):
                group, dep_name = comp.get("group", ""), comp.get("name", "")
                if group and dep_name:
                    declared.add((group, dep_name))
        return declared

    def _run_gradle_tree(self, project_path: Path) -> list[dict]:
        """``gradle dependencies`` output as components with tree edges (§5)."""
        if not list(project_path.rglob("build.gradle*")):
            return []

        results: list[dict] = []
        seen: set[str] = set()

        for gradle_dir in self._find_gradle_roots(project_path):
            try:
                output = subprocess.run(
                    "gradle dependencies --configuration compileClasspath",
                    cwd=str(gradle_dir),
                    capture_output=True,
                    text=True,
                    timeout=300,
                    shell=True,
                )
                if output.returncode == 0 and output.stdout:
                    results.extend(self._parse_dependency_tree(output.stdout, project_path, seen))
                elif output.returncode != 0:
                    tail = (output.stderr or "").strip().splitlines()[-1:]
                    logger.warning(
                        "Command exited with code %s: gradle dependencies%s",
                        output.returncode,
                        f" — {tail[0]}" if tail else "",
                    )
            except (subprocess.TimeoutExpired, FileNotFoundError):
                logger.warning("Command not found or timed out: gradle dependencies")

        return results

    def _find_gradle_roots(self, project_path: Path) -> list[Path]:
        roots = []
        for f in project_path.rglob("build.gradle*"):
            if "buildSrc" not in str(f) and ".gradle" not in str(f):
                parent = f.parent
                if parent not in roots:
                    roots.append(parent)
        return roots[:5]

    def _parse_dependency_tree(
        self, output: str, root_path: Path, seen: set[str]
    ) -> list[dict]:
        """Parse `gradle dependencies` output into components + relationships.

        Nesting is reconstructed from the marker column, so arbitrarily deep
        trees work: a node's parent is the closest earlier node with a smaller
        column. Nodes at column 0 are direct (§5.4); `project :x` entries are
        kept as structural placeholders so their children never attach to the
        wrong parent.
        """
        results: list[dict] = []
        by_coord: dict[str, dict] = {}
        # (marker column, component or None for structural placeholders)
        stack: list[tuple[int, dict | None]] = []

        for line in output.splitlines():
            match = _MARKER.search(line)
            if not match:
                continue
            column = match.start()
            while stack and stack[-1][0] >= column:
                stack.pop()

            tokens = match.group("rest").split()
            component = None
            if tokens and tokens[0] != "project":
                coordinate = self._parse_coordinate(tokens)
                if coordinate is not None:
                    group, name, version = coordinate
                    key = f"{group}:{name}:{version}"
                    component = by_coord.get(key)
                    if component is None:
                        component = self._build_tree_component(
                            group, name, version, root_path
                        )
                        by_coord[key] = component
                        if key not in seen:
                            seen.add(key)
                            results.append(component)

            parent = stack[-1][1] if stack else None
            if component is not None:
                if parent is None:
                    component["direct"] = True
                else:
                    child_purl = purl_for(component)
                    if child_purl not in parent["depends_on"]:
                        parent["depends_on"].append(child_purl)
            stack.append((column, component))

        return results

    def _parse_coordinate(self, tokens: list[str]) -> tuple[str, str, str] | None:
        """`group:name:version`, optionally with a conflict marker (`-> v`)."""
        head = tokens[0]
        if "->" in tokens:
            arrow = tokens.index("->")
            resolved = tokens[arrow + 1] if arrow + 1 < len(tokens) else ""
        else:
            resolved = ""
        parts = head.split(":")
        if len(parts) < 3:
            return None
        group, name, version = parts[0], parts[1], parts[2]
        if resolved:
            version = resolved
        version = version.split("@", 1)[0]
        if not group or not name or not version or any(
            char.isspace() for char in version
        ):
            return None
        return group, name, version

    def _build_tree_component(
        self, group: str, name: str, version: str, root_path: Path
    ) -> dict:
        return {
            "name": name,
            "group": group,
            "version": version,
            "ecosystem": "gradle",
            "scope": "compile",
            "optional": False,
            "direct": False,
            "source_file": "gradle dependencies",
            "registry_url": f"https://mvnrepository.com/artifact/{group}/{name}/{version}",
            "hashes": [],
            "depends_on": [],
        }

    def _parse_gradle_file(self, gradle_path: Path, root_path: Path) -> list[dict]:
        results: list[dict] = []

        try:
            content = gradle_path.read_text(encoding="utf-8-sig")
        except Exception:
            return results

        patterns = [
            re.compile(r"""(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s+['"]([^'"]+):([^'"]+):([^'"]+)['"]"""),
            re.compile(r"""(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s+\((?:group:\s*['"]([^'"]+)['"],?\s*name:\s*['"]([^'"]+)['"],?\s*version:\s*['"]([^'"]+)['"])"""),
        ]

        for pattern in patterns:
            for match in pattern.finditer(content):
                group, name, version = match.groups()
                if group and name and version:
                    results.append({
                        "name": name,
                        "group": group,
                        "version": version,
                        "ecosystem": "gradle",
                        "scope": "compile",
                        "optional": False,
                        "direct": True,
                        "source_file": rel_posix(gradle_path, root_path),
                        "registry_url": f"https://mvnrepository.com/artifact/{group}/{name}/{version}",
                        "hashes": [],
                        "depends_on": [],
                    })

        version_catalog = self._parse_version_catalog(
            gradle_path.parent, root_path
        )
        results.extend(version_catalog)

        return results

    def _parse_version_catalog(
        self, gradle_dir: Path, root_path: Path
    ) -> list[dict]:
        results: list[dict] = []
        catalog_file = gradle_dir / "gradle" / "libs.versions.toml"

        if not catalog_file.exists():
            return results

        try:
            content = catalog_file.read_text(encoding="utf-8-sig")
        except Exception:
            return results

        versions: dict[str, str] = {}
        libraries: dict[str, tuple[str, str, str]] = {}

        current_section = None
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            section_match = re.match(r"^\[(\w+)\]", line)
            if section_match:
                current_section = section_match.group(1)
                continue

            if current_section == "versions":
                kv = line.split("=", 1)
                if len(kv) == 2:
                    versions[kv[0].strip()] = kv[1].strip().strip('"').strip("'")

            elif current_section == "libraries":
                kv = line.split("=", 1)
                if len(kv) == 2:
                    key = kv[0].strip()
                    value = kv[1].strip().strip('"').strip("'")
                    parts = value.split(":")
                    if len(parts) >= 3:
                        group = parts[0]
                        name = parts[1]
                        version_ref = parts[2]
                        if version_ref.startswith("{") and version_ref.endswith("}"):
                            version_ref = versions.get(version_ref[1:-1], version_ref)
                        libraries[key] = (group, name, version_ref)

        for key, (group, name, version) in libraries.items():
            if group and name and version:
                results.append({
                    "name": name,
                    "group": group,
                    "version": version,
                    "ecosystem": "gradle",
                    "scope": "compile",
                    "optional": False,
                    "direct": True,
                    "source_file": rel_posix(catalog_file, root_path),
                    "registry_url": f"https://mvnrepository.com/artifact/{group}/{name}/{version}",
                    "hashes": [],
                    "depends_on": [],
                })

        return results

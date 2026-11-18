import json
from pathlib import Path

from .base import (
    DependencyCollector,
    link_dependencies,
    prefer_static_or_cli,
    rel_posix,
)


class DartCollector(DependencyCollector):

    def supported_files(self) -> list[str]:
        return ["pubspec.yaml", "pubspec.lock"]

    def collect(self, project_path: Path) -> list[dict]:
        """§5.3 pipeline: pubspec.lock → pubspec.yaml → ``dart pub deps``.

        pubspec.lock pins every package with its direct/transitive marker
        but records no package-to-package edges, so the CLI — which reports
        the resolved dependency tree — replaces static evidence because it
        carries the transitive depth static evidence lacks (§5).
        """
        seen: set[str] = set()

        # 1. Lockfile first (§5.3): exact pins and per-package direct flags.
        static: list[dict] = []
        for pubspec in sorted(project_path.rglob("pubspec.yaml")):
            if "pubspec.lock" in pubspec.parts or ".pub-cache" in pubspec.parts:
                continue
            lockfile = pubspec.parent / "pubspec.lock"
            if lockfile.exists():
                static.extend(self._parse_lockfile(lockfile, project_path, seen))

        # 2. Manifest only when no lockfile covered the project (§5.3).
        if not static:
            static_seen: set[str] = set()
            for pubspec in sorted(project_path.rglob("pubspec.yaml")):
                if "pubspec.lock" in pubspec.parts or ".pub-cache" in pubspec.parts:
                    continue
                for comp in self._parse_pubspec(pubspec, project_path):
                    if comp["name"] in static_seen:
                        continue
                    static_seen.add(comp["name"])
                    static.append(comp)
            link_dependencies(static)

        # 3. CLI fallback (§5): only when static evidence has no depth to add.
        cli: list[dict] = []
        if self._command_exists("dart"):
            cli = self._run_dart_pub_deps(project_path)
        return prefer_static_or_cli(static, cli)

    def _run_dart_pub_deps(self, project_path: Path) -> list[dict]:
        results: list[dict] = []
        seen: set[str] = set()

        for pub_dir in self._find_dart_roots(project_path):
            output = self._run_cli(
                ["dart", "pub", "deps", "--json"],
                cwd=pub_dir,
                timeout=120,
            )
            if output:
                try:
                    data = json.loads(output)
                    packages = data.get("packages", [])
                    for pkg in packages:
                        name = pkg.get("name", "")
                        version = pkg.get("version", "")
                        source = pkg.get("source", "")

                        if not name or not version:
                            continue

                        dep_key = f"{name}:{version}"
                        if dep_key in seen:
                            continue
                        seen.add(dep_key)

                        if source == "sdk":
                            homepage = f"https://api.dart.dev/stable/{name}/index.html"
                        elif source == "hosted":
                            homepage = f"https://pub.dev/packages/{name}/versions/{version}"
                        else:
                            homepage = f"https://pub.dev/packages/{name}"

                        results.append({
                            "name": name,
                            "group": "",
                            "version": version,
                            "ecosystem": "dart",
                            "scope": "compile",
                            "optional": False,
                            "direct": pkg.get("kind", "") == "direct",
                            "source_file": "dart pub deps --json",
                            "homepage": homepage,
                            "repository": homepage,
                            "hashes": [],
                            "depends_on": [],
                            "_dep_names": [
                                child for child in (pkg.get("dependencies") or [])
                                if isinstance(child, str)
                            ],
                        })
                except Exception:
                    pass

        link_dependencies(results)
        return results

    def _find_dart_roots(self, project_path: Path) -> list[Path]:
        roots = []
        for pubspec in project_path.rglob("pubspec.yaml"):
            if ".pub-cache" not in str(pubspec):
                roots.append(pubspec.parent)
        return roots[:5]

    def _parse_lockfile(
        self, lockfile: Path, root_path: Path, seen: set[str]
    ) -> list[dict]:
        results: list[dict] = []

        try:
            content = lockfile.read_text(encoding="utf-8-sig")
        except Exception:
            return results

        in_packages = False
        current_name = ""
        current_version = ""
        current_source = "unknown"
        current_dependency = ""

        def build() -> dict:
            return self._build_component(
                current_name, current_version, current_source,
                current_dependency, root_path, lockfile,
            )

        for line in content.splitlines():
            stripped = line.strip()

            if stripped == "packages:":
                in_packages = True
                continue
            if stripped.startswith("sdks:") or stripped.startswith("artifacts:") or stripped.startswith("date:"):
                in_packages = False
                continue

            if not in_packages:
                continue

            indent = len(line) - len(line.lstrip())

            if indent == 2 and stripped.endswith(":"):
                if current_name and current_version:
                    dep_key = f"{current_name}:{current_version}"
                    if dep_key not in seen:
                        seen.add(dep_key)
                        results.append(build())
                current_name = stripped.rstrip(":")
                current_version = ""
                current_source = "unknown"
                current_dependency = ""
            elif indent == 4:
                kv = stripped.split(":", 1)
                if len(kv) == 2:
                    key = kv[0].strip()
                    value = kv[1].strip().strip('"')
                    if key == "version":
                        current_version = value
                    elif key == "source":
                        current_source = value
                    elif key == "dependency":
                        current_dependency = value

        if current_name and current_version:
            dep_key = f"{current_name}:{current_version}"
            if dep_key not in seen:
                results.append(build())

        return results

    def _build_component(
        self, name: str, version: str, source: str, dependency: str,
        root_path: Path, source_path: Path,
    ) -> dict:
        return {
            "name": name,
            "group": "",
            "version": version,
            "ecosystem": "dart",
            "scope": "compile",
            "optional": False,
            # pubspec.lock states it per package: "direct main" / "direct dev"
            # / "transitive" (§5.4).
            "direct": dependency.startswith("direct"),
            "source_file": rel_posix(source_path, root_path),
            "registry_url": f"https://pub.dev/packages/{name}",
            "hashes": [],
            "depends_on": [],
        }

    def _parse_pubspec(self, pubspec_path: Path, root_path: Path) -> list[dict]:
        results: list[dict] = []

        try:
            content = pubspec_path.read_text(encoding="utf-8-sig")
        except Exception:
            return results

        in_deps = False
        in_dev_deps = False
        current_section_indent = 0
        nested_below: int | None = None

        for line in content.splitlines():
            stripped = line.strip()
            indent = len(line) - len(line.lstrip())

            if stripped == "dependencies:":
                in_deps = True
                in_dev_deps = False
                current_section_indent = indent
                nested_below = None
                continue
            elif stripped == "dev_dependencies:":
                in_deps = False
                in_dev_deps = True
                current_section_indent = indent
                nested_below = None
                continue
            elif stripped and not stripped.startswith("#") and indent <= current_section_indent and (in_deps or in_dev_deps):
                in_deps = False
                in_dev_deps = False

            if not in_deps and not in_dev_deps:
                continue

            if stripped.startswith("#") or not stripped:
                continue

            # Lines nested under a source specifier (git:/path:/hosted: ...)
            # belong to that mapping, not to the package list (§5.2).
            if nested_below is not None and indent > nested_below:
                continue

            if ":" in stripped:
                kv = stripped.split(":", 1)
                name = kv[0].strip()
                version_raw = kv[1].strip().strip('"').strip("'")

                # SDK/source-specifier keys inside a dependency mapping.
                # A registry package can legitimately be named "path", so a
                # same-named key is skipped only when its value is not a
                # version constraint (§4: report the package, not guess).
                if name in ("sdk", "flutter", "path", "git",
                            "dependency", "hosted"):
                    is_constraint = bool(version_raw) and (
                        version_raw == "any"
                        or version_raw[0].isdigit()
                        or version_raw[0] in "^~"
                    )
                    if not is_constraint:
                        nested_below = indent
                        continue

                if version_raw == "any" or not version_raw:
                    version = ""
                else:
                    version = version_raw
                if not version_raw:
                    # Empty value: the value is a nested mapping whose
                    # deeper lines are that mapping's details.
                    nested_below = indent

                results.append({
                    "name": name,
                    "group": "",
                    "version": version,
                    "ecosystem": "dart",
                    "scope": "dev" if in_dev_deps else "compile",
                    "optional": False,
                    "direct": True,
                    "source_file": rel_posix(pubspec_path, root_path),
                    "registry_url": f"https://pub.dev/packages/{name}",
                    "hashes": [],
                    "depends_on": [],
                })

        return results

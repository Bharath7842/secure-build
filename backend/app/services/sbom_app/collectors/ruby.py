import re
from pathlib import Path

from .base import (
    DependencyCollector,
    link_dependencies,
    prefer_static_or_cli,
    rel_posix,
)

_SPEC_LINE = re.compile(r"^(?P<name>\S+) \((?P<version>[^)]+)\)$")
_DEP_LINE = re.compile(r"^(?P<name>[A-Za-z0-9_.\-]+)(?: \([^)]*\))?$")
_PLATFORM_LINE = {
    "x86_64-linux", "x86_64-darwin", "arm64-darwin", "x86-mingw-ucrt",
    "x86-mswin32-64", "x64-mingw-ucrt", "universal-darwin-20",
    "universal-darwin-21", "x86_64-linux-musl", "java",
}


class RubyCollector(DependencyCollector):

    def supported_files(self) -> list[str]:
        return ["Gemfile", "Gemfile.lock", "*.gemspec"]

    def collect(self, project_path: Path) -> list[dict]:
        """§5.3 pipeline: Gemfile.lock → Gemfile/gemspec → ``bundle list``.

        The lockfile already yields exact pins, DEPENDENCIES-derived direct
        flags and the gem graph, so it is never preempted by the CLI;
        ``bundle list`` is a flat fallback for repos with no parseable
        manifest or lockfile.
        """
        seen: set[str] = set()

        # 1. Lockfile first (§5.3): exact versions and real edges.
        components: list[dict] = []
        for gemfile in sorted(project_path.rglob("Gemfile")):
            if "vendor" in gemfile.parts:
                continue
            lockfile = gemfile.parent / "Gemfile.lock"
            if lockfile.exists():
                components.extend(self._parse_lockfile(lockfile, project_path, seen))
        if components:
            return components

        # 2. Manifest: declared constraints / gemspec adds — direct-only,
        #    one component per gem name (a Gemfile and its gemspec may both
        #    declare the same gem).
        static_seen: set[str] = set()
        for gemfile in sorted(project_path.rglob("Gemfile")):
            if "vendor" in gemfile.parts:
                continue
            for comp in self._parse_gemfile(gemfile, project_path):
                if comp["name"] in static_seen:
                    continue
                static_seen.add(comp["name"])
                components.append(comp)
        for gemspec in sorted(project_path.rglob("*.gemspec")):
            for comp in self._parse_gemspec(gemspec, project_path):
                if comp["name"] in static_seen:
                    continue
                static_seen.add(comp["name"])
                components.append(comp)

        # 3. CLI fallback (§5): only when static evidence has no depth to add.
        cli: list[dict] = []
        if self._command_exists("bundle"):
            cli = self._run_bundle_list(project_path)
        return prefer_static_or_cli(components, cli)

    def _run_bundle_list(self, project_path: Path) -> list[dict]:
        results: list[dict] = []
        seen: set[str] = set()

        for gemfile in project_path.rglob("Gemfile"):
            if "vendor" in str(gemfile):
                continue

            gem_dir = gemfile.parent
            output = self._run_cli(
                ["bundle", "list", "--parseable"],
                cwd=gem_dir,
                timeout=120,
            )
            if output:
                pattern = re.compile(r"^(\S+)\s+\((\S+)\)")
                for line in output.splitlines():
                    match = pattern.match(line.strip())
                    if match:
                        name, version = match.groups()
                        dep_key = f"{name}:{version}"
                        if dep_key in seen:
                            continue
                        seen.add(dep_key)

                        results.append({
                            "name": name,
                            "group": "",
                            "version": version,
                            "ecosystem": "ruby",
                            "scope": "compile",
                            "optional": False,
                            "direct": True,
                            "source_file": "bundle list --parseable",
                            "registry_url": f"https://rubygems.org/gems/{name}",
                            "hashes": [],
                            "depends_on": [],
                        })

        return results

    def _parse_lockfile(
        self, lockfile: Path, root_path: Path, seen: set[str]
    ) -> list[dict]:
        """Parse Gemfile.lock specs into components plus their gem graph (§5.6).

        Spec entries sit at indent 4 (``name (version)``); their dependencies
        are the lines at indent 6 underneath. The DEPENDENCIES section (indent
        2, after the specs) lists the project's direct gems.
        """
        results: list[dict] = []

        try:
            lines = lockfile.read_text(encoding="utf-8-sig").splitlines()
        except Exception:
            return results

        in_specs = False
        in_dependencies = False
        direct_names: set[str] = set()
        spec: dict | None = None

        def flush() -> None:
            nonlocal spec
            if spec and spec.get("name") and spec.get("version"):
                dep_key = f"{spec['name']}:{spec['version']}"
                if dep_key not in seen:
                    seen.add(dep_key)
                    results.append(
                        self._build_component(spec, root_path, lockfile)
                    )
            spec = None

        for raw in lines:
            stripped = raw.strip()
            indent = len(raw) - len(raw.lstrip())

            if indent == 0 and stripped:
                flush()
                if stripped.startswith(("PATH", "GIT", "GEM", "PLUGIN SOURCE")):
                    in_specs = True
                    in_dependencies = False
                elif stripped.startswith(("DEPENDENCIES", "BUNDLED WITH",
                                          "RUBY VERSION", "PLATFORMS", "CHECKSUMS")):
                    in_specs = False
                    in_dependencies = stripped.startswith("DEPENDENCIES")
                continue

            if not stripped:
                flush()
                continue

            if in_dependencies and indent > 0:
                name = stripped.split()[0].rstrip("!")
                if _DEP_LINE.match(name):
                    direct_names.add(name)
                continue

            if not in_specs:
                continue

            if indent >= 6 and spec is not None:
                if stripped in _PLATFORM_LINE:
                    continue
                match = _DEP_LINE.match(stripped)
                if match:
                    spec["_dep_names"].append(match.group("name"))
                continue

            match = _SPEC_LINE.match(stripped)
            if match and indent <= 4:
                flush()
                spec = {
                    "name": match.group("name"),
                    "version": match.group("version"),
                    "_dep_names": [],
                }

        flush()

        for comp in results:
            if comp.get("name") in direct_names:
                comp["direct"] = True
        link_dependencies(results)
        return results

    def _build_component(
        self, spec: dict, root_path: Path, source_path: Path
    ) -> dict:
        name = spec.get("name", "")
        version = spec.get("version", "")
        return {
            "name": name,
            "group": "",
            "version": version,
            "ecosystem": "ruby",
            "scope": "compile",
            "optional": False,
            "direct": False,
            "source_file": rel_posix(source_path, root_path),
            "registry_url": f"https://rubygems.org/gems/{name}",
            "hashes": [],
            "depends_on": [],
            "_dep_names": list(spec.get("_dep_names") or []),
        }

    def _parse_gemfile(self, gemfile_path: Path, root_path: Path) -> list[dict]:
        results: list[dict] = []

        try:
            lines = gemfile_path.read_text(encoding="utf-8-sig").splitlines()
        except Exception:
            return results

        in_group = False
        optional = False

        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if "group" in stripped and "do" in stripped:
                in_group = True
                optional = "optional" in stripped
                continue

            if in_group and stripped == "end":
                in_group = False
                optional = False
                continue

            match = re.match(r"""gem\s+['"]([^'"]+)['"](?:,\s*['"]([^'"]+)['"])?""", stripped)
            if match:
                name = match.group(1)
                version = match.group(2) or ""

                results.append({
                    "name": name,
                    "group": "",
                    "version": version,
                    "ecosystem": "ruby",
                    "scope": "compile",
                    "optional": optional,
                    "direct": True,
                    "source_file": rel_posix(gemfile_path, root_path),
                    "registry_url": f"https://rubygems.org/gems/{name}",
                    "hashes": [],
                    "depends_on": [],
                })

        return results

    def _parse_gemspec(self, gemspec_path: Path, root_path: Path) -> list[dict]:
        results: list[dict] = []

        try:
            content = gemspec_path.read_text(encoding="utf-8-sig")
        except Exception:
            return results

        patterns = [
            re.compile(r"""add_dependency\s+['"]([^'"]+)['"](?:,\s*['"]([^'"]+)['"])?"""),
            re.compile(r"""add_development_dependency\s+['"]([^'"]+)['"](?:,\s*['"]([^'"]+)['"])?"""),
        ]

        for pattern in patterns:
            for match in pattern.finditer(content):
                name = match.group(1)
                version = match.group(2) or ""

                results.append({
                    "name": name,
                    "group": "",
                    "version": version,
                    "ecosystem": "ruby",
                    "scope": "compile",
                    "optional": False,
                    "direct": True,
                    "source_file": rel_posix(gemspec_path, root_path),
                    "registry_url": f"https://rubygems.org/gems/{name}",
                    "hashes": [],
                    "depends_on": [],
                })

        return results

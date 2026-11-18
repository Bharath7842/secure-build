import json
from pathlib import Path

from .base import (
    DependencyCollector,
    link_dependencies,
    prefer_static_or_cli,
    rel_posix,
)


class ComposerCollector(DependencyCollector):

    def supported_files(self) -> list[str]:
        return ["composer.json", "composer.lock"]

    def collect(self, project_path: Path) -> list[dict]:
        """§5.3 pipeline: composer.lock → composer.json → ``composer show``.

        The lockfile carries exact pins, the require-graph and direct flags
        derived from the sibling manifest, so it is never preempted by the
        CLI; ``composer show`` only runs when static evidence produced
        nothing (flat, direct-only fallback).
        """
        seen: set[str] = set()

        # 1. Lockfile first (§5.3): exact versions and real edges.
        components: list[dict] = []
        for lockfile in sorted(project_path.rglob("composer.lock")):
            if "vendor" in lockfile.parts:
                continue
            components.extend(self._parse_lockfile(lockfile, project_path, seen))
        if components:
            return components

        # 2. Manifest: declared constraints, direct-only evidence.
        for composer_json in sorted(project_path.rglob("composer.json")):
            if "vendor" in composer_json.parts:
                continue
            components.extend(self._parse_composer_json(composer_json, project_path, seen))

        # 3. CLI fallback (§5): only when static evidence has no depth to add.
        cli: list[dict] = []
        if self._command_exists("composer"):
            cli = self._run_composer_show(project_path)
        return prefer_static_or_cli(components, cli)

    def _run_composer_show(self, project_path: Path) -> list[dict]:
        results: list[dict] = []
        seen: set[str] = set()

        output = self._run_cli_json(
            ["composer", "show", "--format=json"],
            cwd=project_path,
            timeout=120,
        )
        if output:
            try:
                installed = output.get("installed", [])
                for pkg in installed:
                    name = pkg.get("name", "")
                    version = pkg.get("version", "")
                    if not name or not version:
                        continue

                    dep_key = f"{name}:{version}"
                    if dep_key in seen:
                        continue
                    seen.add(dep_key)

                    results.append({
                        "name": name,
                        "group": "",
                        "version": version,
                        "ecosystem": "composer",
                        "scope": "compile",
                        "optional": False,
                        # `composer show` lists a flat installed set: with no
                        # graph to read, the honest report is direct-only (§5).
                        "direct": True,
                        "source_file": "composer show --json",
                        "registry_url": f"https://packagist.org/packages/{name}",
                        "hashes": [],
                        "depends_on": [],
                    })
            except Exception:
                pass

        return results

    def _parse_lockfile(
        self, lockfile_path: Path, root_path: Path, seen: set[str]
    ) -> list[dict]:
        results: list[dict] = []

        try:
            data = json.loads(lockfile_path.read_text(encoding="utf-8-sig"))
        except Exception:
            return results
        if not isinstance(data, dict):
            return results

        # composer.lock holds `packages` / `packages-dev` at the top level
        # (older tooling may wrap them under `content`).
        content = data.get("content") if isinstance(data.get("content"), dict) else {}
        packages = list(data.get("packages") or content.get("packages") or [])
        packages += list(data.get("packages-dev") or content.get("packages-dev") or [])

        direct_names = self._direct_names_from_manifest(lockfile_path)

        for pkg in packages:
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name", "")
            version = pkg.get("version", "")
            if not name or not version:
                continue

            dep_key = f"{name}:{version}"
            if dep_key in seen:
                continue
            seen.add(dep_key)

            results.append({
                "name": name,
                "group": "",
                "version": version,
                "ecosystem": "composer",
                "scope": "compile",
                "optional": False,
                "direct": name in direct_names,
                "source_file": rel_posix(lockfile_path, root_path),
                "registry_url": f"https://packagist.org/packages/{name}",
                "hashes": [],
                "depends_on": [],
                # require lists platform keys (php, ext-*, lib-*) — only real
                # packages (vendor/name) can be dependency graph nodes.
                "_dep_names": [
                    child for child in (pkg.get("require") or {})
                    if isinstance(child, str) and "/" in child
                ],
            })

        link_dependencies(results)
        return results

    def _direct_names_from_manifest(self, lockfile_path: Path) -> set[str]:
        """Names declared in the sibling composer.json require / require-dev."""
        try:
            manifest = json.loads(
                (lockfile_path.parent / "composer.json").read_text(encoding="utf-8-sig")
            )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return set()
        if not isinstance(manifest, dict):
            return set()

        names: set[str] = set()
        for section in ("require", "require-dev"):
            for name in (manifest.get(section) or {}):
                if isinstance(name, str) and "/" in name:
                    names.add(name)
        return names

    def _parse_composer_json(
        self, composer_path: Path, root_path: Path, seen: set[str]
    ) -> list[dict]:
        results: list[dict] = []

        try:
            data = json.loads(composer_path.read_text(encoding="utf-8-sig"))
        except Exception:
            return results

        sections = [
            ("require", True),
            ("require-dev", True),
        ]

        for section, is_direct in sections:
            deps = data.get(section, {})
            for name, constraint in deps.items():
                if not name or "/" not in name:
                    continue

                dep_key = f"{name}:{constraint}"
                if dep_key in seen:
                    continue
                seen.add(dep_key)

                version = (
                    constraint if constraint not in ("*", "", ".*") else ""
                )

                results.append({
                    "name": name,
                    "group": "",
                    "version": version,
                    "ecosystem": "composer",
                    "scope": "compile",
                    "optional": False,
                    "direct": is_direct,
                    "source_file": rel_posix(composer_path, root_path),
                    "registry_url": f"https://packagist.org/packages/{name}",
                    "hashes": [],
                    "depends_on": [],
                })

        return results

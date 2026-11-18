"""Elm collector — static parsing of ``elm.json``.

Static only: no ``elm install`` invocation. An application's ``elm.json`` is
the lockfile (exact versions in ``direct``/``indirect`` buckets); a package
declares version ranges and is direct-only (§5).
"""

import json
from pathlib import Path

from .base import DependencyCollector, path_ignored, read_text_safe, rel_posix


def _entries(section) -> list[tuple[str, str]]:
    if not isinstance(section, dict):
        return []
    return [(k, v) for k, v in section.items()
            if isinstance(k, str) and isinstance(v, str) and v]


class ElmCollector(DependencyCollector):

    def supported_files(self) -> list[str]:
        return ["elm.json"]

    def collect(self, project_path: Path) -> list[dict]:
        components: list[dict] = []
        seen: set[str] = set()

        for path in sorted(project_path.rglob("elm.json")):
            if path_ignored(path.relative_to(project_path)):
                continue
            try:
                data = json.loads(read_text_safe(path))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                continue
            if not isinstance(data, dict):
                continue
            source = rel_posix(path, project_path)
            self_name = data.get("name") if data.get("type") == "package" else None

            sections: list[tuple[object, str]] = []
            deps = data.get("dependencies")
            if isinstance(deps, dict):
                sections.append((deps, "compile"))
            tests = data.get("test-dependencies")
            if isinstance(tests, dict):
                sections.append((tests, "dev"))

            for section, scope in sections:
                # Application sections are {direct: …, indirect: …} buckets;
                # package sections are flat name -> range maps.
                buckets = (
                    (("direct", True), ("indirect", False))
                    if "direct" in section
                    else ((None, True),)
                )
                for bucket_key, default_direct in buckets:
                    sub = section.get(bucket_key) if bucket_key else section
                    for pkg, version in _entries(sub):
                        if isinstance(self_name, str) and pkg == self_name:
                            continue
                        if pkg in seen:
                            continue
                        seen.add(pkg)
                        group, _, name = pkg.partition("/")
                        comp = {
                            "name": name or pkg,
                            "group": group if name else "",
                            "version": version,
                            "ecosystem": "elm",
                            "scope": scope,
                            "direct": default_direct,
                            "source_file": source,
                            "hashes": [],
                            "depends_on": [],
                        }
                        comp["registry_url"] = (
                            f"https://package.elm-lang.org/packages/"
                            f"{group}/{name}/{version}" if group else ""
                        )
                        components.append(comp)
        return components

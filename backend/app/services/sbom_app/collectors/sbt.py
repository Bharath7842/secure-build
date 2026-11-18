"""Scala / sbt collector — static parsing of ``*.sbt`` build files.

Static only: no sbt invocation. sbt has no lockfile in common use, so the
evidence is declared direct dependencies only (§5), reported with the
transitive-depth warning downstream.
"""

import re
from pathlib import Path

from .base import DependencyCollector, path_ignored, read_text_safe, rel_posix

# "org" %% "name" % "version" [ % "config" ]  — literal versions only;
# symbolic version vals are not honest versions (§4) and are skipped.
_SBT_DEP = re.compile(
    r'"(?P<org>[^"\s]+)"\s*%%?\s*"(?P<name>[^"\s]+)"\s*%\s*"(?P<version>[^"\s]+)"'
    r'(?:\s*%\s*(?:"(?P<qcfg>[^"]*)"|(?P<icfg>[A-Za-z][A-Za-z0-9_]*)))?'
)


def _scope(config: str | None) -> str:
    if not config:
        return "compile"
    lowered = config.lower()
    if "test" in lowered:
        return "dev"
    if "provided" in lowered:
        return "provided"
    return "compile"


class SbtCollector(DependencyCollector):

    def supported_files(self) -> list[str]:
        return ["build.sbt"]

    def collect(self, project_path: Path) -> list[dict]:
        components: list[dict] = []
        seen: set[tuple[str, str, str]] = set()

        for path in sorted(project_path.rglob("*.sbt")):
            if path_ignored(path.relative_to(project_path)):
                continue
            try:
                content = read_text_safe(path)
            except (OSError, UnicodeDecodeError):
                continue
            source = rel_posix(path, project_path)
            for match in _SBT_DEP.finditer(content):
                org = match.group("org")
                name = match.group("name")
                version = match.group("version")
                key = (org, name, version)
                if key in seen:
                    continue
                seen.add(key)
                components.append({
                    "name": name,
                    "group": org,
                    "version": version,
                    "ecosystem": "sbt",
                    "scope": _scope(match.group("qcfg") or match.group("icfg")),
                    "direct": True,
                    "source_file": source,
                    "hashes": [],
                    "depends_on": [],
                    "registry_url": (
                        f"https://central.sonatype.com/artifact/{org}/{name}/{version}"
                    ),
                })
        return components

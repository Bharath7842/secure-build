"""manifest_parsers.py — per-ecosystem dependency-manifest parsers.

Each parser takes manifest file text and returns a flat list of Dependency
dicts: {"ecosystem", "name", "version", "scope"}. Pure structured/semi-
structured parsing of build/dependency manifests — no LLM, no reading of
application source code.

Covers the manifest formats for every ecosystem the existing marker-file
heuristic (`DEPENDENCY_MARKER_FILES` in sast_scan_agent.py) already
recognizes, plus Ruby/PHP/Rust. Deliberately scoped to *direct* declared
dependencies parsed from the manifest itself — not lockfiles, not full
dependency-resolution (Maven inheritance/BOM imports, Gradle version
catalogs, etc.). A dependency that can't be parsed cleanly is skipped
rather than raising, since a partial manifest read is still strictly more
useful than none.
"""

from __future__ import annotations

import json
import re
import tomllib
from typing import Any, Dict, List, Optional, Tuple
from xml.etree import ElementTree as ET

Dependency = Dict[str, Any]


def _dep(ecosystem: str, name: str, version: Optional[str], scope: str = "runtime") -> Dependency:
    return {"ecosystem": ecosystem, "name": name, "version": version, "scope": scope}


# ===========================================================================
# Maven — pom.xml
# ===========================================================================

_NS_RE = re.compile(r"\{[^}]*\}")


def _strip_ns(tag: str) -> str:
    return _NS_RE.sub("", tag)


def extract_pom_properties(text: str) -> Dict[str, str]:
    """Just the <properties> block — used by callers to seed child-module
    ${property} resolution from a parent pom found elsewhere in the repo."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return {}
    props: Dict[str, str] = {}
    for el in root:
        if _strip_ns(el.tag) == "properties":
            for child in el:
                if child.text:
                    props[_strip_ns(child.tag)] = child.text.strip()
    return props


def parse_pom_xml(text: str, properties: Optional[Dict[str, str]] = None) -> List[Dependency]:
    """<dependencies>/<dependencyManagement> direct declarations.

    Best-effort ${property} resolution against this file's own <properties>
    plus any externally-supplied properties (e.g. a parent pom's, found
    elsewhere in the same repo walk) — unresolved placeholders are left as
    literal text rather than dropped, since "${spring.version}" is still
    more useful signal than silently losing the dependency. Full Maven
    inheritance/BOM-import resolution is out of scope.
    """
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []

    props: Dict[str, str] = dict(properties or {})
    props.update(extract_pom_properties(text))

    def resolve(value: Optional[str]) -> Optional[str]:
        if not value or "${" not in value:
            return value
        return re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), value)

    deps: List[Dependency] = []
    for dep_el in root.iter():
        if _strip_ns(dep_el.tag) != "dependency":
            continue
        group_id = artifact_id = version = scope = None
        for child in dep_el:
            tag = _strip_ns(child.tag)
            value = (child.text or "").strip() or None
            if tag == "groupId":
                group_id = value
            elif tag == "artifactId":
                artifact_id = value
            elif tag == "version":
                version = value
            elif tag == "scope":
                scope = value
        if not artifact_id:
            continue
        name = f"{group_id}:{artifact_id}" if group_id else artifact_id
        deps.append(_dep("maven", name, resolve(version), scope or "runtime"))
    return deps


# ===========================================================================
# Gradle — build.gradle / build.gradle.kts
# ===========================================================================

_GRADLE_DEP_RE = re.compile(
    r"""(?:implementation|api|compile|runtimeOnly|compileOnly|testImplementation)
        \s*[\(\s]\s*
        ['"]([\w.\-]+):([\w.\-]+):([\w.\-+]+)['"]""",
    re.VERBOSE,
)


def parse_gradle(text: str) -> List[Dependency]:
    """Regex-based extraction of `'group:artifact:version'` coordinate
    strings — not a full Groovy/Kotlin DSL parser. Misses computed versions
    (variables, version catalogs); those just don't show up, rather than
    raising."""
    return [
        _dep("maven", f"{group}:{artifact}", version)
        for group, artifact, version in _GRADLE_DEP_RE.findall(text)
    ]


# ===========================================================================
# npm — package.json
# ===========================================================================

def parse_package_json(text: str) -> List[Dependency]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    deps: List[Dependency] = []
    for scope, key in (("runtime", "dependencies"), ("dev", "devDependencies"), ("peer", "peerDependencies")):
        section = data.get(key)
        if not isinstance(section, dict):
            continue
        for name, version in section.items():
            deps.append(_dep("npm", name, str(version) if version is not None else None, scope))
    return deps


# ===========================================================================
# Python — requirements.txt / pyproject.toml
# ===========================================================================

_REQ_LINE_RE = re.compile(
    r"^\s*([A-Za-z0-9_.\-]+)\s*(\[[^\]]*\])?\s*([<>=!~]{1,2}=?[\w.\*]+(?:\s*,\s*[<>=!~]{1,2}=?[\w.\*]+)*)?"
)


def parse_requirements_txt(text: str) -> List[Dependency]:
    deps: List[Dependency] = []
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith(("-r", "-e", "--", "-c")):
            continue
        m = _REQ_LINE_RE.match(line)
        if not m or not m.group(1):
            continue
        version = m.group(3).strip() if m.group(3) else None
        deps.append(_dep("pypi", m.group(1), version))
    return deps


def _split_pep508(entry: str) -> Tuple[str, Optional[str]]:
    m = re.match(r"^\s*([A-Za-z0-9_.\-]+)\s*(\[[^\]]*\])?\s*(.*)$", entry)
    if not m:
        return entry.strip(), None
    return m.group(1), (m.group(3).strip() or None)


def parse_pyproject_toml(text: str) -> List[Dependency]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    deps: List[Dependency] = []

    project_deps = (data.get("project") or {}).get("dependencies")
    if isinstance(project_deps, list):
        for entry in project_deps:
            name, version = _split_pep508(str(entry))
            deps.append(_dep("pypi", name, version))

    poetry_deps = ((data.get("tool") or {}).get("poetry") or {}).get("dependencies") or {}
    if isinstance(poetry_deps, dict):
        for name, spec in poetry_deps.items():
            if name.lower() == "python":
                continue
            version = spec if isinstance(spec, str) else (spec.get("version") if isinstance(spec, dict) else None)
            deps.append(_dep("pypi", name, version))

    return deps


# ===========================================================================
# Go — go.mod
# ===========================================================================

_GO_REQUIRE_LINE_RE = re.compile(r"^\s*([\w.\-/]+)\s+(v[\w.\-+]+)")


def parse_go_mod(text: str) -> List[Dependency]:
    deps: List[Dependency] = []
    in_block = False
    for raw_line in text.splitlines():
        line = raw_line.split("//", 1)[0].strip()
        if not line:
            continue
        if line.startswith("require") and line.endswith("("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        target = line[len("require "):].strip() if (not in_block and line.startswith("require ")) else (line if in_block else None)
        if target is None:
            continue
        m = _GO_REQUIRE_LINE_RE.match(target)
        if m:
            deps.append(_dep("go", m.group(1), m.group(2)))
    return deps


# ===========================================================================
# Ruby — Gemfile
# ===========================================================================

_GEM_LINE_RE = re.compile(r"""gem\s+['"]([\w.\-]+)['"](?:\s*,\s*['"]([^'"]+)['"])?""")


def parse_gemfile(text: str) -> List[Dependency]:
    deps: List[Dependency] = []
    for line in text.splitlines():
        m = _GEM_LINE_RE.search(line)
        if m:
            deps.append(_dep("rubygems", m.group(1), m.group(2)))
    return deps


# ===========================================================================
# PHP — composer.json
# ===========================================================================

def parse_composer_json(text: str) -> List[Dependency]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    deps: List[Dependency] = []
    for scope, key in (("runtime", "require"), ("dev", "require-dev")):
        section = data.get(key)
        if not isinstance(section, dict):
            continue
        for name, version in section.items():
            if name == "php" or name.startswith("ext-"):
                continue
            deps.append(_dep("packagist", name, str(version), scope))
    return deps


# ===========================================================================
# .NET — *.csproj
# ===========================================================================

def parse_csproj(text: str) -> List[Dependency]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    deps: List[Dependency] = []
    for el in root.iter():
        if _strip_ns(el.tag) != "PackageReference":
            continue
        name = el.get("Include") or el.get("Update")
        version = el.get("Version")
        if version is None:
            for child in el:
                if _strip_ns(child.tag) == "Version" and child.text:
                    version = child.text.strip()
        if name:
            deps.append(_dep("nuget", name, version))
    return deps


# ===========================================================================
# Rust — Cargo.toml
# ===========================================================================

def parse_cargo_toml(text: str) -> List[Dependency]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    deps: List[Dependency] = []
    for section_name in ("dependencies", "dev-dependencies", "build-dependencies"):
        section = data.get(section_name)
        if not isinstance(section, dict):
            continue
        scope = "runtime" if section_name == "dependencies" else "dev"
        for name, spec in section.items():
            version = spec if isinstance(spec, str) else (spec.get("version") if isinstance(spec, dict) else None)
            deps.append(_dep("cratesio", name, version, scope))
    return deps


# ===========================================================================
# Dispatch
# ===========================================================================

PARSERS_BY_FILENAME = {
    "pom.xml": parse_pom_xml,
    "build.gradle": parse_gradle,
    "build.gradle.kts": parse_gradle,
    "package.json": parse_package_json,
    "requirements.txt": parse_requirements_txt,
    "pyproject.toml": parse_pyproject_toml,
    "go.mod": parse_go_mod,
    "Gemfile": parse_gemfile,
    "composer.json": parse_composer_json,
    "Cargo.toml": parse_cargo_toml,
}

PARSERS_BY_EXT = {
    ".csproj": parse_csproj,
}


def parse_manifest(filename: str, ext: str, text: str) -> List[Dependency]:
    """Generic dispatch by filename/extension. `pom.xml` callers that need
    multi-module ${property} resolution should call `parse_pom_xml` directly
    with a `properties` dict instead of going through this dispatcher."""
    parser = PARSERS_BY_FILENAME.get(filename) or PARSERS_BY_EXT.get(ext)
    if parser is None:
        return []
    try:
        return parser(text)
    except Exception:  # noqa: BLE001 — a malformed manifest must not sink the scan
        return []

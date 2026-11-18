import logging

from ..graph.state import SBOMState
from ..sbom.purl import generate_purl

logger = logging.getLogger("sbom.normalize")

COLLECTION_METHOD_MAP = {
    "dependency:tree": "mvn dependency:tree",
    "pom.xml": "pom.xml parsing",
    "package-lock.json": "npm lockfile parsing",
    "yarn.lock": "yarn lockfile parsing",
    "pnpm-lock.yaml": "pnpm lockfile parsing",
    "npm ls": "npm ls --json",
    "package.json": "package.json parsing",
    "poetry.lock": "poetry.lock parsing",
    "requirements.txt": "requirements.txt parsing",
    "pyproject.toml": "pyproject.toml parsing",
    "Pipfile": "Pipfile parsing",
    "pip list": "pip list --format=json",
    "go list -m all": "go list -m -json all",
    "go.sum": "go.sum parsing",
    "go.mod": "go.mod parsing",
    "Cargo.lock": "Cargo.lock parsing",
    "Cargo.toml": "Cargo.toml parsing",
    "cargo metadata": "cargo metadata --format-version 1",
    "composer.lock": "composer.lock parsing",
    "composer.json": "composer.json parsing",
    "composer show --json": "composer show --json",
    "Gemfile": "Gemfile parsing",
    "bundle list": "bundle list --json",
    "pubspec.lock": "pubspec.lock parsing",
    "pubspec.yaml": "pubspec.yaml parsing",
    "dart pub deps --json": "dart pub deps --json",
    "gradle dependencies": "gradle dependencies",
    "build.gradle": "build.gradle parsing",
    "libs.versions.toml": "libs.versions.toml parsing",
    "dotnet list package --json": "dotnet list package --json",
    "swift show-dependencies": "swift package show-dependencies",
    "Package.swift": "Package.swift parsing",
    "conanfile.txt": "conanfile.txt parsing",
    "conanfile.py": "conanfile.py parsing",
    "vcpkg.json": "vcpkg.json parsing",
    "CMakeLists.txt": "CMakeLists.txt parsing",
    "mix.exs": "mix.exs parsing",
    "mix.lock": "mix.lock parsing",
    "Project.toml": "Project.toml parsing",
    "Manifest.toml": "Manifest.toml parsing",
    "terraform.lock.hcl": ".terraform.lock.hcl parsing",
    ".terraform.lock.hcl": ".terraform.lock.hcl parsing",
    "Dockerfile": "Dockerfile parsing",
    "docker-compose.yml": "docker-compose.yml parsing",
    "docker-compose.yaml": "docker-compose.yaml parsing",
}

PACKAGE_MANAGER_MAP = {
    "npm": ["npm", "yarn", "pnpm"],
    "maven": ["maven"],
    "gradle": ["gradle"],
    "python": ["pip", "poetry", "pipenv", "pep621", "setuptools"],
    "pypi": ["pip", "poetry", "pipenv", "pep621", "setuptools"],
    "go": ["go"],
    "golang": ["go"],
    "cargo": ["cargo"],
    "nuget": ["nuget"],
    "composer": ["composer"],
    "ruby": ["bundler"],
    "swift": ["swiftpm", "cocoapods"],
    "dart": ["pub"],
    "cpp": ["conan", "vcpkg", "cmake"],
    "conan": ["conan"],
    "vcpkg": ["vcpkg"],
    "cmake": ["cmake"],
    "hex": ["mix"],
    "julia": ["julia-pkg"],
    "terraform": ["terraform"],
    "docker": ["docker"],
}

# source_file basename -> package manager (refines the ecosystem default)
SOURCE_FILE_PACKAGE_MANAGER = {
    "package-lock.json": "npm",
    "yarn.lock": "yarn",
    "pnpm-lock.yaml": "pnpm",
    "package.json": "npm",
    "npm ls": "npm",
    "poetry.lock": "poetry",
    "Pipfile": "pipenv",
    "requirements.txt": "pip",
    "pip list": "pip",
    "pyproject.toml": "pep621",
    "setup.py": "setuptools",
    "setup.cfg": "setuptools",
    "pom.xml": "maven",
    "dependency:tree": "maven",
    "build.gradle": "gradle",
    "gradle dependencies": "gradle",
    "libs.versions.toml": "gradle",
    "go.mod": "go",
    "go.sum": "go",
    "go list -m all": "go",
    "Cargo.toml": "cargo",
    "Cargo.lock": "cargo",
    "cargo metadata": "cargo",
    "composer.json": "composer",
    "composer.lock": "composer",
    "composer show --json": "composer",
    "Gemfile": "bundler",
    "bundle list": "bundler",
    "Package.swift": "swiftpm",
    "Podfile": "cocoapods",
    "Package.resolved": "swiftpm",
    "swift show-dependencies": "swiftpm",
    "pubspec.yaml": "pub",
    "pubspec.lock": "pub",
    "dart pub deps --json": "pub",
    "packages.config": "nuget",
    "packages.lock.json": "nuget",
    "project.assets.json": "nuget",
    "dotnet list package --json": "nuget",
    "conanfile.txt": "conan",
    "conanfile.py": "conan",
    "vcpkg.json": "vcpkg",
    "CMakeLists.txt": "cmake",
    "mix.exs": "mix",
    "mix.lock": "mix",
    "Project.toml": "julia-pkg",
    "Manifest.toml": "julia-pkg",
    "terraform.lock.hcl": "terraform",
    ".terraform.lock.hcl": "terraform",
    "*.tf": "terraform",
    "Dockerfile": "docker",
    "docker-compose.yml": "docker",
    "docker-compose.yaml": "docker",
}

# Evidence confidence by how authoritative the collection source is (§5.9).
LOCKFILE_BASENAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock",
    "go.sum", "Cargo.lock", "composer.lock", "Gemfile.lock", "pubspec.lock",
    "packages.lock.json", "project.assets.json", "mix.lock", "Manifest.toml",
    "Podfile.lock", "Package.resolved", "libs.versions.toml", "terraform.lock.hcl",
    ".terraform.lock.hcl",
    "requirements.txt", "pipfile",
}

CLI_RESOLUTION_BASENAMES = {
    "npm ls", "pip list", "go list -m all", "dependency:tree", "gradle dependencies",
    "dotnet list package --json", "composer show --json", "cargo metadata",
    "dart pub deps --json", "swift show-dependencies", "bundle list",
}


def _basename(source_file: str) -> str:
    if not source_file:
        return ""
    return source_file.replace("\\", "/").rsplit("/", 1)[-1]


def derive_source_project(source_file: str) -> str:
    """Project/subdir a component was discovered under (§6 evidence)."""
    if not source_file:
        return ""
    norm = source_file.replace("\\", "/")
    if "/" not in norm:
        return ""
    parts = norm.split("/")
    if len(parts) == 2:
        return parts[0]
    # Nested manifests: use the outermost directory as the project root.
    return "/".join(parts[:-1])


def resolve_package_manager(component: dict) -> str:
    base = _basename(component.get("source_file", ""))
    if base in SOURCE_FILE_PACKAGE_MANAGER:
        return SOURCE_FILE_PACKAGE_MANAGER[base]
    for candidate, manager in SOURCE_FILE_PACKAGE_MANAGER.items():
        if base and (base == candidate or base.endswith(candidate)):
            return manager
    managers = PACKAGE_MANAGER_MAP.get(component.get("ecosystem", ""), [])
    return managers[0] if managers else component.get("ecosystem", "")


def resolve_collection_method(source_file: str) -> str:
    base = _basename(source_file)
    if source_file in COLLECTION_METHOD_MAP:
        return COLLECTION_METHOD_MAP[source_file]
    if base in COLLECTION_METHOD_MAP:
        return COLLECTION_METHOD_MAP[base]
    if source_file:
        return source_file
    return "unknown"


def resolve_collection_confidence(source_file: str) -> float:
    base = _basename(source_file)
    if base in LOCKFILE_BASENAMES or source_file in LOCKFILE_BASENAMES:
        return 1.0
    if base in CLI_RESOLUTION_BASENAMES or source_file in CLI_RESOLUTION_BASENAMES:
        return 0.95
    if source_file in COLLECTION_METHOD_MAP or base in COLLECTION_METHOD_MAP:
        return 0.8
    if source_file:
        return 0.6
    return 0.5


def _identity_key(component: dict) -> str:
    """§8 identity priority: PURL > namespace+name+version > name+version."""
    purl = component.get("purl", "")
    if purl:
        return f"purl:{purl}"
    group = component.get("group", "")
    name = component.get("name", "")
    version = component.get("version", "")
    if group:
        return f"gnv:{group}:{name}:{version}"
    return f"nv:{name}:{version}"


def _merge_hash_list(target: list, incoming: list) -> list:
    seen = set()
    merged = []
    for item in target + incoming:
        if not isinstance(item, dict):
            continue
        key = (item.get("alg", ""), item.get("content", ""))
        if key in seen:
            continue
        seen.add(key)
        merged.append(item)
    return merged


def _merge_source_files(component: dict, source_file: str) -> list[str]:
    files: list[str] = list((component or {}).get("source_files") or [])
    if source_file and source_file not in files:
        files.append(source_file)
    if not files and component.get("source_file"):
        files.append(component["source_file"])
    return files


def _merge_evidence(existing: dict, incoming: dict, source_file: str,
                    method: str, confidence: float, source_project: str) -> dict:
    evidence = dict(existing or {})
    methods = list(evidence.get("methods") or [])
    if method and method not in methods:
        methods.append(method)
    for m in incoming.get("methods") or []:
        if m and m not in methods:
            methods.append(m)

    source_files = _merge_source_files(evidence, source_file)
    projects = list(evidence.get("project_paths") or [])
    if source_project and source_project not in projects:
        projects.append(source_project)

    previous = float(evidence.get("confidence") or 0.0)
    merged = {
        **evidence,
        "methods": methods,
        "confidence": max(previous, confidence),
        "source_files": source_files,
        "project_paths": projects,
    }
    notes = list(evidence.get("notes") or [])
    for note in (evidence.get("notes") or []) + (incoming.get("notes") or []):
        if note and note not in notes:
            notes.append(note)
    if notes:
        merged["notes"] = notes
    return merged


def _merge_component(existing: dict, new: dict) -> None:
    """§8 merge — never silently discard a second sighting of the same identity."""
    for key in ("version", "group", "description", "ecosystem", "type", "scope",
                "supplier", "homepage", "repository", "download_url", "registry_url",
                "purl", "license", "cpe"):
        current = existing.get(key)
        incoming = new.get(key)
        if incoming and not current:
            existing[key] = incoming

    if isinstance(new.get("direct"), bool) and not existing.get("direct", False):
        existing["direct"] = new["direct"]

    existing["hashes"] = _merge_hash_list(existing.get("hashes") or [], new.get("hashes") or [])

    licenses = list(existing.get("licenses") or [])
    for lic in new.get("licenses") or []:
        if lic not in licenses:
            licenses.append(lic)
    if licenses:
        existing["licenses"] = licenses
    elif new.get("license") and not existing.get("license"):
        existing["license"] = new["license"]

    refs = list(existing.get("external_references") or [])
    for ref in new.get("external_references") or []:
        if ref not in refs:
            refs.append(ref)
    for url_type, url_key in (("website", "homepage"), ("vcs", "repository"),
                              ("distribution", "download_url"),
                              ("other", "registry_url")):
        url = new.get(url_key)
        if url and {"type": url_type, "url": url} not in refs:
            refs.append({"type": url_type, "url": url})
    if refs:
        existing["external_references"] = refs

    depends_on = list(existing.get("depends_on") or [])
    for dep in new.get("depends_on") or []:
        if dep and dep not in depends_on:
            depends_on.append(dep)
    existing["depends_on"] = depends_on

    peer_depends_on = list(existing.get("peer_depends_on") or [])
    for dep in new.get("peer_depends_on") or []:
        if dep and dep not in peer_depends_on:
            peer_depends_on.append(dep)
    if peer_depends_on:
        existing["peer_depends_on"] = peer_depends_on

    if not existing.get("source_file") and new.get("source_file"):
        existing["source_file"] = new["source_file"]
    if not existing.get("source_project") and new.get("source_project"):
        existing["source_project"] = new["source_project"]

    seen_files = list(existing.get("source_files") or [])
    for path in new.get("source_files") or []:
        if path and path not in seen_files:
            seen_files.append(path)
    existing["source_files"] = seen_files

    if not existing.get("package_manager") and new.get("package_manager"):
        existing["package_manager"] = new["package_manager"]


def _enrich(component: dict) -> dict:
    """Attach PURL, package manager, source project and collection evidence (§5, §6, §7)."""
    comp = dict(component)
    comp["purl"] = comp.get("purl") or generate_purl(comp)
    comp["bom-ref"] = comp.get("bom-ref") or comp["purl"]
    comp.setdefault("type", "library")
    comp.setdefault("group", "")
    comp.setdefault("scope", "compile")
    comp.setdefault("direct", True)
    comp.setdefault("hashes", [])
    comp.setdefault("depends_on", [])

    # Evidence paths are repo-relative POSIX paths on every platform (§6).
    source_file = (comp.get("source_file", "") or "").replace("\\", "/")
    source_project = comp.get("source_project") or derive_source_project(source_file)
    comp["source_file"] = source_file
    comp["source_project"] = source_project
    comp["source_files"] = _merge_source_files(
        {"source_files": comp.get("source_files")}, source_file
    )

    comp["package_manager"] = comp.get("package_manager") or resolve_package_manager(comp)
    method = resolve_collection_method(source_file)
    confidence = resolve_collection_confidence(source_file)
    comp["evidence"] = _merge_evidence(
        comp.get("evidence"), {}, source_file, method, confidence, source_project
    )
    return comp


def normalize_node(state: SBOMState) -> dict:
    errors = list(state.get("errors", []))
    warnings = list(state.get("warnings", []))
    components = state.get("components", [])
    state_edges = state.get("edges") or state.get("dependency_edges") or []

    grouped: dict[str, dict] = {}
    order: list[str] = []
    merge_count = 0

    for comp in components:
        enriched = _enrich(comp)
        key = _identity_key(enriched)
        if key in grouped:
            existing = grouped[key]
            incoming_evidence = enriched.get("evidence") or {}
            _merge_component(existing, enriched)
            existing["evidence"] = _merge_evidence(
                existing.get("evidence"),
                incoming_evidence,
                enriched.get("source_file", ""),
                incoming_evidence["methods"][-1] if incoming_evidence.get("methods") else "",
                incoming_evidence.get("confidence", 0.0),
                enriched.get("source_project", ""),
            )
            merge_count += 1
        else:
            grouped[key] = enriched
            order.append(key)

    normalized = [grouped[k] for k in order]

    purl_to_bomref: dict[str, str] = {}
    for comp in normalized:
        purl_to_bomref[comp.get("purl", "")] = comp.get("bom-ref", comp.get("purl", ""))

    edges = _build_edges(normalized, state_edges, purl_to_bomref)

    if merge_count:
        logger.info(
            "Merged %d duplicate component sighting(s) by identity", merge_count
        )

    return {
        "components": normalized,
        "edges": edges,
        "dependency_edges": edges,
        "errors": errors,
        "warnings": warnings,
    }


def _build_edges(components: list[dict], state_edges: list[dict],
                 purl_to_bomref: dict[str, str]) -> list[dict]:
    edges: list[dict] = []
    seen_edge_keys: set[str] = set()

    def add_edge(ref: str, depends_on: list[str]) -> None:
        if not ref or not depends_on:
            return
        valid = [d for d in depends_on if d]
        if not valid:
            return
        key = f"{ref}:{','.join(sorted(valid))}"
        if key in seen_edge_keys:
            return
        seen_edge_keys.add(key)
        edges.append({"ref": ref, "dependsOn": valid})

    for comp in components:
        parent = comp.get("bom-ref") or comp.get("purl", "")
        children = [
            purl_to_bomref.get(child, child) for child in (comp.get("depends_on") or [])
        ]
        add_edge(parent, children)

    for edge in state_edges:
        ref = edge.get("ref", "")
        depends_on = edge.get("dependsOn") or []
        add_edge(ref, depends_on)

    return edges


def _find_orphans(components: list[dict], edges: list[dict]) -> list[str]:
    referenced: set[str] = set()
    parents: set[str] = set()
    for edge in edges:
        parents.add(edge.get("ref", ""))
        referenced.update(edge.get("dependsOn") or [])

    orphans = []
    for comp in components:
        ref = comp.get("bom-ref") or comp.get("purl", "")
        if ref and ref not in referenced and ref not in parents:
            orphans.append(ref)
    return orphans

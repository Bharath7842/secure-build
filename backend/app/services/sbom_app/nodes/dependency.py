from fnmatch import fnmatch
from pathlib import Path

from ..graph.state import SBOMState
from ..collectors import (
    CLI_SOURCE_MARKERS,
    COLLECTOR_MAP,
    LOCKFILE_MARKERS,
    MANIFEST_MARKERS,
    SUPPORTED_ECOSYSTEMS,
)
from ..collectors.base import canonicalize_relationships
from ..sbom.purl import generate_purl
from .dependency_graph import _project_ref

UNSUPPORTED_WARNING = (
    "Ecosystem detected but dependency collection is not currently supported."
)

# §5: never silently ship a manifest-only ecosystem — when the source evidence
# has no transitive layer at all, say so explicitly in the scan report.
TRANSITIVE_NONE_WARNING = (
    "Transitive dependency graph unavailable: source evidence provides direct "
    "dependencies only."
)

# A few collectors emit component `ecosystem` values that differ from the
# detected ecosystem key (python emits `pypi`, go emits `golang`, the cpp
# collector emits conan/vcpkg/cmake for one detected `cpp` ecosystem).
_COMPONENT_ECOSYSTEMS: dict[str, frozenset[str]] = {
    "python": frozenset({"python", "pypi"}),
    "go": frozenset({"go", "golang"}),
    "cpp": frozenset({"cpp", "conan", "vcpkg", "cmake"}),
}

# Ecosystems whose static dependency model is flat by design (docker images
# have no statically knowable package layer) — `none` is complete there.
_FLAT_BY_DESIGN: frozenset[str] = frozenset({"docker"})

# Lockfile-pinned ecosystems that emit no inter-package edges of their own:
# every collected package belongs to the scanned project, so the project-root
# edge is synthesized here (a collector cannot know the project purl, §9).
_ROOT_ATTACH_ECOSYSTEMS: frozenset[str] = frozenset(
    {"terraform", "r", "elm", "crystal", "haskell"}
)

_MANIFEST_PATTERNS: tuple[str, ...] = tuple(
    p for marks in MANIFEST_MARKERS.values() for p in marks
)
_LOCKFILE_PATTERNS: tuple[str, ...] = tuple(
    p for marks in LOCKFILE_MARKERS.values() for p in marks
)


def _classify_source(source_file: str) -> str:
    """manifest | lockfile | cli | other for a collector ``source_file`` (§5.9)."""
    if not source_file:
        return ""
    base = source_file.rsplit("/", 1)[-1]
    # Manifests win: some ecosystems list their manifest as their lockfile too
    # (pom.xml), but evidence from a manifest is a manifest.
    if any(fnmatch(base, p) for p in _MANIFEST_PATTERNS):
        return "manifest"
    if any(fnmatch(base, p) for p in _LOCKFILE_PATTERNS):
        return "lockfile"
    if source_file in CLI_SOURCE_MARKERS:
        return "cli"
    return "other"


def _collection_method(components: list[dict]) -> str:
    """Primary evidence kind(s) for one ecosystem: single kind, mixed, unknown."""
    kinds = {_classify_source(str(c.get("source_file", ""))) for c in components} - {""}
    if not kinds:
        return "unknown"
    return next(iter(kinds)) if len(kinds) == 1 else "mixed"


def _compute_transitive(components: list[dict]) -> str:
    """How much transitive depth the collected evidence carries (§5).

    - ``full``: at least one inter-package dependency edge was derived
    - ``partial``: transitive components exist but without edges (pin files)
    - ``none``: every component is a declared direct dependency
    """
    if not components:
        return "none"
    if any(c.get("depends_on") for c in components):
        return "full"
    if any(not c.get("direct") for c in components):
        return "partial"
    return "none"


def _attach_project_root_edges(components: list[dict], edges: list[dict],
                               metadata: dict) -> None:
    """Give flat lockfile ecosystems a project-root edge (§9).

    Terraform providers have no provider-to-provider relationships, so the
    graph would otherwise report every pinned-but-undeclared provider as an
    orphan. All collected packages of such an ecosystem belong to the scanned
    project itself.
    """
    children = sorted({
        str(c.get("purl", "")) for c in components
        if c.get("ecosystem") in _ROOT_ATTACH_ECOSYSTEMS and c.get("purl")
    })
    if not children:
        return
    root_ref = _project_ref(metadata)
    if not root_ref:
        return
    if any(e.get("ref") == root_ref for e in edges):
        return
    edges.append({"ref": root_ref, "dependsOn": children})


def dependency_node(state: SBOMState) -> dict:
    """Collect dependencies.

    Native collectors parse manifests and lockfiles directly so every
    component carries real file-level evidence (§5.8/§5.9), including
    transitive relationships derived from the lockfile graph. Each ecosystem
    record reports its collection method and transitive depth.
    """
    repo_path = Path(state["repository_path"])
    errors = list(state.get("errors", []))
    warnings = list(state.get("warnings", []))
    report = [dict(r) for r in state.get("ecosystem_report", [])]

    all_components: list[dict] = []
    all_edges: list[dict] = []

    ecosystems = state.get("ecosystems", [])
    collectable = [
        e for e in ecosystems
        if e in SUPPORTED_ECOSYSTEMS
        and not any(r.get("ecosystem") == e and r.get("collector") == "unsupported" for r in report)
    ]

    native_components, native_edges = _run_native_collectors(
        repo_path, collectable, report, errors, warnings
    )
    all_components.extend(native_components)
    all_edges.extend(native_edges)

    # PURL is the stable identity; duplicates are merged (with evidence) by normalize.
    for comp in all_components:
        comp["purl"] = comp.get("purl", "") or generate_purl(comp)

    canonicalize_relationships(all_components, all_edges)
    _attach_project_root_edges(all_components, all_edges,
                               state.get("project_metadata") or {})

    by_ecosystem: dict[str, list[dict]] = {}
    for comp in all_components:
        by_ecosystem.setdefault(str(comp.get("ecosystem", "")), []).append(comp)

    for record in report:
        eco = record.get("ecosystem")
        if record.get("collector") == "unsupported" or record.get("status") != "detected":
            continue
        failed = any(e.get("ecosystem") == eco for e in errors)
        record["status"] = "failed" if failed else "collected"

        eco_components: list[dict] = []
        for comp_eco in _COMPONENT_ECOSYSTEMS.get(eco, frozenset({eco})):
            eco_components.extend(by_ecosystem.get(comp_eco, []))

        record["collection_method"] = _collection_method(eco_components)
        transitive = _compute_transitive(eco_components)
        record["transitive"] = transitive
        if transitive == "none" and eco_components and eco not in _FLAT_BY_DESIGN:
            warnings.append({
                "node": "dependencies",
                "ecosystem": eco,
                "warning": TRANSITIVE_NONE_WARNING,
            })

    return {
        "dependencies": all_components,
        "components": all_components,
        "edges": all_edges,
        "dependency_edges": all_edges,
        "ecosystem_report": report,
        "warnings": warnings,
        "errors": errors,
    }


def _run_native_collectors(repo_path: Path, ecosystems: list[str], report: list[dict],
                           errors: list[dict], warnings: list[dict],
                           ) -> tuple[list[dict], list[dict]]:
    all_components: list[dict] = []
    all_edges: list[dict] = []

    for ecosystem in ecosystems:
        collector = COLLECTOR_MAP.get(ecosystem)
        if collector is None:
            # §5: never silently ignore an ecosystem.
            warnings.append({
                "node": "dependencies",
                "ecosystem": ecosystem,
                "warning": UNSUPPORTED_WARNING,
            })
            continue
        try:
            result = collector.collect(repo_path)
            if isinstance(result, tuple):
                comps, collector_edges = result
                all_components.extend(comps)
                all_edges.extend(collector_edges)
            else:
                all_components.extend(result)
        except Exception as e:
            # Collection failure degrades the scan, it does not fail it (§26).
            record = next((r for r in report if r.get("ecosystem") == ecosystem), None)
            if record is not None:
                record["status"] = "failed"
            warnings.append({
                "node": "dependencies",
                "ecosystem": ecosystem,
                "warning": f"Dependency collection failed: {e}",
            })

    return all_components, all_edges

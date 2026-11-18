import fnmatch
import os
from pathlib import Path

from ..graph.state import SBOMState
from ..collectors import LOCKFILE_MARKERS, MANIFEST_MARKERS, SUPPORTED_ECOSYSTEMS

# Marker files that are *not* manifests (pure lockfiles), used to classify a match.
LOCKFILE_ONLY = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock",
    "go.sum", "Cargo.lock", "composer.lock", "Gemfile.lock", "pubspec.lock",
    "packages.lock.json", "project.assets.json", "mix.lock", "Manifest.toml",
    "Podfile.lock", "Package.resolved", "gradle.lockfile", "libs.versions.toml",
    ".terraform.lock.hcl", "conan.lock", "deno.lock", "renv.lock", "shard.lock",
    "stack.yaml.lock", "cabal.project.freeze", "cpanfile.snapshot",
}

# Directories that never hold a project root worth reporting.
IGNORE_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "vendor", "target", "build", "dist",
    "out", ".venv", "venv", ".tox", ".gradle", ".terraform", "__pycache__",
    ".next", ".nuxt", ".idea", ".vscode", "coverage", ".mypy_cache", ".pytest_cache",
    ".dart_tool", ".stack-work", "Pods", ".bundle", "bower_components",
}

UNSUPPORTED_WARNING = (
    "Ecosystem detected but dependency collection is not currently supported."
)


def _classify(eco: str, pattern: str) -> str:
    if pattern in LOCKFILE_ONLY and pattern not in (MANIFEST_MARKERS.get(eco) or []):
        return "lockfile"
    return "manifest"


def ecosystem_node(state: SBOMState) -> dict:
    repo_path = Path(state["repository_path"])
    warnings = list(state.get("warnings", []))
    errors = list(state.get("errors", []))

    ecosystems: list[str] = []
    dependency_files: list[str] = []
    report: list[dict] = []

    # pattern -> (ecosystem, kind)
    seen_pairs: set[tuple[str, str]] = set()
    patterns: list[tuple[str, str, str]] = []
    for eco, marks in MANIFEST_MARKERS.items():
        for mark in marks:
            seen_pairs.add((mark, eco))
            patterns.append((mark, eco, _classify(eco, mark)))
    for eco, marks in LOCKFILE_MARKERS.items():
        for mark in marks:
            if (mark, eco) in seen_pairs:
                continue
            seen_pairs.add((mark, eco))
            patterns.append((mark, eco, _classify(eco, mark)))

    found: dict[str, dict] = {}
    for dirpath, dirnames, filenames in os.walk(repo_path):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
        rel_dir = os.path.relpath(dirpath, repo_path)
        rel_dir = "" if rel_dir == "." else rel_dir.replace("\\", "/")
        for filename in filenames:
            for pattern, eco, kind in patterns:
                if not fnmatch.fnmatch(filename, pattern):
                    continue
                rel = f"{rel_dir}/{filename}" if rel_dir else filename
                entry = found.setdefault(eco, {"manifests": [], "lockfiles": []})
                bucket = entry["lockfiles" if kind == "lockfile" else "manifests"]
                if rel not in bucket:
                    bucket.append(rel)

    for eco in MANIFEST_MARKERS:
        entry = found.get(eco)
        if not entry:
            continue
        if eco not in ecosystems:
            ecosystems.append(eco)
        dependency_files.extend(entry["lockfiles"] + entry["manifests"])

        supported = eco in SUPPORTED_ECOSYSTEMS
        collector_name = "unsupported" if not supported else eco
        has_lockfile = bool(entry["lockfiles"])
        record = {
            "ecosystem": eco,
            "status": "detected",
            "collector": collector_name,
            "warning": None if supported else UNSUPPORTED_WARNING,
            "manifest_files": entry["manifests"],
            "lockfiles": entry["lockfiles"],
            # Lockfile presence makes detection authoritative (§5).
            "confidence": 1.0 if has_lockfile else 0.8,
        }
        report.append(record)
        if not supported:
            warnings.append({
                "node": "ecosystem",
                "warning": UNSUPPORTED_WARNING,
                "ecosystem": eco,
            })

    return {
        "ecosystems": ecosystems,
        "dependency_files": dependency_files,
        "ecosystem_report": report,
        "warnings": warnings,
        "errors": errors,
    }

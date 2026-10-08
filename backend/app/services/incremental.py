"""Incremental scan helpers: content hashing and snapshot diffing."""

import hashlib
from pathlib import Path

from app.models import FileSnapshot

SCAN_EXTENSIONS = {".java", ".ts"}
SCAN_FILENAMES = {"pom.xml", "package.json"}
SKIP_DIRS = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    "dist",
    "build",
    "target",
    ".next",
    "vendor",
}


def _is_scan_file(path: Path) -> bool:
    return path.suffix in SCAN_EXTENSIONS or path.name in SCAN_FILENAMES


def iter_scan_files(root: Path) -> list[Path]:
    """Return absolute paths of scannable files under root."""
    if not root.is_dir():
        return []

    results: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if _is_scan_file(path):
            results.append(path)
    return results


def file_content_hash(path: Path) -> str:
    """Return SHA-256 hex digest of file contents."""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def compute_changed_paths(
    project_id: str,
    root: Path,
    commit_sha: str | None,
    db,
) -> list[str] | None:
    """Return relative posix paths that are new, changed, or deleted vs FileSnapshot.

    Returns None when no prior snapshots existed (full index signal). Snapshot
    changes are flushed but not committed; caller commits after a successful scan.
    """
    existing = {
        row.path: row
        for row in db.query(FileSnapshot).filter_by(project_id=project_id).all()
    }
    is_first = len(existing) == 0

    changed: list[str] = []
    seen_paths: set[str] = set()

    for abs_path in iter_scan_files(root):
        rel = abs_path.relative_to(root).as_posix()
        seen_paths.add(rel)
        content_hash = file_content_hash(abs_path)
        snapshot = existing.get(rel)

        if snapshot is None or snapshot.content_hash != content_hash:
            changed.append(rel)

        if snapshot is None:
            db.add(
                FileSnapshot(
                    project_id=project_id,
                    path=rel,
                    content_hash=content_hash,
                    commit_sha=commit_sha,
                )
            )
        else:
            snapshot.content_hash = content_hash
            if rel in changed:
                snapshot.commit_sha = commit_sha

    for path, snapshot in existing.items():
        if path not in seen_paths:
            changed.append(path)
            db.delete(snapshot)

    db.flush()
    if is_first:
        return None
    return changed

"""Display/storage helper: strip workspace/env prefixes from finding paths.

Mirrors `sast_engine.pipeline.path_utils.to_module_path` so the API layer can
normalize without importing the engine package.
"""

from __future__ import annotations

import re
from pathlib import Path

_WORKSPACE_UUID = re.compile(
    r"(?:^|/)workspaces/[0-9a-fA-F-]{36}/(?P<rel>.+)$",
    re.IGNORECASE,
)
_MODULE_ROOTS = {
    "src",
    "app",
    "apps",
    "backend",
    "frontend",
    "packages",
    "services",
    "lib",
    "libs",
    "modules",
    "server",
    "client",
    "web",
    "api",
    "cmd",
    "internal",
    "pkg",
}


def to_module_path(path: str | None, repo_root: str | Path | None = None) -> str | None:
    if path is None:
        return None
    raw = str(path).strip()
    if not raw:
        return raw

    p = raw.replace("\\", "/")
    if p.startswith("file://"):
        p = p[7:]
        if re.match(r"^/[A-Za-z]:/", p):
            p = p[1:]

    if repo_root:
        try:
            rel = Path(p).resolve().relative_to(Path(repo_root).resolve())
            return rel.as_posix()
        except (OSError, ValueError):
            root = str(Path(repo_root).resolve()).replace("\\", "/").rstrip("/")
            if p.lower().startswith(root.lower() + "/"):
                return p[len(root) + 1 :]

    m = _WORKSPACE_UUID.search(p)
    if m:
        return m.group("rel")

    is_abs = bool(re.match(r"^[A-Za-z]:/", p) or p.startswith("/"))
    if is_abs:
        parts = [part for part in p.split("/") if part and part != "."]
        if parts and re.match(r"^[A-Za-z]:$", parts[0]):
            parts = parts[1:]
        for i, part in enumerate(parts):
            if part.lower() in _MODULE_ROOTS:
                return "/".join(parts[i:])
        if len(parts) > 2:
            return "/".join(parts[-3:])
        return "/".join(parts)

    return p.lstrip("./")

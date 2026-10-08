"""ast_index.py — persistent, per-commit AST cache for CRITICAL-tier files.

Parses every CRITICAL-risk file (per `node_map_modules_and_risk`) with
tree-sitter and stores every node as a row in a real on-disk SQLite database
(not `:memory:`), so a repeat scan of the *same* project at the *same*
resolved commit SHA reuses the cache instead of re-parsing from scratch —
the expensive part for large/enterprise repos scanned repeatedly.

Cache key: `<project_id>_<commit_sha>.db` under the configured cache dir
(state["ast_cache_dir"], default `~/.sast_ast_cache`). When project_id/
commit_sha aren't supplied (standalone CLI runs against a plain local path),
falls back to a hash of the resolved scan root so repeat CLI runs on the
same directory still get cache reuse.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

import ast_struct

_LANG_BY_EXT = {
    ".java": "java",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".py": "python",
}

AST_SCHEMA = """
CREATE TABLE IF NOT EXISTS ast_nodes (
    id            INTEGER PRIMARY KEY,
    file_path     TEXT NOT NULL,
    lang          TEXT NOT NULL,
    node_type     TEXT NOT NULL,
    node_text     TEXT,
    line_number   INTEGER,
    depth         INTEGER,
    parent_id     INTEGER
);
CREATE TABLE IF NOT EXISTS symbols (
    id            INTEGER PRIMARY KEY,
    file_path     TEXT NOT NULL,
    name          TEXT,
    node_id       INTEGER,
    symbol_type   TEXT
);
CREATE TABLE IF NOT EXISTS indexed_files (
    file_path     TEXT PRIMARY KEY,
    lang          TEXT NOT NULL,
    node_count    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ast_nodes_type ON ast_nodes(node_type);
CREATE INDEX IF NOT EXISTS idx_ast_nodes_file ON ast_nodes(file_path);
"""

# Node types worth persisting — everything else (punctuation, whitespace-only
# leaves) is noise that would 10x the row count for no detection value.
_INTERESTING_NODE_TYPES = {
    # calls / invocations (SQL concat, subprocess, eval, etc. all show up here)
    "method_invocation", "call_expression", "call",
    # literals (hardcoded secrets, connection strings)
    "string_literal", "string_fragment", "string", "template_string",
    # declarations (annotations, decorators — auth/authz checks)
    "annotation", "marker_annotation", "decorator",
    "method_declaration", "function_declaration", "function_definition",
    "class_declaration", "class_definition",
    # binary/assignment (string concatenation building a query)
    "binary_expression", "assignment_expression", "assignment",
    "variable_declarator",
    # imports (weak crypto, insecure libs)
    "import_declaration", "import_statement", "import_from_statement",
}


def _cache_dir(state: Dict[str, Any]) -> Path:
    raw = state.get("ast_cache_dir") or os.environ.get("SAST_AST_CACHE_DIR")
    d = Path(raw) if raw else (Path.home() / ".sast_ast_cache")
    d.mkdir(parents=True, exist_ok=True)
    return d


def get_ast_cache_path(state: Dict[str, Any], scan_root: Path) -> Path:
    project_id = (state.get("project_id") or "").strip()
    commit_sha = (state.get("commit_sha") or "").strip()
    if project_id and commit_sha:
        key = f"{project_id}_{commit_sha}"
    else:
        key = hashlib.sha1(str(scan_root).encode("utf-8")).hexdigest()[:16]
    return _cache_dir(state) / f"{key}.db"


def _text(node: Any, src: bytes) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _traverse(node: Any, conn: sqlite3.Connection, file_path: str, lang: str,
              src: bytes, depth: int, parent_id: Optional[int]) -> int:
    count = 0
    this_id: Optional[int] = parent_id
    if node.type in _INTERESTING_NODE_TYPES:
        node_text = _text(node, src)
        if len(node_text) > 500:
            node_text = node_text[:500] + "..."
        cur = conn.execute(
            "INSERT INTO ast_nodes (file_path, lang, node_type, node_text, line_number, depth, parent_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (file_path, lang, node.type, node_text, node.start_point[0] + 1, depth, parent_id),
        )
        this_id = cur.lastrowid
        count += 1
        if node.type in ("method_declaration", "function_declaration", "function_definition",
                          "class_declaration", "class_definition"):
            name = next((c for c in node.children if c.type == "identifier"), None)
            if name is not None:
                conn.execute(
                    "INSERT INTO symbols (file_path, name, node_id, symbol_type) VALUES (?, ?, ?, ?)",
                    (file_path, _text(name, src), this_id, node.type),
                )

    for child in node.children:
        count += _traverse(child, conn, file_path, lang, src, depth + 1, this_id)
    return count


def _index_file(conn: sqlite3.Connection, repo_root: Path, rel_path: str, lang: str) -> int:
    parser = ast_struct.parser_for_lang(lang)
    if parser is None:
        return 0
    try:
        src = (repo_root / rel_path).read_bytes()
    except OSError:
        return 0
    try:
        tree = parser.parse(src)
    except Exception:  # noqa: BLE001 — a bad parse must not sink the scan
        return 0
    n = _traverse(tree.root_node, conn, rel_path, lang, src, 0, None)
    conn.execute(
        "INSERT OR REPLACE INTO indexed_files (file_path, lang, node_count) VALUES (?, ?, ?)",
        (rel_path, lang, n),
    )
    return n


def node_ast_cache_load_or_create(state: Dict[str, Any]) -> dict:
    """Opens (or creates) the persistent AST cache for this project/commit and
    indexes every not-yet-indexed CRITICAL file. Fully reused when the cache
    file for this exact key already has rows for every CRITICAL file."""
    tracer = state["_tracer"]
    scan_root = Path(state["scan"]["root"])
    cache_path = get_ast_cache_path(state, scan_root)
    is_new = not cache_path.exists()

    conn = sqlite3.connect(str(cache_path))
    conn.executescript(AST_SCHEMA)

    critical_files = [
        e["path"] for e in (state.get("module_plan") or {}).get("files", [])
        if e.get("risk_level") == "CRITICAL"
    ]
    already = {
        row[0] for row in conn.execute("SELECT file_path FROM indexed_files").fetchall()
    }
    to_index = [
        p for p in critical_files
        if p not in already and (Path(p).suffix.lower() in _LANG_BY_EXT)
    ]

    if is_new:
        tracer.log(5, "ast_cache", f"No AST cache found — creating {cache_path.name}",
                    narrative=f"No cached AST for this commit yet — parsing {len(to_index)} CRITICAL file(s).")
    elif to_index:
        tracer.log(5, "ast_cache", f"Reusing AST cache {cache_path.name} — {len(to_index)} new file(s) to index",
                    narrative=f"Found an AST cache for this commit — {len(already)} file(s) already indexed, "
                              f"parsing {len(to_index)} new one(s).")
    else:
        tracer.log(5, "ast_cache", f"AST cache fully reused: {cache_path.name}",
                    narrative=f"AST cache hit — all {len(already)} CRITICAL file(s) already indexed for this commit, "
                              f"skipping re-parse.")

    indexed = 0
    for rel in to_index:
        lang = _LANG_BY_EXT[Path(rel).suffix.lower()]
        n = _index_file(conn, scan_root, rel, lang)
        if n:
            indexed += 1
    conn.commit()
    conn.close()

    tracer.log(5, "ast_cache", f"AST cache ready: {cache_path}",
                detail=f"indexed_now={indexed}, reused={len(already)}, total_critical={len(critical_files)}",
                narrative=f"AST indexing done — {indexed} file(s) parsed just now, "
                          f"{len(already)} reused from cache.")

    return {"ast_db_path": str(cache_path)}

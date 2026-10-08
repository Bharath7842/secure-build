"""ast_struct.py — lightweight AST structural pass for tech-stack detection.

Sits between marker-file detection and the LLM call in
`sast_scan_agent.node_analyze_tech_stack`. Where marker files (pom.xml,
angular.json) only say *what tools* a project uses, this parses the actual
source with tree-sitter and counts what's *built* with them — annotation /
decorator usage, REST entry points, and Angular route-guard coverage — so
the LLM reasons over real architecture instead of a file-extension histogram.

Structure only: no data-flow, no cross-file resolution. Each file is parsed
once and its top-level class/method shape is walked in a single pass, which
is why this stays fast even across thousands of files.

Currently covers Maven/Java (Spring-style annotations) and Angular
(decorators + route guards) — the two stacks with annotation/decorator
conventions rich enough for this to pay off. Other stacks (.NET, Python,
Node) fall back to heuristic-only detection, same as before this module
existed.
"""

from __future__ import annotations

from collections import Counter
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ===========================================================================
# tree-sitter setup — lazy imports so the rest of the pipeline (and its
# tests) never hard-depend on tree-sitter being installed.
# ===========================================================================


@lru_cache(maxsize=1)
def tree_sitter_available() -> bool:
    try:
        import tree_sitter  # noqa: F401
        import tree_sitter_java  # noqa: F401
        import tree_sitter_typescript  # noqa: F401
    except ImportError:
        return False
    return True


@lru_cache(maxsize=1)
def python_tree_sitter_available() -> bool:
    try:
        import tree_sitter  # noqa: F401
        import tree_sitter_python  # noqa: F401
    except ImportError:
        return False
    return True


@lru_cache(maxsize=1)
def _java_parser() -> Any:
    import tree_sitter_java as tsjava
    from tree_sitter import Language, Parser

    return Parser(Language(tsjava.language()))


@lru_cache(maxsize=1)
def _ts_parser() -> Any:
    import tree_sitter_typescript as tsts
    from tree_sitter import Language, Parser

    return Parser(Language(tsts.language_typescript()))


@lru_cache(maxsize=1)
def _python_parser() -> Any:
    import tree_sitter_python as tspython
    from tree_sitter import Language, Parser

    return Parser(Language(tspython.language()))


def parser_for_lang(lang: str) -> Optional[Any]:
    """Returns the shared tree-sitter parser singleton for `lang` ("java",
    "typescript", "python"), or None if that language's grammar isn't
    installed. Used by pipeline/ast_index.py so the AST-cache indexer reuses
    the exact same parser objects as the tech-stack structural pass instead
    of bootstrapping tree-sitter a second time."""
    if lang == "java":
        return _java_parser() if tree_sitter_available() else None
    if lang == "typescript":
        return _ts_parser() if tree_sitter_available() else None
    if lang == "python":
        return _python_parser() if python_tree_sitter_available() else None
    return None


def _text(node: Any, src: bytes) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _read_text(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


# ===========================================================================
# Java / Spring — annotation counts + REST entry points
# ===========================================================================

CLASS_LEVEL_ANNOTATIONS = (
    "RestController", "Controller", "Entity", "Repository", "Service", "Configuration", "Component",
)
MAPPING_VERBS = {
    "GetMapping": "GET", "PostMapping": "POST", "PutMapping": "PUT",
    "DeleteMapping": "DELETE", "PatchMapping": "PATCH", "RequestMapping": "ANY",
}
AUTH_ANNOTATIONS = ("PreAuthorize", "PostAuthorize", "Secured", "RolesAllowed")

_NESTED_TYPE_DECLS = (
    "class_declaration", "interface_declaration", "enum_declaration",
    "record_declaration", "annotation_type_declaration",
)


def _decl_name(node: Any, src: bytes) -> Optional[str]:
    """Name of a class/method declaration — the first top-level `identifier`
    child (annotation names live nested under `modifiers`, so this never
    picks those up by mistake)."""
    for c in node.children:
        if c.type == "identifier":
            return _text(c, src)
    return None


def _direct_annotations(node: Any, src: bytes) -> List[Tuple[str, Any]]:
    """(name, annotation_node) pairs directly modifying this declaration."""
    out: List[Tuple[str, Any]] = []
    for child in node.children:
        if child.type != "modifiers":
            continue
        for c in child.children:
            if c.type in ("marker_annotation", "annotation"):
                for cc in c.children:
                    if cc.type == "identifier":
                        out.append((_text(cc, src), c))
                        break
        break
    return out


def _string_literal_text(node: Any, src: bytes) -> Optional[str]:
    for c in node.children:
        if c.type == "string_fragment":
            return _text(c, src)
    return None


def _annotation_arg_values(ann_node: Any, src: bytes) -> List[str]:
    """String values passed to an annotation — positional (`@X("v")`),
    named (`@X(value = "v")` / `@X(path = "v")`), or array (`@X(path = {"a","b"})`)."""
    values: List[str] = []
    for c in ann_node.children:
        if c.type != "annotation_argument_list":
            continue
        for cc in c.children:
            if cc.type == "string_literal":
                v = _string_literal_text(cc, src)
                if v is not None:
                    values.append(v)
            elif cc.type == "element_value_pair":
                key_node = cc.children[0] if cc.children else None
                key = _text(key_node, src) if key_node is not None else ""
                if key not in ("value", "path"):
                    continue
                for ccc in cc.children:
                    if ccc.type == "string_literal":
                        v = _string_literal_text(ccc, src)
                        if v is not None:
                            values.append(v)
                    elif ccc.type == "array_initializer":
                        for cccc in ccc.children:
                            if cccc.type == "string_literal":
                                v = _string_literal_text(cccc, src)
                                if v is not None:
                                    values.append(v)
    return values


def _iter_methods_shallow(class_body: Any) -> List[Any]:
    """`method_declaration` nodes belonging to this class body — stops at
    nested type boundaries so an inner class's methods aren't double-counted
    against the outer class."""
    out: List[Any] = []
    stack = [class_body]
    while stack:
        n = stack.pop()
        for c in n.children:
            if c.type in _NESTED_TYPE_DECLS:
                continue
            if c.type == "method_declaration":
                out.append(c)
            stack.append(c)
    return out


def analyze_java_source(rel_path: str, source_text: str) -> Tuple[Counter, List[Dict[str, Any]]]:
    """Returns (class-annotation counts, entry-point list) for one file."""
    src = source_text.encode("utf-8", errors="replace")
    tree = _java_parser().parse(src)

    class_counts: Counter = Counter()
    entry_points: List[Dict[str, Any]] = []

    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type in ("class_declaration", "interface_declaration"):
            class_name = _decl_name(node, src)
            anns = _direct_annotations(node, src)
            ann_names = {n for n, _ in anns}

            for n in ann_names:
                if n in CLASS_LEVEL_ANNOTATIONS:
                    class_counts[n] += 1

            class_has_auth = any(n in AUTH_ANNOTATIONS for n in ann_names)
            base_path = ""
            for n, ann_node in anns:
                if n == "RequestMapping":
                    vals = _annotation_arg_values(ann_node, src)
                    if vals:
                        base_path = vals[0]

            body = next((c for c in node.children if c.type == "class_body"), None)
            if body is not None:
                for m in _iter_methods_shallow(body):
                    m_anns = _direct_annotations(m, src)
                    m_ann_names = {n for n, _ in m_anns}
                    mapping = [(n, an) for n, an in m_anns if n in MAPPING_VERBS]
                    if not mapping:
                        continue
                    verb_name, ann_node = mapping[0]
                    vals = _annotation_arg_values(ann_node, src)
                    sub_path = vals[0] if vals else ""
                    if base_path or sub_path:
                        full_path = base_path.rstrip("/") + "/" + sub_path.lstrip("/")
                    else:
                        full_path = "/"
                    entry_points.append({
                        "class": class_name,
                        "method": _decl_name(m, src),
                        "verb": MAPPING_VERBS[verb_name],
                        "path": full_path,
                        "authorized": class_has_auth or any(n in AUTH_ANNOTATIONS for n in m_ann_names),
                        "file": rel_path,
                    })
        stack.extend(node.children)

    return class_counts, entry_points


# ===========================================================================
# Angular — decorator counts, guard coverage, route entries
# ===========================================================================

DECORATORS_OF_INTEREST = ("Component", "Injectable", "Directive", "Pipe", "NgModule")
GUARD_INTERFACES = ("CanActivate", "CanActivateChild", "CanDeactivate", "CanLoad", "CanMatch")


def _decorator_name(dec_node: Any, src: bytes) -> Optional[str]:
    for c in dec_node.children:
        if c.type == "call_expression":
            for cc in c.children:
                if cc.type == "identifier":
                    return _text(cc, src)
        elif c.type == "identifier":
            return _text(c, src)
    return None


def _decorator_target(dec_node: Any) -> Optional[Any]:
    """The declaration a decorator modifies. Grammar puts it in one of two
    shapes: nested *inside* the declaration (bare `class X`, decorator is
    `class_declaration`'s own child) or as a *sibling* preceding it
    (`export class X`, decorator and class share the `export_statement`
    parent) — handle both."""
    parent = dec_node.parent
    if parent is None:
        return None
    if parent.type == "class_declaration":
        return parent
    siblings = parent.children
    idx = next((i for i, s in enumerate(siblings) if s.id == dec_node.id), None)
    if idx is None:
        return None
    for sib in siblings[idx + 1 :]:
        if sib.type == "decorator" or not sib.is_named:
            continue
        return sib
    return None


def _object_pairs(obj_node: Any, src: bytes) -> Dict[str, Any]:
    pairs: Dict[str, Any] = {}
    for c in obj_node.children:
        if c.type != "pair":
            continue
        key_node = c.children[0] if c.children else None
        if key_node is None:
            continue
        pairs[_text(key_node, src).strip("\"'")] = c
    return pairs


def _pair_string_value(pair_node: Any, src: bytes) -> Optional[str]:
    for c in pair_node.children:
        if c.type == "string":
            for cc in c.children:
                if cc.type == "string_fragment":
                    return _text(cc, src)
    return None


def analyze_ts_source(rel_path: str, source_text: str) -> Tuple[Counter, int, List[Dict[str, Any]]]:
    """Returns (decorator counts, guard-class hits, route entries) for one file."""
    src = source_text.encode("utf-8", errors="replace")
    tree = _ts_parser().parse(src)

    decorator_counts: Counter = Counter()
    guard_class_hits = 0
    routes: List[Dict[str, Any]] = []

    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type == "decorator":
            name = _decorator_name(node, src)
            if name in DECORATORS_OF_INTEREST:
                target = _decorator_target(node)
                if target is not None and target.type == "class_declaration":
                    decorator_counts[name] += 1
        elif node.type == "class_declaration":
            heritage_text = ""
            for c in node.children:
                if c.type == "class_heritage":
                    heritage_text = _text(c, src)
                    break
            if any(g in heritage_text for g in GUARD_INTERFACES):
                guard_class_hits += 1
        elif node.type == "object":
            pairs = _object_pairs(node, src)
            if "path" in pairs:
                path_val = _pair_string_value(pairs["path"], src)
                if path_val is not None:
                    routes.append({
                        "path": path_val,
                        "guarded": "canActivate" in pairs,
                        "file": rel_path,
                    })
        stack.extend(node.children)

    return decorator_counts, guard_class_hits, routes


# ===========================================================================
# Orchestration — one summary across all detected stacks
# ===========================================================================

MAX_FILES_PER_STACK = 1500


def build_ast_summary(
    scan: Dict[str, Any],
    heuristic_stacks: List[str],
    repo_root: Path,
    max_files_per_stack: int = MAX_FILES_PER_STACK,
) -> Optional[Dict[str, Any]]:
    """Runs the AST pass for every stack we know how to structurally parse.
    Returns None when tree-sitter isn't installed or no covered stack was
    detected — callers should treat that as "skip, fall back to heuristics"."""
    if not tree_sitter_available():
        return None

    summary: Dict[str, Any] = {"parsed_files": {}, "capped": {}, "stacks": {}}
    ran_any = False

    if "maven-java" in heuristic_stacks:
        java_files = [f["path"] for f in scan["files"] if f["ext"] == ".java"]
        capped = len(java_files) > max_files_per_stack
        if capped:
            java_files = java_files[:max_files_per_stack]

        class_counts: Counter = Counter()
        entry_points: List[Dict[str, Any]] = []
        parsed = 0
        for rel in java_files:
            text = _read_text(repo_root / rel)
            if text is None:
                continue
            try:
                c, eps = analyze_java_source(rel, text)
            except Exception:  # noqa: BLE001 — a bad parse must not sink the scan
                continue
            class_counts.update(c)
            entry_points.extend(eps)
            parsed += 1

        unauthenticated = [e for e in entry_points if not e["authorized"]]
        summary["stacks"]["maven-java"] = {
            "annotations": dict(class_counts),
            "entry_points": entry_points,
            "entry_point_count": len(entry_points),
            "unauthenticated_entry_points": len(unauthenticated),
        }
        summary["parsed_files"]["java"] = parsed
        summary["capped"]["java"] = capped
        ran_any = True

    if "angular" in heuristic_stacks:
        ts_files = [f["path"] for f in scan["files"] if f["ext"] == ".ts"]
        capped = len(ts_files) > max_files_per_stack
        if capped:
            ts_files = ts_files[:max_files_per_stack]

        decorator_counts: Counter = Counter()
        guard_file_count = 0
        routes: List[Dict[str, Any]] = []
        parsed = 0
        for rel in ts_files:
            text = _read_text(repo_root / rel)
            if text is None:
                continue
            try:
                d, guard_hits, r = analyze_ts_source(rel, text)
            except Exception:  # noqa: BLE001 — a bad parse must not sink the scan
                continue
            decorator_counts.update(d)
            if rel.endswith(".guard.ts") or guard_hits > 0 or "CanActivateFn" in text:
                guard_file_count += 1
            routes.extend(r)
            parsed += 1

        unguarded = [r for r in routes if not r["guarded"]]
        summary["stacks"]["angular"] = {
            "decorators": dict(decorator_counts),
            "guard_files": guard_file_count,
            "routes": routes,
            "route_count": len(routes),
            "unguarded_route_count": len(unguarded),
        }
        summary["parsed_files"]["typescript"] = parsed
        summary["capped"]["typescript"] = capped
        ran_any = True

    return summary if ran_any else None


def structural_risk_areas(ast_summary: Optional[Dict[str, Any]]) -> List[str]:
    """Risk areas derivable from AST facts alone — used both as a fallback
    when the LLM call fails/is skipped, and as ground truth the LLM prompt
    is built from."""
    if not ast_summary:
        return []
    areas: List[str] = []

    mj = ast_summary["stacks"].get("maven-java")
    if mj:
        n = mj["unauthenticated_entry_points"]
        if n:
            areas.append(f"{n} REST endpoint(s) with no @PreAuthorize/@Secured")
        entity_count = mj["annotations"].get("Entity", 0)
        if entity_count:
            noun = "entity" if entity_count == 1 else "entities"
            areas.append(f"{entity_count} JPA {noun} — check repository layer for raw query usage")

    ng = ast_summary["stacks"].get("angular")
    if ng:
        n = ng["unguarded_route_count"]
        if n:
            areas.append(f"{n} Angular route(s) with no route guard")

    return areas


def format_ast_summary_for_prompt(ast_summary: Optional[Dict[str, Any]], max_entry_points: int = 20) -> str:
    """Renders the AST summary as evidence lines for the tech-stack LLM prompt."""
    if not ast_summary:
        return ""
    lines = ["AST structural evidence (parsed from real source, not just marker files):"]

    mj = ast_summary["stacks"].get("maven-java")
    if mj:
        lines.append(f"- Maven/Java ({ast_summary['parsed_files'].get('java', 0)} files parsed):")
        lines.append(f"  annotation counts: {mj['annotations']}")
        lines.append(
            f"  REST entry points: {mj['entry_point_count']} total, "
            f"{mj['unauthenticated_entry_points']} with no @PreAuthorize/@Secured"
        )
        sample = mj["entry_points"][:max_entry_points]
        for e in sample:
            auth = "authorized" if e["authorized"] else "UNAUTHENTICATED"
            lines.append(f"    {e['verb']} {e['path']} -> {e['class']}.{e['method']} [{auth}]")
        remaining = len(mj["entry_points"]) - len(sample)
        if remaining > 0:
            lines.append(f"    ...and {remaining} more")

    ng = ast_summary["stacks"].get("angular")
    if ng:
        lines.append(f"- Angular ({ast_summary['parsed_files'].get('typescript', 0)} files parsed):")
        lines.append(f"  decorator counts: {ng['decorators']}")
        lines.append(
            f"  guard files: {ng['guard_files']}; routes found: {ng['route_count']} total, "
            f"{ng['unguarded_route_count']} with no canActivate guard"
        )

    return "\n".join(lines)


def narrate_stack_summary(stack_key: str, data: Dict[str, Any]) -> str:
    """One-line human narration for the live agent trace."""
    if stack_key == "maven-java":
        a = data["annotations"]
        return (
            f"Maven/Java AST: @RestController={a.get('RestController', 0)}, @Entity={a.get('Entity', 0)}, "
            f"@Repository={a.get('Repository', 0)}, @Service={a.get('Service', 0)}, "
            f"@Configuration={a.get('Configuration', 0)} — {data['entry_point_count']} REST endpoint(s) found, "
            f"{data['unauthenticated_entry_points']} unauthenticated."
        )
    if stack_key == "angular":
        d = data["decorators"]
        return (
            f"Angular AST: @Component={d.get('Component', 0)}, @Injectable={d.get('Injectable', 0)}, "
            f"@Directive={d.get('Directive', 0)}, @Pipe={d.get('Pipe', 0)} — {data['guard_files']} guard file(s), "
            f"{data['route_count']} route(s) found, {data['unguarded_route_count']} unguarded."
        )
    return ""

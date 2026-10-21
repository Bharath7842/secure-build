"""occurrence.py — the engine half of a finding occurrence's identity.

An occurrence id has to survive a rescan and unrelated line shifts, so it is
built from *what* the finding is and *where in the code structure* it sits —
never from its line number:

    project | file | rule | cwe | normalized sink expression
            | enclosing method signature | ordinal of the sink within the method

The app hashes those parts (`app/services/occurrence.py`; it alone knows the
project id). This module computes the parts that need the file's text: the
normalized sink expression, the enclosing method (tree-sitter, Java /
TypeScript / Python) and the sink's ordinal inside it, and stamps them on each
finding dict before the findings writer sees it.

Everything here is best-effort: a file that cannot be read or parsed yields
`identity_quality="file_level"` (ordinal counted over the whole file), never an
exception.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import ast_struct

EXACT = "exact"
FILE_LEVEL = "file_level"

# Sink expressions are stored and hashed in this normalized, bounded form.
SINK_EXPRESSION_MAX_CHARS = 300

_CLASS_NODES = {
    "java": ("class_declaration", "interface_declaration", "enum_declaration",
             "record_declaration"),
    "typescript": ("class_declaration", "abstract_class_declaration", "interface_declaration"),
    "python": ("class_definition",),
}
_FUNCTION_NODES = {
    "java": ("method_declaration", "constructor_declaration"),
    "typescript": ("function_declaration", "generator_function_declaration", "method_definition"),
    "python": ("function_definition",),
}
_NAMED_VALUE_PARENTS = ("variable_declarator", "public_field_definition", "pair")
_ANONYMOUS_FUNCTION_NODES = ("arrow_function", "function_expression", "function")

# (start line, end line, signature) of one function; 1-based, inclusive.
MethodSpan = Tuple[int, int, str]


def normalize_expression(text: Any) -> str:
    """Whitespace-collapsed form shared with `scan_export._normalized_match`."""
    return " ".join(str(text or "").split())


def sink_expression(finding: Dict[str, Any], line_text: str = "") -> str:
    """The code that makes this finding the finding it is.

    Pattern-based findings (regex, Joern queries, SCA) use the literal match.
    LLM findings use the `sink` the model named, falling back to the flagged
    source line (not `snippet`: finalize_findings swaps that for a multi-line
    context window, which would tie identity to the neighbouring code)."""
    kind = finding.get("kind")
    matched = finding.get("matched_text")
    if kind in ("regex", "joern", "sca") and matched:
        chosen = matched
    else:
        chosen = finding.get("sink") or line_text or matched or ""
    return normalize_expression(chosen)[:SINK_EXPRESSION_MAX_CHARS]


def _lang(path: str) -> Optional[str]:
    suffix = Path(path).suffix.lower()
    if suffix == ".java":
        return "java"
    if suffix in (".ts", ".tsx"):
        return "typescript"
    if suffix == ".py":
        return "python"
    return None


def _node_text(node: Any, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _signature(lang: str, node: Any, src: bytes, classes: Sequence[str]) -> Optional[str]:
    name_node = node.child_by_field_name("name")
    name = _node_text(name_node, src) if name_node is not None else None
    if name is None and node.type in _ANONYMOUS_FUNCTION_NODES:
        parent = node.parent
        if parent is not None and parent.type in _NAMED_VALUE_PARENTS:
            holder = parent.child_by_field_name("name") or parent.child_by_field_name("key")
            if holder is not None:
                name = _node_text(holder, src)
    if not name:
        return None
    params = node.child_by_field_name("parameters")
    if params is None:
        rendered = ""
    elif lang == "java":
        # Parameter *types* only: renaming a parameter is not a new method.
        types = []
        for param in params.named_children:
            type_node = param.child_by_field_name("type")
            if type_node is not None:
                types.append(normalize_expression(_node_text(type_node, src)))
            elif param.named_children:
                types.append(normalize_expression(_node_text(param.named_children[0], src)))
        rendered = ",".join(types)
    else:
        rendered = normalize_expression(_node_text(params, src)).strip("()")
    owner = ".".join(classes)
    return f"{owner + '.' if owner else ''}{name}({rendered})"


@lru_cache(maxsize=16)
def _method_spans(lang: str, text: str) -> Tuple[MethodSpan, ...]:
    """Every named function in `text` with its enclosing classes, outermost
    class first. Nested functions get their own span; callers pick the
    innermost one that contains a line."""
    parser = ast_struct.parser_for_lang(lang)
    if parser is None:
        return ()
    src = text.encode("utf-8", errors="replace")
    root = parser.parse(src).root_node
    class_types = _CLASS_NODES[lang]
    function_types = _FUNCTION_NODES[lang] + _ANONYMOUS_FUNCTION_NODES
    spans: List[MethodSpan] = []
    stack: List[Tuple[Any, Tuple[str, ...]]] = [(root, ())]
    while stack:
        node, classes = stack.pop()
        inner = classes
        if node.type in class_types:
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                inner = classes + (_node_text(name_node, src),)
        elif node.type in function_types:
            signature = _signature(lang, node, src, classes)
            if signature:
                spans.append((node.start_point[0] + 1, node.end_point[0] + 1, signature))
        for child in node.children:
            stack.append((child, inner))
    return tuple(spans)


def enclosing_method(text: str, path: str, line: int) -> Optional[MethodSpan]:
    """(start line, end line, signature) of the innermost function containing
    `line`, or None when the language is unsupported or no function does."""
    lang = _lang(path)
    if lang is None:
        return None
    try:
        spans = _method_spans(lang, text)
    except Exception:  # noqa: BLE001 - a parse problem must not fail a scan
        return None
    containing = [s for s in spans if s[0] <= line <= s[1]]
    if not containing:
        return None
    return max(containing, key=lambda s: (s[0], -s[1]))


def sink_ordinal(lines: Sequence[str], first_line: int, line: int, expression: str) -> Optional[int]:
    """How many times `expression` already appears in `lines[first_line-1:line-1]`
    (1-based `first_line`), i.e. this sink's zero-based position among identical
    ones. None when the expression never appears textually (a paraphrased LLM
    sink), so the caller can fall back to ordering."""
    if not expression:
        return None
    # The sink starts on the flagged line but may spill onto the next ones.
    window = normalize_expression("\n".join(lines[line - 1:line + 2]))
    if expression not in window:
        return None
    before = normalize_expression("\n".join(lines[first_line - 1:line - 1]))
    return before.count(expression)


def stamp_identity(root: Path, file_path: str, findings: List[Dict[str, Any]]) -> None:
    """Set `sink_expression`, `enclosing_method`, `sink_ordinal` and
    `identity_quality` on every finding in place. Never raises."""
    by_path: Dict[str, List[Dict[str, Any]]] = {}
    for finding in findings:
        by_path.setdefault(finding.get("file_path") or file_path, []).append(finding)

    for path, group in by_path.items():
        try:
            text: Optional[str] = (root / path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = None
        lines = text.splitlines() if text is not None else []
        # Fallback ordering for sinks that never appear textually.
        fallback_seen: Dict[Tuple[Any, ...], int] = {}
        for finding in sorted(group, key=lambda f: int(f.get("line") or 0)):
            line = int(finding.get("line") or 0)
            line_text = lines[line - 1] if 0 < line <= len(lines) else ""
            expression = sink_expression(finding, line_text)
            span = enclosing_method(text, path, line) if text is not None else None
            if span is not None:
                start, _end, signature = span
                finding["enclosing_method"] = signature
                finding["identity_quality"] = EXACT
            else:
                start = 1
                finding["enclosing_method"] = None
                finding["identity_quality"] = FILE_LEVEL
            ordinal = sink_ordinal(lines, start, line, expression) if lines else None
            if ordinal is None:
                key = (finding.get("rule_id"), finding.get("cwe"), finding["enclosing_method"], expression)
                ordinal = fallback_seen.get(key, 0)
                fallback_seen[key] = ordinal + 1
            finding["sink_expression"] = expression
            finding["sink_ordinal"] = ordinal

"""ast_chunker.py — split an oversized source file on declaration boundaries.

The deep scan reviews a file larger than `llm_file_scan.SINGLE_CALL_CHAR_BUDGET`
in chunks. The line-window splitter cut every few hundred lines (snapped to a
line that merely looked like a declaration), so a method could be split in
half, and every chunk after the first lost the class's own annotations
(`@RequestMapping`, `@PreAuthorize`) and its field types. This one reads the
tree-sitter parse instead:

* a cut is only made between two declarations — a method together with its
  annotations, decorators and adjacent doc comment is one unit — and complete
  declarations are packed greedily up to the budget;
* a declaration larger than the whole budget on its own is split by line
  windows with an overlap, as before;
* a chunk that starts inside a class carries `class_header`: the enclosing
  classes' annotations and declaration lines and the innermost class's fields,
  with their true line numbers.

Every chunk list covers the file's lines without gaps, whatever the parse
looked like: an ERROR node is just one more unit. Pure and best-effort: without
the grammar, or for a language it does not parse, `chunk_by_declarations`
returns None and the caller keeps the line-window splitter.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import ast_struct

CLASS_HEADER_MAX_LINES = 25
CLASS_HEADER_DECL_MAX_LINES = 8
CLASS_HEADER_FIELD_MAX_LINES = 3
CLASS_HEADER_LINE_MAX_CHARS = 200

# Only real source of these grammars: a `.jsp` is tagged "java" for the rule
# catalog and a `.tsx` "typescript", but neither parses as one.
AST_LANG_BY_SUFFIX = {".java": "java", ".ts": "typescript", ".py": "python"}

_TYPE_NODES = {
    "java": frozenset({
        "class_declaration", "interface_declaration", "enum_declaration",
        "record_declaration", "annotation_type_declaration",
    }),
    "typescript": frozenset({
        "class_declaration", "abstract_class_declaration", "interface_declaration",
    }),
    "python": frozenset({"class_definition"}),
}
_FIELD_NODES = {
    "java": frozenset({"field_declaration", "constant_declaration"}),
    "typescript": frozenset({"public_field_definition"}),
    "python": frozenset({"expression_statement"}),
}
# Preceding siblings that belong to the declaration after them when adjacent.
_PREFIX_NODES = frozenset({"comment", "line_comment", "block_comment", "decorator"})
# Wrappers whose declaration is the real member (Java enum members, TS export).
_TRANSPARENT_NODES = frozenset({"enum_body_declarations"})


@dataclass
class _Type:
    start: int  # 1-based, including annotations / decorators / export
    end: int
    header_end: int  # last line of the declaration itself (the `{` or `:` line)
    fields: List[Tuple[int, int]]


def ast_lang_for(path: Optional[str], lang: Optional[str]) -> Optional[str]:
    """The grammar to chunk `path` with, or None. Without a path the catalog
    tag is trusted (tests, callers that only know the language)."""
    if path:
        return AST_LANG_BY_SUFFIX.get(Path(path).suffix.lower())
    return lang if lang in _TYPE_NODES else None


def _type_target(node: Any, lang: str) -> Optional[Any]:
    """The type declaration `node` is, or wraps (`export class`, a decorated
    Python class); None for anything else."""
    if node.type in _TYPE_NODES[lang]:
        return node
    if node.type in ("export_statement", "decorated_definition"):
        inner = node.child_by_field_name("declaration") or node.child_by_field_name("definition")
        if inner is not None and inner.type in _TYPE_NODES[lang]:
            return inner
    return None


def _collect(container: Any, lang: str, units: List[Tuple[int, int, bool]], types: List[_Type]) -> None:
    """Every declaration-level node under `container` as a (start, end,
    is_type) unit, descending into type bodies. Rows are made 1-based here."""
    pending: Optional[int] = None  # first line of an adjacent comment/decorator run
    prev_end: Optional[int] = None
    for child in container.named_children:
        first, last = child.start_point[0] + 1, child.end_point[0] + 1
        if child.type in _PREFIX_NODES:
            if pending is None or prev_end is None or first > prev_end + 1:
                pending = first
            prev_end = last
            continue
        if child.type in _TRANSPARENT_NODES:
            pending = prev_end = None
            _collect(child, lang, units, types)
            continue
        start = pending if pending is not None and prev_end is not None and first <= prev_end + 1 else first
        pending, prev_end = None, last
        target = _type_target(child, lang)
        if target is None:
            units.append((start, last, False))
            continue
        units.append((start, last, True))
        body = target.child_by_field_name("body")
        if body is None:
            continue
        body_row = body.start_point[0] + 1
        # Python's body starts on the first statement; the declaration ends
        # the line before it. Java/TS bodies start on the `{` line.
        header_end = max(target.start_point[0] + 1, body_row - 1) if lang == "python" else body_row
        fields = [
            (c.start_point[0] + 1, c.end_point[0] + 1)
            for c in body.named_children if c.type in _FIELD_NODES[lang]
        ]
        types.append(_Type(start=start, end=last, header_end=header_end, fields=fields))
        _collect(body, lang, units, types)


def _class_header(
    types: Sequence[_Type], lines: Sequence[str], start: int, end: int,
) -> Tuple[str, List[int]]:
    """The declarations of the classes enclosing line `start` (outermost
    first) and the innermost one's fields — only lines outside [start, end],
    at most CLASS_HEADER_MAX_LINES — rendered `n: text`."""
    enclosing = sorted((t for t in types if t.start < start <= t.end), key=lambda t: t.start)
    if not enclosing:
        return "", []
    picked: List[int] = []
    for jtype in enclosing:
        last = min(jtype.header_end, jtype.start + CLASS_HEADER_DECL_MAX_LINES - 1)
        picked.extend(range(jtype.start, last + 1))
    for first, last in enclosing[-1].fields:
        picked.extend(range(first, min(last, first + CLASS_HEADER_FIELD_MAX_LINES - 1) + 1))
    chosen: List[int] = []
    for n in sorted(set(picked)):
        if start <= n <= end or n > len(lines) or not lines[n - 1].strip():
            continue
        chosen.append(n)
        if len(chosen) >= CLASS_HEADER_MAX_LINES:
            break
    rendered = "\n".join(
        f"{n}: {lines[n - 1].rstrip()[:CLASS_HEADER_LINE_MAX_CHARS]}" for n in chosen
    )
    return rendered, chosen


def chunk_by_declarations(
    text: str,
    lang: str,
    *,
    char_budget: int,
    overlap_lines: int,
) -> Optional[List[Dict[str, Any]]]:
    """Chunks of `text` ({start_line, end_line, text[, class_header,
    class_header_lines]}) cut only between declarations, or None when `lang`
    cannot be parsed here."""
    if lang not in _TYPE_NODES:
        return None
    try:
        parser = ast_struct.parser_for_lang(lang)
        if parser is None:
            return None
        root = parser.parse(text.encode("utf-8", errors="replace")).root_node
    except Exception:  # noqa: BLE001 - a parse problem must never fail a scan
        return None

    lines = text.splitlines()
    n = len(lines)
    if n == 0:
        return []
    units: List[Tuple[int, int, bool]] = []
    types: List[_Type] = []
    _collect(root, lang, units, types)

    prefix = [0] * (n + 1)
    for i, line in enumerate(lines, start=1):
        prefix[i] = prefix[i - 1] + len(line) + 1

    def size(a: int, b: int) -> int:
        return prefix[b] - prefix[a - 1]

    # A cut before line L is clean when no unit spans it. A type larger than
    # the budget is not a unit: its members are.
    blocked = [False] * (n + 2)
    for first, last, is_type in units:
        last = min(last, n)
        if is_type and size(first, last) > char_budget:
            continue
        for line_no in range(first + 1, last + 1):
            blocked[line_no] = True

    def windows(a: int, b: int) -> List[Tuple[int, int]]:
        out: List[Tuple[int, int]] = []
        s = a
        while True:
            e = s
            while e < b and size(s, e + 1) <= char_budget:
                e += 1
            out.append((s, e))
            if e >= b:
                return out
            s = max(e - overlap_lines + 1, s + 1)

    spans: List[Tuple[int, int]] = []
    start = 1
    while start <= n:
        if size(start, n) <= char_budget:
            spans.append((start, n))
            break
        best = None
        cut = start + 1
        while cut <= n and size(start, cut - 1) <= char_budget:
            if not blocked[cut]:
                best = cut
            cut += 1
        if best is not None:
            spans.append((start, best - 1))
            start = best
            continue
        # One declaration is larger than the budget: window it, then go on
        # from the first clean cut after it.
        nxt = next((c for c in range(start + 1, n + 1) if not blocked[c]), n + 1)
        spans.extend(windows(start, nxt - 1))
        start = nxt

    chunks: List[Dict[str, Any]] = []
    for first, last in spans:
        chunk: Dict[str, Any] = {
            "start_line": first, "end_line": last, "text": "\n".join(lines[first - 1:last]),
        }
        header, header_lines = _class_header(types, lines, first, last)
        if header:
            chunk["class_header"] = header
            chunk["class_header_lines"] = header_lines
        chunks.append(chunk)
    return chunks

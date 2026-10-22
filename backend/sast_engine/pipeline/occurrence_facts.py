"""occurrence_facts.py — the resolved AST facts of one finding occurrence.

Grouping, validators, prompts and the publish filter used to reason from text
near a line. This works the facts out once, from a tree-sitter parse, and
attaches them to the finding (`finding["facts"]`, persisted as
`Finding.facts`), so every consumer reasons from the same answers:

* `enclosing` — owner type, method name, parameter types, arity and the
  method's line span;
* `is_declaration` — the anchor is a method *declaration*, not a call;
* `is_stub` — the method body is only `return <literal>;`, empty, or a
  `throw new UnsupportedOperationException(...)`;
* `call` — the invocation at the anchor: callee, receiver expression, the
  receiver's resolved type, argument count and start position;
* `args` — one entry per argument with a kind (`string_literal`, `constant`,
  `numeric`, `boolean`, `enum`, `string_var`, `call_result`, `throwable`,
  `object`, `unknown`) and its source text;
* `in_comment` — the match lies inside a comment token.

Facts are inputs to decisions, never decisions. The module is pure — source
text in, facts out, no repository, no network — and best-effort: when
tree-sitter or the grammar is missing, or the file does not parse, `facts_for`
returns None and every consumer behaves exactly as it did before facts existed.
"""

from __future__ import annotations

import hashlib
import re
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

import ast_struct

ARG_KINDS = (
    "string_literal", "constant", "numeric", "boolean", "enum",
    "string_var", "call_result", "throwable", "object", "unknown",
)
ARG_TEXT_MAX_CHARS = 200
FACTS_MAX_JSON_CHARS = 2000
UNRESOLVED_SIGNATURE = "unresolved"

_PARSE_CACHE_SIZE = 32
_parse_cache: "OrderedDict[Tuple[str, str], Tuple[Any, bytes, Dict[str, Any]]]" = OrderedDict()
_parse_lock = threading.Lock()

# --- type tables --------------------------------------------------------------

_NUMERIC_TYPES = frozenset({
    "int", "long", "short", "byte", "float", "double", "char",
    "Integer", "Long", "Short", "Byte", "Float", "Double", "Character",
    "BigInteger", "AtomicInteger", "AtomicLong", "number",
})
_BOOLEAN_TYPES = frozenset({"boolean", "Boolean", "AtomicBoolean"})
_STRING_TYPES = frozenset({"String", "CharSequence", "StringBuilder", "StringBuffer", "string"})
_PARSE_METHODS = frozenset({
    "parseInt", "parseLong", "parseShort", "parseByte", "parseFloat", "parseDouble",
})
_NUMBER_BOXES = frozenset({"Integer", "Long", "Short", "Byte", "Float", "Double"})
_BIGDECIMAL_NUMERIC_CALLS = frozenset({"valueOf", "getBigDecimal"})

_JAVA_LANG = frozenset({
    "String", "Object", "Integer", "Long", "Short", "Byte", "Float", "Double", "Boolean",
    "Character", "Math", "System", "Thread", "Throwable", "Exception", "RuntimeException",
    "Error", "StringBuilder", "StringBuffer", "Class", "Number", "Runtime", "Process",
    "ProcessBuilder", "Iterable", "CharSequence", "Enum", "Record",
    "UnsupportedOperationException", "IllegalArgumentException", "IllegalStateException",
})
# Types the call graph's well-known table lacks but the accuracy checks need:
# the logging frameworks and the odd JDK type a rule's receiver test names.
_EXTRA_TYPES: Dict[str, str] = {
    "PrintStream": "java.io.PrintStream",
    "PrintWriter": "java.io.PrintWriter",
    "Calendar": "java.util.Calendar",
    "Date": "java.util.Date",
    "BigDecimal": "java.math.BigDecimal",
    "BigInteger": "java.math.BigInteger",
    "HttpServletRequest": "javax.servlet.http.HttpServletRequest",
    "HttpServletResponse": "javax.servlet.http.HttpServletResponse",
}
LOGGER_PACKAGES = (
    "org.slf4j.", "org.apache.logging.log4j.", "org.apache.log4j.",
    "java.util.logging.", "org.apache.commons.logging.", "org.jboss.logging.",
)
# Lombok's logging annotations declare an implicit `log` field.
_LOMBOK_LOG_FIELD: Dict[str, str] = {
    "Slf4j": "org.slf4j.Logger",
    "XSlf4j": "org.slf4j.ext.XLogger",
    "Log4j": "org.apache.log4j.Logger",
    "Log4j2": "org.apache.logging.log4j.Logger",
    "Log": "java.util.logging.Logger",
    "CommonsLog": "org.apache.commons.logging.Log",
    "JBossLog": "org.jboss.logging.Logger",
}
# `Factory.method(...)` calls whose result is a logger.
_LOGGER_FACTORIES: Dict[Tuple[str, str], str] = {
    ("LoggerFactory", "getLogger"): "org.slf4j.Logger",
    ("LogManager", "getLogger"): "org.apache.logging.log4j.Logger",
    ("LogManager", "getRootLogger"): "org.apache.log4j.Logger",
    ("LogFactory", "getLog"): "org.apache.commons.logging.Log",
    ("Logger", "getLogger"): "java.util.logging.Logger",
}
_JAVA_COMMENT_NODES = frozenset({"line_comment", "block_comment"})
_TS_COMMENT_NODES = frozenset({"comment"})
_JAVA_METHOD_NODES = frozenset({"method_declaration", "constructor_declaration"})
_JAVA_TYPE_NODES = frozenset({
    "class_declaration", "interface_declaration", "enum_declaration", "record_declaration",
})
_JAVA_LITERALS = frozenset({
    "decimal_integer_literal", "hex_integer_literal", "octal_integer_literal",
    "binary_integer_literal", "decimal_floating_point_literal",
    "hex_floating_point_literal",
})
_THROWABLE_RE = re.compile(r"(Throwable|Exception|Error)$")


# --- parsing ------------------------------------------------------------------

def _lang_for(path: str) -> Optional[str]:
    suffix = Path(path).suffix.lower()
    if suffix == ".java":
        return "java"
    if suffix in (".ts", ".tsx"):
        return "typescript"
    return None


def _parse(lang: str, text: str) -> Optional[Tuple[Any, bytes, Dict[str, Any]]]:
    """(root node, source bytes, per-file memo), parsed once per distinct file
    text per scan window. The memo holds what is derived from the whole file
    (names, imports) so the findings of one file do not each recompute it.
    None when the grammar is unavailable or the parse raises."""
    key = (lang, hashlib.sha1(text.encode("utf-8", errors="replace")).hexdigest())
    with _parse_lock:
        hit = _parse_cache.get(key)
        if hit is not None:
            _parse_cache.move_to_end(key)
            return hit
    try:
        parser = ast_struct.parser_for_lang(lang)
        if parser is None:
            return None
        src = text.encode("utf-8", errors="replace")
        entry = (parser.parse(src).root_node, src, {})
    except Exception:  # noqa: BLE001 - a parse problem must never fail a scan
        return None
    with _parse_lock:
        _parse_cache[key] = entry
        while len(_parse_cache) > _PARSE_CACHE_SIZE:
            _parse_cache.popitem(last=False)
    return entry


def clear_parse_cache() -> None:
    with _parse_lock:
        _parse_cache.clear()


# --- small node helpers -------------------------------------------------------

def _t(node: Any, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _f(node: Any, name: str) -> Optional[Any]:
    return node.child_by_field_name(name) if node is not None else None


def _named(node: Any) -> List[Any]:
    return [c for c in node.children if c.is_named]


def _code_children(node: Any, comments: frozenset) -> List[Any]:
    return [c for c in node.children if c.is_named and c.type not in comments]


def _cut(text: str, limit: int = ARG_TEXT_MAX_CHARS) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _simple_type(node: Optional[Any], src: bytes) -> str:
    """`List<String>` -> `List`, `a.b.Foo[]` -> `Foo`."""
    if node is None:
        return ""
    raw = _t(node, src).replace("[]", "").strip()
    raw = raw.split("<", 1)[0].strip()
    return raw.rsplit(".", 1)[-1]


def _row_col(src: bytes, line: int, col: int) -> Tuple[int, int]:
    return (max(line - 1, 0), max(col, 0))


def _line_start_byte(src: bytes, row: int) -> int:
    offset = 0
    for _ in range(row):
        nxt = src.find(b"\n", offset)
        if nxt < 0:
            return len(src)
        offset = nxt + 1
    return offset


def _anchor_point(src: bytes, text: str, line: int, match_span: Optional[Tuple[int, int]]) -> Tuple[int, int]:
    """(row, byte column) the finding points at: the match start when a span is
    known, else the first non-blank character of the line."""
    lines = text.splitlines()
    row = max(line - 1, 0)
    raw = lines[row] if row < len(lines) else ""
    if match_span is not None:
        col_chars = max(0, min(int(match_span[0]), len(raw)))
    else:
        col_chars = len(raw) - len(raw.lstrip())
    return row, len(raw[:col_chars].encode("utf-8", errors="replace"))


CALL_TEXT_MAX_CHARS = 300
STATEMENT_MAX_CHARS = 400
_STATEMENT_SUFFIXES = ("_statement", "_declaration")


def _statement_text(node: Optional[Any], src: bytes) -> Optional[str]:
    """Source of the innermost statement (or declaration) around `node`: what a
    reader means by "this statement", for checks that must not look past it."""
    cur = node
    while cur is not None:
        if cur.type.endswith(_STATEMENT_SUFFIXES) and cur.type not in (
            "class_declaration", "interface_declaration", "enum_declaration",
            "method_declaration", "constructor_declaration", "function_declaration",
            "record_declaration",
        ):
            return _cut(_t(cur, src), STATEMENT_MAX_CHARS)
        cur = cur.parent
    return None


def _anchor_is_broken(node: Optional[Any], scope_node: Optional[Any]) -> bool:
    """tree-sitter always returns a tree, repairing what it cannot parse. Facts
    read from a repaired region would be guesses, so the occurrence has none
    when its own enclosing function, or any ancestor, is an error node."""
    if scope_node is not None and scope_node.has_error:
        return True
    cur = node
    while cur is not None:
        if cur.type == "ERROR" or cur.is_missing:
            return True
        cur = cur.parent
    return False


# --- Java ---------------------------------------------------------------------

class _JavaFile:
    """What one Java file says about names: imports, types, fields, constants."""

    def __init__(self, root: Any, src: bytes) -> None:
        from pipeline import call_graph as cg  # lazy: call_graph imports llm_file_scan

        self.cg = cg
        self.root = root
        self.src = src
        self.package, self.imports, self.stars = cg._parse_imports(root, src)
        self.type_names: Set[str] = set()
        self.enum_types: Set[str] = set()
        self._collect_types(root)

    def _collect_types(self, node: Any) -> None:
        stack = [node]
        while stack:
            n = stack.pop()
            if n.type in _JAVA_TYPE_NODES:
                name = _f(n, "name")
                if name is not None:
                    text = _t(name, self.src)
                    self.type_names.add(text)
                    if n.type == "enum_declaration":
                        self.enum_types.add(text)
            stack.extend(n.children)

    def resolve(self, simple: str) -> Optional[str]:
        if not simple:
            return None
        if simple in self.imports:
            return self.imports[simple]
        if simple in self.cg._WELL_KNOWN_TYPES:
            return self.cg._WELL_KNOWN_TYPES[simple]
        if simple in _EXTRA_TYPES:
            return _EXTRA_TYPES[simple]
        if simple in self.type_names:
            return f"{self.package}.{simple}" if self.package else simple
        if simple in _JAVA_LANG:
            return f"java.lang.{simple}"
        known = set(self.cg._WELL_KNOWN_TYPES.values()) | set(_EXTRA_TYPES.values()) | set(_LOMBOK_LOG_FIELD.values())
        for star in self.stars:
            if f"{star}.{simple}" in known:
                return f"{star}.{simple}"
        return None


class _Scope:
    """The variables visible at the anchor: method parameters and locals, plus
    the fields of the enclosing class."""

    def __init__(self) -> None:
        # name -> (simple type, initializer node, is_final)
        self.locals: Dict[str, Tuple[str, Optional[Any], bool]] = {}
        self.fields: Dict[str, Tuple[str, Optional[Any], bool, bool]] = {}  # + is_static_final
        self.throwables: Set[str] = set()
        self.lombok_log: Optional[str] = None
        self.class_simple: str = ""
        self.class_fqn: str = ""


def _has_modifier(node: Any, src: bytes, word: str) -> bool:
    for child in node.children:
        if child.type == "modifiers":
            return re.search(rf"\b{word}\b", _t(child, src)) is not None
    return False


def _annotation_names(node: Any, src: bytes) -> List[str]:
    out: List[str] = []
    for child in node.children:
        if child.type == "modifiers":
            for ann in child.children:
                if ann.type in ("marker_annotation", "annotation"):
                    name = _f(ann, "name")
                    if name is not None:
                        out.append(_t(name, src).rsplit(".", 1)[-1])
    return out


def _enclosing_types(node: Any, src: bytes) -> List[Any]:
    chain: List[Any] = []
    cur = node.parent
    while cur is not None:
        if cur.type in _JAVA_TYPE_NODES:
            chain.append(cur)
        cur = cur.parent
    chain.reverse()
    return chain


def _fill_scope(jf: _JavaFile, method: Any, scope: _Scope) -> None:
    src = jf.src
    types = _enclosing_types(method, src)
    names = [_t(_f(t, "name"), src) for t in types if _f(t, "name") is not None]
    scope.class_simple = names[-1] if names else ""
    owner = ".".join(names)
    scope.class_fqn = f"{jf.package}.{owner}" if jf.package and owner else owner
    for tnode in types:
        for ann in _annotation_names(tnode, src):
            if ann in _LOMBOK_LOG_FIELD:
                scope.lombok_log = _LOMBOK_LOG_FIELD[ann]
    if types:
        body = _f(types[-1], "body")
        for child in (body.children if body is not None else []):
            if child.type != "field_declaration":
                continue
            ftype = _simple_type(_f(child, "type"), src)
            static_final = _has_modifier(child, src, "static") and _has_modifier(child, src, "final")
            is_final = _has_modifier(child, src, "final")
            for decl in _named(child):
                if decl.type == "variable_declarator" and _f(decl, "name") is not None:
                    scope.fields[_t(_f(decl, "name"), src)] = (
                        ftype, _f(decl, "value"), is_final, static_final,
                    )
    params = _f(method, "parameters")
    for p in (_named(params) if params is not None else []):
        pname = _f(p, "name")
        if pname is not None:
            scope.locals[_t(pname, src)] = (_simple_type(_f(p, "type"), src), None, False)
    body = _f(method, "body")
    if body is None:
        return
    stack = [body]
    while stack:
        n = stack.pop()
        if n.type == "local_variable_declaration":
            ltype = _simple_type(_f(n, "type"), src)
            is_final = _has_modifier(n, src, "final")
            for decl in _named(n):
                if decl.type == "variable_declarator" and _f(decl, "name") is not None:
                    init = _f(decl, "value")
                    name = _t(_f(decl, "name"), src)
                    resolved = ltype
                    if ltype == "var" and init is not None:
                        resolved = _infer_var_type(init, src)
                    scope.locals[name] = (resolved, init, is_final)
        elif n.type == "catch_formal_parameter":
            name = _f(n, "name")
            if name is not None:
                scope.locals[_t(name, src)] = ("Throwable", None, False)
                scope.throwables.add(_t(name, src))
        elif n.type == "enhanced_for_statement":
            name, tnode = _f(n, "name"), _f(n, "type")
            if name is not None:
                scope.locals[_t(name, src)] = (_simple_type(tnode, src), None, False)
        elif n.type == "resource":
            name, tnode = _f(n, "name"), _f(n, "type")
            if name is not None:
                scope.locals[_t(name, src)] = (_simple_type(tnode, src), None, False)
        stack.extend(n.children)


def _infer_var_type(init: Any, src: bytes) -> str:
    if init.type == "string_literal":
        return "String"
    if init.type == "object_creation_expression":
        return _simple_type(_f(init, "type"), src)
    if init.type in _JAVA_LITERALS:
        return "int"
    return ""


def _folded_constant(node: Any, scope: _Scope, jf: _JavaFile, depth: int = 0) -> bool:
    """Is `node` a compile-time constant: literals, same-class `static final`
    constants, local `final` variables assigned a constant, and `+` chains."""
    if node is None or depth > 6:
        return False
    src = jf.src
    t = node.type
    if t in ("string_literal", "character_literal", "true", "false", "null_literal") or t in _JAVA_LITERALS:
        return True
    if t == "parenthesized_expression":
        inner = _code_children(node, _JAVA_COMMENT_NODES)
        return bool(inner) and _folded_constant(inner[0], scope, jf, depth + 1)
    if t == "binary_expression":
        return (
            _folded_constant(_f(node, "left"), scope, jf, depth + 1)
            and _folded_constant(_f(node, "right"), scope, jf, depth + 1)
        )
    if t == "identifier":
        name = _t(node, src)
        if name in scope.locals:
            _type, init, is_final = scope.locals[name]
            return is_final and init is not None and _folded_constant(init, scope, jf, depth + 1)
        if name in scope.fields:
            _type, init, _final, static_final = scope.fields[name]
            return static_final and init is not None and _folded_constant(init, scope, jf, depth + 1)
        return False
    if t == "field_access":
        obj, field = _f(node, "object"), _f(node, "field")
        if obj is not None and field is not None and _t(obj, src) in (scope.class_simple, "this"):
            entry = scope.fields.get(_t(field, src))
            return bool(entry and entry[3] and entry[1] is not None and _folded_constant(entry[1], scope, jf, depth + 1))
    return False


def _kind_for_type(simple: str, init: Optional[Any], jf: _JavaFile) -> str:
    """Kind of a variable's *value* from its declared type. BigDecimal is not
    numeric unless it demonstrably came from a numeric source."""
    if simple in _NUMERIC_TYPES:
        return "numeric"
    if simple in _BOOLEAN_TYPES:
        return "boolean"
    if simple in _STRING_TYPES:
        return "string_var"
    if simple == "BigDecimal":
        return "numeric" if init is not None and _bigdecimal_from_numeric(init, jf.src) else "object"
    if simple in jf.enum_types:
        return "enum"
    if simple == "Throwable" or _THROWABLE_RE.search(simple or ""):
        return "throwable"
    if simple:
        return "object"
    return "unknown"


def _bigdecimal_from_numeric(init: Any, src: bytes) -> bool:
    text = _t(init, src)
    return bool(re.match(r"\s*(new\s+BigDecimal\s*\(|BigDecimal\s*\.\s*valueOf\s*\(|.*\.getBigDecimal\s*\()", text))


def _flatten_plus(node: Any) -> List[Any]:
    if node.type == "binary_expression":
        op = _f(node, "operator")
        if op is not None and op.type == "+":
            return _flatten_plus(_f(node, "left")) + _flatten_plus(_f(node, "right"))
    if node.type == "parenthesized_expression":
        inner = [c for c in node.children if c.is_named and c.type not in _JAVA_COMMENT_NODES]
        if len(inner) == 1 and inner[0].type == "binary_expression":
            return _flatten_plus(inner[0])
    return [node]


def _java_kind(node: Any, scope: _Scope, jf: _JavaFile, depth: int = 0) -> str:
    src = jf.src
    t = node.type
    if depth > 8:
        return "unknown"
    if t in ("string_literal", "text_block"):
        return "string_literal"
    if t in _JAVA_LITERALS:
        return "numeric"
    if t in ("true", "false"):
        return "boolean"
    if t in ("character_literal", "null_literal"):
        return "constant"
    if t == "parenthesized_expression":
        inner = _code_children(node, _JAVA_COMMENT_NODES)
        return _java_kind(inner[0], scope, jf, depth + 1) if inner else "unknown"
    if t == "cast_expression":
        return _kind_for_type(_simple_type(_f(node, "type"), src), None, jf)
    if t == "ternary_expression":
        a = _java_kind(_f(node, "consequence"), scope, jf, depth + 1)
        b = _java_kind(_f(node, "alternative"), scope, jf, depth + 1)
        return a if a == b else "unknown"
    if t == "binary_expression":
        op = _f(node, "operator")
        if op is not None and op.type == "+":
            if _folded_constant(node, scope, jf):
                return "constant"
            parts = [_java_kind(p, scope, jf, depth + 1) for p in _flatten_plus(node)]
            parts = ["constant" if p in ("string_literal", "constant") else p for p in parts]
            ordered: List[str] = []
            for p in parts:
                if p not in ordered:
                    ordered.append(p)
            if ordered == ["numeric"]:
                return "numeric"
            return "+".join(ordered)
        # comparison, arithmetic, boolean operators
        return "boolean" if op is not None and op.type in ("==", "!=", "<", ">", "<=", ">=", "&&", "||") else "numeric"
    if t == "identifier":
        name = _t(node, src)
        if name in scope.throwables:
            return "throwable"
        if _folded_constant(node, scope, jf):
            entry = scope.locals.get(name) or scope.fields.get(name)
            return "constant" if _kind_for_type(entry[0], entry[1], jf) in ("string_var", "unknown") else _kind_for_type(entry[0], entry[1], jf)
        if name in scope.locals:
            stype, init, _final = scope.locals[name]
            return _kind_for_type(stype, init, jf)
        if name in scope.fields:
            stype, init, _final, _sf = scope.fields[name]
            return _kind_for_type(stype, init, jf)
        return "unknown"
    if t == "field_access":
        obj, field = _f(node, "object"), _f(node, "field")
        if obj is not None and field is not None:
            oname, fname = _t(obj, src), _t(field, src)
            if oname in jf.enum_types:
                return "enum"
            if oname in (scope.class_simple, "this") and fname in scope.fields:
                stype, init, _fin, static_final = scope.fields[fname]
                if static_final and init is not None and _folded_constant(node, scope, jf):
                    return "constant"
                return _kind_for_type(stype, init, jf)
            if fname == "length":
                return "numeric"
        return "unknown"
    if t == "method_invocation":
        name_node, obj = _f(node, "name"), _f(node, "object")
        name = _t(name_node, src) if name_node is not None else ""
        oname = _t(obj, src) if obj is not None else ""
        if name in _PARSE_METHODS or (name == "valueOf" and oname in _NUMBER_BOXES):
            return "numeric"
        if name in ("size", "length", "count", "indexOf") and not _f(node, "arguments").named_children:
            return "numeric"
        if oname == "BigDecimal" and name in _BIGDECIMAL_NUMERIC_CALLS:
            return "numeric"
        return "call_result"
    if t == "object_creation_expression":
        tname = _simple_type(_f(node, "type"), src)
        if tname == "BigDecimal":
            return "numeric"
        if tname in _STRING_TYPES:
            return "string_var"
        if tname in _NUMERIC_TYPES:
            return "numeric"
        return "throwable" if _THROWABLE_RE.search(tname) else "object"
    if t in ("array_creation_expression", "lambda_expression", "method_reference", "this", "array_initializer"):
        return "object"
    return "unknown"


def _call_via(node: Any, scope: _Scope, jf: _JavaFile) -> Optional[str]:
    """For an argument built from calls (`ex.toString()`, `"a" + cal.getTime()`),
    what the calls are made on: `<declared type>.<method>`, with every
    exception class folded to `throwable`. Two arguments that are both "a call
    result" are still different when one is an exception's text and the other
    a Calendar's."""
    vias: List[str] = []
    for operand in _flatten_plus(node):
        if operand.type != "method_invocation":
            continue
        name_node, obj = _f(operand, "name"), _f(operand, "object")
        if name_node is None:
            continue
        declared = ""
        if obj is not None and obj.type == "identifier":
            ident = _t(obj, jf.src)
            if ident in scope.locals:
                declared = scope.locals[ident][0]
            elif ident in scope.fields:
                declared = scope.fields[ident][0]
            else:
                declared = ident
        elif obj is not None and obj.type == "field_access":
            declared = _t(obj, jf.src)
        if declared == "Throwable" or _THROWABLE_RE.search(declared or ""):
            declared = "throwable"
        vias.append(f"{declared or '?'}.{_t(name_node, jf.src)}")
    return ",".join(dict.fromkeys(vias)) or None


def _java_receiver(
    obj: Optional[Any], scope: _Scope, jf: _JavaFile
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """(receiver expression text, resolved receiver FQN or None, declared simple
    type name or None). The simple name survives when the FQN cannot be
    resolved (a type from another file of the package), so two receivers of
    different declared types are still told apart."""
    src = jf.src
    if obj is None:
        return None, scope.class_fqn or None, scope.class_simple or None
    text = _cut(_t(obj, src))
    t = obj.type
    if t == "this" or t == "super":
        return text, scope.class_fqn or None, scope.class_simple or None
    if t == "identifier":
        name = _t(obj, src)
        if name in scope.locals:
            declared = scope.locals[name][0]
            return text, jf.resolve(declared), declared or None
        if name in scope.fields:
            declared = scope.fields[name][0]
            return text, jf.resolve(declared), declared or None
        if name == "log" and scope.lombok_log:
            return text, scope.lombok_log, scope.lombok_log.rsplit(".", 1)[-1]
        return text, jf.resolve(name), name  # a static call on a type name
    if t == "field_access":
        o, field = _f(obj, "object"), _f(obj, "field")
        if o is not None and field is not None:
            oname, fname = _t(o, src), _t(field, src)
            if oname == "System" and fname in ("out", "err"):
                return text, "java.io.PrintStream", "PrintStream"
            if oname == "this" and fname in scope.fields:
                declared = scope.fields[fname][0]
                return text, jf.resolve(declared), declared or None
            if oname in jf.type_names or oname in jf.imports:
                return text, jf.resolve(oname), oname
        return text, None, None
    if t == "method_invocation":
        o, name_node = _f(obj, "object"), _f(obj, "name")
        if o is not None and name_node is not None:
            key = (_t(o, src), _t(name_node, src))
            if key in _LOGGER_FACTORIES:
                fqn = _LOGGER_FACTORIES[key]
                return text, fqn, fqn.rsplit(".", 1)[-1]
        return text, None, None
    if t == "object_creation_expression":
        declared = _simple_type(_f(obj, "type"), src)
        return text, jf.resolve(declared), declared or None
    return text, None, None


def _call_candidates(root: Any, row: int) -> List[Any]:
    """Invocations that start on `row`, outermost first."""
    found: List[Any] = []
    stack = [root]
    while stack:
        n = stack.pop()
        if n.start_point[0] > row or n.end_point[0] < row:
            continue
        if n.type in ("method_invocation", "object_creation_expression") and n.start_point[0] == row:
            found.append(n)
        stack.extend(n.children)
    found.sort(key=lambda n: (n.start_byte, -n.end_byte))
    return found


def _pick_call(candidates: List[Any], anchor_byte: Optional[int], hint: Optional[str], src: bytes,
               has_span: bool) -> Optional[Any]:
    if not candidates:
        return None
    if has_span and anchor_byte is not None:
        containing = [c for c in candidates if c.start_byte <= anchor_byte < c.end_byte]
        # A match that begins exactly where an invocation begins is that call.
        starting = [c for c in containing if c.start_byte == anchor_byte]
        if starting:
            return starting[0]
        # A match on a callee's name selects that call, not an enclosing one.
        named: List[Any] = []
        for c in containing:
            name = _f(c, "name") or _f(c, "type")
            if name is not None and name.start_byte <= anchor_byte < name.end_byte:
                named.append(c)
        if named:
            return named[-1]
        if containing:
            return containing[-1]
    if hint:
        tail = re.split(r"[.\s(]+", hint.strip().rstrip(")"))
        wanted = {w for w in tail if w}
        for c in candidates:
            name = _f(c, "name") or _f(c, "type")
            if name is not None and _t(name, src).rsplit(".", 1)[-1] in wanted:
                return c
    return candidates[0]


def _is_stub_body(body: Optional[Any], jf: _JavaFile) -> bool:
    if body is None:
        return False
    statements = _code_children(body, _JAVA_COMMENT_NODES)
    if not statements:
        return True
    if len(statements) != 1:
        return False
    s = statements[0]
    if s.type == "return_statement":
        value = _code_children(s, _JAVA_COMMENT_NODES)
        return not value or value[0].type in (
            "true", "false", "null_literal", "string_literal", "character_literal",
        ) or value[0].type in _JAVA_LITERALS
    if s.type == "throw_statement":
        value = _code_children(s, _JAVA_COMMENT_NODES)
        return bool(value) and value[0].type == "object_creation_expression" and _simple_type(
            _f(value[0], "type"), jf.src
        ) == "UnsupportedOperationException"
    return False


def _java_facts(root: Any, src: bytes, memo: Dict[str, Any], text: str, line: int,
                match_span: Optional[Tuple[int, int]], hint: Optional[str]) -> Dict[str, Any]:
    jf = memo.get("file")
    if jf is None:
        jf = memo["file"] = _JavaFile(root, src)
    row, col = _anchor_point(src, text, line, match_span)
    anchor = (row, col)
    anchor_byte = _line_start_byte(src, row) + col

    node = root.descendant_for_point_range(anchor, anchor)
    in_comment = False
    probe = node
    while probe is not None:
        if probe.type in _JAVA_COMMENT_NODES:
            in_comment = True
            break
        probe = probe.parent

    method = node
    while method is not None and method.type not in _JAVA_METHOD_NODES:
        method = method.parent

    if _anchor_is_broken(node, method):
        return {}
    scope = _Scope()
    enclosing: Optional[Dict[str, Any]] = None
    is_declaration = False
    is_stub = False
    if method is not None:
        _fill_scope(jf, method, scope)
        mname = _f(method, "name")
        params = _f(method, "parameters")
        ptypes = [_simple_type(_f(p, "type"), src) for p in (_named(params) if params is not None else [])]
        enclosing = {
            "owner": scope.class_fqn or None,
            "method": _t(mname, src) if mname is not None else None,
            "params": ptypes,
            "arity": len(ptypes),
            "start_line": method.start_point[0] + 1,
            "end_line": method.end_point[0] + 1,
        }
        body = _f(method, "body")
        header_end = body.start_point if body is not None else method.end_point
        is_declaration = (
            method.type == "method_declaration" and method.start_point <= anchor < header_end
        )
        is_stub = method.type == "method_declaration" and _is_stub_body(body, jf)
    else:
        # Outside a method (a field initializer): still give names their class.
        types = _enclosing_types(node, src) if node is not None else []
        if types:
            names = [_t(_f(t, "name"), src) for t in types if _f(t, "name") is not None]
            owner = ".".join(names)
            scope.class_simple = names[-1] if names else ""
            scope.class_fqn = f"{jf.package}.{owner}" if jf.package and owner else owner

    call: Optional[Dict[str, Any]] = None
    args: List[Dict[str, str]] = []
    statement: Optional[str] = None
    if not is_declaration and not in_comment:
        candidates = _call_candidates(root, row)
        if not candidates and method is not None:
            # A finding anchored on an argument line of a multi-line call.
            inner = node
            while inner is not None and inner.type not in ("method_invocation", "object_creation_expression"):
                inner = inner.parent
            candidates = [inner] if inner is not None else []
        chosen = _pick_call(candidates, anchor_byte, hint, src, match_span is not None)
        if chosen is not None:
            if chosen.type == "method_invocation":
                obj, name_node = _f(chosen, "object"), _f(chosen, "name")
                receiver, receiver_fqn, receiver_type = _java_receiver(obj, scope, jf)
                callee = _t(name_node, src) if name_node is not None else ""
            else:
                tnode = _f(chosen, "type")
                callee = _simple_type(tnode, src)
                receiver, receiver_fqn, receiver_type = None, jf.resolve(callee), callee
            arg_node = _f(chosen, "arguments")
            arg_nodes = _code_children(arg_node, _JAVA_COMMENT_NODES) if arg_node is not None else []
            owner_fqn = receiver_fqn
            call = {
                "callee": callee,
                "is_constructor": chosen.type == "object_creation_expression",
                "receiver": receiver,
                "receiver_fqn": receiver_fqn,
                "receiver_type": receiver_type,
                "owner_fqn": owner_fqn,
                "arity": len(arg_nodes),
                "start_line": chosen.start_point[0] + 1,
                "start_col": chosen.start_point[1],
                "end_line": chosen.end_point[0] + 1,
            }
            args = []
            for a in arg_nodes:
                arg = {"kind": _java_kind(a, scope, jf), "text": _cut(_t(a, src))}
                if "call_result" in arg["kind"]:
                    via = _call_via(a, scope, jf)
                    if via:
                        arg["via"] = via
                args.append(arg)
            call["text"] = _cut(_t(chosen, src), CALL_TEXT_MAX_CHARS)
            statement = _statement_text(chosen, src)
        else:
            statement = _statement_text(node, src)
    else:
        statement = _statement_text(node, src)

    return {
        "lang": "java",
        "statement": statement,
        "enclosing": enclosing,
        "is_declaration": bool(is_declaration),
        "is_stub": bool(is_stub),
        "call": call,
        "args": args,
        "in_comment": in_comment,
    }


# --- TypeScript ---------------------------------------------------------------

_TS_FUNCTION_NODES = frozenset({
    "method_definition", "function_declaration", "generator_function_declaration",
    "arrow_function", "function_expression", "function",
})


class _TsFile:
    def __init__(self, root: Any, src: bytes) -> None:
        self.root, self.src = root, src
        self.imports: Dict[str, str] = {}  # local name -> module
        for child in root.children:
            if child.type != "import_statement":
                continue
            source = _f(child, "source")
            module = _t(source, src).strip("'\"") if source is not None else ""
            stack = [child]
            while stack:
                n = stack.pop()
                if n.type == "import_specifier":
                    alias = _f(n, "alias") or _f(n, "name")
                    if alias is not None:
                        self.imports[_t(alias, src)] = module
                elif n.type == "identifier" and n.parent is not None and n.parent.type == "import_clause":
                    self.imports[_t(n, src)] = module
                elif n.type == "namespace_import":
                    for c in n.children:
                        if c.type == "identifier":
                            self.imports[_t(c, src)] = module
                stack.extend(n.children)


def _ts_type_name(node: Optional[Any], src: bytes) -> str:
    """The identifier inside a `: Type` annotation, generics stripped."""
    if node is None:
        return ""
    raw = _t(node, src).lstrip(":").strip()
    raw = raw.split("<", 1)[0].replace("[]", "").strip()
    return raw.rsplit(".", 1)[-1]


def _ts_class_of(node: Any) -> Optional[Any]:
    cur = node.parent
    while cur is not None:
        if cur.type in ("class_declaration", "abstract_class_declaration", "class"):
            return cur
        cur = cur.parent
    return None


def _ts_members(klass: Any, src: bytes) -> Dict[str, str]:
    """property name -> declared/injected type, from constructor parameter
    properties (`constructor(private t: TranslateService)`), typed fields and
    Angular `inject(Type)` initializers."""
    members: Dict[str, str] = {}
    body = _f(klass, "body")
    for child in (body.children if body is not None else []):
        if child.type == "method_definition":
            name = _f(child, "name")
            if name is not None and _t(name, src) == "constructor":
                params = _f(child, "parameters")
                for p in (_named(params) if params is not None else []):
                    has_modifier = any(c.type in ("accessibility_modifier", "readonly") for c in p.children)
                    pat = _f(p, "pattern")
                    if has_modifier and pat is not None:
                        members[_t(pat, src)] = _ts_type_name(_f(p, "type"), src)
        elif child.type in ("public_field_definition", "field_definition"):
            name = _f(child, "name") or _f(child, "property")
            if name is None:
                continue
            declared = _ts_type_name(_f(child, "type"), src)
            if not declared:
                value = _f(child, "value")
                if value is not None and value.type == "call_expression":
                    fn = _f(value, "function")
                    if fn is not None and _t(fn, src) == "inject":
                        args = _f(value, "arguments")
                        first = _named(args)[0] if args is not None and _named(args) else None
                        declared = _ts_type_name(first, src) if first is not None else ""
                elif value is not None and value.type == "new_expression":
                    declared = _ts_type_name(_f(value, "constructor"), src)
            members[_t(name, src)] = declared
    return members


def _ts_locals(fn: Optional[Any], src: bytes) -> Dict[str, Tuple[str, Optional[Any], bool]]:
    out: Dict[str, Tuple[str, Optional[Any], bool]] = {}
    if fn is None:
        return out
    params = _f(fn, "parameters")
    for p in (_named(params) if params is not None else []):
        pat = _f(p, "pattern")
        if pat is not None:
            out[_t(pat, src)] = (_ts_type_name(_f(p, "type"), src), None, False)
    stack = [fn]
    while stack:
        n = stack.pop()
        if n.type == "variable_declarator":
            name = _f(n, "name")
            if name is not None and name.type == "identifier":
                declared = _ts_type_name(_f(n, "type"), src)
                value = _f(n, "value")
                if not declared and value is not None and value.type == "new_expression":
                    declared = _ts_type_name(_f(value, "constructor"), src)
                is_const = n.parent is not None and n.parent.type == "lexical_declaration" and _t(
                    n.parent.children[0], src
                ) == "const"
                out[_t(name, src)] = (declared, value, is_const)
        stack.extend(n.children)
    return out


def _ts_kind(node: Any, locals_: Dict[str, Tuple[str, Optional[Any], bool]],
             members: Dict[str, str], src: bytes, depth: int = 0) -> str:
    t = node.type
    if depth > 8:
        return "unknown"
    if t == "string":
        return "string_literal"
    if t == "template_string":
        return "string_literal" if not any(c.type == "template_substitution" for c in node.children) else "constant+unknown"
    if t == "number":
        return "numeric"
    if t in ("true", "false"):
        return "boolean"
    if t in ("null", "undefined"):
        return "constant"
    if t == "parenthesized_expression":
        inner = _code_children(node, _TS_COMMENT_NODES)
        return _ts_kind(inner[0], locals_, members, src, depth + 1) if inner else "unknown"
    if t == "binary_expression":
        op = _f(node, "operator")
        if op is not None and op.type == "+":
            parts = [_ts_kind(_f(node, "left"), locals_, members, src, depth + 1),
                     _ts_kind(_f(node, "right"), locals_, members, src, depth + 1)]
            parts = ["constant" if p in ("string_literal", "constant") else p for p in parts]
            ordered: List[str] = []
            for p in parts:
                for piece in p.split("+"):
                    if piece not in ordered:
                        ordered.append(piece)
            return ordered[0] if len(ordered) == 1 else "+".join(ordered)
        return "boolean" if op is not None and op.type in ("==", "===", "!=", "!==", "<", ">", "<=", ">=", "&&", "||") else "numeric"
    if t == "identifier":
        name = _t(node, src)
        if name in locals_:
            declared, value, is_const = locals_[name]
            if is_const and value is not None and value.type in ("string", "number", "true", "false"):
                return "constant"
            if declared in _NUMERIC_TYPES:
                return "numeric"
            if declared in _BOOLEAN_TYPES:
                return "boolean"
            if declared in _STRING_TYPES:
                return "string_var"
            if declared in ("Error", "Exception") or _THROWABLE_RE.search(declared or ""):
                return "throwable"
            return "object" if declared else "unknown"
        return "unknown"
    if t == "call_expression":
        return "call_result"
    if t in ("new_expression", "object", "array", "arrow_function", "function_expression"):
        return "object"
    return "unknown"


def _ts_receiver(obj: Optional[Any], members: Dict[str, str], locals_: Dict[str, Any],
                 tf: _TsFile, src: bytes) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """(receiver text, resolved type name, defining module)."""
    if obj is None:
        return None, None, None
    text = _cut(_t(obj, src))
    t = obj.type
    if t == "identifier":
        name = _t(obj, src)
        if name == "console":
            return text, "console", None
        if name in locals_ and locals_[name][0]:
            tname = locals_[name][0]
            return text, tname, tf.imports.get(tname)
        return text, name, tf.imports.get(name)
    if t == "member_expression":
        inner, prop = _f(obj, "object"), _f(obj, "property")
        if inner is not None and prop is not None and inner.type == "this":
            tname = members.get(_t(prop, src), "")
            return text, tname or None, tf.imports.get(tname) if tname else None
        return text, None, None
    if t == "this":
        return text, None, None
    return text, None, None


def _ts_facts(root: Any, src: bytes, memo: Dict[str, Any], text: str, line: int,
              match_span: Optional[Tuple[int, int]], hint: Optional[str]) -> Dict[str, Any]:
    tf = memo.get("file")
    if tf is None:
        tf = memo["file"] = _TsFile(root, src)
    row, col = _anchor_point(src, text, line, match_span)
    anchor = (row, col)
    anchor_byte = _line_start_byte(src, row) + col
    node = root.descendant_for_point_range(anchor, anchor)
    in_comment = False
    probe = node
    while probe is not None:
        if probe.type in _TS_COMMENT_NODES:
            in_comment = True
            break
        probe = probe.parent
    fn = node
    while fn is not None and fn.type not in _TS_FUNCTION_NODES:
        fn = fn.parent
    # An arrow function used as a callback is not the method a reader means.
    named_fn = fn
    while named_fn is not None and named_fn.type in ("arrow_function", "function_expression", "function"):
        up = named_fn.parent
        while up is not None and up.type not in _TS_FUNCTION_NODES:
            up = up.parent
        if up is None:
            break
        named_fn = up
    if _anchor_is_broken(node, named_fn):
        return {}
    klass = _ts_class_of(node) if node is not None else None
    members = _ts_members(klass, src) if klass is not None else {}
    locals_ = _ts_locals(named_fn, src)
    owner = _t(_f(klass, "name"), src) if klass is not None and _f(klass, "name") is not None else None

    enclosing: Optional[Dict[str, Any]] = None
    is_declaration = False
    if named_fn is not None:
        mname = _f(named_fn, "name")
        params = _f(named_fn, "parameters")
        ptypes = [_ts_type_name(_f(p, "type"), src) for p in (_named(params) if params is not None else [])]
        name_text = _t(mname, src) if mname is not None else None
        if name_text is None and named_fn.parent is not None and named_fn.parent.type == "variable_declarator":
            holder = _f(named_fn.parent, "name")
            name_text = _t(holder, src) if holder is not None else None
        enclosing = {
            "owner": owner, "method": name_text, "params": ptypes, "arity": len(ptypes),
            "start_line": named_fn.start_point[0] + 1, "end_line": named_fn.end_point[0] + 1,
        }
        body = _f(named_fn, "body")
        header_end = body.start_point if body is not None else named_fn.end_point
        is_declaration = named_fn.type in ("method_definition", "function_declaration") and (
            named_fn.start_point <= anchor < header_end
        )

    call: Optional[Dict[str, Any]] = None
    args: List[Dict[str, str]] = []
    statement: Optional[str] = None
    if not is_declaration and not in_comment:
        found: List[Any] = []
        stack = [root]
        while stack:
            n = stack.pop()
            if n.start_point[0] > row or n.end_point[0] < row:
                continue
            if n.type in ("call_expression", "new_expression") and n.start_point[0] == row:
                found.append(n)
            stack.extend(n.children)
        found.sort(key=lambda n: (n.start_byte, -n.end_byte))
        chosen = None
        if found:
            if match_span is not None:
                containing = [c for c in found if c.start_byte <= anchor_byte < c.end_byte]
                starting = [c for c in containing if c.start_byte == anchor_byte]
                chosen = starting[0] if starting else (containing[-1] if containing else found[0])
            elif hint:
                chosen = next((c for c in found if hint.split("(")[0].split(".")[-1].strip() in _t(c, src)), found[0])
            else:
                chosen = found[0]
        if chosen is not None:
            fn_node = _f(chosen, "function") or _f(chosen, "constructor")
            receiver = receiver_type = module = None
            callee = ""
            if fn_node is not None and fn_node.type == "member_expression":
                prop = _f(fn_node, "property")
                callee = _t(prop, src) if prop is not None else ""
                receiver, receiver_type, module = _ts_receiver(_f(fn_node, "object"), members, locals_, tf, src)
            elif fn_node is not None:
                callee = _cut(_t(fn_node, src))
            arg_node = _f(chosen, "arguments")
            arg_nodes = _code_children(arg_node, _TS_COMMENT_NODES) if arg_node is not None else []
            call = {
                "callee": callee,
                "is_constructor": chosen.type == "new_expression",
                "receiver": receiver,
                "receiver_fqn": receiver_type,
                "receiver_type": receiver_type,
                "receiver_module": module,
                "owner_fqn": receiver_type,
                "arity": len(arg_nodes),
                "start_line": chosen.start_point[0] + 1,
                "start_col": chosen.start_point[1],
                "end_line": chosen.end_point[0] + 1,
            }
            args = [{"kind": _ts_kind(a, locals_, members, src), "text": _cut(_t(a, src))} for a in arg_nodes]
            call["text"] = _cut(_t(chosen, src), CALL_TEXT_MAX_CHARS)
            statement = _statement_text(chosen, src)
        else:
            statement = _statement_text(node, src)
    else:
        statement = _statement_text(node, src)
    return {
        "lang": "typescript",
        "statement": statement,
        "enclosing": enclosing,
        "is_declaration": bool(is_declaration),
        "is_stub": False,
        "call": call,
        "args": args,
        "in_comment": in_comment,
    }


# --- public API ---------------------------------------------------------------

class OccurrenceFacts(dict):
    """The facts as a plain JSON-ready dict (so they persist and round-trip
    untouched), with attribute access for the handful of fields callers use."""

    __slots__ = ()

    @property
    def call(self) -> Optional[Dict[str, Any]]:
        return self.get("call")

    @property
    def enclosing(self) -> Optional[Dict[str, Any]]:
        return self.get("enclosing")

    @property
    def is_declaration(self) -> bool:
        return bool(self.get("is_declaration"))

    @property
    def is_stub(self) -> bool:
        return bool(self.get("is_stub"))

    @property
    def in_comment(self) -> bool:
        return bool(self.get("in_comment"))


def _bounded(facts: Dict[str, Any]) -> Dict[str, Any]:
    """Keep a finding's serialized facts under FACTS_MAX_JSON_CHARS: trim the
    argument list first (the signature needs only the kinds), then the texts."""
    import json

    def size() -> int:
        return len(json.dumps(facts, separators=(",", ":")))

    if size() <= FACTS_MAX_JSON_CHARS:
        return facts
    if facts.get("statement"):
        facts["statement"] = facts["statement"][:120]
    if facts.get("call") and facts["call"].get("text"):
        facts["call"]["text"] = facts["call"]["text"][:120]
    for arg in facts.get("args") or []:
        arg["text"] = arg["text"][:40]
    if size() > FACTS_MAX_JSON_CHARS and facts.get("call"):
        facts["call"]["receiver"] = (facts["call"].get("receiver") or "")[:60] or None
    while size() > FACTS_MAX_JSON_CHARS and len(facts.get("args") or []) > 4:
        facts["args"].pop()
    return facts


def facts_for(
    file_path: str,
    source_text: str,
    line: int,
    match_span: Optional[Tuple[int, int]] = None,
    *,
    sink_hint: Optional[str] = None,
) -> Optional[OccurrenceFacts]:
    """Facts for the occurrence at `line` of `file_path`, or None when the
    language is unsupported, tree-sitter/the grammar is missing, or the file
    does not parse. `match_span` is (start, end) *columns on that line*;
    `sink_hint` (an LLM finding's `sink`) picks among several calls on a line."""
    lang = _lang_for(file_path or "")
    if lang is None or not source_text or line is None or int(line) < 1:
        return None
    parsed = _parse(lang, source_text)
    if parsed is None:
        return None
    root, src, memo = parsed
    try:
        if lang == "java":
            facts = _java_facts(root, src, memo, source_text, int(line), match_span, sink_hint)
        else:
            facts = _ts_facts(root, src, memo, source_text, int(line), match_span, sink_hint)
    except Exception:  # noqa: BLE001 - facts are best-effort, never fatal
        return None
    if not facts:  # the anchor sits in a region tree-sitter had to repair
        return None
    return OccurrenceFacts(_bounded(facts))


def semantic_signature(facts: Optional[Dict[str, Any]]) -> str:
    """The part of an occurrence's facts that decides whether two occurrences
    are the same construct, as one string (SAST-01-060).

    A call is identified by what it calls — owner type, name, arity — on what
    kind of receiver, with which kinds of arguments. A match that is not a call
    is a declaration (identified by method name, arity and whether its body is
    a stub, never by the class: the same method across 100 files is one
    construct) or some other construct. No facts at all is `unresolved`, which
    groups with other unresolved members but never with resolved ones."""
    if not facts:
        return UNRESOLVED_SIGNATURE
    if facts.get("in_comment"):
        return "comment"
    call = facts.get("call")
    if call:
        kinds = ",".join(
            a.get("kind", "unknown") + (f":{a['via']}" if a.get("via") else "")
            for a in facts.get("args") or []
        )
        declared = call.get("receiver_type")
        owner = call.get("owner_fqn") or (f"~{declared}" if declared else "?")
        receiver = call.get("receiver_fqn") or (f"~{declared}" if declared else "?")
        return f"call:{owner}.{call.get('callee')}/{call.get('arity')}|{receiver}|({kinds})"
    enclosing = facts.get("enclosing") or {}
    if facts.get("is_declaration"):
        shape = "stub" if facts.get("is_stub") else "impl"
        return f"decl:{enclosing.get('method')}/{enclosing.get('arity')}|{shape}"
    return f"other:{'stub' if facts.get('is_stub') else 'body'}"

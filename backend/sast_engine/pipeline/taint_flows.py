"""taint_flows.py — argument-level taint along Java call-graph flows.

`call_graph.discover_flows` proves only that methods call each other. This
module follows *values*: does the entry's untrusted input reach the sink
call's dangerous argument through the arguments of each call on the path?

Two layers, both deterministic (no LLM):

1. A per-method summary, computed once per method regardless of caller.
   Every parameter gets a symbolic label `P<i>` and every request accessor in
   the body (`request.getParameter(..)`, ...) a source label. A small
   flow-insensitive fixpoint over the body (assignments, `+=`, builder/collection
   mutation, for-each and lambda parameters) gives every call's arguments and
   receiver a label set. Conversions to a number, boolean, enum or UUID kill a
   label; known library encoders mark it sanitized.
2. Composition along one flow: the labels of the edge call's arguments are
   substituted hop by hop (`P<i>` of the next method = what the caller passed
   at position i), and the sink call's dangerous argument decides the outcome.

Outcomes (`STATUS_*`):

- `path`            untrusted input reaches the sink argument unsanitized.
- `sanitized_path`  it reaches it only through a library encoder.
- `unknown`         the trace lost the value (a field, an untyped lambda, a
                    call that could not be located). Never treated as safe.
- `no_path`         every value at the sink argument was followed and none
                    derives from untrusted input.

Best-effort and unsound by design: fields, collections passed by reference,
reflection and callbacks are not modelled. Every such gap yields `unknown`,
never `no_path`, and the only thing `no_path` does is keep a flow out of LLM
verification (its call chain is still reachability evidence). Propagation is
deliberately generous (a call's result carries its arguments' and receiver's
labels unless a conversion is known), so the error it makes is calling a flow
`path` that is not, never dropping one that is. The model still decides.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Sequence, Set, Tuple

import ast_struct
from pipeline import reachability

STATUS_PATH = reachability.STATUS_PATH
STATUS_SANITIZED = reachability.STATUS_SANITIZED
STATUS_UNKNOWN = "unknown"
STATUS_NO_PATH = "no_path"
_RANK = {STATUS_PATH: 0, STATUS_SANITIZED: 1, STATUS_UNKNOWN: 2, STATUS_NO_PATH: 3}

_FIXPOINT_ROUNDS = 25
_MAX_EVAL_DEPTH = 60
_CODE_CHARS = 160
_MAX_UNKNOWN_REASONS = 3

# Types whose values cannot carry injectable text.
_NON_TEXT_TYPES = frozenset({
    "int", "long", "short", "byte", "double", "float", "boolean", "char", "void",
    "Integer", "Long", "Short", "Byte", "Double", "Float", "Boolean", "Character",
    "Number", "BigDecimal", "BigInteger", "AtomicInteger", "AtomicLong",
    "UUID", "LocalDate", "LocalDateTime", "LocalTime", "ZonedDateTime",
    "OffsetDateTime", "Instant", "Date", "Duration", "Period",
})
# Entry-method parameters the container fills with something other than
# request input.
_NON_INPUT_PARAM_TYPES = _NON_TEXT_TYPES | frozenset({
    "HttpServletResponse", "ServletResponse", "Model", "ModelMap", "ModelAndView",
    "RedirectAttributes", "BindingResult", "Errors", "Principal", "Authentication",
    "Locale", "TimeZone", "ZoneId", "UriComponentsBuilder", "SessionStatus",
})
_STRING_LIKE = frozenset({
    "String", "CharSequence", "Object", "byte[]", "Byte[]",
    "Collection", "List", "Map", "Set", "CharBuffer",
})

# Results that are a count, a test or a position — never the text itself.
_NON_TEXT_RESULT_METHODS = frozenset({
    "length", "size", "isEmpty", "isBlank", "equals", "equalsIgnoreCase", "contains",
    "containsKey", "containsValue", "startsWith", "endsWith", "matches", "hashCode",
    "compareTo", "compareToIgnoreCase", "indexOf", "lastIndexOf", "count", "hasNext",
    "isPresent", "intValue", "longValue", "doubleValue", "floatValue", "shortValue",
    "byteValue", "booleanValue", "getTime", "ordinal", "signum", "exists",
    "isDirectory", "isFile", "canRead", "canWrite", "parseInt", "parseLong",
    "parseShort", "parseByte", "parseDouble", "parseFloat", "parseBoolean",
})
# `X.valueOf(s)` on these keeps the text; on any other type it converts.
_TEXT_VALUE_OF_OWNERS = frozenset({"String", "Objects", "StringBuilder", "StringBuffer", "CharSequence"})

# Library encoders: method name -> (required receiver, or None for any; the
# sink kinds it defends). An encoder counts only against those kinds — HTML
# escaping before a SQL query is not a SQL defence, so that path stays `path`.
_MARKUP = ("xss",)
_URL = ("redirect", "ssrf", "xss")
_SQL = ("jdbc_template", "jpa", "sql")
_SANITIZERS: Dict[str, Tuple[Optional[FrozenSet[str]], Tuple[str, ...]]] = {
    **{name: (None, _MARKUP) for name in (
        "htmlEscape", "htmlEscapeDecimal", "htmlEscapeHex", "escapeHtml", "escapeHtml3",
        "escapeHtml4", "escapeXml", "escapeXml10", "escapeXml11", "escapeEcmaScript",
        "escapeJavaScript", "escapeJson", "forHtml", "forHtmlContent", "forHtmlAttribute",
        "forHtmlUnquotedAttribute", "forJavaScript", "forJavaScriptBlock",
        "forJavaScriptAttribute", "forXml", "forXmlContent", "forXmlAttribute",
        "forCssString", "encodeForHTML", "encodeForHTMLAttribute", "encodeForJavaScript",
        "encodeForCSS", "encodeForXML", "encodeForXMLAttribute",
    )},
    **{name: (None, _URL) for name in ("forUri", "forUriComponent", "encodeForURL")},
    **{name: (None, _SQL) for name in ("escapeSql", "encodeForSQL")},
    **{name: (None, ("ldap",)) for name in ("encodeForLDAP", "encodeForDN", "filterEncode", "nameEncode")},
    "encodeForOS": (None, ("command",)),
    "encode": (frozenset({"URLEncoder", "UriUtils"}), _URL),
    "getName": (frozenset({"FilenameUtils"}), ("files",)),
    "clean": (frozenset({"Jsoup"}), _MARKUP),
    "sanitize": (frozenset({"policy", "POLICY", "sanitizer", "SANITIZER", "PolicyFactory"}), _MARKUP),
}

# HttpServletRequest accessors that return client-controlled data.
_SOURCE_METHODS = frozenset({
    "getParameter", "getParameterValues", "getParameterMap", "getParameterNames",
    "getHeader", "getHeaders", "getHeaderNames", "getQueryString", "getRequestURI",
    "getRequestURL", "getPathInfo", "getServletPath", "getCookies", "getInputStream",
    "getReader", "getPart", "getParts", "getRemoteUser",
})
_REQUEST_TYPES = frozenset({
    "HttpServletRequest", "ServletRequest", "HttpServletRequestWrapper",
    "MultipartHttpServletRequest", "WebRequest", "NativeWebRequest", "ServerHttpRequest",
})
_REQUEST_NAMES = frozenset({"request", "req", "httpRequest", "servletRequest", "httpServletRequest"})

# Methods that write their argument into their (local) receiver.
_MUTATORS = frozenset({
    "append", "insert", "add", "addAll", "put", "putAll", "push", "offer",
    "addFirst", "addLast", "set", "setLength",
})

# Which arguments of a sink call carry the dangerous value, per sink kind /
# method. Absent: every argument (or the receiver for a zero-argument call).
_SINK_ARG_POSITIONS: Dict[Tuple[str, str], Tuple[int, ...]] = {
    ("sql", "executeQuery"): (0,), ("sql", "executeUpdate"): (0,), ("sql", "execute"): (0,),
    ("sql", "executeLargeUpdate"): (0,),
    ("jpa", "createQuery"): (0,), ("jpa", "createNativeQuery"): (0,),
    ("jdbc_template", "query"): (0,), ("jdbc_template", "update"): (0,),
    ("jdbc_template", "execute"): (0,),
    ("eval", "parseExpression"): (0,), ("eval", "eval"): (0,),
    ("reflect", "forName"): (0,),
    ("ssrf", "getForObject"): (0,), ("ssrf", "getForEntity"): (0,),
    ("ssrf", "postForObject"): (0,), ("ssrf", "postForEntity"): (0,),
    ("ssrf", "exchange"): (0,), ("ssrf", "put"): (0,), ("ssrf", "delete"): (0,),
    ("ssrf", "patchForObject"): (0,),
}


# ---------------------------------------------------------------------------
# Values
# ---------------------------------------------------------------------------

# A label: (origin, sanitizers). origin is "P<i>" (the method's i-th parameter)
# or "S|<line>|<code>" (a request accessor in the body); sanitizers is a sorted
# tuple of (line, code, sink kinds it defends) encoder calls the value went through.
Label = Tuple[str, Tuple[Tuple[int, str, Tuple[str, ...]], ...]]


@dataclass(frozen=True)
class Val:
    labels: FrozenSet[Label] = frozenset()
    unknown: FrozenSet[str] = frozenset()

    def __or__(self, other: "Val") -> "Val":
        if not other.labels and not other.unknown:
            return self
        if not self.labels and not self.unknown:
            return other
        return Val(self.labels | other.labels, self.unknown | other.unknown)

    def sanitized(self, line: int, code: str, kinds: Tuple[str, ...]) -> "Val":
        mark = (line, code, kinds)
        return Val(
            frozenset((o, tuple(sorted(set(s) | {mark}))) for o, s in self.labels),
            self.unknown,
        )


CLEAN = Val()


def _unknown(reason: str) -> Val:
    return Val(unknown=frozenset({reason}))


def _union(vals: Iterable[Val]) -> Val:
    out = CLEAN
    for v in vals:
        out = out | v
    return out


@dataclass
class CallRecord:
    line: int
    name: str
    argc: int
    args: List[Val]
    receiver: Val
    code: str


@dataclass
class MethodTaint:
    params: List[Tuple[str, str, str, int]]  # (name, simple type, declaration text, line)
    calls: List[CallRecord]

    def calls_at(self, line: int, name: str, argc: Optional[int] = None) -> List[CallRecord]:
        hits = [c for c in self.calls if c.line == line and c.name == name]
        if argc is not None:
            exact = [c for c in hits if c.argc == argc]
            if exact:
                return exact
        return hits


# ---------------------------------------------------------------------------
# Tree helpers
# ---------------------------------------------------------------------------

def _text(node: Any, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _field(node: Any, name: str) -> Optional[Any]:
    return node.child_by_field_name(name)


def _named(node: Any) -> List[Any]:
    return [c for c in node.children if c.is_named and c.type not in ("line_comment", "block_comment")]


def _simple_type(node: Optional[Any], src: bytes) -> str:
    if node is None:
        return ""
    raw = _text(node, src).strip()
    if raw.endswith("[]"):
        return raw.split("<", 1)[0].rsplit(".", 1)[-1].replace(" ", "")
    return raw.split("<", 1)[0].strip().rsplit(".", 1)[-1]


def _one_line(text: str) -> str:
    return " ".join(text.split())[:_CODE_CHARS]


def _walk(node: Any) -> Iterable[Any]:
    """Every node under `node` in source order, not entering nested or
    anonymous type bodies (their methods are summarised on their own)."""
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        for child in reversed(n.children):
            if child.type in ast_struct._NESTED_TYPE_DECLS or child.type == "class_body":
                continue
            stack.append(child)


# ---------------------------------------------------------------------------
# Per-method summary
# ---------------------------------------------------------------------------

class _MethodAnalysis:
    def __init__(self, analyzer: "TaintAnalyzer", method: Any, node: Any, src: bytes) -> None:
        self.analyzer = analyzer
        self.method = method
        self.node = node
        self.src = src
        self.types: Dict[str, str] = {}
        self.env: Dict[str, Val] = {}
        self.params: List[Tuple[str, str, str, int]] = []

    # -- setup ---------------------------------------------------------------

    def _declare(self, name: str, type_name: str, initial: Val = CLEAN) -> None:
        self.types.setdefault(name, type_name)
        self.env.setdefault(name, initial)

    def _collect_declarations(self) -> List[Tuple[str, Any]]:
        """Declare every local and return the bindings (target, expression):
        the expression's value flows into the target. A for-each variable or
        a lambda parameter is bound to the collection/stream it iterates."""
        params_node = _field(self.node, "parameters")
        if params_node is not None:
            formal = [p for p in _named(params_node) if p.type in ("formal_parameter", "spread_parameter")]
            for i, p in enumerate(formal):
                name_node = _field(p, "name")
                if name_node is None:  # spread_parameter: name sits on its declarator
                    decl = next((c for c in _named(p) if c.type == "variable_declarator"), None)
                    name_node = _field(decl, "name") if decl is not None else None
                if name_node is None:
                    continue
                pname = _text(name_node, self.src)
                type_node = _field(p, "type") or next(  # spread_parameter's type has no field name
                    (c for c in _named(p) if c.type.endswith("type") or c.type == "type_identifier"), None)
                ptype = _simple_type(type_node, self.src)
                self.params.append((pname, ptype, _one_line(_text(p, self.src)), p.start_point[0] + 1))
                label = CLEAN if ptype in _NON_TEXT_TYPES else Val(frozenset({(f"P{i}", ())}))
                self._declare(pname, ptype, label)

        bindings: List[Tuple[str, Any]] = []
        body = _field(self.node, "body")
        if body is None:
            return bindings
        for n in _walk(body):
            t = n.type
            if t == "local_variable_declaration":
                type_name = _simple_type(_field(n, "type"), self.src)
                for decl in _named(n):
                    if decl.type != "variable_declarator":
                        continue
                    name_node, value = _field(decl, "name"), _field(decl, "value")
                    if name_node is None:
                        continue
                    name = _text(name_node, self.src)
                    self._declare(name, type_name)
                    if value is not None and type_name not in _NON_TEXT_TYPES:
                        bindings.append((name, value))
            elif t == "resource":
                name_node, value = _field(n, "name"), _field(n, "value")
                if name_node is not None:
                    name = _text(name_node, self.src)
                    type_name = _simple_type(_field(n, "type"), self.src)
                    self._declare(name, type_name)
                    if value is not None and type_name not in _NON_TEXT_TYPES:
                        bindings.append((name, value))
            elif t == "enhanced_for_statement":
                name_node, value = _field(n, "name"), _field(n, "value")
                if name_node is not None:
                    name = _text(name_node, self.src)
                    type_name = _simple_type(_field(n, "type"), self.src)
                    self._declare(name, type_name)
                    if value is not None and type_name not in _NON_TEXT_TYPES:
                        bindings.append((name, value))
            elif t == "catch_formal_parameter":
                name_node = _field(n, "name")
                if name_node is not None:
                    self._declare(_text(name_node, self.src), "Throwable")
            elif t == "lambda_expression":
                self._bind_lambda(n, bindings)
            elif t == "assignment_expression":
                target = self._assign_target(_field(n, "left"))
                right = _field(n, "right")
                if target and right is not None:
                    bindings.append((target, right))
            elif t == "method_invocation":
                name_node = _field(n, "name")
                if name_node is not None and _text(name_node, self.src) in _MUTATORS:
                    root = self._mutation_root(n)
                    args = _field(n, "arguments")
                    if root and args is not None:
                        bindings.append((root, args))
        return bindings

    def _bind_lambda(self, lam: Any, bindings: List[Tuple[str, Any]]) -> None:
        params = _field(lam, "parameters")
        if params is None:
            return
        if params.type == "identifier":
            names = [params]
        else:
            names = []
            for p in _named(params):
                if p.type == "identifier":
                    names.append(p)
                else:
                    n = _field(p, "name")
                    if n is not None:
                        names.append(n)
        # `xs.forEach(x -> ..)` / `stream.map(x -> ..)`: the element comes
        # from the receiver the lambda is handed to.
        parent = lam.parent
        invocation = parent.parent if parent is not None and parent.type == "argument_list" else None
        receiver = _field(invocation, "object") if invocation is not None and invocation.type == "method_invocation" else None
        for name_node in names:
            name = _text(name_node, self.src)
            if receiver is None:
                self._declare(name, "", _unknown(f"lambda parameter `{name}`"))
            else:
                self._declare(name, "")
                bindings.append((name, receiver))

    def _assign_target(self, left: Optional[Any]) -> Optional[str]:
        while left is not None and left.type == "array_access":
            left = _field(left, "array")
        if left is not None and left.type == "identifier":
            name = _text(left, self.src)
            if name in self.env:
                return name
        return None  # a field write: not modelled

    def _mutation_root(self, inv: Any) -> Optional[str]:
        obj = _field(inv, "object")
        while obj is not None and obj.type == "method_invocation":
            name_node = _field(obj, "name")
            if name_node is None or _text(name_node, self.src) not in _MUTATORS:
                return None
            obj = _field(obj, "object")
        if obj is not None and obj.type == "identifier":
            name = _text(obj, self.src)
            if name in self.env and self.types.get(name, "") not in _NON_TEXT_TYPES:
                return name
        return None

    # -- evaluation ----------------------------------------------------------

    def value_of(self, node: Optional[Any], depth: int = 0) -> Val:
        if node is None or depth > _MAX_EVAL_DEPTH:
            return CLEAN if node is None else _unknown("expression too deep")
        t = node.type
        if t.endswith("_literal") or t in ("true", "false", "text_block", "this", "super",
                                            "lambda_expression", "method_reference",
                                            "instanceof_expression", "update_expression"):
            return CLEAN
        if t == "identifier":
            return self._identifier(_text(node, self.src))
        if t == "field_access":
            obj = _field(node, "object")
            fld = _field(node, "field")
            if obj is not None and obj.type in ("this", "super"):
                return self._field_value(_text(fld, self.src) if fld is not None else "?")
            if obj is not None and obj.type == "identifier" and _text(obj, self.src)[:1].isupper():
                return CLEAN  # Type.CONSTANT
            return self.value_of(obj, depth + 1)
        if t == "binary_expression":
            op_node = _field(node, "operator")
            op = _text(op_node, self.src) if op_node is not None else "+"
            if op != "+":
                return CLEAN  # comparisons, logic and arithmetic other than concatenation
            return self.value_of(_field(node, "left"), depth + 1) | self.value_of(_field(node, "right"), depth + 1)
        if t == "unary_expression":
            return CLEAN
        if t == "cast_expression":
            if _simple_type(_field(node, "type"), self.src) in _NON_TEXT_TYPES:
                return CLEAN
            return self.value_of(_field(node, "value"), depth + 1)
        if t == "ternary_expression":
            return self.value_of(_field(node, "consequence"), depth + 1) | self.value_of(_field(node, "alternative"), depth + 1)
        if t == "array_access":
            return self.value_of(_field(node, "array"), depth + 1)
        if t == "assignment_expression":
            return self.value_of(_field(node, "right"), depth + 1)
        if t == "method_invocation":
            return self._invocation(node, depth)
        if t == "object_creation_expression":
            if _simple_type(_field(node, "type"), self.src) in _NON_TEXT_TYPES:
                return CLEAN
            return self._args(_field(node, "arguments"), depth)
        if t == "argument_list":
            return self._args(node, depth)
        # parenthesized expressions, array initialisers, switch expressions, ...
        return _union(self.value_of(c, depth + 1) for c in _named(node))

    def _args(self, args: Optional[Any], depth: int) -> Val:
        if args is None:
            return CLEAN
        return _union(self.value_of(a, depth + 1) for a in _named(args))

    def _identifier(self, name: str) -> Val:
        if name in self.env:
            return self.env[name]
        if name[:1].isupper():
            return CLEAN  # a constant or a type name
        return self._field_value(name)

    def _field_value(self, name: str) -> Val:
        if name[:1].isupper() or name.isupper():
            return CLEAN
        jtype = self.analyzer.graph.types.get(self.method.fqcn)
        ftype = (jtype.fields.get(name) if jtype is not None else None) or ""
        if ftype in _NON_TEXT_TYPES:
            return CLEAN
        return _unknown(f"field `{name}`")

    def _invocation(self, node: Any, depth: int) -> Val:
        name_node = _field(node, "name")
        name = _text(name_node, self.src) if name_node is not None else ""
        obj = _field(node, "object")
        args = _field(node, "arguments")
        line = node.start_point[0] + 1
        obj_text = _text(obj, self.src) if obj is not None else ""

        if name in _SOURCE_METHODS and self._is_request(obj):
            code = _one_line(_text(node, self.src))
            return Val(frozenset({(f"S|{line}|{code}", ())}))
        if name in _NON_TEXT_RESULT_METHODS:
            return CLEAN
        if obj is not None and obj.type == "identifier" and obj_text in _NON_TEXT_TYPES:
            return CLEAN  # Integer.valueOf, UUID.fromString, Math.max, ...
        if name == "valueOf" and obj_text[:1].isupper() and obj_text not in _TEXT_VALUE_OF_OWNERS:
            return CLEAN  # an enum or wrapper conversion
        encoder = _SANITIZERS.get(name)
        if encoder is not None and (encoder[0] is None or obj_text.rsplit(".", 1)[-1] in encoder[0]):
            return self._args(args, depth).sanitized(line, _one_line(_text(node, self.src)), encoder[1])
        if self._returns_non_text(obj, name, args):
            return CLEAN
        receiver = self.value_of(obj, depth + 1)
        if self._is_field_ref(obj):
            # A field receiver is a collaborator (connection, DAO, template),
            # not data: what it may hold is no reason to lose the trace.
            receiver = Val(receiver.labels)
        return receiver | self._args(args, depth)

    def _is_field_ref(self, node: Optional[Any]) -> bool:
        if node is None:
            return False
        if node.type == "identifier":
            return _text(node, self.src) not in self.env
        return node.type == "field_access" and (_field(node, "object") is not None
                                                and _field(node, "object").type in ("this", "super"))

    def _is_request(self, obj: Optional[Any]) -> bool:
        if obj is None:
            return False
        if obj.type == "identifier":
            name = _text(obj, self.src)
            return self.types.get(name, "") in _REQUEST_TYPES or name in _REQUEST_NAMES
        if obj.type == "method_invocation":
            inner = _field(obj, "name")
            return inner is not None and _text(inner, self.src) in ("getRequest", "getNativeRequest")
        return False

    def _returns_non_text(self, obj: Optional[Any], name: str, args: Optional[Any]) -> bool:
        """An in-repo callee whose declared return type is a number/boolean."""
        graph = self.analyzer.graph
        argc = len(_named(args)) if args is not None else 0
        owner: Optional[str] = None
        if obj is None or obj.type == "this":
            owner = self.method.fqcn
        elif obj.type == "identifier":
            simple = self.types.get(_text(obj, self.src))
            if simple is None:
                jtype = graph.types.get(self.method.fqcn)
                simple = jtype.fields.get(_text(obj, self.src)) if jtype is not None else None
            candidates = graph.types_by_simple.get(simple or "", [])
            owner = candidates[0] if len(candidates) == 1 else None
        if owner is None:
            return False
        keys = graph.methods_by_sig.get((owner, name, argc)) or []
        types = {graph.methods[k].return_type for k in keys if k in graph.methods}
        return bool(types) and types <= _NON_TEXT_TYPES

    # -- run -----------------------------------------------------------------

    def run(self) -> MethodTaint:
        bindings = self._collect_declarations()
        for _ in range(_FIXPOINT_ROUNDS):
            changed = False
            for target, expr in bindings:
                new = self.env.get(target, CLEAN) | self.value_of(expr)
                if new != self.env.get(target, CLEAN):
                    self.env[target] = new
                    changed = True
            if not changed:
                break
        calls: List[CallRecord] = []
        body = _field(self.node, "body")
        if body is not None:
            for n in _walk(body):
                if n.type == "method_invocation":
                    name_node = _field(n, "name")
                    obj = _field(n, "object")
                    name = _text(name_node, self.src) if name_node is not None else ""
                elif n.type == "object_creation_expression":
                    obj = None
                    name = _simple_type(_field(n, "type"), self.src)
                else:
                    continue
                arg_nodes = _named(_field(n, "arguments")) if _field(n, "arguments") is not None else []
                calls.append(CallRecord(
                    line=n.start_point[0] + 1,
                    name=name,
                    argc=len(arg_nodes),
                    args=[self.value_of(a) for a in arg_nodes],
                    receiver=self.value_of(obj) if obj is not None else CLEAN,
                    code=_one_line(_text(n, self.src)),
                ))
        return MethodTaint(params=self.params, calls=calls)


# ---------------------------------------------------------------------------
# Composition along a flow
# ---------------------------------------------------------------------------

# A concrete taint: where it came from (hop index, file, line, code) and the
# encoders it went through ((file, line, code, sink kinds), ...).
@dataclass(frozen=True)
class _Concrete:
    hop: int
    file: str
    line: int
    code: str
    sanitizers: FrozenSet[Tuple[str, int, str, Tuple[str, ...]]] = frozenset()


@dataclass
class _ParamTaint:
    taints: Set[_Concrete] = field(default_factory=set)
    unknown: Set[str] = field(default_factory=set)


class TaintAnalyzer:
    """Summaries for one call graph, memoised per method."""

    def __init__(self, graph: Any) -> None:
        self.graph = graph
        self._trees: Dict[str, Any] = {}
        self._summaries: Dict[str, Optional[MethodTaint]] = {}

    def _tree(self, rel: str) -> Optional[Tuple[Any, bytes]]:
        if rel not in self._trees:
            from pipeline import call_graph

            text = call_graph._file_text(self.graph, rel)
            parser = ast_struct.parser_for_lang("java")
            if text is None or parser is None:
                self._trees[rel] = None
            else:
                src = text.encode("utf-8", errors="replace")
                self._trees[rel] = (parser.parse(src), src)
        return self._trees[rel]

    def summary(self, method_key: str) -> Optional[MethodTaint]:
        if method_key in self._summaries:
            return self._summaries[method_key]
        result: Optional[MethodTaint] = None
        method = self.graph.methods.get(method_key)
        parsed = self._tree(method.file) if method is not None else None
        if method is not None and parsed is not None:
            tree, src = parsed
            node = _find_declaration(tree.root_node, method.start_line)
            if node is not None:
                result = _MethodAnalysis(self, method, node, src).run()
        self._summaries[method_key] = result
        return result

    # -- entry -----------------------------------------------------------------

    def _entry_context(self, method: Any, summ: MethodTaint, tier: str) -> Dict[str, _ParamTaint]:
        ctx: Dict[str, _ParamTaint] = {}
        for i, (name, ptype, decl, line) in enumerate(summ.params):
            pt = _ParamTaint()
            if tier == "framework":
                untrusted = ptype not in _NON_INPUT_PARAM_TYPES
            elif tier == "public_api":
                untrusted = ptype in _STRING_LIKE or ptype.endswith("[]")
            else:
                untrusted = False
            if untrusted:
                pt.taints.add(_Concrete(hop=0, file=method.file, line=line, code=decl))
            ctx[f"P{i}"] = pt
        return ctx

    @staticmethod
    def _resolve(val: Val, ctx: Dict[str, _ParamTaint], hop: int, file: str) -> _ParamTaint:
        out = _ParamTaint(unknown=set(val.unknown))
        for origin, sanitizers in val.labels:
            marks = frozenset((file, line, code, kinds) for line, code, kinds in sanitizers)
            if origin.startswith("P"):
                pt = ctx.get(origin)
                if pt is None:
                    continue
                out.unknown |= pt.unknown
                for c in pt.taints:
                    out.taints.add(_Concrete(c.hop, c.file, c.line, c.code, c.sanitizers | marks))
            else:
                _s, line, code = origin.split("|", 2)
                out.taints.add(_Concrete(hop, file, int(line), code, marks))
        return out

    # -- flow ------------------------------------------------------------------

    def trace(self, flow: Any) -> Dict[str, Any]:
        keys: Sequence[str] = getattr(flow, "method_keys", None) or []
        call_lines: Sequence[int] = getattr(flow, "call_lines", None) or []
        if len(keys) != len(flow.hops) or len(call_lines) != len(keys) - 1 or not flow.sink_method:
            return _result(STATUS_UNKNOWN, unknown=["the flow carries no call positions"])
        methods = [self.graph.methods.get(k) for k in keys]
        summaries = [self.summary(k) for k in keys]
        for m, s, k in zip(methods, summaries, keys):
            if m is None or s is None:
                return _result(STATUS_UNKNOWN, unknown=[f"could not analyse {k.split('::')[2] if '::' in k else k}"])

        ctx = self._entry_context(methods[0], summaries[0], flow.entry_tier)
        call_steps: List[Dict[str, Any]] = []
        for i in range(len(keys) - 1):
            method, summ, nxt = methods[i], summaries[i], methods[i + 1]
            records = summ.calls_at(call_lines[i], nxt.name, nxt.argc)
            if not records:
                return _result(STATUS_UNKNOWN, unknown=[
                    f"call to {nxt.name} at {method.file}:{call_lines[i]} not found"])
            call_steps.append(_step(method, call_lines[i], records[0].code))
            next_ctx: Dict[str, _ParamTaint] = {}
            for j in range(nxt.argc):
                val = _union(r.args[j] for r in records if j < len(r.args))
                next_ctx[f"P{j}"] = self._resolve(val, ctx, i, method.file)
            ctx = next_ctx

        last = len(keys) - 1
        method, summ = methods[last], summaries[last]
        sink_line = flow.hops[-1].line
        records = summ.calls_at(sink_line, flow.sink_method)
        if not records:
            return _result(STATUS_UNKNOWN, unknown=[
                f"sink call {flow.sink_method} at {method.file}:{sink_line} not found"])
        positions = _SINK_ARG_POSITIONS.get((flow.sink_kind, flow.sink_method))
        dangerous: List[Val] = []
        for r in records:
            if r.argc == 0:
                dangerous.append(r.receiver)
            elif positions is None:
                dangerous.extend(r.args)
            else:
                dangerous.extend(r.args[p] for p in positions if p < len(r.args))
        reached = self._resolve(_union(dangerous), ctx, last, method.file)
        sink_step = _step(method, sink_line, records[0].code)
        where = "receiver" if all(r.argc == 0 for r in records) else (
            "argument " + ", ".join(str(p + 1) for p in positions) if positions else "arguments")

        def defended(c: _Concrete) -> List[Tuple[str, int, str, Tuple[str, ...]]]:
            return sorted(s for s in c.sanitizers if flow.sink_kind in s[3])

        raw = sorted((c for c in reached.taints if not defended(c)), key=_concrete_key)
        clean_path = sorted(reached.taints, key=_concrete_key)
        if raw or clean_path:
            src = (raw or clean_path)[0]
            steps = [{"file": src.file, "line": src.line, "method": _short(methods[src.hop]), "code": src.code}]
            steps += call_steps[src.hop:]
            steps.append(sink_step)
            sanitizers = [] if raw else [
                {"file": f, "line": ln, "code": code} for f, ln, code, _kinds in defended(src)]
            return _result(
                STATUS_PATH if raw else STATUS_SANITIZED, steps=steps, sanitizers=sanitizers,
                sink_position=where, sources=len({(c.file, c.line) for c in reached.taints}),
            )
        if reached.unknown:
            return _result(STATUS_UNKNOWN, unknown=sorted(reached.unknown)[:_MAX_UNKNOWN_REASONS],
                           sink_position=where, steps=call_steps + [sink_step])
        return _result(STATUS_NO_PATH, sink_position=where, steps=call_steps + [sink_step])


def _find_declaration(root: Any, start_line: int) -> Optional[Any]:
    """The method or constructor declared at `start_line`, nested types included."""
    stack = [root]
    while stack:
        n = stack.pop()
        if n.type in ("method_declaration", "constructor_declaration") and n.start_point[0] + 1 == start_line:
            return n
        stack.extend(n.children)
    return None


def _concrete_key(c: _Concrete) -> Tuple[int, str, int, str]:
    return (c.hop, c.file, c.line, c.code)


def _short(method: Any) -> str:
    return f"{method.fqcn.rsplit('.', 1)[-1]}.{method.name}"


def _step(method: Any, line: int, code: str) -> Dict[str, Any]:
    return {"file": method.file, "line": line, "method": _short(method), "code": code}


def _result(status: str, **extra: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {"status": status, "steps": [], "sanitizers": [], "unknown": []}
    out.update(extra)
    return out


# ---------------------------------------------------------------------------
# Public
# ---------------------------------------------------------------------------

def status_of(flow: Any) -> Optional[str]:
    return (getattr(flow, "taint", None) or {}).get("status")


def rank(flow: Any) -> int:
    """Sort key: proven paths first, flows with no input at the sink last.
    A flow never traced ranks with `unknown`."""
    return _RANK.get(status_of(flow) or STATUS_UNKNOWN, _RANK[STATUS_UNKNOWN])


def annotate_flows(graph: Any, flows: Sequence[Any]) -> Dict[str, int]:
    """Set `flow.taint` on every flow; returns the count per status. One
    analyzer serves every flow, so each method is summarised once. An error
    tracing one flow makes that flow `unknown`, never the scan fail."""
    analyzer = TaintAnalyzer(graph)
    counts: Dict[str, int] = {s: 0 for s in _RANK}
    for flow in flows:
        try:
            flow.taint = analyzer.trace(flow)
        except Exception as exc:  # noqa: BLE001 — best effort, never fatal
            flow.taint = _result(STATUS_UNKNOWN, unknown=[f"analysis error: {type(exc).__name__}"])
        counts[flow.taint["status"]] += 1
    return counts


def prompt_note(flow: Any) -> str:
    """One paragraph for the flow-verify prompt, or "" when the flow was not
    traced (taint tracking off, or a Python flow)."""
    taint = getattr(flow, "taint", None)
    if not taint:
        return ""
    status = taint.get("status")
    head = "Taint analysis (deterministic and best effort — check it against the code): "
    steps = taint.get("steps") or []
    chain = " → ".join(f"`{s['code']}` ({s['file']}:{s['line']})" for s in steps)
    if status in (STATUS_PATH, STATUS_SANITIZED):
        text = (f"untrusted input reaches the sink's {taint.get('sink_position', 'arguments')} "
                f"through the call arguments: {chain}.")
        if status == STATUS_SANITIZED:
            text += " Every such path goes through an encoder — judge whether it fits this sink: " + "; ".join(
                f"`{s['code']}` ({s['file']}:{s['line']})" for s in taint.get("sanitizers") or [])
        return head + text
    if status == STATUS_UNKNOWN:
        reasons = "; ".join(taint.get("unknown") or []) or "unmodelled code"
        return head + f"could not follow the input to the sink's argument ({reasons}); decide from the code."
    return head + "no untrusted input reaches the sink's argument through these calls."

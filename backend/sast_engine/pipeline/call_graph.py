"""call_graph.py — Java call graph + typed-sink flow discovery.

Best-effort static resolution (not sound taint). Edges are method-level
"A calls B"; argument binding is left to the LLM on full method bodies.

Sinks are fail-closed: a call is a sink only when the method name *and* the
resolved receiver type match an allowlist (or a syntactic form the regex
catalog already uses). Bare ``execute(`` is not a sink.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

import ast_struct
from pipeline import llm_file_scan
from pipeline.call_graph_common import CallerInfo

MAX_HOP_DEPTH = 4
FLOW_VERIFY_CAP = 30

_JDK_PREFIXES = ("java.", "javax.", "jakarta.")
_FRAMEWORK_PREFIXES = ("org.springframework.",)

# Spring / JAX-RS / SOAP / EJB / messaging / servlet / Struts
_SPRING_HTTP = frozenset(ast_struct.MAPPING_VERBS.keys())
_JAXRS_HTTP = frozenset({"GET", "POST", "PUT", "DELETE", "PATCH", "Path"})
_SOAP_EJB = frozenset({
    "WebMethod", "WebService", "Stateless", "Stateful", "MessageDriven",
})
_MESSAGING_JOBS = frozenset({
    "JmsListener", "KafkaListener", "RabbitListener", "Scheduled",
})
_SERVLET_METHODS = frozenset({"doGet", "doPost", "doPut", "doDelete", "service"})
_STRUTS_METHODS = frozenset({"execute", "doExecute"})
_AUTH_ANNOTATIONS = frozenset(ast_struct.AUTH_ANNOTATIONS)

_SQL_RECEIVERS = frozenset({
    "java.sql.Statement",
    "java.sql.PreparedStatement",
    "java.sql.CallableStatement",
})
_JPA_RECEIVERS = frozenset({
    "jakarta.persistence.Query",
    "javax.persistence.Query",
    "org.hibernate.Query",
    "org.hibernate.query.Query",
    "jakarta.persistence.EntityManager",
    "javax.persistence.EntityManager",
    "org.hibernate.Session",
})
_JDBC_TEMPLATE_RECEIVERS = frozenset({
    "org.springframework.jdbc.core.JdbcTemplate",
    "org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate",
})
_SQL_METHODS = frozenset({
    "executeQuery", "executeUpdate", "execute", "executeBatch", "executeLargeUpdate",
})
_JPA_METHODS = frozenset({
    "createQuery", "createNativeQuery", "getResultList", "getSingleResult",
})
_JDBC_TEMPLATE_METHODS = frozenset({"query", "update", "execute"})
_FILES_METHODS = frozenset({"write", "writeString", "newInputStream"})

_WELL_KNOWN_TYPES: Dict[str, str] = {
    "Statement": "java.sql.Statement",
    "PreparedStatement": "java.sql.PreparedStatement",
    "CallableStatement": "java.sql.CallableStatement",
    "Connection": "java.sql.Connection",
    "ResultSet": "java.sql.ResultSet",
    "Query": "jakarta.persistence.Query",
    "EntityManager": "jakarta.persistence.EntityManager",
    "Session": "org.hibernate.Session",
    "JdbcTemplate": "org.springframework.jdbc.core.JdbcTemplate",
    "NamedParameterJdbcTemplate": (
        "org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate"
    ),
    "Runtime": "java.lang.Runtime",
    "ProcessBuilder": "java.lang.ProcessBuilder",
    "ObjectInputStream": "java.io.ObjectInputStream",
    "Files": "java.nio.file.Files",
    "ExecutorService": "java.util.concurrent.ExecutorService",
    "TransactionTemplate": "org.springframework.transaction.support.TransactionTemplate",
    "RestTemplate": "org.springframework.web.client.RestTemplate",
    # java.lang is auto-imported, so it never appears in a file's import map.
    "Class": "java.lang.Class",
}

_CHAIN_TO_TYPE = {
    "prepareStatement": "java.sql.PreparedStatement",
    "prepareCall": "java.sql.CallableStatement",
    "createStatement": "java.sql.Statement",
    "getRuntime": "java.lang.Runtime",
    "createQuery": "jakarta.persistence.Query",
    "createNativeQuery": "jakarta.persistence.Query",
    # `response.getWriter().print(tainted)` — without these the write call's
    # receiver is an unresolved chain, so the sink is never seen.
    "getWriter": "java.io.PrintWriter",
    "getOutputStream": "jakarta.servlet.ServletOutputStream",
}

_STRING_LIKE = frozenset({
    "String", "CharSequence", "Object", "byte[]", "Byte[]",
    "Collection", "List", "Map", "Set", "CharBuffer",
})

_SINK_SEVERITY = {
    "sql": 0,
    "jpa": 0,
    "jdbc_template": 0,
    "eval": 0,
    "command": 1,
    "ssrf": 1,
    "ldap": 1,
    "deser": 2,
    "xxe": 2,
    "xss": 2,
    "reflect": 2,
    "files": 3,
    "redirect": 3,
    # Joern-only kinds (joern/taint_spec.json). Real but lower-impact, and far
    # more numerous on a typical web app — see joern_flows._LOW_VALUE_KINDS.
    "header": 3,
    "response_body": 3,
    "log": 4,
}

# (receiver FQCNs, method names, sink kind). An empty method set means any
# method on that receiver is a sink. Kept as data so a new sink class is a row
# rather than another branch in _typed_sink.
_RECEIVER_SINKS: Tuple[Tuple[frozenset, frozenset, str], ...] = (
    # Untrusted data written straight into an HTTP response body (reflected XSS).
    (frozenset({
        "java.io.PrintWriter", "java.io.Writer",
        "jakarta.servlet.ServletOutputStream", "javax.servlet.ServletOutputStream",
    }), frozenset({"print", "println", "write", "append", "format", "printf"}), "xss"),
    # Redirect target or response header built from request data
    # (open redirect / response splitting).
    (frozenset({
        "jakarta.servlet.http.HttpServletResponse",
        "javax.servlet.http.HttpServletResponse",
    }), frozenset({"sendRedirect", "setHeader", "addHeader"}), "redirect"),
    # Outbound HTTP whose URL is built from user input (SSRF).
    (frozenset({"org.springframework.web.client.RestTemplate"}), frozenset({
        "getForObject", "getForEntity", "postForObject", "postForEntity",
        "exchange", "execute", "put", "delete", "patchForObject",
    }), "ssrf"),
    (frozenset({"java.net.URL", "java.net.URI"}),
     frozenset({"openConnection", "openStream"}), "ssrf"),
    (frozenset({"java.net.http.HttpClient"}), frozenset({"send", "sendAsync"}), "ssrf"),
    # XML parsed from user input (XXE when the parser isn't hardened).
    (frozenset({
        "javax.xml.parsers.DocumentBuilder", "javax.xml.parsers.SAXParser",
        "org.xml.sax.XMLReader", "javax.xml.transform.Transformer",
        "jakarta.xml.bind.Unmarshaller", "javax.xml.bind.Unmarshaller",
    }), frozenset({"parse", "unmarshal", "transform"}), "xxe"),
    # LDAP filter/DN built from user input.
    (frozenset({
        "javax.naming.directory.DirContext",
        "javax.naming.directory.InitialDirContext",
        "javax.naming.ldap.LdapContext",
    }), frozenset({"search", "lookup"}), "ldap"),
    # Expression / script evaluation (RCE).
    (frozenset({
        "org.springframework.expression.spel.standard.SpelExpressionParser",
        "org.springframework.expression.ExpressionParser",
    }), frozenset({"parseExpression"}), "eval"),
    (frozenset({"javax.script.ScriptEngine"}), frozenset({"eval"}), "eval"),
    # Reflection driven by user input.
    (frozenset({"java.lang.Class"}), frozenset({"forName"}), "reflect"),
    (frozenset({"java.lang.reflect.Method"}), frozenset({"invoke"}), "reflect"),
    # Filesystem path built from user input (path traversal).
    (frozenset({"java.nio.file.Paths"}), frozenset({"get"}), "files"),
    (frozenset({"java.nio.file.Path"}), frozenset({"resolve", "of"}), "files"),
)

# Constructors that are themselves sinks when built from user input.
_CONSTRUCTOR_SINKS: Dict[str, str] = {
    "java.io.File": "files",
    "java.io.FileInputStream": "files",
    "java.io.FileOutputStream": "files",
    "java.io.FileReader": "files",
    "java.io.FileWriter": "files",
    "java.io.RandomAccessFile": "files",
    "java.net.URL": "ssrf",
    "java.net.URI": "ssrf",
}

# Base types whose *subtypes* are candidate sinks, keyed by simple name ->
# sink kind.
#
# The receiver-based rules above only fire on a known framework type at the
# call site. That misses the dominant persistence idiom, where the project
# declares its own interface (`interface OrderRepository extends
# JpaRepository<Order, Long>`) and the querying implementation is generated at
# runtime, so it never exists in the repo to be resolved or hopped into. Every
# call on such a type is *routed through* this table (see
# _spring_data_repository_sink), but it is a real sink only when the project's
# own declared method is `@Query(..., nativeQuery = true)` — a derived query
# method (`findByEmail`) and a plain JPQL `@Query` are both parameterized by
# construction (and a Java annotation value is a compile-time constant, so
# neither can ever have untrusted input concatenated into its query text).
# Only nativeQuery=true executes a literal SQL string the project wrote
# itself, which is also the one case that can defeat parameter binding via a
# SpEL `?#{...}` substitution.
#
# Keyed by simple name because these base types belong to the framework and so
# are never present in `graph.types` to be matched by FQCN. This table is the
# extension point for new persistence frameworks; adding a *language* also
# needs a parser, since the graph builder is Java-only today.
_SINK_BASE_TYPES: Dict[str, str] = {
    "Repository": "jpa",
    "CrudRepository": "jpa",
    "JpaRepository": "jpa",
    "PagingAndSortingRepository": "jpa",
    "JpaSpecificationExecutor": "jpa",
    "MongoRepository": "jpa",
    "ReactiveCrudRepository": "jpa",
    "ReactiveMongoRepository": "jpa",
    "R2dbcRepository": "jpa",
    "CassandraRepository": "jpa",
    "ElasticsearchRepository": "jpa",
}


def _text(node: Any, src: bytes) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _named(node: Any) -> List[Any]:
    return [c for c in node.children if getattr(c, "is_named", False)]


def _field(node: Any, name: str) -> Optional[Any]:
    getter = getattr(node, "child_by_field_name", None)
    if getter is None:
        return None
    return getter(name)


def _simple_type_name(node: Any, src: bytes) -> str:
    """Strip generics/arrays down to the rightmost identifier."""
    raw = _text(node, src).replace("[]", "").strip()
    if "<" in raw:
        raw = raw.split("<", 1)[0].strip()
    return raw.rsplit(".", 1)[-1]


def _arg_count(args_node: Optional[Any]) -> int:
    if args_node is None:
        return 0
    return sum(1 for c in args_node.children if getattr(c, "is_named", False))


def _annotation_names(node: Any, src: bytes) -> List[str]:
    return [name for name, _ in ast_struct._direct_annotations(node, src)]


def _has_modifier(node: Any, src: bytes, word: str) -> bool:
    for child in node.children:
        if child.type != "modifiers":
            continue
        return word in _text(child, src).split()
    return False


def _is_jdk_or_framework(fqcn: str) -> bool:
    return fqcn.startswith(_JDK_PREFIXES) or fqcn.startswith(_FRAMEWORK_PREFIXES)


def _norm_file(rel_path: str) -> str:
    return (rel_path or "").replace("\\", "/").lower()


def _is_test_path(rel_path: str) -> bool:
    return llm_file_scan.is_test_path(rel_path)


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------

@dataclass
class JavaMethod:
    key: str
    file: str
    fqcn: str
    name: str
    argc: int
    param_types: List[str]
    start_line: int
    end_line: int
    annotations: List[str]
    is_public: bool
    is_static: bool
    is_constructor: bool
    is_api_visible: bool
    body: str
    enclosing_kind: str  # class | interface
    locals: Dict[str, str] = field(default_factory=dict)  # name -> simple type


@dataclass
class JavaType:
    fqcn: str
    file: str
    simple_name: str
    kind: str  # class | interface
    super_types: List[str]
    fields: Dict[str, str]  # name -> simple type
    methods: List[str]  # method keys


@dataclass
class CallSite:
    file: str
    line: int
    caller_key: str
    method_name: str
    argc: int
    receiver_simple: Optional[str]
    receiver_kind: str  # field|this|type|local|chain|none|unknown
    is_constructor: bool
    syntactic_runtime_exec: bool
    syntactic_process_builder: bool


@dataclass
class Edge:
    caller_key: str
    callee_key: str
    call_line: int


@dataclass
class SinkHit:
    caller_key: str
    kind: str
    line: int
    file: str
    method_name: str
    label: str
    # Declared repository method's own source (signature + any @Query
    # annotation), when the sink is a Spring Data nativeQuery call — see
    # _typed_sink. Appended to the sink hop's body so the LLM sees the actual
    # SQL text, not just the caller's wrapper code. Empty for every other
    # sink kind.
    declaration: str = ""


@dataclass
class FlowHop:
    file: str
    method: str
    fqcn: str
    name: str
    line: int
    start_line: int
    end_line: int
    body: str
    role: str
    label: str


@dataclass
class Flow:
    hops: List[FlowHop]
    entry_tier: str
    sink_kind: str
    authenticated: bool
    files: List[str]
    unresolved: List[str] = field(default_factory=list)
    # Expression-level dataflow path ({file, line, method, code} per step).
    # Only Joern flows (pipeline/joern_flows.py) carry one; this graph is
    # method-level and leaves it empty.
    taint_path: List[Dict[str, Any]] = field(default_factory=list)
    # Joern only, like taint_path ({file, line, code} each): conditions the
    # path's nodes are control-dependent on, and sanitizer calls (taint_spec
    # "sanitizers") the value passes through. Context for the verifier — a
    # flow is never dropped for having either.
    guards: List[Dict[str, Any]] = field(default_factory=list)
    sanitizers: List[Dict[str, Any]] = field(default_factory=list)
    # Entry points of flows collapsed into this one because they reach the
    # same sink ({file, line, method, label} each; collapse_flows_by_sink).
    other_sources: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def entry_key(self) -> str:
        return f"{self.hops[0].file}:{self.hops[0].method}:{self.hops[0].line}"


@dataclass
class CallGraph:
    types: Dict[str, JavaType] = field(default_factory=dict)
    methods: Dict[str, JavaMethod] = field(default_factory=dict)
    methods_by_sig: Dict[Tuple[str, str, int], List[str]] = field(default_factory=lambda: defaultdict(list))
    types_by_simple: Dict[str, List[str]] = field(default_factory=lambda: defaultdict(list))
    edges: List[Edge] = field(default_factory=list)
    sinks: List[SinkHit] = field(default_factory=list)
    unresolved: List[str] = field(default_factory=list)
    impls_of: Dict[str, List[str]] = field(default_factory=lambda: defaultdict(list))
    files_parsed: int = 0
    # Total call sites seen. Calls that are neither an edge nor an `unresolved`
    # reason were skipped as JDK/framework hops, so this is what makes that
    # third bucket visible.
    call_sites: int = 0
    entry_tier: str = ""
    # Total valid source->sink flows the BFS found, before `discover_flows`
    # truncates to `cap`. Lets callers report "found X, sending the top N"
    # instead of silently hiding how many were discovered but dropped.
    flows_discovered_total: int = 0


# ---------------------------------------------------------------------------
# Parse one file
# ---------------------------------------------------------------------------

def _collect_locals(method_node: Any, src: bytes) -> Dict[str, str]:
    locals_: Dict[str, str] = {}
    params = _field(method_node, "parameters")
    if params is not None:
        for p in _named(params):
            if p.type not in ("formal_parameter", "spread_parameter"):
                continue
            tnode = _field(p, "type")
            nnode = _field(p, "name")
            if tnode is None or nnode is None:
                continue
            locals_[_text(nnode, src)] = _simple_type_name(tnode, src)
    body = _field(method_node, "body")
    if body is None:
        return locals_
    stack = [body]
    while stack:
        n = stack.pop()
        if n.type in ast_struct._NESTED_TYPE_DECLS:
            continue
        if n.type == "local_variable_declaration":
            tnode = _field(n, "type")
            simple = _simple_type_name(tnode, src) if tnode is not None else ""
            for ch in _named(n):
                if ch.type == "variable_declarator":
                    ident = _field(ch, "name")
                    if ident is not None and simple:
                        locals_[_text(ident, src)] = simple
        stack.extend(n.children)
    return locals_


_SUPER_CLAUSE_TYPES = ("superclass", "super_interfaces", "extends_interfaces")


def _superclass_names(type_node: Any, src: bytes) -> List[str]:
    """Simple names of a type's declared supertypes.

    A class's `extends`/`implements` are named fields, but an interface's
    `extends` is an *unnamed* `extends_interfaces` child, so looking only at
    named fields silently returns nothing for every interface — which is what
    hid `interface FooRepository extends JpaRepository<...>` from sink
    detection. Generic argument subtrees are skipped so `Repo<Txn, Long>`
    contributes `Repo`, not `Txn`/`Long`.
    """
    clauses: List[Any] = []
    seen_spans: Set[Tuple[int, int]] = set()

    def add(node: Optional[Any]) -> None:
        if node is None:
            return
        span = (node.start_byte, node.end_byte)
        if span in seen_spans:
            return
        seen_spans.add(span)
        clauses.append(node)

    for field_name in ("superclass", "interfaces", "super_interfaces"):
        add(_field(type_node, field_name))
    for child in type_node.children:
        if child.type in _SUPER_CLAUSE_TYPES:
            add(child)

    names: List[str] = []
    for clause in clauses:
        stack = [clause]
        while stack:
            n = stack.pop()
            if n.type == "type_arguments":
                continue
            if n.type in ("type_identifier", "identifier", "scoped_type_identifier"):
                name = _simple_type_name(n, src)
                if name:
                    names.append(name)
                continue
            stack.extend(n.children)
    return names


def _parse_imports(root: Any, src: bytes) -> Tuple[str, Dict[str, str], Set[str]]:
    package = ""
    imports: Dict[str, str] = {}
    stars: Set[str] = set()
    for child in root.children:
        if child.type == "package_declaration":
            package = _text(child, src).replace("package", "").replace(";", "").strip()
        elif child.type == "import_declaration":
            raw = _text(child, src)
            is_static = " static " in f" {raw} "
            path = raw.replace("import", "").replace("static", "").replace(";", "").strip()
            if path.endswith(".*"):
                stars.add(path[:-2])
                continue
            simple = path.rsplit(".", 1)[-1]
            imports[simple] = path
            if is_static:
                imports[simple] = path
    return package, imports, stars


def _resolve_simple(
    simple: str,
    *,
    package: str,
    imports: Dict[str, str],
    stars: Set[str],
    graph: Optional[CallGraph],
) -> Optional[str]:
    """`graph` may be None (one file, no repo index): the lookups that need the
    project's types are then skipped and only imports, well-known types and
    JDK/framework star imports resolve."""
    if not simple:
        return None
    if simple in imports:
        return imports[simple]
    if simple in _WELL_KNOWN_TYPES:
        return _WELL_KNOWN_TYPES[simple]
    if graph is not None:
        same_pkg = f"{package}.{simple}" if package else simple
        if same_pkg in graph.types:
            return same_pkg
        matches = graph.types_by_simple.get(simple) or []
        if len(matches) == 1:
            return matches[0]
    for star in stars:
        candidate = f"{star}.{simple}"
        if (graph is not None and candidate in graph.types) or candidate in _WELL_KNOWN_TYPES.values():
            return candidate
        if candidate.startswith(("java.", "javax.", "jakarta.", "org.springframework.")):
            return candidate
    return None


def _receiver_of_invocation(inv: Any, src: bytes) -> Tuple[str, Optional[str], str]:
    """Return (kind, simple_name, extra) for a method_invocation."""
    obj = _field(inv, "object")
    if obj is None:
        return "none", None, ""
    if obj.type == "identifier":
        return "local", _text(obj, src), ""
    if obj.type == "this":
        return "this", None, ""
    if obj.type == "super":
        return "this", None, ""
    if obj.type == "field_access":
        field = _field(obj, "field") or _field(obj, "name")
        name = _text(field, src) if field is not None else _text(obj, src).rsplit(".", 1)[-1]
        return "field", name, ""
    if obj.type == "type_identifier":
        return "type", _text(obj, src), ""
    if obj.type == "method_invocation":
        name_node = _field(obj, "name")
        chained = _text(name_node, src) if name_node is not None else ""
        return "chain", chained, chained
    if obj.type == "object_creation_expression":
        tnode = _field(obj, "type")
        tname = _simple_type_name(tnode, src) if tnode is not None else ""
        return "chain", tname, tname
    ident = None
    for c in _named(obj):
        if c.type == "identifier":
            ident = _text(c, src)
    return "unknown", ident, ""


def _is_runtime_exec(inv: Any, src: bytes) -> bool:
    name_node = _field(inv, "name")
    if name_node is None or _text(name_node, src) != "exec":
        return False
    blob = _text(inv, src).replace(" ", "")
    return "Runtime.getRuntime().exec(" in blob or blob.startswith("Runtime.getRuntime().exec")


def _walk_calls(
    method: JavaMethod,
    method_node: Any,
    src: bytes,
) -> List[CallSite]:
    calls: List[CallSite] = []
    body = _field(method_node, "body")
    if body is None:
        return calls
    stack = [body]
    while stack:
        n = stack.pop()
        if n.type in ast_struct._NESTED_TYPE_DECLS:
            continue
        if n.type == "method_invocation":
            name_node = _field(n, "name")
            name = _text(name_node, src) if name_node is not None else ""
            argc = _arg_count(_field(n, "arguments"))
            kind, simple, extra = _receiver_of_invocation(n, src)
            pb = extra == "ProcessBuilder" or simple == "ProcessBuilder"
            calls.append(CallSite(
                file=method.file,
                line=n.start_point[0] + 1,
                caller_key=method.key,
                method_name=name,
                argc=argc,
                receiver_simple=simple,
                receiver_kind=kind,
                is_constructor=False,
                syntactic_runtime_exec=_is_runtime_exec(n, src),
                syntactic_process_builder=pb and name in ("start", "command"),
            ))
        elif n.type == "object_creation_expression":
            tnode = _field(n, "type")
            tname = _simple_type_name(tnode, src) if tnode is not None else ""
            argc = _arg_count(_field(n, "arguments"))
            calls.append(CallSite(
                file=method.file,
                line=n.start_point[0] + 1,
                caller_key=method.key,
                method_name=tname or "<init>",
                argc=argc,
                receiver_simple=tname,
                receiver_kind="type",
                is_constructor=True,
                syntactic_runtime_exec=False,
                syntactic_process_builder=tname == "ProcessBuilder",
            ))
        stack.extend(reversed(n.children))
    return calls


def _index_type(
    type_node: Any,
    src: bytes,
    rel_path: str,
    package: str,
    graph: CallGraph,
) -> None:
    name = ast_struct._decl_name(type_node, src)
    if not name:
        return
    fqcn = f"{package}.{name}" if package else name
    kind = "interface" if type_node.type == "interface_declaration" else "class"
    jtype = JavaType(
        fqcn=fqcn,
        file=rel_path,
        simple_name=name,
        kind=kind,
        super_types=_superclass_names(type_node, src),
        fields={},
        methods=[],
    )
    body = _field(type_node, "body")
    if body is not None:
        for child in body.children:
            if child.type == "field_declaration":
                tnode = _field(child, "type")
                simple = _simple_type_name(tnode, src) if tnode is not None else ""
                for ch in _named(child):
                    if ch.type == "variable_declarator":
                        ident = _field(ch, "name")
                        if ident is not None and simple:
                            jtype.fields[_text(ident, src)] = simple
            elif child.type in ("method_declaration", "constructor_declaration"):
                mname = ast_struct._decl_name(child, src) or name
                argc = _arg_count(_field(child, "parameters"))
                params: List[str] = []
                pnode = _field(child, "parameters")
                if pnode is not None:
                    for p in _named(pnode):
                        tnode = _field(p, "type")
                        if tnode is not None:
                            params.append(_simple_type_name(tnode, src))
                start = child.start_point[0] + 1
                end = child.end_point[0] + 1
                key = f"{rel_path}::{fqcn}::{mname}::{argc}::{start}"
                is_public = (
                    _has_modifier(child, src, "public") or kind == "interface"
                )
                is_private = _has_modifier(child, src, "private")
                is_protected = _has_modifier(child, src, "protected")
                method = JavaMethod(
                    key=key,
                    file=rel_path,
                    fqcn=fqcn,
                    name=mname,
                    argc=argc,
                    param_types=params,
                    start_line=start,
                    end_line=end,
                    annotations=_annotation_names(child, src) + _annotation_names(type_node, src),
                    is_public=is_public,
                    is_static=_has_modifier(child, src, "static"),
                    is_constructor=child.type == "constructor_declaration",
                    is_api_visible=is_public or (not is_private and not is_protected),
                    body=_text(child, src),
                    enclosing_kind=kind,
                    locals=_collect_locals(child, src),
                )
                graph.methods[key] = method
                graph.methods_by_sig[(fqcn, mname, argc)].append(key)
                jtype.methods.append(key)
    graph.types[fqcn] = jtype
    graph.types_by_simple[name].append(fqcn)


def _parse_java_file(rel_path: str, source_text: str, graph: CallGraph) -> List[CallSite]:
    parser = ast_struct.parser_for_lang("java")
    if parser is None:
        return []
    src = source_text.encode("utf-8", errors="replace")
    try:
        tree = parser.parse(src)
    except Exception:  # noqa: BLE001
        return []
    root = tree.root_node
    package, imports, stars = _parse_imports(root, src)
    graph._file_imports = getattr(graph, "_file_imports", {})  # type: ignore[attr-defined]
    graph._file_imports[rel_path] = (package, imports, stars)  # type: ignore[attr-defined]

    stack = [root]
    while stack:
        n = stack.pop()
        if n.type in ("class_declaration", "interface_declaration"):
            _index_type(n, src, rel_path, package, graph)
            # still walk nested types
        stack.extend(n.children)

    calls: List[CallSite] = []
    # Re-walk methods with their nodes for call sites — parse tree again per method
    # by matching start lines.
    methods_by_line = {
        (m.file, m.start_line): m
        for m in graph.methods.values()
        if m.file == rel_path
    }
    stack = [root]
    while stack:
        n = stack.pop()
        if n.type in ("method_declaration", "constructor_declaration"):
            start = n.start_point[0] + 1
            method = methods_by_line.get((rel_path, start))
            if method is not None:
                calls.extend(_walk_calls(method, n, src))
        stack.extend(n.children)
    return calls


# ---------------------------------------------------------------------------
# Resolve calls → edges / sinks
# ---------------------------------------------------------------------------

def _lookup_methods(graph: CallGraph, fqcn: str, name: str, argc: int) -> List[str]:
    return list(graph.methods_by_sig.get((fqcn, name, argc)) or [])


def _implementors(graph: CallGraph, iface_fqcn: str) -> List[str]:
    return list(graph.impls_of.get(iface_fqcn) or [])


def _identifier_simple_type(graph: CallGraph, caller: JavaMethod, name: str) -> Optional[str]:
    if name in caller.locals:
        return caller.locals[name]
    enclosing = graph.types.get(caller.fqcn)
    if enclosing and name in enclosing.fields:
        return enclosing.fields[name]
    return name


def _resolve_receiver_fqcn(
    graph: CallGraph,
    call: CallSite,
    caller: JavaMethod,
    package: str,
    imports: Dict[str, str],
    stars: Set[str],
) -> Optional[str]:
    if call.syntactic_runtime_exec:
        return "java.lang.Runtime"
    if call.syntactic_process_builder:
        return "java.lang.ProcessBuilder"
    if call.receiver_kind in ("this", "none"):
        return caller.fqcn
    if call.receiver_kind == "chain" and call.receiver_simple in _CHAIN_TO_TYPE:
        return _CHAIN_TO_TYPE[call.receiver_simple]

    simple: Optional[str] = call.receiver_simple
    if call.receiver_kind in ("local", "field", "unknown") and call.receiver_simple:
        simple = _identifier_simple_type(graph, caller, call.receiver_simple)
    if not simple:
        return None
    return _resolve_simple(simple, package=package, imports=imports, stars=stars, graph=graph)


def _sink_kind_for_declared_type(graph: "CallGraph", fqcn: Optional[str]) -> Optional[str]:
    """Sink kind if `fqcn` transitively extends a type in `_SINK_BASE_TYPES`.

    Walks the declared supertype chain through in-repo types, so a project's
    own `BaseRepository extends JpaRepository` still marks its subtypes.
    """
    if not fqcn:
        return None
    seen: Set[str] = set()
    queue: List[str] = [fqcn]
    while queue:
        current = queue.pop()
        if not current or current in seen:
            continue
        seen.add(current)
        kind = _SINK_BASE_TYPES.get(current.rsplit(".", 1)[-1])
        if kind:
            return kind
        jtype = graph.types.get(current)
        if jtype is None:
            continue
        for super_name in jtype.super_types:
            simple = super_name.rsplit(".", 1)[-1]
            kind = _SINK_BASE_TYPES.get(simple)
            if kind:
                return kind
            queue.extend(graph.types_by_simple.get(simple, []))
    return None


_NATIVE_QUERY_RE = re.compile(r"nativeQuery\s*=\s*true")


def _resolve_repository_method(
    graph: "CallGraph", fqcn: Optional[str], name: str, argc: int,
) -> Optional[JavaMethod]:
    """The in-repo declaration of `fqcn.name(argc args)`, if the project
    declares it directly (true for every custom Spring Data repository
    method — derived or @Query — even though the implementation itself is
    generated at runtime and never appears in the repo)."""
    if not fqcn:
        return None
    keys = _lookup_methods(graph, fqcn, name, argc)
    return graph.methods.get(keys[0]) if len(keys) == 1 else None


def _spring_data_repository_sink(
    graph: "CallGraph", receiver_fqcn: str, method_name: str, argc: int,
) -> Tuple[Optional[str], str]:
    """Sink kind + declaration text for a Spring Data repository call.

    A derived query method (no `@Query`) is always parameterized by Spring
    Data's name-derivation, and a JPQL `@Query` is a Java annotation value —
    a compile-time constant no runtime string can be concatenated into —
    so neither can ever embed untrusted input into the query text. Only
    `@Query(..., nativeQuery = true)` executes a literal SQL string the
    project wrote itself (and can defeat parameter binding via a SpEL
    `?#{...}` substitution), so that is the only case kept as a sink.
    A method inherited from `JpaRepository` itself (`save`, `findById`, ...)
    isn't declared in-repo at all and binds typed entity/id values, never a
    raw string, so it is never a sink either.
    """
    method = _resolve_repository_method(graph, receiver_fqcn, method_name, argc)
    if method is None or "Query" not in method.annotations:
        return None, ""
    if not _NATIVE_QUERY_RE.search(method.body):
        return None, ""
    return "jpa", method.body


def _typed_sink(
    graph: "CallGraph",
    method_name: str,
    receiver_fqcn: Optional[str],
    call: CallSite,
) -> Tuple[Optional[str], str]:
    if call.syntactic_runtime_exec:
        return "command", ""
    if call.syntactic_process_builder:
        return "command", ""
    if receiver_fqcn is None:
        return None, ""
    declared = _sink_kind_for_declared_type(graph, receiver_fqcn)
    if declared == "jpa":
        return _spring_data_repository_sink(graph, receiver_fqcn, method_name, call.argc)
    if declared:
        return declared, ""
    if method_name in _SQL_METHODS and receiver_fqcn in _SQL_RECEIVERS:
        return "sql", ""
    if method_name in _JPA_METHODS and receiver_fqcn in _JPA_RECEIVERS:
        return "jpa", ""
    if method_name in _JDBC_TEMPLATE_METHODS and receiver_fqcn in _JDBC_TEMPLATE_RECEIVERS:
        return "jdbc_template", ""
    if method_name == "exec" and receiver_fqcn == "java.lang.Runtime":
        return "command", ""
    if method_name in ("start", "command") and receiver_fqcn == "java.lang.ProcessBuilder":
        return "command", ""
    if call.is_constructor and receiver_fqcn == "java.lang.ProcessBuilder":
        return "command", ""
    if method_name == "readObject" and receiver_fqcn == "java.io.ObjectInputStream":
        return "deser", ""
    if method_name in _FILES_METHODS and receiver_fqcn == "java.nio.file.Files":
        return "files", ""
    for receivers, methods, kind in _RECEIVER_SINKS:
        if receiver_fqcn in receivers and (not methods or method_name in methods):
            return kind, ""
    if call.is_constructor:
        ctor_kind = _CONSTRUCTOR_SINKS.get(receiver_fqcn)
        if ctor_kind:
            return ctor_kind, ""
    return None, ""


def _resolve_callee_keys(
    graph: CallGraph,
    call: CallSite,
    receiver_fqcn: Optional[str],
) -> Tuple[List[str], Optional[str]]:
    """Return (method keys, unresolved reason)."""
    if receiver_fqcn is None:
        return [], "unresolved_type"
    if _is_jdk_or_framework(receiver_fqcn):
        return [], None  # hop into JDK/framework body is skipped (may still be a sink)
    keys = _lookup_methods(graph, receiver_fqcn, call.method_name, call.argc)
    jtype = graph.types.get(receiver_fqcn)
    if jtype is not None and jtype.kind == "interface":
        impls = _implementors(graph, receiver_fqcn)
        impl_keys: List[str] = []
        for impl in impls:
            impl_keys.extend(_lookup_methods(graph, impl, call.method_name, call.argc))
        if len(impl_keys) == 1:
            return impl_keys, None
        if len(impl_keys) != 1:
            return [], "unresolved_interface"
    if call.is_constructor:
        keys = _lookup_methods(graph, receiver_fqcn, jtype.simple_name if jtype else call.method_name, call.argc)
        # constructors are stored under the type's simple name
        if not keys and jtype is not None:
            keys = _lookup_methods(graph, receiver_fqcn, jtype.simple_name, call.argc)
    if len(keys) == 1:
        return keys, None
    if len(keys) > 1:
        return [], "unresolved_overload"
    if len(keys) == 0:
        return [], "unresolved_type"
    return keys, None


def _build_impl_index(graph: CallGraph) -> None:
    graph.impls_of.clear()
    for fqcn, jtype in graph.types.items():
        if jtype.kind == "interface":
            continue
        file_meta = graph._file_imports.get(jtype.file, ("", {}, set()))  # type: ignore[attr-defined]
        package, imports, stars = file_meta
        for super_name in jtype.super_types:
            resolved = _resolve_simple(
                super_name, package=package, imports=imports, stars=stars, graph=graph,
            )
            if resolved and resolved in graph.types and graph.types[resolved].kind == "interface":
                graph.impls_of[resolved].append(fqcn)


def _wire_calls(graph: CallGraph, calls: List[CallSite]) -> None:
    _build_impl_index(graph)
    for call in calls:
        caller = graph.methods.get(call.caller_key)
        if caller is None:
            continue
        package, imports, stars = graph._file_imports.get(  # type: ignore[attr-defined]
            caller.file, ("", {}, set())
        )
        receiver = _resolve_receiver_fqcn(graph, call, caller, package, imports, stars)
        sink_kind, declaration = _typed_sink(graph, call.method_name, receiver, call)
        if sink_kind:
            graph.sinks.append(SinkHit(
                caller_key=caller.key,
                kind=sink_kind,
                line=call.line,
                file=caller.file,
                method_name=call.method_name,
                label=f"{(receiver or '').rsplit('.', 1)[-1]}.{call.method_name}(...)",
                declaration=declaration,
            ))
        keys, reason = _resolve_callee_keys(graph, call, receiver)
        # A sink terminates the flow by design — its body is framework or
        # runtime-generated code we never hop into — so a failed callee lookup
        # there is not a coverage gap and would otherwise dominate the
        # unresolved counts with calls that were handled correctly.
        if reason and not sink_kind:
            graph.unresolved.append(reason)
        for callee_key in keys:
            graph.edges.append(Edge(caller_key=caller.key, callee_key=callee_key, call_line=call.line))


# ---------------------------------------------------------------------------
# Public: build graph
# ---------------------------------------------------------------------------

def java_paths_from_scan(scan: Optional[Dict[str, Any]]) -> List[str]:
    files = (scan or {}).get("files") or []
    return [f["path"] for f in files if str(f.get("ext") or "").lower() == ".java"]


def is_java_stack(state: Dict[str, Any]) -> bool:
    analysis = state.get("llm_analysis") or {}
    stacks = analysis.get("heuristic_stacks") or []
    return "maven-java" in stacks


def build_call_graph(repo_root: Path, rel_paths: Sequence[str]) -> CallGraph:
    graph = CallGraph()
    graph._file_imports = {}  # type: ignore[attr-defined]
    all_calls: List[CallSite] = []
    for rel in rel_paths:
        posix = rel.replace("\\", "/")
        path = repo_root / posix
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if llm_file_scan.is_non_analyzable_file(repo_root, posix, text):
            continue
        calls = _parse_java_file(posix, text, graph)
        all_calls.extend(calls)
        graph.files_parsed += 1
    graph.call_sites = len(all_calls)
    _wire_calls(graph, all_calls)
    return graph


# ---------------------------------------------------------------------------
# Entries + discover_flows
# ---------------------------------------------------------------------------

def _ann_set(method: JavaMethod) -> Set[str]:
    return set(method.annotations)


def _is_framework_entry(method: JavaMethod) -> bool:
    if method.is_constructor:
        return False
    anns = _ann_set(method)
    if anns & _SPRING_HTTP:
        return True
    if anns & _JAXRS_HTTP:
        return True
    if anns & {"WebMethod"}:
        return True
    if method.is_public and (anns & (_SOAP_EJB - {"WebMethod"})):
        return True
    if anns & _MESSAGING_JOBS:
        return True
    if method.name in _SERVLET_METHODS:
        return True
    if method.name == "main" and method.is_static and method.argc == 1:
        return True
    if method.name in _STRUTS_METHODS and "Action" in method.fqcn:
        return True
    return False


def attack_surface_counts(graph: "CallGraph") -> Tuple[Counter, Counter]:
    """(framework entry points per file, typed sinks per file) — how exposed
    a file is, used to rank which CRITICAL/HIGH files get the deep scan."""
    entries = Counter(m.file for m in graph.methods.values() if _is_framework_entry(m))
    sinks = Counter(s.file for s in graph.sinks)
    return entries, sinks


def _is_authenticated(method: JavaMethod) -> bool:
    return bool(_ann_set(method) & _AUTH_ANNOTATIONS)


def _has_taint_source(method: JavaMethod) -> bool:
    return bool(llm_file_scan._TAINT_SOURCE_RE.search(method.body))


def _takes_string_like(method: JavaMethod) -> bool:
    return any(p in _STRING_LIKE or p.endswith("[]") for p in method.param_types)


def _collect_entries(graph: CallGraph) -> Tuple[str, List[str]]:
    framework = [m.key for m in graph.methods.values() if _is_framework_entry(m)]
    if framework:
        return "framework", framework
    source = [m.key for m in graph.methods.values() if _has_taint_source(m)]
    if source:
        return "source", source
    # Tier 3: reverse-walk from sink-containing methods to a public API method.
    return "public_api", _public_api_entries(graph)


def _outgoing(graph: CallGraph) -> Dict[str, List[Edge]]:
    out: Dict[str, List[Edge]] = defaultdict(list)
    for e in graph.edges:
        out[e.caller_key].append(e)
    return out


def _incoming(graph: CallGraph) -> Dict[str, List[Edge]]:
    inn: Dict[str, List[Edge]] = defaultdict(list)
    for e in graph.edges:
        inn[e.callee_key].append(e)
    return inn


def _public_api_entries(graph: CallGraph) -> List[str]:
    inn = _incoming(graph)
    sink_methods = {s.caller_key for s in graph.sinks}
    entries: Set[str] = set()
    for sink_key in sink_methods:
        dq: deque[Tuple[str, int]] = deque([(sink_key, 0)])
        seen = {sink_key}
        while dq:
            key, depth = dq.popleft()
            method = graph.methods.get(key)
            if method is None:
                continue
            if (
                method.is_api_visible
                and not _is_test_path(method.file)
                and method.enclosing_kind == "class"
                and key != sink_key
            ):
                entries.add(key)
                continue
            if depth >= MAX_HOP_DEPTH:
                continue
            for edge in inn.get(key, []):
                if edge.caller_key not in seen:
                    seen.add(edge.caller_key)
                    dq.append((edge.caller_key, depth + 1))
        # sink method itself can be the public API (e.g. public query() on a DAO
        # called from another file's service — the service is the entry). If the
        # sink method is public and has callers in other files, those callers
        # were added. If a public method *is* the sink and callers exist in
        # another file, prefer the caller.
        method = graph.methods.get(sink_key)
        if method and method.is_api_visible and not _is_test_path(method.file):
            callers = [e.caller_key for e in inn.get(sink_key, [])]
            other_file = [
                c for c in callers
                if graph.methods.get(c)
                and _norm_file(graph.methods[c].file) != _norm_file(method.file)
            ]
            if other_file:
                for c in other_file:
                    callee = graph.methods[c]
                    if callee.is_api_visible:
                        entries.add(c)
            elif not callers:
                pass
    return sorted(entries)


def _hop_from_method(
    method: JavaMethod, *, line: int, role: str, label: str, extra_body: str = "",
) -> FlowHop:
    short = f"{method.fqcn.rsplit('.', 1)[-1]}.{method.name}"
    body = method.body
    if extra_body:
        # The sink call's own declaration (e.g. a nativeQuery=true @Query) —
        # the repository interface is a different file the BFS never hops
        # into (its implementation is generated at runtime), so without this
        # the LLM would see only the caller's wrapper code and never the
        # actual SQL text it's judging.
        body = f"{body}\n\n// Declaration of the sink call above:\n{extra_body}"
    return FlowHop(
        file=method.file,
        method=short,
        fqcn=method.fqcn,
        name=method.name,
        line=line,
        start_line=method.start_line,
        end_line=method.end_line,
        body=body,
        role=role,
        label=label,
    )


def _score(flow: Flow, graph: CallGraph) -> Tuple[int, int, int, int, int]:
    auth_rank = 0 if not flow.authenticated else 1
    sink_rank = _SINK_SEVERITY.get(flow.sink_kind, 9)
    if flow.entry_tier == "framework":
        tier_rank = 0
    elif flow.entry_tier == "source":
        tier_rank = 1
    else:
        tier_rank = 2
    entry = next(
        (m for m in graph.methods.values()
         if m.file == flow.hops[0].file and m.start_line == flow.hops[0].start_line),
        None,
    )
    string_rank = 0 if (entry is not None and _takes_string_like(entry)) else 1
    return (tier_rank, auth_rank, string_rank, sink_rank, len(flow.hops))


def discover_flows(
    graph: CallGraph,
    *,
    cap: int = FLOW_VERIFY_CAP,
    max_hop_depth: int = MAX_HOP_DEPTH,
) -> List[Flow]:
    """BFS from tiered entries to a typed sink. Skip same-file paths."""
    if not graph.sinks:
        graph.entry_tier = ""
        return []
    tier, entries = _collect_entries(graph)
    graph.entry_tier = tier
    if not entries:
        return []
    out_edges = _outgoing(graph)
    sinks_by_method: Dict[str, List[SinkHit]] = defaultdict(list)
    for s in graph.sinks:
        sinks_by_method[s.caller_key].append(s)

    flows: List[Flow] = []
    seen_sigs: Set[Tuple] = set()

    for entry_key in entries:
        entry_method = graph.methods.get(entry_key)
        if entry_method is None:
            continue
        # path of method keys + the call line that entered each (None for entry)
        dq: deque[Tuple[List[str], List[int]]] = deque([([entry_key], [entry_method.start_line])])
        while dq:
            path, lines = dq.popleft()
            current = path[-1]
            depth = len(path) - 1
            for sink in sinks_by_method.get(current, []):
                files = []
                seen_files: Set[str] = set()
                hops: List[FlowHop] = []
                for i, key in enumerate(path):
                    m = graph.methods[key]
                    if i == 0:
                        role, label, line = "source", f"{m.name}(...)", lines[i]
                    elif i == len(path) - 1:
                        role, label, line = "sink", sink.label, sink.line
                    else:
                        # Marker on the call inside this method that reaches the next hop.
                        out_line = lines[i + 1] if i + 1 < len(lines) else lines[i]
                        role, label, line = "hop", f"{m.name}(...)", out_line
                    extra_body = sink.declaration if role == "sink" else ""
                    hops.append(_hop_from_method(m, line=line, role=role, label=label, extra_body=extra_body))
                    nfile = _norm_file(m.file)
                    if nfile not in seen_files:
                        seen_files.add(nfile)
                        files.append(m.file)
                if len(files) < 2:
                    continue
                sig = tuple((h.file, h.method, h.line) for h in hops)
                if sig in seen_sigs:
                    continue
                seen_sigs.add(sig)
                flow = Flow(
                    hops=hops,
                    entry_tier=tier,
                    sink_kind=sink.kind,
                    authenticated=_is_authenticated(entry_method),
                    files=files,
                )
                flows.append(flow)

            if depth >= max_hop_depth:
                continue
            for edge in out_edges.get(current, []):
                if edge.callee_key in path:
                    continue
                dq.append((path + [edge.callee_key], lines + [edge.call_line]))

    flows.sort(key=lambda f: _score(f, graph))
    graph.flows_discovered_total = len(flows)
    return flows[: max(0, cap)]


class JavaGraphAdapter:
    """`GraphAdapter` view over a Java `CallGraph`, for `derive_rules.py`.

    Thin wrapper only — no behavior change to any of the logic it delegates
    to, just exposing it through the language-agnostic seam.
    """

    language = "java"

    def __init__(self, graph: CallGraph) -> None:
        self._graph = graph

    def sink_hits(self) -> Sequence[SinkHit]:
        return self._graph.sinks

    def caller_info(self, caller_key: str) -> Optional[CallerInfo]:
        method = self._graph.methods.get(caller_key)
        if method is None:
            return None
        return CallerInfo(
            name=method.name,
            display=f"{method.fqcn}.{method.name}",
            file=method.file,
            is_constructor=method.is_constructor,
        )

    def is_test_path(self, path: str) -> bool:
        return _is_test_path(path)

    def type_names(self, limit: int) -> List[str]:
        return sample_type_names_from_graph(self._graph, limit=limit)


def sample_type_names_from_graph(graph: CallGraph, *, limit: int) -> List[str]:
    """Distinct non-JDK/framework simple type names, capped at `limit`.

    Extracted out of the old `derive_rules.sample_type_names` so both the
    adapter and (for backward compatibility) any direct caller can use it.
    """
    names: List[str] = []
    seen: Set[str] = set()
    for fqcn, jtype in graph.types.items():
        if _is_jdk_or_framework(fqcn):
            continue
        simple = (jtype.simple_name or "").strip()
        if not simple or simple in seen:
            continue
        seen.add(simple)
        names.append(simple)
        if len(names) >= limit:
            break
    return names


MAX_OTHER_SOURCES = 10


def collapse_flows_by_sink(flows: Sequence[Flow]) -> List[Flow]:
    """One flow per (sink file, sink line, sink kind), in the given order.

    Several entry points often reach one sink (every endpoint that calls the
    same DAO method). Verifying each separately costs a call per entry point
    and yields the same finding several times, so `flows` must already be
    ranked best-first: the first flow per sink is kept and the rest are listed
    on it as `other_sources`, which the verify prompt names."""
    kept: Dict[Tuple[str, int, str], Flow] = {}
    out: List[Flow] = []
    for flow in flows:
        sink = flow.hops[-1]
        key = (_norm_file(sink.file), sink.line, flow.sink_kind)
        first = kept.get(key)
        if first is None:
            kept[key] = flow
            out.append(flow)
            continue
        src = flow.hops[0]
        entry = {"file": src.file, "line": src.line, "method": src.method, "label": src.label}
        seen = {(s["file"], s["line"]) for s in first.other_sources}
        seen.add((first.hops[0].file, first.hops[0].line))
        if (src.file, src.line) not in seen and len(first.other_sources) < MAX_OTHER_SOURCES:
            first.other_sources.append(entry)
    return out


def flow_to_dict(flow: Flow) -> Dict[str, Any]:
    return {
        "entry_tier": flow.entry_tier,
        "sink_kind": flow.sink_kind,
        "files": list(flow.files),
        "hops": [
            {
                "file": h.file,
                "method": h.method,
                "fqcn": h.fqcn,
                "name": h.name,
                "line": h.line,
                "start_line": h.start_line,
                "end_line": h.end_line,
                "body": h.body,
                "role": h.role,
                "label": h.label,
            }
            for h in flow.hops
        ],
        "taint_path": list(flow.taint_path),
        "guards": list(flow.guards),
        "sanitizers": list(flow.sanitizers),
        "other_sources": list(flow.other_sources),
    }

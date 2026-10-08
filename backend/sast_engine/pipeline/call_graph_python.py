"""call_graph_python.py — Python call graph + typed-sink flow discovery.

Parallel to `pipeline/call_graph.py` (the Java module), not a refactor of it:
same fail-closed philosophy — a call is a sink only when its shape matches a
known API (import-resolved module/function, or a narrow receiver-name
heuristic for the DB-cursor idiom) — adapted to Python's dynamic typing.

Best-effort static resolution, not sound taint. Edges are function-level "A
calls B"; argument binding (literal vs. tainted) is left to the LLM on full
function bodies, exactly like the Java module — the two checks here that do
look at argument text (`open(...)` with a literal path, `yaml.load(...)`
without `Loader=yaml.SafeLoader`, ...) are syntactic call-shape checks, not
taint analysis.

`Flow`/`FlowHop`/`flow_to_dict` are imported from `call_graph.py` and reused
as-is — `flow_verify.py` only depends on their shape, and duplicating them
would just be two copies to keep in sync. `FlowHop.fqcn` (a Java-only concept)
is populated with the function's dotted module path so the field is never
left unset.
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

import ast_struct
from pipeline import llm_file_scan
from pipeline.call_graph import (
    FLOW_VERIFY_CAP,
    MAX_HOP_DEPTH,
    Flow,
    FlowHop,
    flow_to_dict,
)
from pipeline.call_graph_common import CallerInfo

__all__ = [
    "PyFunction", "PyModule", "CallSite", "Edge", "SinkHit", "PyCallGraph",
    "PythonGraphAdapter",
    "python_paths_from_scan", "is_python_stack",
    "build_call_graph", "discover_flows", "flow_to_dict",
    "FLOW_VERIFY_CAP", "MAX_HOP_DEPTH",
]

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

_SINK_SEVERITY = {
    "sql": 0,
    "eval": 0,
    "command": 1,
    "ssrf": 1,
    "deser": 2,
    "xxe": 2,
    "template": 2,
    "django_signing": 2,
    "files": 3,
}

_CURSOR_RECEIVER_NAMES = frozenset({"cursor", "conn", "connection", "db", "session"})
_CURSOR_METHODS = frozenset({"execute", "executemany"})

_SQL_DB_MODULES = frozenset({"sqlite3", "psycopg2", "pymysql", "mysql.connector"})

_SUBPROCESS_METHODS = frozenset({"run", "Popen", "call", "check_call", "check_output"})
_REQUESTS_METHODS = frozenset({"get", "post", "put", "delete", "patch", "request"})
_HTTPX_CLIENT_RECEIVERS = frozenset({"client", "session", "async_client"})

_AUTH_DECORATORS = frozenset({
    "login_required", "permission_required", "user_passes_test", "requires_auth",
})
_DRF_BASE_CLASSES = frozenset({
    "APIView", "ViewSet", "ModelViewSet", "GenericViewSet",
})
_DRF_METHOD_NAMES = frozenset({
    "get", "post", "put", "patch", "delete", "list", "retrieve", "create",
    "update", "destroy",
})
_FLASK_FASTAPI_VERBS = frozenset({"route", "get", "post", "put", "delete", "patch"})
_CELERY_DECORATORS = frozenset({"task", "shared_task"})

# Local, Python-only taint-source heuristic — deliberately not sharing
# `llm_file_scan._TAINT_SOURCE_RE` (which already happens to cover most of
# these idioms) so a future edit to the Java/JS-oriented shared regex can
# never silently change Python entry-tier behavior, and vice versa.
_PY_TAINT_SOURCE_RE = re.compile(
    r"""(?x)
    \brequest\s*\.\s*(?:args|form|json|GET|POST|values|data|headers|cookies)\b
  | \bos\.environ\b
  | \binput\s*\(
  | \bsys\.argv\b
    """
)

_STDLIB_MODULE_PREFIXES = (
    "os", "sys", "re", "json", "itertools", "functools", "collections",
    "typing", "abc", "logging", "unittest", "pathlib", "datetime", "enum",
    "dataclasses", "contextlib",
)


def _text(node: Any, src: bytes) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _field(node: Any, name: str) -> Optional[Any]:
    getter = getattr(node, "child_by_field_name", None)
    if getter is None:
        return None
    return getter(name)


def _is_test_path(rel_path: str) -> bool:
    posix = "/" + rel_path.replace("\\", "/").lstrip("/") + "/"
    return "/test/" in posix or "/tests/" in posix or posix.startswith("/test/")


def _norm_file(rel_path: str) -> str:
    return (rel_path or "").replace("\\", "/").lower()


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------

@dataclass
class PyFunction:
    key: str
    file: str
    module: str
    qualname: str
    name: str
    is_method: bool
    class_name: Optional[str]
    params: List[str] = field(default_factory=list)
    has_varargs: bool = False
    has_kwargs: bool = False
    start_line: int = 0
    end_line: int = 0
    decorators: List[str] = field(default_factory=list)
    is_async: bool = False
    body: str = ""
    locals_assumed_types: Dict[str, str] = field(default_factory=dict)
    # Names of decorators/bases on the enclosing class, folded in for the
    # DRF `permission_classes` / class-based-view auth check.
    class_decorators: List[str] = field(default_factory=list)
    class_bases: List[str] = field(default_factory=list)
    has_permission_classes: bool = False


@dataclass
class PyModule:
    module: str
    file: str
    imports: Dict[str, str] = field(default_factory=dict)
    import_modules: Dict[str, str] = field(default_factory=dict)
    classes: Dict[str, List[str]] = field(default_factory=dict)
    functions: List[str] = field(default_factory=list)


@dataclass
class CallSite:
    file: str
    line: int
    caller_key: str
    call_name: str
    receiver_expr: str
    receiver_kind: str  # module | self | attr | local | chain | none | unknown
    resolved_target: Optional[str]
    argc: int
    args_text: str = ""
    is_constructor_like: bool = False


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


@dataclass
class PyCallGraph:
    modules: Dict[str, PyModule] = field(default_factory=dict)
    functions: Dict[str, PyFunction] = field(default_factory=dict)
    functions_by_name: Dict[str, List[str]] = field(default_factory=lambda: defaultdict(list))
    edges: List[Edge] = field(default_factory=list)
    sinks: List[SinkHit] = field(default_factory=list)
    unresolved: List[str] = field(default_factory=list)
    files_parsed: int = 0
    call_sites: int = 0
    entry_tier: str = ""
    flows_discovered_total: int = 0


class PythonGraphAdapter:
    """`GraphAdapter` view over a `PyCallGraph`, for `derive_rules.py`."""

    language = "python"

    def __init__(self, graph: PyCallGraph) -> None:
        self._graph = graph

    def sink_hits(self) -> Sequence[SinkHit]:
        return self._graph.sinks

    def caller_info(self, caller_key: str) -> Optional[CallerInfo]:
        func = self._graph.functions.get(caller_key)
        if func is None:
            return None
        return CallerInfo(
            name=func.name,
            display=f"{func.module}.{func.qualname}",
            file=func.file,
            is_constructor=False,
        )

    def is_test_path(self, path: str) -> bool:
        return _is_test_path(path)

    def type_names(self, limit: int) -> List[str]:
        names: List[str] = []
        seen: Set[str] = set()
        for mod_name, mod in self._graph.modules.items():
            if mod_name.startswith(_STDLIB_MODULE_PREFIXES):
                continue
            for class_name in mod.classes:
                if not class_name or class_name in seen:
                    continue
                seen.add(class_name)
                names.append(class_name)
                if len(names) >= limit:
                    return names
        return names


# ---------------------------------------------------------------------------
# Module-path derivation
# ---------------------------------------------------------------------------

def _module_name(repo_root: Path, rel_posix: str) -> str:
    """Dotted module path, derived from position relative to the nearest
    `__init__.py` chain (falls back to the filename stem when there is none)."""
    parts = Path(rel_posix).parts
    dirs = list(parts[:-1])
    stem = Path(parts[-1]).stem

    included: List[str] = []
    i = len(dirs)
    while i > 0:
        candidate = repo_root.joinpath(*dirs[:i])
        if (candidate / "__init__.py").is_file():
            included.insert(0, dirs[i - 1])
            i -= 1
        else:
            break

    if stem == "__init__":
        mod_parts = included
    else:
        mod_parts = included + [stem]
    return ".".join(mod_parts) if mod_parts else stem


def _package_of(module: str, *, is_init: bool) -> List[str]:
    parts = module.split(".") if module else []
    if is_init:
        return parts
    return parts[:-1] if parts else []


# ---------------------------------------------------------------------------
# Parse imports
# ---------------------------------------------------------------------------

def _dotted_name_text(node: Any, src: bytes) -> str:
    return _text(node, src).strip()


def _parse_import_statement(node: Any, src: bytes, module: PyModule) -> None:
    # `import a.b.c` / `import a.b.c as x` — possibly several comma-separated.
    for child in node.children:
        if child.type == "dotted_name":
            dotted = _dotted_name_text(child, src)
            top = dotted.split(".", 1)[0]
            module.import_modules[top] = dotted
        elif child.type == "aliased_import":
            name_node = _field(child, "name")
            alias_node = _field(child, "alias")
            if name_node is None or alias_node is None:
                continue
            dotted = _dotted_name_text(name_node, src)
            alias = _text(alias_node, src)
            module.import_modules[alias] = dotted


def _parse_import_from_statement(
    node: Any, src: bytes, module: PyModule, package_parts: List[str],
) -> None:
    module_name_node = _field(node, "module_name")
    base_parts: List[str] = []
    if module_name_node is not None:
        if module_name_node.type == "relative_import":
            dots = 0
            trailing_dotted: Optional[Any] = None
            for c in module_name_node.children:
                if c.type == "import_prefix":
                    dots = sum(1 for cc in c.children if cc.type == ".")
                elif c.type == "dotted_name":
                    trailing_dotted = c
            base = package_parts[: max(0, len(package_parts) - (dots - 1))] if dots > 0 else list(package_parts)
            if trailing_dotted is not None:
                base = base + _dotted_name_text(trailing_dotted, src).split(".")
            base_parts = base
        else:
            base_parts = _dotted_name_text(module_name_node, src).split(".")

    base_dotted = ".".join(p for p in base_parts if p)

    # Everything after the `import` keyword that names an imported symbol.
    seen_import_kw = False
    for child in node.children:
        if child.type == "import":
            seen_import_kw = True
            continue
        if not seen_import_kw:
            continue
        if child.type == "wildcard_import":
            continue
        if child.type == "dotted_name":
            name = _dotted_name_text(child, src)
            target = f"{base_dotted}.{name}" if base_dotted else name
            module.imports[name] = target
        elif child.type == "aliased_import":
            name_node = _field(child, "name")
            alias_node = _field(child, "alias")
            if name_node is None or alias_node is None:
                continue
            name = _dotted_name_text(name_node, src)
            alias = _text(alias_node, src)
            target = f"{base_dotted}.{name}" if base_dotted else name
            module.imports[alias] = target


def _parse_module_imports(root: Any, src: bytes, module: PyModule, package_parts: List[str]) -> None:
    for child in root.children:
        if child.type == "import_statement":
            _parse_import_statement(child, src, module)
        elif child.type == "import_from_statement":
            _parse_import_from_statement(child, src, module, package_parts)


# ---------------------------------------------------------------------------
# Parse one file — functions, classes, decorators
# ---------------------------------------------------------------------------

def _decorator_text_and_name(dec_node: Any, src: bytes) -> Tuple[str, str, str]:
    """Returns (raw_text, call_name, receiver_expr) for one `decorator` node."""
    raw = _text(dec_node, src)
    inner = None
    for c in dec_node.children:
        if c.type in ("call", "attribute", "identifier"):
            inner = c
            break
    if inner is None:
        return raw, "", ""
    target = inner
    if inner.type == "call":
        fn = _field(inner, "function")
        target = fn if fn is not None else inner
    if target.type == "attribute":
        attr = _field(target, "attribute")
        obj = _field(target, "object")
        name = _text(attr, src) if attr is not None else ""
        receiver = _text(obj, src) if obj is not None else ""
        return raw, name, receiver
    if target.type == "identifier":
        return raw, _text(target, src), ""
    return raw, "", ""


def _collect_decorators(decorated_node: Any, src: bytes) -> List[str]:
    out = []
    for c in decorated_node.children:
        if c.type == "decorator":
            out.append(_text(c, src))
    return out


def _param_names(params_node: Optional[Any], src: bytes) -> Tuple[List[str], bool, bool]:
    names: List[str] = []
    has_varargs = False
    has_kwargs = False
    if params_node is None:
        return names, has_varargs, has_kwargs
    for c in params_node.children:
        if c.type == "identifier":
            names.append(_text(c, src))
        elif c.type in ("default_parameter", "typed_parameter", "typed_default_parameter"):
            name_node = _field(c, "name")
            if name_node is not None:
                names.append(_text(name_node, src))
            else:
                for cc in c.children:
                    if cc.type == "identifier":
                        names.append(_text(cc, src))
                        break
        elif c.type == "list_splat_pattern":
            has_varargs = True
        elif c.type == "dictionary_splat_pattern":
            has_kwargs = True
    return names, has_varargs, has_kwargs


def _class_bases(class_node: Any, src: bytes) -> List[str]:
    args = _field(class_node, "superclasses")
    if args is None:
        return []
    bases: List[str] = []
    for c in args.children:
        if c.type == "identifier":
            bases.append(_text(c, src))
        elif c.type == "attribute":
            attr = _field(c, "attribute")
            if attr is not None:
                bases.append(_text(attr, src))
        elif c.type == "keyword_argument":
            continue
    return bases


def _is_async_def(func_node: Any) -> bool:
    return bool(func_node.children) and func_node.children[0].type == "async"


def _collect_locals_assumed_types(body_node: Optional[Any], src: bytes) -> Dict[str, str]:
    """Best-effort `x = Module.Class(...)` / `x: Class = ...` hints, textually
    preceding a call in the same function body."""
    hints: Dict[str, str] = {}
    if body_node is None:
        return hints
    stack = [body_node]
    while stack:
        n = stack.pop()
        if n.type in ("function_definition", "class_definition"):
            continue
        if n.type == "assignment":
            left = _field(n, "left")
            right = _field(n, "right")
            type_node = _field(n, "type")
            if left is not None and left.type == "identifier":
                name = _text(left, src)
                if type_node is not None:
                    hints[name] = _text(type_node, src).strip()
                elif right is not None and right.type == "call":
                    fn = _field(right, "function")
                    if fn is not None:
                        hints[name] = _text(fn, src).strip()
        stack.extend(n.children)
    return hints


def _walk_functions(
    node: Any,
    src: bytes,
    rel_path: str,
    module_name: str,
    graph: PyCallGraph,
    module: PyModule,
    *,
    class_stack: List[Tuple[str, List[str], List[str], bool]],
) -> None:
    """Recursively index function/class definitions. `class_stack` carries
    (class_name, class_bases, class_decorators, has_permission_classes) for
    every enclosing class, innermost last."""
    for child in node.children:
        if child.type == "decorated_definition":
            decorators = _collect_decorators(child, src)
            inner = None
            for c in child.children:
                if c.type in ("function_definition", "class_definition"):
                    inner = c
                    break
            if inner is None:
                continue
            if inner.type == "function_definition":
                _index_function(inner, src, rel_path, module_name, graph, module, class_stack, decorators)
            elif inner.type == "class_definition":
                _index_class(inner, src, rel_path, module_name, graph, module, class_stack, decorators)
        elif child.type == "function_definition":
            _index_function(child, src, rel_path, module_name, graph, module, class_stack, [])
        elif child.type == "class_definition":
            _index_class(child, src, rel_path, module_name, graph, module, class_stack, [])
        else:
            _walk_functions(child, src, rel_path, module_name, graph, module, class_stack=class_stack)


def _index_class(
    class_node: Any, src: bytes, rel_path: str, module_name: str,
    graph: PyCallGraph, module: PyModule,
    class_stack: List[Tuple[str, List[str], List[str], bool]],
    decorators: List[str],
) -> None:
    name_node = _field(class_node, "name")
    class_name = _text(name_node, src) if name_node is not None else ""
    bases = _class_bases(class_node, src)
    body = _field(class_node, "body")
    has_permission_classes = False
    if body is not None:
        for c in body.children:
            if c.type == "expression_statement":
                for cc in c.children:
                    if cc.type == "assignment":
                        left = _field(cc, "left")
                        if left is not None and _text(left, src) == "permission_classes":
                            has_permission_classes = True
    if not class_name:
        return
    module.classes.setdefault(class_name, [])
    new_stack = class_stack + [(class_name, bases, decorators, has_permission_classes)]
    if body is not None:
        _walk_functions(body, src, rel_path, module_name, graph, module, class_stack=new_stack)


def _index_function(
    func_node: Any, src: bytes, rel_path: str, module_name: str,
    graph: PyCallGraph, module: PyModule,
    class_stack: List[Tuple[str, List[str], List[str], bool]],
    decorators: List[str],
) -> None:
    name_node = _field(func_node, "name")
    name = _text(name_node, src) if name_node is not None else ""
    if not name:
        return
    is_method = bool(class_stack)
    class_name = class_stack[-1][0] if class_stack else None
    class_bases = class_stack[-1][1] if class_stack else []
    class_decorators = class_stack[-1][2] if class_stack else []
    has_permission_classes = class_stack[-1][3] if class_stack else False
    qualname = f"{class_name}.{name}" if class_name else name
    start = func_node.start_point[0] + 1
    end = func_node.end_point[0] + 1
    key = f"{rel_path}::{module_name}::{qualname}::{start}"
    params_node = _field(func_node, "parameters")
    params, has_varargs, has_kwargs = _param_names(params_node, src)
    body_node = _field(func_node, "body")

    func = PyFunction(
        key=key,
        file=rel_path,
        module=module_name,
        qualname=qualname,
        name=name,
        is_method=is_method,
        class_name=class_name,
        params=params,
        has_varargs=has_varargs,
        has_kwargs=has_kwargs,
        start_line=start,
        end_line=end,
        decorators=decorators,
        is_async=_is_async_def(func_node),
        body=_text(func_node, src),
        locals_assumed_types=_collect_locals_assumed_types(body_node, src),
        class_decorators=list(class_decorators),
        class_bases=list(class_bases),
        has_permission_classes=has_permission_classes,
    )
    graph.functions[key] = func
    graph.functions_by_name[name].append(key)
    if is_method and class_name:
        module.classes.setdefault(class_name, []).append(key)
    else:
        module.functions.append(key)

    # Recurse for nested functions/classes (closures, nested helpers).
    if body_node is not None:
        _walk_functions(body_node, src, rel_path, module_name, graph, module, class_stack=class_stack)


# ---------------------------------------------------------------------------
# Parse one file — call sites
# ---------------------------------------------------------------------------

def _call_shape(call_node: Any, src: bytes) -> Tuple[str, str, str]:
    """Returns (receiver_kind, call_name, receiver_expr) for a `call` node."""
    fn = _field(call_node, "function")
    if fn is None:
        return "unknown", "", ""
    if fn.type == "identifier":
        return "none", _text(fn, src), ""
    if fn.type == "attribute":
        attr = _field(fn, "attribute")
        obj = _field(fn, "object")
        call_name = _text(attr, src) if attr is not None else ""
        if obj is None:
            return "unknown", call_name, ""
        if obj.type == "identifier":
            receiver = _text(obj, src)
            if receiver == "self":
                return "self", call_name, receiver
            return "local", call_name, receiver
        if obj.type == "attribute":
            return "chain", call_name, _text(obj, src)
        if obj.type == "call":
            return "chain", call_name, _text(obj, src)
        return "unknown", call_name, _text(obj, src)
    return "unknown", "", ""


def _arg_count_and_text(call_node: Any, src: bytes) -> Tuple[int, str]:
    args = _field(call_node, "arguments")
    if args is None:
        return 0, ""
    count = sum(1 for c in args.children if getattr(c, "is_named", False))
    return count, _text(args, src)


def _walk_calls(
    func: PyFunction,
    func_node: Any,
    src: bytes,
) -> List[CallSite]:
    calls: List[CallSite] = []
    body = _field(func_node, "body")
    if body is None:
        return calls
    stack = [body]
    while stack:
        n = stack.pop()
        if n.type in ("function_definition", "class_definition"):
            continue
        if n.type == "call":
            receiver_kind, call_name, receiver_expr = _call_shape(n, src)
            argc, args_text = _arg_count_and_text(n, src)
            calls.append(CallSite(
                file=func.file,
                line=n.start_point[0] + 1,
                caller_key=func.key,
                call_name=call_name,
                receiver_expr=receiver_expr,
                receiver_kind=receiver_kind,
                resolved_target=None,
                argc=argc,
                args_text=args_text,
            ))
        stack.extend(n.children)
    return calls


def _parse_python_file(
    rel_path: str, source_text: str, module_name: str, package_parts: List[str], graph: PyCallGraph,
) -> List[CallSite]:
    parser = ast_struct.parser_for_lang("python")
    if parser is None:
        return []
    src = source_text.encode("utf-8", errors="replace")
    try:
        tree = parser.parse(src)
    except Exception:  # noqa: BLE001
        return []
    root = tree.root_node

    module = PyModule(module=module_name, file=rel_path)
    _parse_module_imports(root, src, module, package_parts)
    graph.modules[module_name] = module

    _walk_functions(root, src, rel_path, module_name, graph, module, class_stack=[])

    calls: List[CallSite] = []
    funcs_by_start = {
        (f.file, f.start_line): f for f in graph.functions.values() if f.file == rel_path
    }
    stack = [root]
    while stack:
        n = stack.pop()
        if n.type == "function_definition":
            start = n.start_point[0] + 1
            func = funcs_by_start.get((rel_path, start))
            if func is not None:
                calls.extend(_walk_calls(func, n, src))
        stack.extend(n.children)
    return calls


# ---------------------------------------------------------------------------
# Resolve calls -> edges / sinks
# ---------------------------------------------------------------------------

def _resolve_call_target(
    call: CallSite, func: PyFunction, module: PyModule,
) -> Optional[str]:
    """Best-effort dotted tag for a call (e.g. "subprocess.run"), resolved
    via this file's import map. None means unresolved."""
    if call.receiver_kind == "none":
        # Bare call — the callee identifier itself may be an imported name.
        if call.call_name in module.imports:
            return module.imports[call.call_name]
        return None
    if call.receiver_kind == "local":
        receiver = call.receiver_expr
        if receiver in module.import_modules:
            return f"{module.import_modules[receiver]}.{call.call_name}"
        if receiver in module.imports:
            return f"{module.imports[receiver]}.{call.call_name}"
        hint = func.locals_assumed_types.get(receiver)
        if hint:
            return f"{hint}.{call.call_name}"
        return None
    if call.receiver_kind == "chain":
        # `a.b.method(...)` — resolve the leftmost identifier of the chain.
        root_name = call.receiver_expr.split(".", 1)[0].split("(", 1)[0]
        if root_name in module.import_modules:
            return f"{module.import_modules[root_name]}.{call.call_name}"
        if root_name in module.imports:
            return f"{module.imports[root_name]}.{call.call_name}"
        return None
    return None


def _module_alias_of(receiver: str, module: PyModule) -> Optional[str]:
    if receiver in module.import_modules:
        return module.import_modules[receiver]
    if receiver in module.imports:
        return module.imports[receiver]
    return None


def _has_literal_arg(args_text: str) -> bool:
    """True when the argument list's first token looks like a string/bytes
    literal — used only for the narrow, explicitly-named non-literal checks
    in the sink catalog (open/shutil/Template), never for general taint."""
    stripped = args_text.lstrip("(").lstrip()
    return stripped.startswith(("'", '"', "f'", 'f"', "b'", 'b"', "r'", 'r"'))


def _typed_sink_python(
    call: CallSite, module: PyModule, resolved: Optional[str],
) -> Optional[Tuple[str, str]]:
    """Returns (kind, label_hint) if this call site is a typed sink."""
    receiver = call.receiver_expr

    # eval / exec / compile — always builtins, no import required.
    if call.receiver_kind == "none" and call.call_name in ("eval", "exec", "compile"):
        return "eval", ""

    # SQL: cursor/conn/... receiver-name heuristic (no import needed), or an
    # import of a DB driver module in this file.
    if call.call_name in _CURSOR_METHODS:
        if receiver in _CURSOR_RECEIVER_NAMES:
            return "sql", ""
        if any(m in module.import_modules.values() or m in module.imports.values()
               for m in _SQL_DB_MODULES):
            return "sql", ""

    # A bare call resolved through an aliased import (e.g. `from subprocess
    # import run as r` then `r(...)`) has `call.call_name == "r"`, not "run" —
    # the real method name is the resolved dotted target's last segment.
    # For an attribute call (`subprocess.run(...)`) the two already agree.
    name = resolved.rsplit(".", 1)[-1] if resolved else call.call_name

    if resolved:
        # sqlalchemy: `.execute(text(...))` / `Session.execute`
        if resolved.startswith("sqlalchemy") and name == "execute":
            return "sql", ""
        # django QuerySet .raw(/.extra(
        if name in ("raw", "extra") and resolved.startswith("django"):
            return "sql", ""

        if resolved in ("os.system", "os.popen"):
            return "command", ""
        if resolved.startswith("subprocess.") and name in _SUBPROCESS_METHODS:
            label = ""
            if "shell=True" in call.args_text or "shell =True" in call.args_text:
                label = "shell=True"
            return "command", label

        if resolved.startswith("requests.") and name in _REQUESTS_METHODS:
            return "ssrf", ""
        if resolved == "urllib.request.urlopen" or resolved.endswith(".urlopen") and "urllib" in resolved:
            return "ssrf", ""
        if (resolved.startswith("httpx.") or resolved.startswith("aiohttp.")) and name in (
            "get", "post", "request",
        ):
            return "ssrf", ""

        if resolved.startswith("pickle.") and name in ("loads", "load"):
            return "deser", ""
        if resolved.startswith("marshal.") and name == "loads":
            return "deser", ""
        if resolved.startswith("yaml.") and name == "load":
            if "SafeLoader" not in call.args_text:
                return "deser", ""

        if resolved.startswith("lxml.etree") and name in ("parse", "fromstring"):
            if "resolve_entities=False" not in call.args_text:
                return "xxe", ""
        if any(resolved.startswith(p) for p in (
            "xml.etree.ElementTree", "xml.sax", "xml.dom.minidom",
        )) and name in ("parse", "fromstring", "parseString"):
            return "xxe", ""

        if resolved.startswith("jinja2.") and name == "Template":
            if not _has_literal_arg(call.args_text) and call.args_text.strip("()"):
                return "template", ""
        if name == "render_template_string":
            return "template", ""

        if resolved.startswith("shutil.") and name in ("copy", "move", "rmtree"):
            if not _has_literal_arg(call.args_text):
                return "files", ""

        if resolved.startswith("django.core.signing") and name == "loads":
            return "django_signing", ""

    # `open(...)` — builtin, non-literal path only.
    if call.receiver_kind == "none" and name == "open":
        if not _has_literal_arg(call.args_text):
            return "files", ""

    return None


def _resolve_callee_keys(
    graph: PyCallGraph, call: CallSite, func: PyFunction, module: PyModule,
) -> Tuple[List[str], Optional[str]]:
    """Return (function keys, unresolved reason)."""
    if call.receiver_kind == "self":
        if func.class_name:
            class_methods = module.classes.get(func.class_name, [])
            matches = [
                k for k in class_methods
                if graph.functions.get(k) and graph.functions[k].name == call.call_name
            ]
            if len(matches) == 1:
                return matches, None
            if len(matches) > 1:
                return [], "unresolved_overload"
        return [], "unresolved_self_method"

    if call.receiver_kind in ("local", "chain"):
        root_name = call.receiver_expr.split(".", 1)[0].split("(", 1)[0]
        target_module = _module_alias_of(root_name, module)
        if target_module and target_module in graph.modules:
            target = graph.modules[target_module]
            matches = [
                k for k in target.functions
                if graph.functions.get(k) and graph.functions[k].name == call.call_name
            ]
            if len(matches) == 1:
                return matches, None
            if len(matches) > 1:
                return [], "unresolved_overload"
            return [], "unresolved_type"
        if target_module:
            # Resolved to a known (likely third-party/stdlib) module we never
            # parsed — not a coverage gap, just nothing to hop into.
            return [], None

    if call.receiver_kind == "none":
        if call.call_name in module.imports:
            # A resolved import of a name we don't have source for (stdlib,
            # third-party, or an unparsed in-repo module) — no hop, no
            # unresolved reason; this is not a failure to resolve.
            target_dotted = module.imports[call.call_name]
            target_module_name = target_dotted.rsplit(".", 1)[0]
            if target_module_name in graph.modules:
                candidates = [
                    k for k in graph.modules[target_module_name].functions
                    if graph.functions.get(k) and graph.functions[k].name == call.call_name
                ]
                if len(candidates) == 1:
                    return candidates, None
                if len(candidates) > 1:
                    return [], "unresolved_overload"
            return [], None

        # Cross-file resolution fallback: unique match on simple name only
        # when the call's target module couldn't be pinned down via imports.
        candidates = list(graph.functions_by_name.get(call.call_name) or [])
        candidates = [k for k in candidates if k != func.key]
        if not candidates:
            return [], None
        if len(candidates) == 1:
            return candidates, None
        return [], "unresolved_ambiguous_name"

    return [], None


def _wire_calls(graph: PyCallGraph, calls: List[CallSite]) -> None:
    for call in calls:
        func = graph.functions.get(call.caller_key)
        if func is None:
            continue
        module = graph.modules.get(func.module)
        if module is None:
            continue
        resolved = _resolve_call_target(call, func, module)
        call.resolved_target = resolved

        sink = _typed_sink_python(call, module, resolved)
        if sink:
            kind, label_hint = sink
            label = f"{call.receiver_expr + '.' if call.receiver_expr else ''}{call.call_name}(...)"
            if label_hint:
                label = f"{label} [{label_hint}]"
            graph.sinks.append(SinkHit(
                caller_key=func.key,
                kind=kind,
                line=call.line,
                file=func.file,
                method_name=call.call_name,
                label=label,
            ))

        keys, reason = _resolve_callee_keys(graph, call, func, module)
        # Mirrors Java's philosophy: a sink terminates the flow by design, so
        # a failed callee lookup there is not a coverage gap.
        if reason and not sink:
            graph.unresolved.append(reason)
        for callee_key in keys:
            graph.edges.append(Edge(caller_key=func.key, callee_key=callee_key, call_line=call.line))


# ---------------------------------------------------------------------------
# Public: build graph
# ---------------------------------------------------------------------------

def python_paths_from_scan(scan: Optional[Dict[str, Any]]) -> List[str]:
    files = (scan or {}).get("files") or []
    return [f["path"] for f in files if str(f.get("ext") or "").lower() == ".py"]


def is_python_stack(state: Dict[str, Any]) -> bool:
    analysis = state.get("llm_analysis") or {}
    stacks = analysis.get("heuristic_stacks") or []
    return "python" in stacks


def build_call_graph(repo_root: Path, rel_paths: Sequence[str]) -> PyCallGraph:
    graph = PyCallGraph()
    all_calls: List[CallSite] = []
    file_packages: Dict[str, List[str]] = {}
    file_modules: Dict[str, str] = {}

    for rel in rel_paths:
        posix = rel.replace("\\", "/")
        path = repo_root / posix
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if llm_file_scan.is_non_analyzable_file(repo_root, posix, text):
            continue
        module_name = _module_name(repo_root, posix)
        is_init = Path(posix).name == "__init__.py"
        package_parts = _package_of(module_name, is_init=is_init)
        file_modules[posix] = module_name
        file_packages[posix] = package_parts
        calls = _parse_python_file(posix, text, module_name, package_parts, graph)
        all_calls.extend(calls)
        graph.files_parsed += 1

    graph.call_sites = len(all_calls)
    _wire_calls(graph, all_calls)
    return graph


# ---------------------------------------------------------------------------
# Entries + discover_flows
# ---------------------------------------------------------------------------

def _decorator_call_name(dec_text: str) -> Tuple[str, str]:
    """(receiver, verb) for a decorator's raw text, e.g. "@app.route(...)" ->
    ("app", "route"), "@shared_task" -> ("", "shared_task")."""
    body = dec_text.lstrip("@").strip()
    head = body.split("(", 1)[0].strip()
    if "." in head:
        receiver, verb = head.rsplit(".", 1)
        return receiver, verb
    return "", head


def _is_framework_entry(func: PyFunction) -> bool:
    for dec in func.decorators:
        receiver, verb = _decorator_call_name(dec)
        if verb in _FLASK_FASTAPI_VERBS and receiver:
            return True
        if verb in _CELERY_DECORATORS:
            return True
        if verb == "api_view":
            return True
    if func.class_bases and any(b in _DRF_BASE_CLASSES for b in func.class_bases):
        if func.name in _DRF_METHOD_NAMES:
            return True
    return False


def _is_authenticated(func: PyFunction) -> bool:
    for dec in func.decorators:
        _, verb = _decorator_call_name(dec)
        if verb in _AUTH_DECORATORS:
            return True
    for dec in func.class_decorators:
        _, verb = _decorator_call_name(dec)
        if verb in _AUTH_DECORATORS:
            return True
    return func.has_permission_classes


def _has_taint_source(func: PyFunction) -> bool:
    return bool(_PY_TAINT_SOURCE_RE.search(func.body))


def _collect_entries(graph: PyCallGraph) -> Tuple[str, List[str]]:
    framework = [f.key for f in graph.functions.values() if _is_framework_entry(f)]
    if framework:
        return "framework", framework
    source = [f.key for f in graph.functions.values() if _has_taint_source(f)]
    if source:
        return "source", source
    return "public_api", _public_api_entries(graph)


def _outgoing(graph: PyCallGraph) -> Dict[str, List[Edge]]:
    out: Dict[str, List[Edge]] = defaultdict(list)
    for e in graph.edges:
        out[e.caller_key].append(e)
    return out


def _incoming(graph: PyCallGraph) -> Dict[str, List[Edge]]:
    inn: Dict[str, List[Edge]] = defaultdict(list)
    for e in graph.edges:
        inn[e.callee_key].append(e)
    return inn


def _is_public_api_visible(func: PyFunction) -> bool:
    return not func.name.startswith("_") and not _is_test_path(func.file)


def _public_api_entries(graph: PyCallGraph) -> List[str]:
    inn = _incoming(graph)
    sink_funcs = {s.caller_key for s in graph.sinks}
    entries: Set[str] = set()
    for sink_key in sink_funcs:
        dq: deque[Tuple[str, int]] = deque([(sink_key, 0)])
        seen = {sink_key}
        while dq:
            key, depth = dq.popleft()
            func = graph.functions.get(key)
            if func is None:
                continue
            if _is_public_api_visible(func) and key != sink_key:
                entries.add(key)
                continue
            if depth >= MAX_HOP_DEPTH:
                continue
            for edge in inn.get(key, []):
                if edge.caller_key not in seen:
                    seen.add(edge.caller_key)
                    dq.append((edge.caller_key, depth + 1))
        func = graph.functions.get(sink_key)
        if func and _is_public_api_visible(func):
            callers = [e.caller_key for e in inn.get(sink_key, [])]
            other_file = [
                c for c in callers
                if graph.functions.get(c)
                and _norm_file(graph.functions[c].file) != _norm_file(func.file)
            ]
            for c in other_file:
                callee = graph.functions[c]
                if _is_public_api_visible(callee):
                    entries.add(c)
    return sorted(entries)


def _hop_from_function(func: PyFunction, *, line: int, role: str, label: str) -> FlowHop:
    return FlowHop(
        file=func.file,
        method=func.qualname,
        fqcn=func.module,
        name=func.name,
        line=line,
        start_line=func.start_line,
        end_line=func.end_line,
        body=func.body,
        role=role,
        label=label,
    )


def _score(flow: Flow, graph: PyCallGraph) -> Tuple[int, int, int]:
    auth_rank = 0 if not flow.authenticated else 1
    sink_rank = _SINK_SEVERITY.get(flow.sink_kind, 9)
    if flow.entry_tier == "framework":
        tier_rank = 0
    elif flow.entry_tier == "source":
        tier_rank = 1
    else:
        tier_rank = 2
    return (tier_rank, auth_rank, sink_rank)


def discover_flows(
    graph: PyCallGraph,
    *,
    cap: int = FLOW_VERIFY_CAP,
    max_hop_depth: int = MAX_HOP_DEPTH,
) -> List[Flow]:
    """BFS from tiered entries to a typed sink. Skip same-file-only paths."""
    if not graph.sinks:
        graph.entry_tier = ""
        return []
    tier, entries = _collect_entries(graph)
    graph.entry_tier = tier
    if not entries:
        return []
    out_edges = _outgoing(graph)
    sinks_by_func: Dict[str, List[SinkHit]] = defaultdict(list)
    for s in graph.sinks:
        sinks_by_func[s.caller_key].append(s)

    flows: List[Flow] = []
    seen_sigs: Set[Tuple] = set()

    for entry_key in entries:
        entry_func = graph.functions.get(entry_key)
        if entry_func is None:
            continue
        dq: deque[Tuple[List[str], List[int]]] = deque([([entry_key], [entry_func.start_line])])
        while dq:
            path, lines = dq.popleft()
            current = path[-1]
            depth = len(path) - 1
            for sink in sinks_by_func.get(current, []):
                files: List[str] = []
                seen_files: Set[str] = set()
                hops: List[FlowHop] = []
                for i, key in enumerate(path):
                    f = graph.functions[key]
                    if i == 0:
                        role, label, line = "source", f"{f.name}(...)", lines[i]
                    elif i == len(path) - 1:
                        role, label, line = "sink", sink.label, sink.line
                    else:
                        out_line = lines[i + 1] if i + 1 < len(lines) else lines[i]
                        role, label, line = "hop", f"{f.name}(...)", out_line
                    hops.append(_hop_from_function(f, line=line, role=role, label=label))
                    nfile = _norm_file(f.file)
                    if nfile not in seen_files:
                        seen_files.add(nfile)
                        files.append(f.file)
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
                    authenticated=_is_authenticated(entry_func),
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

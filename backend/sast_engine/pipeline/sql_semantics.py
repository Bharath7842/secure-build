"""sql_semantics.py — what a Java method does with SQL, as checkable facts (EPIC-02).

A SQL-injection finding is only real when external text can change the
*executed SQL grammar*. A value bound to a placeholder cannot; a constant query
cannot; a commented-out concatenation is not code. This module works out, from
a tree-sitter parse, which JDBC statements a method prepares, which values it
binds to them and where it executes them, so the `sql_binding` validator can
decide from structure rather than from text near a line.

`statements_in_method` (SAST-02-010) returns one `StatementFact` per statement
*allocation*:

* `var` — the statement variable or field; `scope` says which (`local`,
  `field`, `param`), and `complete` is False when the allocation, binds or
  executions live outside this method;
* `alloc` / `alloc_line` / `query_expr` — the allocation call
  (`prepareStatement`, `prepareCall`, `createStatement`) and the query node it
  was given (for a plain `Statement`, the first `execute*(String)` argument);
* `binds` — `setXxx(index, value)` calls on the same variable, with the
  value's argument kind (`occurrence_facts`);
* `executions` — `executeQuery()`, `executeUpdate()`, `execute()`,
  `addBatch()`, `executeBatch()` and their `(String)` overloads, each with the
  SQL argument it was passed, if any;
* `api_misuse` — a `PreparedStatement` executed with a SQL string argument,
  which ignores the prepared query (#54).

Spring `JdbcTemplate` / `NamedParameterJdbcTemplate` calls are one fact each
(`alloc="jdbc_template"`): the SQL string is the query, and `bound_by_args`
says whether bind values (an args array, varargs, a `Map` or
`SqlParameterSource`) were passed with it.

LIMITATION: statement identity follows the variable in *source order*, not by
real control-flow dominance. Each bind and execution records its `branch`
(the if/else arm, switch group, loop or lambda body it sits in), and a later
allocation replaces an earlier one only when it is at the same or an outer
level, so branch-specific binding stays visible to the validator. That is
enough for the shapes the accuracy review found; a `goto`-like early return
that skips a bind is not modelled.

Comment tokens are never part of any expression: tree-sitter keeps them as
separate nodes, and every walk here skips them, so commented-out legacy
concatenation (#33/#34/#40/#59) can never reach `query_expr`.

The module is pure — source text in, facts out, no LLM, no I/O — and reuses
`occurrence_facts`' parse cache, name resolution and argument kinds, and
`call_graph`'s statement type table; it adds no resolver of its own.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from pipeline import occurrence_facts as of

_ALLOC_TO_TYPE = {
    "prepareStatement": "java.sql.PreparedStatement",
    "prepareCall": "java.sql.CallableStatement",
    "createStatement": "java.sql.Statement",
}
_PREPARED_TYPES = frozenset({"java.sql.PreparedStatement", "java.sql.CallableStatement"})
_EXECUTE_METHODS = frozenset({
    "executeQuery", "executeUpdate", "execute", "addBatch", "executeBatch",
    "executeLargeUpdate", "executeLargeBatch",
})
# Setters whose first argument is not a parameter index.
_NON_BIND_SETTERS = frozenset({
    "setFetchSize", "setFetchDirection", "setMaxRows", "setMaxFieldSize", "setQueryTimeout",
    "setEscapeProcessing", "setCursorName", "setPoolable", "setLargeMaxRows",
})
_JDBC_TEMPLATE_METHODS = frozenset({
    "query", "update", "execute", "batchUpdate", "queryForObject", "queryForList",
    "queryForMap", "queryForRowSet", "queryForStream", "queryForInt", "queryForLong",
})
# Arguments after the SQL string that are callbacks or result types, not values.
_TEMPLATE_CALLBACK_SUFFIXES = ("Mapper", "Extractor", "Handler", "Callback", "Creator", "Setter")

# A branch step: (node id, arm). Arms of one node are mutually exclusive.
Branch = Tuple[Tuple[int, str], ...]


@dataclass
class Bind:
    index: Any  # int position, a named parameter (str), or None when computed
    value: Any  # tree-sitter node
    kind: str
    line: int
    branch: Branch
    setter: str = ""


@dataclass
class Execution:
    method: str
    line: int
    sql_arg: Any  # tree-sitter node, or None for the no-argument overload
    branch: Branch

    @property
    def has_sql_arg(self) -> bool:
        return self.sql_arg is not None


@dataclass
class StatementFact:
    var: str
    scope: str  # local | field | param
    statement_type: str
    alloc: Optional[str] = None
    alloc_line: Optional[int] = None
    alloc_branch: Branch = ()
    query_expr: Any = None
    binds: List[Bind] = field(default_factory=list)
    executions: List[Execution] = field(default_factory=list)
    complete: bool = True
    bound_by_args: bool = False

    @property
    def api_misuse(self) -> bool:
        """A prepared statement executed with its own SQL string: the prepared
        query (and anything bound to it) is ignored."""
        return self.statement_type in _PREPARED_TYPES and self.alloc != "jdbc_template" and any(
            e.has_sql_arg for e in self.executions
        )


@dataclass
class MethodContext:
    """One method plus what its file says about names: the node, the source
    bytes, `occurrence_facts`' file and scope objects."""

    node: Any
    src: bytes
    jf: Any
    scope: Any

    @property
    def start_line(self) -> int:
        return self.node.start_point[0] + 1

    @property
    def end_line(self) -> int:
        return self.node.end_point[0] + 1

    def text(self, node: Any) -> str:
        return of._t(node, self.src)


def _java_file(root: Any, src: bytes, memo: Optional[Dict[str, Any]] = None) -> Any:
    if memo is None:
        return of._JavaFile(root, src)
    jf = memo.get("file")
    if jf is None:
        jf = memo["file"] = of._JavaFile(root, src)
    return jf


def method_context(method_node: Any, src: bytes, jf: Any = None) -> MethodContext:
    if jf is None:
        root = method_node
        while root.parent is not None:
            root = root.parent
        jf = _java_file(root, src)
    scope = of._Scope()
    of._fill_scope(jf, method_node, scope)
    return MethodContext(node=method_node, src=src, jf=jf, scope=scope)


def method_at(source_text: str, line: int) -> Optional[MethodContext]:
    """The method or constructor enclosing `line` (1-based), or None when the
    file does not parse or the line is outside any method."""
    parsed = of._parse("java", source_text)
    if parsed is None:
        return None
    root, src, memo = parsed
    row = max(line - 1, 0)
    node = root.descendant_for_point_range((row, 0), (row, 0))
    # A line that starts with whitespace resolves to the enclosing block, not
    # to the method; descend to the first code node on that row.
    while node is not None and node.type not in of._JAVA_METHOD_NODES:
        node = node.parent
    if node is None:
        for candidate in _methods(root):
            if candidate.start_point[0] <= row <= candidate.end_point[0]:
                node = candidate
    if node is None or node.has_error:
        return None
    return method_context(node, src, _java_file(root, src, memo))


def methods_in_file(source_text: str) -> List[MethodContext]:
    parsed = of._parse("java", source_text)
    if parsed is None:
        return []
    root, src, memo = parsed
    jf = _java_file(root, src, memo)
    return [method_context(m, src, jf) for m in _methods(root) if not m.has_error]


def _methods(root: Any) -> List[Any]:
    out: List[Any] = []
    stack = [root]
    while stack:
        n = stack.pop()
        if n.type in of._JAVA_METHOD_NODES:
            out.append(n)
        stack.extend(n.children)
    out.sort(key=lambda n: n.start_byte)
    return out


# --- branches -----------------------------------------------------------------

def _child_branch(parent: Any, child: Any, index: int) -> Optional[Tuple[int, str]]:
    """The branch step entering `child` from `parent`, if `child` is a
    conditionally executed region."""
    t = parent.type
    name = parent.field_name_for_child(index)
    if t == "if_statement" and name in ("consequence", "alternative"):
        return (parent.id, "then" if name == "consequence" else "else")
    if t in ("for_statement", "enhanced_for_statement", "while_statement", "do_statement") and name == "body":
        return (parent.id, "loop")
    if t == "switch_block" and child.type in ("switch_block_statement_group", "switch_rule"):
        return (parent.id, "default" if _switch_default(child) else f"case{index}")
    if t == "try_statement" and child.type == "catch_clause":
        return (parent.id, f"catch{index}")
    if t == "lambda_expression" and name == "body":
        return (parent.id, "lambda")
    if t == "ternary_expression" and name in ("consequence", "alternative"):
        return (parent.id, "then" if name == "consequence" else "else")
    return None


def exclusive(a: Branch, b: Branch) -> bool:
    """Can two regions never both run? True when, at the first step where
    their paths differ, both step into different arms of the same node."""
    for x, y in zip(a, b):
        if x == y:
            continue
        return x[0] == y[0] and x[1] != y[1]
    return False


def encloses(outer: Branch, inner: Branch) -> bool:
    """Is every run of `inner` also a run of `outer` (`outer` is a prefix)?"""
    return len(outer) <= len(inner) and inner[: len(outer)] == outer


def _walk(node: Any, branch: Branch, out: List[Tuple[Any, Branch]]) -> None:
    """Pre-order, source-order walk of a method body, skipping comments and
    nested type declarations, recording each node's branch path."""
    for index, child in enumerate(node.children):
        if not child.is_named or child.type in of._JAVA_COMMENT_NODES:
            continue
        # A nested type's (or anonymous class's) methods are methods of their own.
        if child.type in of._JAVA_TYPE_NODES or child.type in of._JAVA_METHOD_NODES:
            continue
        step = _child_branch(node, child, index)
        child_branch = branch + (step,) if step is not None else branch
        out.append((child, child_branch))
        _walk(child, child_branch, out)


def _switch_default(group: Any) -> bool:
    for label in group.children:
        if label.type == "switch_label" and any(c.type == "default" for c in label.children):
            return True
    return False


# --- statements ---------------------------------------------------------------

def _int_literal(node: Any, ctx: MethodContext) -> Any:
    if node is None:
        return None
    if node.type == "decimal_integer_literal":
        try:
            return int(ctx.text(node).rstrip("lL"))
        except ValueError:
            return None
    if node.type == "string_literal":
        return ctx.text(node).strip('"')
    return None


def _var_name(node: Any, ctx: MethodContext) -> Tuple[Optional[str], Optional[str]]:
    """(name, scope) of a statement reference: `ps`, `this.ps`."""
    if node is None:
        return None, None
    if node.type == "identifier":
        name = ctx.text(node)
        if name in ctx.scope.locals:
            return name, "local"
        if name in ctx.scope.fields:
            return name, "field"
        return name, "local"
    if node.type == "field_access":
        obj, fld = of._f(node, "object"), of._f(node, "field")
        if obj is not None and fld is not None and obj.type == "this":
            return ctx.text(fld), "field"
    return None, None


def _declared_statement_type(name: str, scope: str, ctx: MethodContext) -> Optional[str]:
    entry = ctx.scope.fields.get(name) if scope == "field" else ctx.scope.locals.get(name)
    if entry is None and scope == "local":
        entry = ctx.scope.fields.get(name)
    if entry is None:
        return None
    simple = entry[0]
    resolved = ctx.jf.resolve(simple) or ""
    for fqn in _ALLOC_TO_TYPE.values():
        if resolved == fqn or simple == fqn.rsplit(".", 1)[-1]:
            return fqn
    return None


def _is_param(name: str, ctx: MethodContext) -> bool:
    params = of._f(ctx.node, "parameters")
    for p in (of._named(params) if params is not None else []):
        pname = of._f(p, "name")
        if pname is not None and ctx.text(pname) == name:
            return True
    return False


def _args(invocation: Any) -> List[Any]:
    arg_node = of._f(invocation, "arguments")
    return of._code_children(arg_node, of._JAVA_COMMENT_NODES) if arg_node is not None else []


def _alloc_call(node: Any, ctx: MethodContext) -> Optional[Tuple[str, Any]]:
    """(allocation method, query node) when `node` is `x.prepareStatement(q)`."""
    if node is None or node.type != "method_invocation":
        return None
    name = of._f(node, "name")
    method = ctx.text(name) if name is not None else ""
    if method not in _ALLOC_TO_TYPE:
        return None
    args = _args(node)
    return method, (args[0] if args else None)


def _is_assigned(invocation: Any) -> bool:
    """Is this allocation the value of a declaration, assignment or resource
    (so the statement has a variable)?"""
    parent = invocation.parent
    if parent is None:
        return False
    if parent.type in ("variable_declarator", "resource"):
        return of._f(parent, "value") == invocation
    if parent.type == "assignment_expression":
        return of._f(parent, "right") == invocation
    return False


def _is_template_receiver(obj: Any, ctx: MethodContext) -> bool:
    _text, fqn, simple = of._java_receiver(obj, ctx.scope, ctx.jf)
    return bool(
        (fqn and fqn.rsplit(".", 1)[-1] in ("JdbcTemplate", "NamedParameterJdbcTemplate"))
        or simple in ("JdbcTemplate", "NamedParameterJdbcTemplate")
    )


def _is_value_arg(node: Any, ctx: MethodContext) -> bool:
    """Is an argument after a template's SQL string a bind value, rather than a
    row mapper, extractor, callback or result class?"""
    if node.type in ("lambda_expression", "method_reference", "class_literal"):
        return False
    if node.type == "object_creation_expression":
        return not of._simple_type(of._f(node, "type"), ctx.src).endswith(_TEMPLATE_CALLBACK_SUFFIXES)
    if node.type == "identifier":
        name = ctx.text(node)
        entry = ctx.scope.locals.get(name) or ctx.scope.fields.get(name)
        if entry is not None and str(entry[0]).endswith(_TEMPLATE_CALLBACK_SUFFIXES):
            return False
    return True


def statements_in_method(method_node: Any, src: bytes, ctx: Optional[MethodContext] = None) -> List[StatementFact]:
    """Every JDBC statement the method allocates, binds or executes, in source
    order. See the module docstring for what each fact holds."""
    ctx = ctx or method_context(method_node, src)
    body = of._f(method_node, "body")
    if body is None:
        return []
    nodes: List[Tuple[Any, Branch]] = []
    _walk(body, (), nodes)

    facts: List[StatementFact] = []
    live: Dict[Tuple[str, str], List[StatementFact]] = {}

    def allocate(name: str, scope: str, method: str, query: Any, line: int, branch: Branch) -> None:
        key = (name, scope)
        survivors = [f for f in live.get(key, []) if not encloses(branch, f.alloc_branch)]
        fact = StatementFact(
            var=name, scope=scope, statement_type=_ALLOC_TO_TYPE[method], alloc=method,
            alloc_line=line, alloc_branch=branch, query_expr=query,
            # A field statement is used wherever the class likes; this method
            # alone never shows the whole picture.
            complete=scope == "local",
        )
        facts.append(fact)
        live[key] = survivors + [fact]

    def targets(name: str, scope: str, branch: Branch) -> List[StatementFact]:
        key = (name, scope)
        found = [f for f in live.get(key, []) if not exclusive(f.alloc_branch, branch)]
        if found:
            return found
        stype = _declared_statement_type(name, scope, ctx)
        if stype is None:
            return []
        # Bound or executed here, allocated elsewhere (a field, a parameter, a
        # helper's return value): the allocation is not in this method.
        kind = scope if scope == "field" else ("param" if _is_param(name, ctx) else "local")
        fact = StatementFact(var=name, scope=kind, statement_type=stype, complete=False,
                             alloc_branch=branch)
        facts.append(fact)
        live[key] = live.get(key, []) + [fact]
        return [fact]

    for node, branch in nodes:
        line = node.start_point[0] + 1
        if node.type == "variable_declarator":
            alloc = _alloc_call(of._f(node, "value"), ctx)
            name = of._f(node, "name")
            if alloc and name is not None:
                allocate(ctx.text(name), "local", alloc[0], alloc[1], line, branch)
        elif node.type == "resource":
            alloc = _alloc_call(of._f(node, "value"), ctx)
            name = of._f(node, "name")
            if alloc and name is not None:
                allocate(ctx.text(name), "local", alloc[0], alloc[1], line, branch)
        elif node.type == "assignment_expression":
            alloc = _alloc_call(of._f(node, "right"), ctx)
            name, scope = _var_name(of._f(node, "left"), ctx)
            if alloc and name:
                allocate(name, scope or "local", alloc[0], alloc[1], line, branch)
        elif node.type == "method_invocation":
            name_node, obj = of._f(node, "name"), of._f(node, "object")
            method = ctx.text(name_node) if name_node is not None else ""
            args = _args(node)
            if method in _ALLOC_TO_TYPE and not _is_assigned(node):
                # Returned, passed on or chained: a statement with no variable.
                # Only a chained execution is visible here.
                parent = node.parent
                chained = (
                    parent is not None and parent.type == "method_invocation"
                    and of._f(parent, "object") == node
                    and ctx.text(of._f(parent, "name")) in _EXECUTE_METHODS
                )
                fact = StatementFact(
                    var="", scope="local", statement_type=_ALLOC_TO_TYPE[method], alloc=method,
                    alloc_line=line, alloc_branch=branch, query_expr=args[0] if args else None,
                    complete=chained,
                )
                if chained:
                    parent_args = _args(parent)
                    fact.executions.append(Execution(
                        method=ctx.text(of._f(parent, "name")), line=parent.start_point[0] + 1,
                        sql_arg=parent_args[0] if parent_args else None, branch=branch,
                    ))
                facts.append(fact)
                continue
            if method in _JDBC_TEMPLATE_METHODS and obj is not None and args and _is_template_receiver(obj, ctx):
                rest = args[1:]
                fact = StatementFact(
                    var=ctx.text(obj), scope="local", statement_type="jdbc_template",
                    alloc="jdbc_template", alloc_line=line, alloc_branch=branch,
                    query_expr=args[0], bound_by_args=any(_is_value_arg(a, ctx) for a in rest),
                )
                fact.executions.append(Execution(method=method, line=line, sql_arg=None, branch=branch))
                facts.append(fact)
                continue
            var, scope = _var_name(obj, ctx)
            if not var:
                continue
            if method in _EXECUTE_METHODS:
                for fact in targets(var, scope or "local", branch):
                    sql_arg = args[0] if args else None
                    fact.executions.append(Execution(method=method, line=line, sql_arg=sql_arg, branch=branch))
                    if fact.statement_type == "java.sql.Statement" and fact.query_expr is None and sql_arg is not None:
                        fact.query_expr = sql_arg
            elif method.startswith("set") and method not in _NON_BIND_SETTERS and len(args) >= 2:
                for fact in targets(var, scope or "local", branch):
                    if fact.statement_type not in _PREPARED_TYPES:
                        continue
                    fact.binds.append(Bind(
                        index=_int_literal(args[0], ctx), value=args[1],
                        kind=of._java_kind(args[1], ctx.scope, ctx.jf), line=line, branch=branch,
                        setter=method,
                    ))
    return facts


def statements_at(source_text: str, line: int) -> Tuple[Optional[MethodContext], List[StatementFact]]:
    """The method enclosing `line` and its statements."""
    ctx = method_at(source_text, line)
    if ctx is None:
        return None, []
    return ctx, statements_in_method(ctx.node, ctx.src, ctx)


def fact_lines(fact: StatementFact) -> List[int]:
    """Every line a statement touches: allocation, binds and executions."""
    lines = [fact.alloc_line] if fact.alloc_line else []
    lines += [b.line for b in fact.binds] + [e.line for e in fact.executions]
    return lines


# --- SAST-02-020: query classification ----------------------------------------
#
# A query expression is folded into *variants* (one per way the text can be
# built: two plain assignments, a ternary), each a list of segments: literal
# SQL text, a dynamic part (a value the method does not fix), an unknown part
# (text built by a helper or constant this method cannot see) and a
# placeholder list (`?,` repeated n times). The class follows from the
# segments: only text that can change the SQL grammar makes a query dynamic.

QUERY_CLASSES = ("fixed", "fixed_placeholders", "dynamic_value", "dynamic_identifier", "unknown")
MAX_VARIANTS = 8
MAX_FOLD_DEPTH = 12

_BUILDER_TYPES = frozenset({"StringBuilder", "StringBuffer"})
_TEXT_PRESERVING_CALLS = frozenset({
    "trim", "strip", "toUpperCase", "toLowerCase", "intern", "toString", "stripTrailing",
    "stripLeading",
})
_EXTERNAL_PREFIXES = ("java.", "javax.", "jakarta.", "org.springframework.", "org.apache.", "com.google.")
# A placeholder: `?`, `?1` (JPA positional) or `:name` (named; not a `::` cast).
_PLACEHOLDER_RE = re.compile(r"\?\d*|(?<![:\w]):[A-Za-z_]\w*")
_IDENTIFIER_TAIL_RE = re.compile(
    r"(?:\bFROM|\bJOIN|\bINTO|\bUPDATE|\bTABLE|\bORDER\s+BY|\bGROUP\s+BY|\bSELECT|\bDISTINCT|"
    r"\bWHERE|\bAND|\bOR|\bON|\bHAVING|\bSET|\bIN\s*\(|\bBY|\.)\s*$",
    re.IGNORECASE,
)
_VALUE_TAIL_RE = re.compile(
    r"(?:=|<|>|<>|!=|\+|-|\*|/|%|\bLIKE|\bBETWEEN|\bTHEN|\bELSE|\bWHEN|\bLIMIT|\bOFFSET|\bTOP|"
    r"\bVALUES\s*\(|\bIS)\s*$",
    re.IGNORECASE,
)
_PLACEHOLDER_ONLY_RE = re.compile(r"^[\s?,]*\?[\s?,]*$")


@dataclass
class Lit:
    text: str


@dataclass
class Dyn:
    node: Any
    kind: str
    param_index: Optional[int] = None
    origin: Optional[str] = None


@dataclass
class Unk:
    resolver: str
    node: Any = None


@dataclass
class PList:
    count: str


@dataclass
class DynamicPart:
    text: str
    kind: str
    position: str  # value | identifier
    line: int
    param_index: Optional[int] = None
    origin: Optional[str] = None


@dataclass
class QueryClass:
    kind: str
    dynamic_parts: List[DynamicPart] = field(default_factory=list)
    unknown: List[str] = field(default_factory=list)  # what would resolve each unknown part
    placeholders: int = 0  # the most placeholders any variant has
    placeholder_list: Optional[str] = None  # the count expression of a `?,` list
    variants: List[str] = field(default_factory=list)  # each variant's template, parts as {n}

    @property
    def is_fixed(self) -> bool:
        return self.kind in ("fixed", "fixed_placeholders")

    @property
    def resolver(self) -> Optional[str]:
        return self.unknown[0] if self.unknown else None


Variant = List[Any]  # segments


def _literal_text(node: Any, ctx: MethodContext) -> str:
    raw = ctx.text(node)
    if node.type == "text_block":
        body = raw[3:-3]
    elif node.type == "character_literal":
        body = raw[1:-1]
    else:
        body = raw[1:-1] if len(raw) >= 2 else ""
    return body.replace('\\"', '"').replace("\\'", "'").replace("\\n", "\n").replace("\\t", "\t")


def _product(left: List[Variant], right: List[Variant]) -> List[Variant]:
    out = [a + b for a in left for b in right]
    return out[:MAX_VARIANTS] if len(out) > MAX_VARIANTS else out


def _param_index(name: str, ctx: MethodContext) -> Optional[int]:
    params = of._f(ctx.node, "parameters")
    for position, p in enumerate(of._named(params) if params is not None else []):
        pname = of._f(p, "name")
        if pname is not None and ctx.text(pname) == name:
            return position
    return None


@dataclass
class _Defs:
    """How a local variable gets its value before a use: plain definitions
    (initializer or `=`), `+=` appends, and builder `append` calls."""

    plain: List[Any] = field(default_factory=list)
    appends: List[Tuple[Any, Branch]] = field(default_factory=list)
    escapes: List[str] = field(default_factory=list)  # helpers the builder was handed to


class QueryFolder:
    """Folds query expressions within one method. `constants` resolves a
    constant of another class (`Other.NAME`) to its literal text, or None;
    without it such constants are `unknown`, never assumed constant."""

    def __init__(self, ctx: MethodContext, constants: Optional[Any] = None) -> None:
        self.ctx = ctx
        self.constants = constants
        # Lines whose code contributed to a folded query: the declaration and
        # appends of `sql`, not only the statement line it is executed on.
        self.touched: set = set()
        body = of._f(ctx.node, "body")
        self.nodes: List[Tuple[Any, Branch]] = []
        if body is not None:
            _walk(body, (), self.nodes)

    # definitions -------------------------------------------------------------

    def _defs(self, name: str, before: int) -> _Defs:
        ctx = self.ctx
        defs = _Defs()
        for node, branch in self.nodes:
            if node.start_byte >= before:
                break
            if node.type == "variable_declarator":
                ident, value = of._f(node, "name"), of._f(node, "value")
                if ident is not None and ctx.text(ident) == name and value is not None:
                    defs.plain = [value]
                    defs.appends = []
            elif node.type == "assignment_expression":
                left, right = of._f(node, "left"), of._f(node, "right")
                if left is None or right is None or left.type != "identifier" or ctx.text(left) != name:
                    continue
                op = of._f(node, "operator")
                if op is not None and op.type == "+=":
                    defs.appends.append((right, branch))
                else:
                    # A plain reassignment at the same level replaces what came
                    # before; inside a branch it is an alternative.
                    defs.plain = [right] if not branch else defs.plain + [right]
                    if not branch:
                        defs.appends = []
            elif node.type == "method_invocation":
                obj, mname = of._f(node, "object"), of._f(node, "name")
                if obj is not None and obj.type == "identifier" and ctx.text(obj) == name and mname is not None:
                    method = ctx.text(mname)
                    if method in ("append", "insert"):
                        args = _args(node)
                        if args:
                            defs.appends.append((args[-1], branch))
                    continue
                for arg in _args(node):
                    if arg.type == "identifier" and ctx.text(arg) == name and mname is not None:
                        defs.escapes.append(ctx.text(mname))
        return defs

    def _builder_appends(self, defs: _Defs, depth: int) -> List[Variant]:
        variants: List[Variant] = [[]]
        for node, branch in defs.appends:
            folded = self.fold(node, depth + 1)
            in_loop = any(arm == "loop" for _id, arm in branch)
            if in_loop and all(
                all(isinstance(s, Lit) and _PLACEHOLDER_ONLY_RE.match(s.text) for s in v) for v in folded
            ):
                variants = _product(variants, [[PList(self._loop_count(branch))]])
                continue
            variants = _product(variants, folded)
        return variants

    def _loop_count(self, branch: Branch) -> str:
        loop_ids = [node_id for node_id, arm in branch if arm == "loop"]
        for node, _b in self.nodes:
            if loop_ids and node.id == loop_ids[-1]:
                cond = of._f(node, "condition") or of._f(node, "value")
                return " ".join(self.ctx.text(cond).split()) if cond is not None else "loop"
        return "loop"

    # folding ------------------------------------------------------------------

    def fold(self, node: Any, depth: int = 0) -> List[Variant]:
        ctx = self.ctx
        if node is None:
            return [[Unk("missing expression")]]
        if depth > MAX_FOLD_DEPTH:
            return [[Unk("expression too deep to fold", node)]]
        self.touched.update(range(node.start_point[0] + 1, node.end_point[0] + 2))
        t = node.type
        if t in ("string_literal", "text_block", "character_literal"):
            return [[Lit(_literal_text(node, ctx))]]
        if t in of._JAVA_LITERALS:
            return [[Lit(ctx.text(node))]]
        if t == "parenthesized_expression":
            inner = of._code_children(node, of._JAVA_COMMENT_NODES)
            return self.fold(inner[0], depth + 1) if inner else [[Unk("empty expression")]]
        if t == "cast_expression":
            return self.fold(of._f(node, "value"), depth + 1)
        if t == "binary_expression":
            op = of._f(node, "operator")
            if op is not None and op.type == "+":
                return _product(self.fold(of._f(node, "left"), depth + 1),
                                self.fold(of._f(node, "right"), depth + 1))
            return [[self._dyn(node)]]
        if t == "ternary_expression":
            out = self.fold(of._f(node, "consequence"), depth + 1) + self.fold(of._f(node, "alternative"), depth + 1)
            return out[:MAX_VARIANTS]
        if t == "identifier":
            return self._fold_identifier(node, depth)
        if t == "field_access":
            return self._fold_field_access(node, depth)
        if t == "method_invocation":
            return self._fold_call(node, depth)
        if t == "object_creation_expression":
            tname = of._simple_type(of._f(node, "type"), ctx.src)
            args = _args(node)
            if tname == "String" or tname in _BUILDER_TYPES:
                if not args or (tname in _BUILDER_TYPES and of._java_kind(args[0], ctx.scope, ctx.jf) == "numeric"):
                    return [[]]
                return self.fold(args[0], depth + 1)
        return [[self._dyn(node)]]

    def _dyn(self, node: Any) -> Dyn:
        ctx = self.ctx
        kind = of._java_kind(node, ctx.scope, ctx.jf)
        index = _param_index(ctx.text(node), ctx) if node.type == "identifier" else None
        return Dyn(node=node, kind=kind, param_index=index, origin=of.value_origin(node, ctx.scope, ctx.jf))

    def _fold_identifier(self, node: Any, depth: int) -> List[Variant]:
        ctx = self.ctx
        name = ctx.text(node)
        if name in ctx.scope.locals:
            stype, _init, _final = ctx.scope.locals[name]
            if _param_index(name, ctx) is not None:
                return [[self._dyn(node)]]
            defs = self._defs(name, node.start_byte)
            if defs.escapes and stype in _BUILDER_TYPES:
                # The builder was handed to a helper that may append anything.
                return [[Unk(defs.escapes[0], node)]]
            if not defs.plain and not defs.appends:
                return [[self._dyn(node)]]
            base: List[Variant] = [[]]
            if defs.plain:
                base = []
                for value in defs.plain:
                    base.extend(self.fold(value, depth + 1))
                base = base[:MAX_VARIANTS]
            return _product(base, self._builder_appends(defs, depth))
        if name in ctx.scope.fields:
            _type, init, _final, static_final = ctx.scope.fields[name]
            if static_final and init is not None:
                return self.fold(init, depth + 1)
            return [[self._dyn(node)]]
        # Not declared here: a constant inherited or statically imported.
        if self.constants is not None:
            text = self.constants(None, name)
            if text is not None:
                return [[Lit(text)]]
        return [[Unk(name, node)]]

    def _fold_field_access(self, node: Any, depth: int) -> List[Variant]:
        ctx = self.ctx
        obj, fld = of._f(node, "object"), of._f(node, "field")
        if obj is None or fld is None:
            return [[self._dyn(node)]]
        oname, fname = ctx.text(obj), ctx.text(fld)
        if oname in ("this", ctx.scope.class_simple) and fname in ctx.scope.fields:
            _type, init, _final, static_final = ctx.scope.fields[fname]
            if static_final and init is not None:
                return self.fold(init, depth + 1)
            return [[self._dyn(node)]]
        if obj.type == "identifier" and oname in ctx.jf.enum_types:
            return [[self._dyn(node)]]
        if obj.type == "identifier" and oname[:1].isupper():
            if self.constants is not None:
                text = self.constants(oname, fname)
                if text is not None:
                    return [[Lit(text)]]
            if (ctx.jf.resolve(oname) or "").startswith(_EXTERNAL_PREFIXES):
                return [[self._dyn(node)]]
            return [[Unk(f"{oname}.{fname}", node)]]
        return [[self._dyn(node)]]

    def _fold_call(self, node: Any, depth: int) -> List[Variant]:
        ctx = self.ctx
        name_node, obj = of._f(node, "name"), of._f(node, "object")
        method = ctx.text(name_node) if name_node is not None else ""
        args = _args(node)
        oname = ctx.text(obj) if obj is not None else ""
        if oname in ("String", "MessageFormat") and method == "format" and args:
            return self._fold_format(args[0], args[1:], depth, message_format=oname == "MessageFormat")
        if oname == "String" and method == "join" and len(args) >= 2:
            return self._fold_join(args, depth)
        if oname == "String" and method == "valueOf" and len(args) == 1:
            return self.fold(args[0], depth + 1)
        if obj is not None and method == "repeat" and len(args) == 1:
            folded = self.fold(obj, depth + 1)
            if all(all(isinstance(s, Lit) and _PLACEHOLDER_ONLY_RE.match(s.text) for s in v) for v in folded):
                return [[PList(ctx.text(args[0]))]]
            return [[self._dyn(node)]]
        if obj is not None and method == "concat" and len(args) == 1:
            return _product(self.fold(obj, depth + 1), self.fold(args[0], depth + 1))
        if obj is not None and method in _TEXT_PRESERVING_CALLS and not args:
            return self.fold(obj, depth + 1)
        if obj is not None and method in ("substring", "replaceAll", "replace", "replaceFirst"):
            # Trimming or rewriting folded text keeps its segments; the
            # rewrite's own arguments are constants or dynamic parts.
            out = self.fold(obj, depth + 1)
            for arg in args:
                if not of._folded_constant(arg, ctx.scope, ctx.jf) and of._java_kind(arg, ctx.scope, ctx.jf) != "numeric":
                    out = _product(out, [[self._dyn(arg)]])
            return out
        kind = of._java_kind(node, ctx.scope, ctx.jf)
        if kind == "numeric":
            return [[self._dyn(node)]]
        resolver = self._project_helper(obj, method)
        if resolver is not None:
            return [[Unk(resolver, node)]]
        return [[self._dyn(node)]]

    def _project_helper(self, obj: Any, method: str) -> Optional[str]:
        """The `Type.method` a call's text would be resolved from, when the
        callee is plausibly a project query-building helper: a call on this
        class, a static call on a project type. A call on an object variable
        (a DTO getter, a request accessor) is a dynamic value, not a helper —
        so `prepareStatement("..." + msg.getPortID())` stays dynamic text."""
        ctx = self.ctx
        if obj is None or obj.type in ("this", "super"):
            owner = ctx.scope.class_simple or "this"
            return f"{owner}.{method}"
        if obj.type == "identifier":
            oname = ctx.text(obj)
            if oname in ctx.scope.locals or oname in ctx.scope.fields:
                return None
            if oname[:1].isupper() and not (ctx.jf.resolve(oname) or "").startswith(_EXTERNAL_PREFIXES):
                return f"{oname}.{method}"
        return None

    def _fold_format(self, fmt: Any, args: List[Any], depth: int, *, message_format: bool) -> List[Variant]:
        folded = self.fold(fmt, depth + 1)
        if len(folded) != 1 or not all(isinstance(s, Lit) for s in folded[0]):
            return [[Unk("format string is not a constant", fmt)]]
        text = "".join(s.text for s in folded[0])
        spec = r"\{(\d+)[^}]*\}" if message_format else r"%(?:(\d+)\$)?[-#+ 0,(]*\d*(?:\.\d+)?[a-zA-Z%]"
        out: List[Variant] = [[]]
        cursor, auto = 0, 0
        for m in re.finditer(spec, text):
            out = _product(out, [[Lit(text[cursor:m.start()])]])
            cursor = m.end()
            if not message_format and m.group(0) in ("%%", "%n"):
                out = _product(out, [[Lit("%" if m.group(0) == "%%" else "\n")]])
                continue
            if m.group(1):
                index = int(m.group(1)) - (0 if message_format else 1)
            else:
                index, auto = auto, auto + 1
            out = _product(out, self.fold(args[index], depth + 1) if 0 <= index < len(args)
                           else [[Unk("format argument missing", fmt)]])
        return _product(out, [[Lit(text[cursor:])]])

    def _fold_join(self, args: List[Any], depth: int) -> List[Variant]:
        ctx = self.ctx
        sep = self.fold(args[0], depth + 1)
        items = args[1:]
        if len(items) == 1 and items[0].type == "method_invocation":
            inner = items[0]
            iname = of._f(inner, "name")
            inner_args = _args(inner)
            if iname is not None and ctx.text(iname) == "nCopies" and len(inner_args) == 2:
                copy = self.fold(inner_args[1], depth + 1)
                if all(all(isinstance(s, Lit) and _PLACEHOLDER_ONLY_RE.match(s.text) for s in v) for v in copy):
                    return [[PList(ctx.text(inner_args[0]))]]
        out: List[Variant] = [[]]
        for position, item in enumerate(items):
            if position:
                out = _product(out, sep)
            out = _product(out, self.fold(item, depth + 1))
        return out


def _quote_open(text: str) -> bool:
    return text.replace("''", "").count("'") % 2 == 1


def _position(before: str) -> str:
    """Where a dynamic part sits, from the literal SQL before it: inside a
    quoted literal or after an operator is a *value*; after a keyword that
    introduces a table, column, condition or list (FROM, ORDER BY, WHERE,
    IN (, a select-list comma), or with nothing before it, an *identifier*
    position that can carry SQL grammar."""
    if _quote_open(before):
        return "value"
    tail = before.rstrip()
    if not tail:
        return "identifier"
    if _IDENTIFIER_TAIL_RE.search(tail):
        return "identifier"
    if _VALUE_TAIL_RE.search(tail):
        return "value"
    if tail.endswith(("(", ",")):
        upper = tail.upper()
        values_at = upper.rfind("VALUES")
        if values_at >= 0 and upper.count("(", values_at) > upper.count(")", values_at):
            return "value"
        return "identifier"
    return "identifier"


def _count_placeholders(text: str) -> int:
    # Strip quoted SQL literals before counting: a `?` inside '...' is data.
    stripped, quoted = [], False
    for ch in text:
        if ch == "'":
            quoted = not quoted
        elif not quoted:
            stripped.append(ch)
    return len(_PLACEHOLDER_RE.findall("".join(stripped)))


def classify_query(query_expr: Any, method_ctx: MethodContext, *, constants: Optional[Any] = None,
                   folder: Optional[QueryFolder] = None) -> QueryClass:
    """Classify the text a statement executes (see QUERY_CLASSES). A numeric
    value is still a `dynamic_value` here; its kind travels in `dynamic_parts`
    and the SQL validator decides what it means."""
    folder = folder or QueryFolder(method_ctx, constants)
    variants = folder.fold(query_expr)
    parts: List[DynamicPart] = []
    unknown: List[str] = []
    templates: List[str] = []
    placeholders = 0
    plist: Optional[str] = None
    seen_parts = set()
    for variant in variants:
        text, template = "", ""
        for seg in variant:
            if isinstance(seg, Lit):
                text += seg.text
                template += seg.text
            elif isinstance(seg, PList):
                plist = plist or seg.count
                text += "?"
                template += "?…"
            elif isinstance(seg, Unk):
                if seg.resolver not in unknown:
                    unknown.append(seg.resolver)
                template += "{?}"
            else:
                key = (seg.node.start_byte, seg.node.end_byte)
                template += f"{{{len(parts)}}}"
                if key not in seen_parts:
                    seen_parts.add(key)
                    parts.append(DynamicPart(
                        text=" ".join(method_ctx.text(seg.node).split())[:200], kind=seg.kind,
                        position=_position(text), line=seg.node.start_point[0] + 1,
                        param_index=seg.param_index, origin=seg.origin,
                    ))
                text += "\x00"
        placeholders = max(placeholders, _count_placeholders(text.replace("\x00", "")))
        templates.append(template)
    if parts:
        kind = "dynamic_identifier" if any(p.position == "identifier" for p in parts) else "dynamic_value"
    elif unknown:
        kind = "unknown"
    elif placeholders or plist:
        kind = "fixed_placeholders"
    else:
        kind = "fixed"
    return QueryClass(kind=kind, dynamic_parts=parts, unknown=unknown, placeholders=placeholders,
                      placeholder_list=plist, variants=templates)


# --- binding coverage -----------------------------------------------------------

def _arms(node: Any) -> Optional[List[str]]:
    """Every arm of a branching node, or None when one path takes no arm at all
    (an `if` without `else`, a `switch` without `default`, any loop)."""
    if node.type == "if_statement":
        return ["then", "else"] if of._f(node, "alternative") is not None else None
    if node.type == "switch_block":
        groups = [(i, c) for i, c in enumerate(node.children)
                  if c.type in ("switch_block_statement_group", "switch_rule")]
        if not any(_switch_default(c) for _i, c in groups):
            return None
        return ["default" if _switch_default(c) else f"case{i}" for i, c in groups]
    return None


def _nodes_by_id(ctx: MethodContext) -> Dict[int, Any]:
    out: Dict[int, Any] = {}
    stack = [ctx.node]
    while stack:
        n = stack.pop()
        out[n.id] = n
        stack.extend(n.children)
    return out


def _covered(prefix: Branch, binds: List[Bind], by_id: Dict[int, Any]) -> bool:
    """Does every run through `prefix` pass one of `binds`? Directly, when a
    bind sits at this level (or an enclosing one); otherwise when some branch
    node right below has a bind on every one of its arms."""
    if any(encloses(b.branch, prefix) for b in binds):
        return True
    below: Dict[int, set] = {}
    for b in binds:
        if len(b.branch) > len(prefix) and b.branch[: len(prefix)] == prefix:
            node_id, arm = b.branch[len(prefix)]
            below.setdefault(node_id, set()).add(arm)
    for node_id in below:
        node = by_id.get(node_id)
        arms = _arms(node) if node is not None else None
        if arms and all(_covered(prefix + ((node_id, arm),), binds, by_id) for arm in arms):
            return True
    return False


def unbound_placeholders(fact: StatementFact, qc: QueryClass, ctx: MethodContext) -> List[str]:
    """What is not bound before some execution: placeholder indexes (or the
    placeholder list) without a bind on every path that reaches it. Empty when
    every placeholder is bound for every execution."""
    if fact.alloc == "jdbc_template":
        return [] if (qc.placeholders == 0 and not qc.placeholder_list) or fact.bound_by_args else ["the template's bind arguments"]
    by_id = _nodes_by_id(ctx)
    missing: List[str] = []
    for execution in fact.executions:
        if execution.has_sql_arg:
            continue
        before = [b for b in fact.binds if b.line <= execution.line and not exclusive(b.branch, execution.branch)]
        computed = [b for b in before if not isinstance(b.index, int)]
        literal = qc.placeholders - (1 if qc.placeholder_list else 0)
        if qc.placeholder_list:
            if not any(any(arm == "loop" for _id, arm in b.branch) for b in computed):
                missing.append(f"the placeholder list before {execution.method} at line {execution.line}")
            computed = [b for b in computed if not any(arm == "loop" for _id, arm in b.branch)]
        if computed and not any(isinstance(b.index, int) for b in before):
            # Indexes computed as `i++`: count the binds on the execution's path.
            if len([b for b in computed if encloses(b.branch, execution.branch)]) < literal:
                missing.append(f"{literal} placeholders, fewer binds before line {execution.line}")
            continue
        for index in range(1, literal + 1):
            binds = [b for b in before if b.index == index]
            if not _covered(execution.branch, binds, by_id):
                missing.append(f"index {index} before {execution.method} at line {execution.line}")
    return missing

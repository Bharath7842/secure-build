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

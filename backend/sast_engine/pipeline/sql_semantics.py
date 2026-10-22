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


def _is_append_link(node: Any, ctx: MethodContext) -> bool:
    if node.type != "method_invocation":
        return False
    name = of._f(node, "name")
    return name is not None and ctx.text(name) in ("append", "insert")


def _append_chain_root(node: Any, ctx: MethodContext) -> Optional[Any]:
    """The receiver an `append` chain starts from (`sb` in `sb.append(a).append(b)`)."""
    if not _is_append_link(node, ctx):
        return None
    obj = of._f(node, "object")
    while obj is not None and _is_append_link(obj, ctx):
        obj = of._f(obj, "object")
    return obj


def _append_links(node: Any, ctx: MethodContext) -> List[Any]:
    """The links of an append chain, innermost (first appended) first."""
    links = []
    while node is not None and _is_append_link(node, ctx):
        links.append(node)
        node = of._f(node, "object")
    return list(reversed(links))


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
    text: str = ""  # the expression's source, kept because summaries carry
    line: int = 0   # segments out of the method (and file) that made them


@dataclass
class Param:
    """A summary's placeholder for "the text of argument `index`", filled in
    with the caller's own folded argument at each call site."""

    index: int
    kind: str = ""  # how the callee uses the argument (`string_var`: as text)


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
    # Helpers the builder was handed to: (method name, call node, argument index).
    escapes: List[Tuple[str, Any, int]] = field(default_factory=list)


class QueryFolder:
    """Folds query expressions within one method. `constants` resolves a
    constant of another class (`Other.NAME`) to its literal text, or None;
    without it such constants are `unknown`, never assumed constant. `calls`
    (method summaries, SAST-02-050) folds what a project helper returns, or
    appends to a builder it is handed; without it a helper is `unknown`."""

    def __init__(self, ctx: MethodContext, constants: Optional[Any] = None, calls: Optional[Any] = None) -> None:
        self.ctx = ctx
        self.constants = constants
        self.calls = calls
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
                root = _append_chain_root(node, ctx)
                if root is not None and root.type == "identifier" and ctx.text(root) == name and mname is not None:
                    # `sb.append(a).append(b)`: every link is an append to `sb`;
                    # the walk visits the outer link first, so record in order.
                    if node.parent is None or not _is_append_link(node.parent, ctx):
                        for link in _append_links(node, ctx):
                            args = _args(link)
                            if args:
                                defs.appends.append((args[-1], branch))
                    continue
                if obj is not None and obj.type == "identifier" and ctx.text(obj) == name and mname is not None:
                    continue
                for index, arg in enumerate(_args(node)):
                    if arg.type == "identifier" and ctx.text(arg) == name and mname is not None:
                        defs.escapes.append((ctx.text(mname), node, index))
        return defs

    def fold_param_appends(self, name: str) -> List[Variant]:
        """What the method appends to its builder parameter `name`."""
        defs = self._defs(name, self.ctx.node.end_byte)
        if defs.escapes:
            return self._escaped(defs, 0) or [[Unk(defs.escapes[0][0])]]
        return self._builder_appends(defs, 0)

    def _escaped(self, defs: _Defs, depth: int) -> Optional[List[Variant]]:
        """What helpers append to a builder they were handed, in call order;
        None when any of them cannot be resolved."""
        if self.calls is None:
            return None
        out: List[Variant] = [[]]
        for _name, call, index in defs.escapes:
            appended = self.calls.escape_variants(call, index, self)
            if appended is None:
                return None
            out = _product(out, appended)
        return out

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
        if t in ("array_initializer", "array_creation_expression"):
            init = of._f(node, "value") if t == "array_creation_expression" else node
            items = of._code_children(init, of._JAVA_COMMENT_NODES) if init is not None else []
            constant = self._constant_elements(items, depth) if init is not None else None
            if constant is not None:
                return constant
        if t == "object_creation_expression":
            tname = of._simple_type(of._f(node, "type"), ctx.src)
            args = _args(node)
            if tname == "String" or tname in _BUILDER_TYPES:
                if not args or (tname in _BUILDER_TYPES and of._java_kind(args[0], ctx.scope, ctx.jf) == "numeric"):
                    return [[]]
                return self.fold(args[0], depth + 1)
        return [[self._dyn(node)]]

    def _dyn(self, node: Any, kind: Optional[str] = None) -> Dyn:
        ctx = self.ctx
        kind = kind or of._java_kind(node, ctx.scope, ctx.jf)
        index = _param_index(ctx.text(node), ctx) if node.type == "identifier" else None
        return Dyn(node=node, kind=kind, param_index=index, origin=of.value_origin(node, ctx.scope, ctx.jf),
                   text=" ".join(ctx.text(node).split())[:200], line=node.start_point[0] + 1)

    def _fold_identifier(self, node: Any, depth: int) -> List[Variant]:
        ctx = self.ctx
        name = ctx.text(node)
        if name in ctx.scope.locals:
            stype, _init, _final = ctx.scope.locals[name]
            if _param_index(name, ctx) is not None:
                return [[self._dyn(node)]]
            defs = self._defs(name, node.start_byte)
            escaped: List[Variant] = [[]]
            if defs.escapes and stype in _BUILDER_TYPES:
                # The builder was handed to helpers: what they append is known
                # only from their summaries.
                resolved = self._escaped(defs, depth)
                if resolved is None:
                    return [[Unk(defs.escapes[0][0], node)]]
                escaped = resolved
            if not defs.plain and not defs.appends and escaped == [[]]:
                iterable = self._loop_iterable(name, node.start_byte)
                if iterable is not None:
                    return self._elements(iterable, depth)
                return [[self._dyn(node)]]
            base: List[Variant] = [[]]
            if defs.plain:
                base = []
                for value in defs.plain:
                    base.extend(self.fold(value, depth + 1))
                base = base[:MAX_VARIANTS]
            # Appends made here and appends made by helpers are merged in no
            # particular order; the grammar positions they produce are kept.
            return _product(_product(base, self._builder_appends(defs, depth)), escaped)
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

    def _loop_iterable(self, name: str, before: int) -> Optional[Any]:
        """The collection `name` iterates in `for (T name : collection)`."""
        found = None
        for node, _branch in self.nodes:
            if node.start_byte >= before:
                break
            if node.type == "enhanced_for_statement":
                ident = of._f(node, "name")
                if ident is not None and self.ctx.text(ident) == name:
                    found = of._f(node, "value")
        return found

    def _elements(self, collection: Any, depth: int) -> List[Variant]:
        """The text of one element of `collection`: the elements of a constant
        array or list are constants (a generated DAO's column names); an
        element of a parameter is that parameter used as text."""
        folded = self.fold(collection, depth + 1)
        return [[Dyn(s.node, "string_var", s.param_index, s.origin, s.text, s.line)
                 if isinstance(s, Dyn) and s.kind == "object" else s for s in v] for v in folded]

    def _constant_elements(self, items: List[Any], depth: int) -> Optional[List[Variant]]:
        texts = []
        for item in items:
            folded = self.fold(item, depth + 1)
            if len(folded) != 1 or not all(isinstance(seg, Lit) for seg in folded[0]):
                return None
            texts.append("".join(seg.text for seg in folded[0]))
        return [[Lit(",".join(texts))]]

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
        if (oname, method) in (("List", "of"), ("Arrays", "asList"), ("Set", "of")) and args:
            constant = self._constant_elements(args, depth)
            if constant is not None:
                return constant
        if obj is not None and method == "repeat" and len(args) == 1:
            folded = self.fold(obj, depth + 1)
            if all(all(isinstance(s, Lit) and _PLACEHOLDER_ONLY_RE.match(s.text) for s in v) for v in folded):
                return [[PList(ctx.text(args[0]))]]
            return [[self._dyn(node)]]
        if obj is not None and method in ("append", "insert") and args and self._is_builder(obj):
            # `new StringBuilder("...").append(x)`, `return sb.append(x)`: the
            # builder's text so far (definitions before this call), then x.
            return _product(self.fold(obj, depth + 1), self.fold(args[-1], depth + 1))
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
        if self.calls is not None:
            summarised = self.calls.call_variants(node, self)
            if summarised is not None:
                return summarised
        resolver = self._project_helper(obj, method)
        if resolver is not None:
            return [[Unk(resolver, node)]]
        return [[self._dyn(node)]]

    def _is_builder(self, expr: Any) -> bool:
        """Is `expr` a StringBuilder/StringBuffer (a variable, a `new`, or an
        append chain on one)?"""
        ctx = self.ctx
        while expr is not None and _is_append_link(expr, ctx):
            expr = of._f(expr, "object")
        if expr is None:
            return False
        if expr.type == "object_creation_expression":
            return of._simple_type(of._f(expr, "type"), ctx.src) in _BUILDER_TYPES
        if expr.type == "identifier":
            entry = ctx.scope.locals.get(ctx.text(expr)) or ctx.scope.fields.get(ctx.text(expr))
            return bool(entry) and entry[0] in _BUILDER_TYPES
        return False

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
            folded = self.fold(item, depth + 1)
            if len(items) == 1:
                # Joining a collection: its elements' text, not the object.
                folded = [[Dyn(s.node, "string_var", s.param_index, s.origin, s.text, s.line)
                           if isinstance(s, Dyn) and s.kind == "object" else s for s in v] for v in folded]
            out = _product(out, folded)
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
    return classify_variants(folder.fold(query_expr))


def classify_variants(variants: List[Variant]) -> QueryClass:
    """`classify_query` for already-folded variants."""
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
            elif isinstance(seg, Param):
                # A bare summary template (never seen at a call site).
                template += f"{{param{seg.index}}}"
                text += "\x00"
            else:
                key = (seg.text, seg.line, seg.kind)
                template += f"{{{len(parts)}}}"
                if key not in seen_parts:
                    seen_parts.add(key)
                    parts.append(DynamicPart(
                        text=seg.text, kind=seg.kind, position=_position(text), line=seg.line,
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


# --- judging one statement ----------------------------------------------------------
#
# The decision the `sql_binding` validator reports and a method summary
# aggregates. Kept here, with the facts, so the two can never disagree.

# Dynamic parts that can carry SQL grammar. Numeric parts are judged on their
# own; enum, boolean and object parts give no judgement.
TEXT_KINDS = frozenset({"string_var", "call_result", "unknown"})
POSITIVE_JUDGEMENTS = frozenset({"dynamic_text", "second_order", "misuse_dynamic"})
NEGATIVE_JUDGEMENTS = frozenset({"fixed_bound", "numeric_only", "misuse_constant", "statement_constant",
                                 "callee_no_sql"})
GAP_JUDGEMENTS = frozenset({"unknown", "incomplete"})


def is_text_kind(kind: str) -> bool:
    return any(k in TEXT_KINDS for k in str(kind).split("+"))


@dataclass
class Judgement:
    """What one statement (or one call into a summarised method) does with
    SQL text. `tag` is one of the *_JUDGEMENTS sets above, or `unbound` (a
    placeholder without a bind on some path), `no_text` (only enum/boolean
    parts), `wrapper_constant` (a wrapper called with constants) or `none`."""

    tag: str
    line: int = 0
    qc: Optional[QueryClass] = None
    parts: List[DynamicPart] = field(default_factory=list)
    missing: Optional[str] = None
    detail: str = ""  # proof material: binds, the callee, the field
    fact: Optional[StatementFact] = None
    execution: Optional[Execution] = None
    callee: Optional[str] = None


def _judge_text(qc: QueryClass, line: int, *, misuse: bool) -> Optional[Judgement]:
    text_parts = [p for p in qc.dynamic_parts if is_text_kind(p.kind)]
    if text_parts:
        persisted = [p for p in text_parts if p.origin == "persisted"]
        if persisted and not misuse:
            return Judgement("second_order", line, qc, persisted)
        return Judgement("misuse_dynamic" if misuse else "dynamic_text", line, qc, text_parts)
    if qc.unknown:
        return Judgement("unknown", line, qc, missing=(
            f"the SQL text at line {line} depends on `{qc.resolver}`, whose value is not resolved"
        ))
    if qc.dynamic_parts and all(p.kind == "numeric" for p in qc.dynamic_parts):
        return Judgement("numeric_only", line, qc, list(qc.dynamic_parts))
    if qc.dynamic_parts:
        return Judgement("no_text", line, qc)
    return None


def binds_text(fact: StatementFact) -> str:
    if fact.alloc == "jdbc_template":
        return "bound through the template's arguments"
    binds = [f"{b.index if b.index is not None else '?'} with {b.setter} (line {b.line})" for b in fact.binds[:3]]
    return "bound: " + "; ".join(binds) if binds else "no placeholders to bind"


def incomplete_reason(fact: StatementFact, ctx: MethodContext) -> str:
    owner = ctx.scope.class_simple or "the class"
    if not fact.var:
        return (f"the statement prepared at line {fact.alloc_line} is returned or passed on; its binds "
                "and executions are in code that is not summarised")
    where = {"field": f"a field of {owner}", "param": "a method parameter"}.get(
        fact.scope, "allocated by another method")
    return (f"statement `{fact.var}` is {where}: its allocation, binds or executions are in other "
            "methods, which are not summarised")


def judge_statement(fact: StatementFact, ctx: MethodContext, folder: QueryFolder,
                    *, fields: Optional[Any] = None) -> Judgement:
    """Judge one statement: the texts it runs, then its binding. `fields`
    (`SqlSummaries.field_judgement`) completes a statement held in a field."""
    query_line = fact.alloc_line or (fact.executions[0].line if fact.executions else 0)
    qc: Optional[QueryClass] = None
    # A text that is unsafe or unresolved decides at once; a numeric-only
    # judgement waits until every text the statement runs has been checked.
    numeric: Optional[Judgement] = None
    if fact.query_expr is not None and fact.statement_type != "java.sql.Statement":
        qc = classify_query(fact.query_expr, ctx, folder=folder)
        verdict = _judge_text(qc, query_line, misuse=False)
        if verdict is not None and verdict.tag != "numeric_only":
            if verdict.tag != "no_text":
                verdict.fact = fact
                return verdict
        else:
            numeric = numeric or verdict
    misuse_constant: Optional[int] = None
    for execution in fact.executions:
        if not execution.has_sql_arg:
            continue
        exec_qc = classify_query(execution.sql_arg, ctx, folder=folder)
        verdict = _judge_text(exec_qc, execution.line, misuse=fact.api_misuse)
        if verdict is not None and verdict.tag not in ("numeric_only", "no_text"):
            verdict.fact, verdict.execution = fact, execution
            return verdict
        numeric = numeric or (verdict if verdict is not None and verdict.tag == "numeric_only" else None)
        if fact.api_misuse and verdict is None:
            misuse_constant = execution.line
    if numeric is not None:
        numeric.fact = fact
        return numeric
    if not fact.complete:
        if fact.scope == "field" and fields is not None:
            joined = fields(ctx, fact)
            if joined is not None:
                return joined
        return Judgement("incomplete", query_line, qc, missing=incomplete_reason(fact, ctx), fact=fact)
    if misuse_constant is not None:
        return Judgement("misuse_constant", misuse_constant, qc, fact=fact)
    if fact.statement_type == "java.sql.Statement":
        if not any(e.has_sql_arg for e in fact.executions):
            return Judgement("none", query_line, fact=fact)
        return Judgement("statement_constant", fact.executions[0].line, fact=fact)
    if qc is None or not fact.executions:
        return Judgement("none", query_line, qc, fact=fact)
    if qc.dynamic_parts:
        return Judgement("no_text", query_line, qc, fact=fact)
    if unbound_placeholders(fact, qc, ctx):
        return Judgement("unbound", query_line, qc, fact=fact)
    return Judgement("fixed_bound", query_line, qc, fact=fact, execution=fact.executions[0],
                     detail=binds_text(fact))


# --- SAST-02-050: method summaries -----------------------------------------------------
#
# A method is summarised once per scan — does it execute SQL, with fixed or
# dynamic text, which of its parameters reach SQL text versus a bind, and what
# SQL text it returns or appends to a builder it is handed — and that summary
# stands in for the method at every call. Calls resolve through the call graph
# by resolved receiver and signature (`call_graph.resolve_targets`), never by
# name: a facade is the union of its implementations, overloads stay apart.
# Summaries are demand-driven (only what a finding or rule derivation asks
# about), bounded in depth and time; past a bound, or around a recursion
# cycle, a method is `unknown` and names why.

SUMMARY_MAX_DEPTH = 6
SUMMARY_TIME_BUDGET_SECONDS = 120.0
_EXECUTES_RANK = {"dynamic": 0, "unknown": 1, "fixed_bound": 2, "none": 3}
_RETURNS_RANK = {"dynamic": 0, "unknown": 1, "opaque": 2, "placeholder_list": 3, "fixed": 4, "none": 5}
_TEXT_RETURN_TYPES = frozenset({"String", "CharSequence", "StringBuilder", "StringBuffer"})


@dataclass
class SqlSummary:
    method: str  # call_graph.method_identity
    executes: str = "none"  # none | fixed_bound | dynamic | unknown
    positions: Tuple[int, ...] = ()  # parameters that reach executed SQL text
    internal: bool = False  # executed dynamic text that is not from a parameter
    returns_sql: str = "none"  # none | fixed | placeholder_list | dynamic | opaque | unknown
    return_positions: Tuple[int, ...] = ()
    return_variants: List[Variant] = field(default_factory=list)
    appends: Dict[int, List[Variant]] = field(default_factory=dict)  # builder parameter -> appended text
    binds_params: Tuple[int, ...] = ()
    reason: Optional[str] = None  # why `unknown`: cycle, summary_depth_exceeded, unresolved, ...
    missing: Optional[str] = None
    detail: str = ""  # one line for proofs
    truncated: bool = False  # cut by a cycle or a bound: not cached

    @property
    def decided(self) -> bool:
        return self.executes != "unknown"


def _merge(summaries: List[SqlSummary], label: str) -> SqlSummary:
    """The union of what several methods may do (a facade's implementations)."""
    if len(summaries) == 1:
        return summaries[0]
    out = SqlSummary(method=label)
    out.executes = min((s.executes for s in summaries), key=_EXECUTES_RANK.__getitem__)
    out.positions = tuple(sorted({p for s in summaries for p in s.positions}))
    out.internal = any(s.internal for s in summaries)
    out.returns_sql = min((s.returns_sql for s in summaries), key=_RETURNS_RANK.__getitem__)
    out.return_positions = tuple(sorted({p for s in summaries for p in s.return_positions}))
    out.return_variants = [v for s in summaries for v in s.return_variants][:MAX_VARIANTS]
    out.binds_params = tuple(sorted({p for s in summaries for p in s.binds_params}))
    unknown = [s for s in summaries if s.executes == "unknown"]
    if unknown:
        out.reason, out.missing = unknown[0].reason, unknown[0].missing
    dynamic = [s for s in summaries if s.executes == "dynamic"]
    out.detail = (dynamic or unknown or summaries)[0].detail
    out.truncated = any(s.truncated for s in summaries)
    return out


def _to_template(variants: List[Variant]) -> List[Variant]:
    """A callee's folded text with its parameters left open (`Param`)."""
    out: List[Variant] = []
    for variant in variants:
        out.append([Param(s.param_index, s.kind) if isinstance(s, Dyn) and s.param_index is not None else s
                    for s in variant])
    return out


def _returns_of(variants: List[Variant]) -> Tuple[str, Tuple[int, ...]]:
    kinds, positions = set(), set()
    for variant in variants:
        for seg in variant:
            if isinstance(seg, Unk):
                kinds.add("unknown")
            elif isinstance(seg, Param):
                kinds.add("dynamic")
                positions.add(seg.index)
            elif isinstance(seg, Dyn) and is_text_kind(seg.kind):
                kinds.add("opaque")
            elif isinstance(seg, PList):
                kinds.add("placeholder_list")
    for kind in ("unknown", "dynamic", "opaque", "placeholder_list"):
        if kind in kinds:
            return kind, tuple(sorted(positions))
    return "fixed", ()


class _Calls:
    """The `QueryFolder.calls` hook for one method: folds a project helper's
    returned or appended text from its summary, at a given summary depth."""

    def __init__(self, summaries: "SqlSummaries", method: Any, depth: int) -> None:
        self.summaries, self.method, self.depth = summaries, method, depth

    def _targets(self, node: Any, folder: QueryFolder) -> Optional[SqlSummary]:
        return self.summaries.call_summary(self.method, folder.ctx, node, self.depth)

    def _substitute(self, template: List[Variant], node: Any, folder: QueryFolder) -> List[Variant]:
        args = _args(node)
        out: List[Variant] = [[]]
        for variant in template:
            built: List[Variant] = [[]]
            for seg in variant:
                if isinstance(seg, Param):
                    arg = args[seg.index] if seg.index < len(args) else None
                    folded = folder.fold(arg) if arg is not None else [[Unk("missing argument")]]
                    if is_text_kind(seg.kind):
                        # The callee uses this argument as text (joins a list's
                        # elements, say): an object passed here is text there.
                        folded = [[Dyn(d.node, "string_var", d.param_index, d.origin, d.text, d.line)
                                   if isinstance(d, Dyn) and d.kind == "object" else d for d in v] for v in folded]
                    built = _product(built, folded)
                else:
                    built = _product(built, [[seg]])
            out = built if out == [[]] else (out + built)[:MAX_VARIANTS]
        return out

    def call_variants(self, node: Any, folder: QueryFolder) -> Optional[List[Variant]]:
        summary = self._targets(node, folder)
        if summary is None or summary.returns_sql == "none":
            return None
        if summary.returns_sql == "unknown":
            return [[Unk(summary.missing or summary.method, node)]]
        if summary.returns_sql == "opaque":
            return [[folder._dyn(node, "call_result")]]
        return self._substitute(summary.return_variants, node, folder)

    def escape_variants(self, node: Any, index: int, folder: QueryFolder) -> Optional[List[Variant]]:
        summary = self._targets(node, folder)
        if summary is None or index not in summary.appends:
            return None
        return self._substitute(summary.appends[index], node, folder)


class SqlSummaries:
    """Per-scan SQL summaries over a call graph (`call_graph.CallGraph`).
    `read_text(path)` returns a repo file's text. Thread-safe: scan stages
    share one instance."""

    def __init__(self, graph: Any, read_text: Any, *, usage: Optional[Dict[str, Any]] = None,
                 max_depth: int = SUMMARY_MAX_DEPTH, time_budget: float = SUMMARY_TIME_BUDGET_SECONDS) -> None:
        import threading
        import time

        from pipeline import call_graph as cg

        self.cg = cg
        self.graph = graph
        self.read_text = read_text
        self.usage = usage
        self.max_depth = max_depth
        # Time spent summarising (not wall time since the scan started: the
        # summaries are consulted throughout a long scan).
        self.time_budget = time_budget
        self.spent = 0.0
        self._clock = time.monotonic
        self._lock = threading.RLock()
        self._memo: Dict[str, SqlSummary] = {}
        self._stack: List[str] = []
        self._contexts: Dict[str, Dict[int, MethodContext]] = {}
        self.stats: Dict[str, int] = {}

    @classmethod
    def for_file(cls, path: str, text: str, *, usage: Optional[Dict[str, Any]] = None) -> "SqlSummaries":
        """Summaries over a one-file graph: same-file helpers resolve, anything
        else is a named gap. Used when the scan built no call graph."""
        from pipeline import call_graph as cg

        graph = cg.CallGraph()
        graph._file_imports = {}  # type: ignore[attr-defined]
        calls = cg._parse_java_file(path, text, graph)
        graph.files_parsed = 1
        cg._wire_calls(graph, calls)
        return cls(graph, {path: text}.get, usage=usage)

    # bookkeeping --------------------------------------------------------------

    def _count(self, key: str, n: int = 1) -> None:
        self.stats[key] = self.stats.get(key, 0) + n
        if self.usage is not None:
            from llm_client import bump_counter

            bump_counter(self.usage, "sql_summaries", key, n)

    def method_for(self, path: str, line: int) -> Any:
        return self.cg.method_at_line(self.graph, path, line)

    def context(self, method: Any) -> Optional[MethodContext]:
        by_line = self._contexts.get(method.file)
        if by_line is None:
            text = self.read_text(method.file)
            by_line = {c.start_line: c for c in methods_in_file(text)} if text else {}
            self._contexts[method.file] = by_line
        return by_line.get(method.start_line)

    def folder(self, method: Any, ctx: MethodContext, depth: int = 0) -> QueryFolder:
        return QueryFolder(ctx, constants=self.constant_text, calls=_Calls(self, method, depth))

    # constants ----------------------------------------------------------------

    def constant_text(self, owner: Optional[str], name: str) -> Optional[str]:
        """The literal text of `Owner.NAME`, a `static final` (or interface)
        String constant of a type parsed in this repo; None otherwise — a
        constant from a jar is never assumed."""
        if owner is None:
            return None
        matches = self.graph.types_by_simple.get(owner) or []
        if len(matches) != 1:
            return None
        jtype = self.graph.types[matches[0]]
        text = self.read_text(jtype.file)
        parsed = of._parse("java", text) if text else None
        if parsed is None:
            return None
        root, src, _memo = parsed
        return _constant_in(root, src, owner, name, self, 0)

    # resolution ----------------------------------------------------------------

    def _arg_types(self, method: Any, invocation: Any, ctx: MethodContext) -> List[str]:
        types = []
        for arg in _args(invocation):
            if arg.type in ("string_literal", "text_block"):
                types.append("String")
            elif arg.type == "null_literal":
                types.append("null")
            elif arg.type == "decimal_integer_literal":
                types.append("int")
            elif arg.type == "identifier":
                types.append(method.locals.get(ctx.text(arg), ""))
            else:
                types.append("")
        return types

    def targets(self, method: Any, ctx: MethodContext, invocation: Any) -> Tuple[List[str], Optional[str]]:
        call = self.cg.call_site_for(method, invocation, ctx.src)
        return self.cg.resolve_targets(self.graph, method, call, arg_types=self._arg_types(method, invocation, ctx))

    def call_summary(self, method: Any, ctx: MethodContext, invocation: Any, depth: int) -> Optional[SqlSummary]:
        """The merged summary of every method `invocation` may run; None for a
        JDK/framework call; `unknown` (naming the callee) when it cannot be
        resolved inside the repo."""
        obj = of._f(invocation, "object")
        if obj is not None:
            _text, fqn, _simple = of._java_receiver(obj, ctx.scope, ctx.jf)
            if fqn and fqn.startswith(_EXTERNAL_PREFIXES):
                return None  # a JDK or framework call: not project code
        keys, reason = self.targets(method, ctx, invocation)
        name_node = of._f(invocation, "name")
        callee = ctx.text(name_node) if name_node is not None else "call"
        if reason is not None:
            obj = of._f(invocation, "object")
            label = f"{ctx.text(obj)}.{callee}" if obj is not None else callee
            return SqlSummary(method=label, executes="unknown", returns_sql="unknown", reason="unresolved",
                              missing=f"callee `{label}(...)` body not resolved ({reason})")
        if not keys:
            return None
        summaries = [self._summarise(k, depth + 1) for k in keys]
        return _merge(summaries, f"{callee} ({len(keys)} implementations)" if len(keys) > 1 else summaries[0].method)

    # summaries -----------------------------------------------------------------

    def summarise(self, method_key: str) -> SqlSummary:
        """The summary of one graph method (by its graph key)."""
        return self._summarise(method_key, 0)

    def _summarise(self, key: str, depth: int) -> SqlSummary:
        with self._lock:
            method = self.graph.methods.get(key)
            if method is None:
                return SqlSummary(method=key, executes="unknown", returns_sql="unknown", reason="unresolved",
                                  missing=f"method `{key}` not in the call graph")
            ident = self.cg.method_identity(method)
            if ident in self._memo:
                self._count("cache_hits")
                return self._memo[ident]
            if ident in self._stack:
                return SqlSummary(method=ident, executes="unknown", returns_sql="unknown", reason="cycle",
                                  missing=f"`{ident}` is part of a recursion cycle", truncated=True)
            if depth > self.max_depth or self.spent > self.time_budget:
                reason = "summary_depth_exceeded" if depth > self.max_depth else "summary_time_exceeded"
                self._count(reason)
                return SqlSummary(method=ident, executes="unknown", returns_sql="unknown", reason=reason,
                                  missing=f"`{ident}` is past the summary bound ({reason})", truncated=True)
            ctx = self.context(method)
            if ctx is None:
                summary = SqlSummary(method=ident, executes="unknown", returns_sql="unknown", reason="unparsed",
                                     missing=f"`{ident}` could not be parsed")
            else:
                top = not self._stack
                started = self._clock()
                self._stack.append(ident)
                try:
                    summary = self._compute(method, ctx, ident, depth)
                finally:
                    self._stack.pop()
                    if top:
                        elapsed = self._clock() - started
                        self.spent += elapsed
                        self._count("milliseconds", int(elapsed * 1000))
            self._count("methods")
            if summary.executes == "unknown":
                self._count(f"unknown.{summary.reason or 'unresolved'}")
            if not summary.truncated:
                self._memo[ident] = summary
            return summary

    def _compute(self, method: Any, ctx: MethodContext, ident: str, depth: int) -> SqlSummary:
        out = SqlSummary(method=ident)
        folder = self.folder(method, ctx, depth)
        judgements = [judge_statement(f, ctx, folder, fields=self.field_judgement)
                      for f in statements_in_method(ctx.node, ctx.src, ctx)]
        executes: List[str] = []
        positions: set = set()
        binds = set()
        cut = False
        for j in judgements:
            if j.tag in POSITIVE_JUDGEMENTS:
                executes.append("dynamic")
                own = {p.param_index for p in j.parts if p.param_index is not None}
                positions |= own
                out.internal = out.internal or len(own) < len(j.parts)
                out.detail = out.detail or f"line {j.line} builds SQL text from `{j.parts[0].text}`"
            elif j.tag in GAP_JUDGEMENTS:
                executes.append("unknown")
                out.reason, out.missing = out.reason or "unresolved", out.missing or j.missing
            elif j.tag != "none":
                executes.append("fixed_bound")
                out.detail = out.detail or f"line {j.line} runs fixed SQL text"
            if j.fact is not None:
                for b in j.fact.binds:
                    if b.value is not None and b.value.type == "identifier":
                        index = _param_index(ctx.text(b.value), ctx)
                        if index is not None:
                            binds.add(index)
        # Calls into other project methods execute their summaries.
        jdbc_lines = {line for j in judgements if j.fact is not None for line in fact_lines(j.fact)}
        for node, _branch in folder.nodes:
            if node.type != "method_invocation" or node.start_point[0] + 1 in jdbc_lines:
                continue
            callee = self.call_summary(method, ctx, node, depth)
            if callee is None:
                continue
            cut = cut or callee.truncated
            if callee.executes == "dynamic":
                reach = self._reaching(callee, node, folder)
                if reach is None:
                    continue  # the call passes constants into the parameters that reach SQL
                executes.append("dynamic")
                positions |= reach[0]
                out.internal = out.internal or reach[1] or callee.internal
                out.detail = out.detail or f"calls `{callee.method}`, whose SQL text {callee.detail or 'is dynamic'}"
            elif callee.executes == "unknown" and callee.reason not in ("cycle",):
                if callee.reason == "unresolved":
                    handed = self._handed(node, folder)
                    if handed == "none":
                        continue  # handed no SQL and no text: it cannot build our SQL
                    if handed == "constant_sql":
                        # An executor we cannot see, given only constant SQL and
                        # non-text values: no outside text reaches its grammar.
                        executes.append("fixed_bound")
                        out.detail = out.detail or f"passes only constant SQL to `{callee.method}`"
                        continue
                executes.append("unknown")
                out.reason, out.missing = out.reason or callee.reason, out.missing or callee.missing
            elif callee.executes == "fixed_bound":
                executes.append("fixed_bound")
        if executes:
            out.executes = min(executes, key=_EXECUTES_RANK.__getitem__)
        elif cut:
            out.executes, out.reason = "unknown", "cycle"
            out.missing = f"`{ident}` is part of a recursion cycle"
        out.positions = tuple(sorted(positions))
        out.binds_params = tuple(sorted(binds))
        out.truncated = cut and out.executes == "unknown"
        self._returns(out, ctx, folder)
        return out

    def _reaching(self, callee: SqlSummary, node: Any, folder: QueryFolder) -> Optional[Tuple[set, bool]]:
        """(our parameters, any non-parameter text) that reach the callee's SQL
        text through the arguments at its tainted positions; None when every
        such argument is a constant here."""
        args = _args(node)
        positions, internal, any_text = set(), False, False
        for index in callee.positions or ():
            if index >= len(args):
                continue
            qc = classify_variants(folder.fold(args[index]))
            text_parts = [p for p in qc.dynamic_parts if is_text_kind(p.kind)]
            if text_parts or qc.unknown:
                any_text = True
            for p in text_parts:
                if p.param_index is not None:
                    positions.add(p.param_index)
                else:
                    internal = True
        if callee.internal:
            return positions, True
        return (positions, internal) if any_text else None

    def _handed(self, node: Any, folder: QueryFolder) -> str:
        """What a call hands its callee: `text` (some argument carries
        dynamic or unresolved text), `constant_sql` (constant SQL text, other
        arguments non-text) or `none`."""
        sql = False
        for arg in _args(node):
            qc = classify_variants(folder.fold(arg))
            if qc.unknown or any(is_text_kind(p.kind) for p in qc.dynamic_parts):
                return "text"
            sql = sql or any(_SQL_WORD_RE.search(v) for v in qc.variants)
        return "constant_sql" if sql else "none"

    def _returns(self, out: SqlSummary, ctx: MethodContext, folder: QueryFolder) -> None:
        rtype = of._simple_type(of._f(ctx.node, "type"), ctx.src)
        params = of._f(ctx.node, "parameters")
        for index, p in enumerate(of._named(params) if params is not None else []):
            if of._simple_type(of._f(p, "type"), ctx.src) in _BUILDER_TYPES:
                pname = of._f(p, "name")
                if pname is not None:
                    out.appends[index] = _to_template(folder.fold_param_appends(ctx.text(pname)))
        if rtype not in _TEXT_RETURN_TYPES:
            return
        variants: List[Variant] = []
        for node, _branch in folder.nodes:
            if node.type == "return_statement":
                value = of._code_children(node, of._JAVA_COMMENT_NODES)
                if value:
                    variants.extend(folder.fold(value[0]))
        variants = _to_template(variants[:MAX_VARIANTS])
        if not variants:
            return
        out.return_variants = variants
        out.returns_sql, out.return_positions = _returns_of(variants)

    # field statements -----------------------------------------------------------

    def field_judgement(self, ctx: MethodContext, fact: StatementFact) -> Optional[Judgement]:
        """Complete a statement held in field `fact.var` by joining every
        allocation, bind and execution of that field across its class's
        methods (#45/#46). None when the class is not in the graph."""
        owner = self.graph.types.get(ctx.scope.class_fqn)
        if owner is None:
            return None
        allocs: List[Tuple[StatementFact, MethodContext, Any]] = []
        all_facts: List[StatementFact] = []
        for key in owner.methods:
            method = self.graph.methods.get(key)
            mctx = self.context(method) if method is not None else None
            if mctx is None:
                continue
            for other in statements_in_method(mctx.node, mctx.src, mctx):
                if other.scope != "field" or other.var != fact.var:
                    continue
                all_facts.append(other)
                if other.alloc:
                    allocs.append((other, mctx, method))
        name = f"`{fact.var}` of {owner.simple_name}"
        if not allocs:
            return Judgement("incomplete", fact.alloc_line or 0, missing=(
                f"field statement {name} is never allocated in its class"), fact=fact)
        placeholders = 0
        plist = False
        for alloc, mctx, method in allocs:
            folder = self.folder(method, mctx)
            qc = classify_query(alloc.query_expr, mctx, folder=folder) if alloc.query_expr is not None else None
            if qc is None:
                return Judgement("incomplete", alloc.alloc_line or 0, missing=f"field statement {name} has no query")
            verdict = _judge_text(qc, alloc.alloc_line or 0, misuse=False)
            if verdict is not None and verdict.tag not in ("numeric_only", "no_text"):
                verdict.fact = alloc
                verdict.detail = f"field statement {name}"
                return verdict
            placeholders = max(placeholders, qc.placeholders)
            plist = plist or bool(qc.placeholder_list)
        for other in all_facts:
            for execution in other.executions:
                if execution.has_sql_arg:
                    return Judgement("misuse_dynamic", execution.line, fact=other, missing=None,
                                     detail=f"field statement {name} is executed with its own SQL string")
        binds = [b for other in all_facts for b in other.binds]
        literal = {b.index for b in binds if isinstance(b.index, int)}
        computed = [b for b in binds if not isinstance(b.index, int)]
        needed = placeholders - (1 if plist else 0)
        if (plist and not computed) or (not computed and not set(range(1, needed + 1)) <= literal):
            return Judgement("unbound", fact.alloc_line or 0, fact=fact)
        alloc = allocs[0][0]
        bind_lines = ", ".join(str(b.line) for b in binds[:3]) or "none needed"
        return Judgement("fixed_bound", alloc.alloc_line or 0, fact=fact, detail=(
            f"field statement {name}: allocated at line {alloc.alloc_line} with fixed SQL text, "
            f"bound in the class (line {bind_lines})"))

    # call sites ------------------------------------------------------------------

    def judge_call(self, method: Any, ctx: MethodContext, invocation: Any) -> Optional[Judgement]:
        """Judge a call into a project method from the callee's summary: does
        what this call passes reach the callee's SQL text?"""
        summary = self.call_summary(method, ctx, invocation, 0)
        if summary is None:
            return None
        line = invocation.start_point[0] + 1
        callee = summary.method
        if summary.executes == "unknown":
            return Judgement("unknown", line, missing=summary.missing, callee=callee)
        if summary.executes == "none":
            return Judgement("callee_no_sql", line, callee=callee) if summary.returns_sql in ("none", "fixed") else None
        if summary.executes == "fixed_bound":
            return Judgement("fixed_bound", line, callee=callee, detail=summary.detail)
        folder = self.folder(method, ctx)
        args = _args(invocation)
        parts: List[DynamicPart] = []
        for index in summary.positions:
            if index < len(args):
                qc = classify_variants(folder.fold(args[index]))
                parts.extend(p for p in qc.dynamic_parts if is_text_kind(p.kind))
                if qc.unknown:
                    return Judgement("unknown", line, missing=(
                        f"argument {index + 1} of `{callee}` depends on `{qc.resolver}`"), callee=callee)
        if parts:
            return Judgement("dynamic_text", line, parts=parts, callee=callee, detail=summary.detail)
        if summary.internal:
            return None  # the callee's own text is dynamic; that is the callee's finding
        return Judgement("wrapper_constant", line, callee=callee)


_SQL_WORD_RE = re.compile(r"\b(?:SELECT|INSERT|UPDATE|DELETE|MERGE|WHERE|FROM)\b", re.IGNORECASE)


def _constant_in(root: Any, src: bytes, owner: str, name: str, summaries: Optional[SqlSummaries], depth: int) -> Optional[str]:
    """Literal text of constant `owner.name` declared in this file."""
    if depth > 4:
        return None
    for node in _iter(root):
        if node.type not in of._JAVA_TYPE_NODES:
            continue
        tname = of._f(node, "name")
        if tname is None or of._t(tname, src) != owner:
            continue
        is_interface = node.type == "interface_declaration"
        body = of._f(node, "body")
        fields: Dict[str, Any] = {}
        for child in (body.children if body is not None else []):
            if child.type not in ("field_declaration", "constant_declaration"):
                continue
            constant = is_interface or (of._has_modifier(child, src, "static") and of._has_modifier(child, src, "final"))
            if not constant:
                continue
            for decl in of._named(child):
                if decl.type == "variable_declarator" and of._f(decl, "name") is not None:
                    fields[of._t(of._f(decl, "name"), src)] = of._f(decl, "value")
        if name in fields and fields[name] is not None:
            return _constant_value(fields[name], src, owner, fields, summaries, depth + 1)
    return None


def _constant_value(node: Any, src: bytes, owner: str, fields: Dict[str, Any],
                    summaries: Optional[SqlSummaries], depth: int) -> Optional[str]:
    if node is None or depth > 8:
        return None
    t = node.type
    if t in ("string_literal", "text_block"):
        raw = of._t(node, src)
        return (raw[3:-3] if t == "text_block" else raw[1:-1]).replace('\\"', '"')
    if t in of._JAVA_LITERALS:
        return of._t(node, src)
    if t == "parenthesized_expression":
        inner = of._code_children(node, of._JAVA_COMMENT_NODES)
        return _constant_value(inner[0], src, owner, fields, summaries, depth + 1) if inner else None
    if t == "binary_expression":
        op = of._f(node, "operator")
        if op is None or op.type != "+":
            return None
        left = _constant_value(of._f(node, "left"), src, owner, fields, summaries, depth + 1)
        right = _constant_value(of._f(node, "right"), src, owner, fields, summaries, depth + 1)
        return None if left is None or right is None else left + right
    if t == "identifier":
        ident = of._t(node, src)
        return _constant_value(fields.get(ident), src, owner, fields, summaries, depth + 1) if ident in fields else None
    if t == "field_access" and summaries is not None:
        obj, fld = of._f(node, "object"), of._f(node, "field")
        if obj is not None and fld is not None and obj.type == "identifier":
            return summaries.constant_text(of._t(obj, src), of._t(fld, src))
    return None


def _iter(root: Any):
    stack = [root]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(n.children)

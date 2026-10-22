"""sql_binding — does external text reach the SQL grammar of this statement?

A SQL-injection finding is decided from the statement the anchor points at
(`sql_semantics`): its query text, the values bound to its placeholders and the
executions that run it.

* **Negative proof `sql_fixed_template_bound`** — the query is fixed text (with
  or without placeholders), every execution runs that query, and every
  placeholder is bound on every path that reaches each execution. The proof
  names the query line, the binds and the execution line. A finding anchored
  on a bind (`setObject`) gets the same proof: a setter is data, never SQL
  text (#15/#209).
* **Negative proof `sql_api_misuse_constant`** (`issue_class=quality`) — a
  PreparedStatement executed with a *constant* SQL string: an API misuse, not
  injection (#54).
* **Positive fact `sql_dynamic_text`** / **`sql_api_misuse_dynamic`** — the
  executed text has a non-constant string, call result or unresolved part;
  **`sql_second_order`** when that string was read back from the database
  (`ResultSet.getString` and friends), which stays untrusted (#53).
* **Negative proof `sql_numeric_only`** (`issue_class=quality`) — every
  dynamic part is a number (a primitive, a boxed or big integer, a `parseX`
  result that is itself the value used): no SQL grammar can come of it, but
  the value should still be bound (review §8). Numbers matter for other sinks;
  this proof is SQL-only.
* **Evidence gap** — the text is built by a helper or constant this method
  cannot see, or the statement lives in a field; the gap names what is missing.
* **No opinion** — the anchor is not on any statement, an enum or boolean part
  is dynamic, or a placeholder is not bound on some path (missing a bind is a
  bug, not proof of safety or of injection).

Never a negative proof for `prepareStatement(dynamicConcatenatedText)`, and
never a SQL-text sink for `setX(...)` (review §5.2).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from pipeline import sql_semantics as sq

from . import register
from .base import ValidatorResult, evidence_gap, negative_proof, no_opinion, positive_fact

SQL_RULE_IDS = (
    "java-sql-string-concat", "java-jdbc-prepare-concat", "java-jdbc-statement-exec-variable",
)
# Dynamic parts that can carry SQL grammar (spec SAST-02-030). Numeric parts are
# decided separately; enum and boolean parts give no opinion.
_TEXT_KINDS = frozenset({"string_var", "call_result", "unknown"})


def _is_text(kind: str) -> bool:
    return any(k in _TEXT_KINDS for k in str(kind).split("+"))


def _anchor_lines(finding: Dict[str, Any], facts: Optional[Dict[str, Any]]) -> List[int]:
    lines: List[int] = []
    call = (facts or {}).get("call") or {}
    for value in (finding.get("line"), call.get("start_line")):
        try:
            number = int(value or 0)
        except (TypeError, ValueError):
            continue
        if number > 0 and number not in lines:
            lines.append(number)
    return lines


def _describe_parts(qc: sq.QueryClass, *, text_only: bool) -> str:
    parts = [p for p in qc.dynamic_parts if _is_text(p.kind) or not text_only]
    return ", ".join(f"`{p.text}` ({p.kind}, {p.position})" for p in parts[:3])


def _binds_text(fact: sq.StatementFact, ctx: sq.MethodContext) -> str:
    if fact.alloc == "jdbc_template":
        return "bound through the template's arguments"
    binds = []
    for bind in fact.binds[:3]:
        binds.append(f"{bind.index if bind.index is not None else '?'} with {bind.setter} (line {bind.line})")
    return "bound: " + "; ".join(binds) if binds else "no placeholders to bind"


def _judge_text(qc: sq.QueryClass, line: int, ctx: sq.MethodContext, *, misuse: bool) -> Optional[ValidatorResult]:
    """Positive fact, numeric proof or evidence gap for one executed text;
    None when it is fixed and the binding check decides."""
    text_parts = [p for p in qc.dynamic_parts if _is_text(p.kind)]
    if text_parts:
        persisted = [p for p in text_parts if p.origin == "persisted"]
        if persisted and not misuse:
            return positive_fact("sql_second_order", (
                f"The SQL text executed at line {line} is built from `{persisted[0].text}`, a string read "
                "back from the database: stored data is untrusted when it is reused as SQL text."
            ))
        tag = "sql_api_misuse_dynamic" if misuse else "sql_dynamic_text"
        return positive_fact(tag, (
            f"The SQL text executed at line {line} is built from {_describe_parts(qc, text_only=True)}; "
            "that text is part of the query grammar, not a bound value."
        ))
    if qc.unknown:
        return evidence_gap(
            f"the SQL text at line {line} depends on `{qc.resolver}`, whose value is not resolved"
        )
    if qc.dynamic_parts and all(p.kind == "numeric" for p in qc.dynamic_parts):
        names = ", ".join(f"`{p.text[:40]}`" for p in qc.dynamic_parts[:2])
        note = ""
        if any(_is_bigdecimal(p, ctx) for p in qc.dynamic_parts):
            note = " BigDecimal may print in scientific notation (1E+3): still no grammar."
        # Proofs are cut at 200 characters; the note must survive the cut.
        return negative_proof("sql_numeric_only", (
            f"Parameterisation hygiene: numeric value concatenated; bind it. Line {line} adds only "
            f"numbers ({names}) to the SQL.{note}"
        ), issue_class="quality")
    if qc.dynamic_parts:
        return no_opinion()  # enum or boolean parts
    return None


def _is_bigdecimal(part: sq.DynamicPart, ctx: sq.MethodContext) -> bool:
    entry = ctx.scope.locals.get(part.text) or ctx.scope.fields.get(part.text)
    return "BigDecimal" in part.text or bool(entry and entry[0] == "BigDecimal")


def _incomplete_reason(fact: sq.StatementFact, ctx: sq.MethodContext) -> str:
    owner = ctx.scope.class_simple or "the class"
    if not fact.var:
        return (f"the statement prepared at line {fact.alloc_line} is returned or passed on; its binds "
                "and executions are in code that is not summarised")
    where = {"field": f"a field of {owner}", "param": "a method parameter"}.get(
        fact.scope, "allocated by another method")
    return (f"statement `{fact.var}` is {where}: its allocation, binds or executions are in other "
            "methods, which are not summarised")


def _judge_statement(fact: sq.StatementFact, ctx: sq.MethodContext, folder: sq.QueryFolder) -> ValidatorResult:
    query_line = fact.alloc_line or (fact.executions[0].line if fact.executions else 0)
    qc = None
    # A text that is unsafe or unresolved decides at once; a numeric-only
    # proof waits until every text the statement runs has been checked.
    numeric: Optional[ValidatorResult] = None
    if fact.query_expr is not None and fact.statement_type != "java.sql.Statement":
        qc = sq.classify_query(fact.query_expr, ctx, folder=folder)
        verdict = _judge_text(qc, query_line, ctx, misuse=False)
        if verdict is not None and verdict.outcome != "negative_proof":
            return verdict
        numeric = numeric or verdict
    # Every (String) execution runs its own text.
    misuse_constant: Optional[int] = None
    for execution in fact.executions:
        if not execution.has_sql_arg:
            continue
        exec_qc = sq.classify_query(execution.sql_arg, ctx, folder=folder)
        verdict = _judge_text(exec_qc, execution.line, ctx, misuse=fact.api_misuse)
        if verdict is not None and verdict.outcome != "negative_proof":
            return verdict
        numeric = numeric or verdict
        if fact.api_misuse and verdict is None:
            misuse_constant = execution.line
    if numeric is not None:
        return numeric
    if not fact.complete:
        return evidence_gap(_incomplete_reason(fact, ctx))
    if misuse_constant is not None:
        return negative_proof("sql_api_misuse_constant", (
            f"Line {misuse_constant} executes a PreparedStatement with a constant SQL string: an API "
            "misuse (the prepared query is ignored), not SQL injection."
        ), issue_class="quality")
    if fact.statement_type == "java.sql.Statement":
        if not any(e.has_sql_arg for e in fact.executions):
            return no_opinion()
        return negative_proof("sql_fixed_template_bound", (
            f"Every execution of statement `{fact.var}` (line {fact.executions[0].line}) runs constant SQL text."
        ))
    if qc is None or not fact.executions:
        return no_opinion()
    if sq.unbound_placeholders(fact, qc, ctx):
        return no_opinion()
    execution = fact.executions[0]
    placeholders = (
        "a placeholder list" if qc.placeholder_list
        else f"{qc.placeholders} placeholder{'s' if qc.placeholders != 1 else ''}"
    )
    return negative_proof("sql_fixed_template_bound", (
        f"The query at line {query_line} is fixed SQL text with {placeholders}, "
        f"{_binds_text(fact, ctx)}, executed by {execution.method} at line {execution.line}."
    ))


def candidate_statements(
    text: str, lines: List[int]
) -> Tuple[Optional[sq.MethodContext], List[Tuple[sq.StatementFact, sq.QueryFolder]]]:
    """The statements an anchor is about: those whose allocation, binds or
    executions sit on an anchor line, or whose query text is built there."""
    ctx, facts = sq.statements_at(text, lines[0])
    if ctx is None:
        return None, []
    out: List[Tuple[sq.StatementFact, sq.QueryFolder]] = []
    wanted = set(lines)
    for fact in facts:
        folder = sq.QueryFolder(ctx)
        touched = set(sq.fact_lines(fact))
        for expr in [fact.query_expr] + [e.sql_arg for e in fact.executions]:
            if expr is not None:
                folder.fold(expr)
        touched |= folder.touched
        folder.touched = set()
        if touched & wanted:
            out.append((fact, folder))
    return ctx, out


def decide(finding: Dict[str, Any], facts: Optional[Dict[str, Any]], text: str) -> ValidatorResult:
    lines = _anchor_lines(finding, facts)
    if not lines:
        return no_opinion()
    ctx, candidates = candidate_statements(text, lines)
    if ctx is None or not candidates:
        return no_opinion()
    results = [_judge_statement(fact, ctx, folder) for fact, folder in candidates]
    for outcome in ("positive_fact", "evidence_gap"):
        for result in results:
            if result.outcome == outcome:
                return result
    if all(r.outcome == "negative_proof" for r in results):
        return results[0]
    return no_opinion()


@register("sql_binding", 1, rule_ids=SQL_RULE_IDS, rule_prefixes=("runtime-sink-sql-",), cwes=(89,))
def sql_binding(finding, facts, ctx) -> ValidatorResult:
    path = str(finding.get("file_path") or "")
    if not path.endswith(".java"):
        return no_opinion()
    if facts and facts.get("in_comment"):
        return negative_proof(
            "sql_in_comment", f"The flagged text at line {finding.get('line')} is inside a comment; it is never executed."
        )
    text = ctx.read_text(path)
    if text is None:
        return no_opinion()
    return decide(finding, facts, text)

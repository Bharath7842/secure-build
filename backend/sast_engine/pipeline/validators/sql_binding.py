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
* **Evidence gap** — the text is built by a helper or constant that cannot be
  resolved, or the statement lives somewhere no summary reaches; the gap names
  what is missing.

Helpers, facades and field-held statements are judged from their method
summaries (`sql_semantics.SqlSummaries`, SAST-02-050): the scan's, when it
built a call graph, else one over the finding's own file. A finding anchored
on a *call* into a project method (a `runtime-sink-sql-*` call site) is judged
from the callee's summary: `sql_callee_no_sql` when the resolved callee runs
no SQL at all, `sql_fixed_template_bound` when it runs only fixed bound SQL,
`sql_dynamic_text` when this call's argument reaches its SQL text.
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


def _describe(parts: List[sq.DynamicPart]) -> str:
    return ", ".join(f"`{p.text}` ({p.kind}, {p.position})" for p in parts[:3])


def _is_bigdecimal(part: sq.DynamicPart, ctx: Optional[sq.MethodContext]) -> bool:
    entry = (ctx.scope.locals.get(part.text) or ctx.scope.fields.get(part.text)) if ctx is not None else None
    return "BigDecimal" in part.text or bool(entry and entry[0] == "BigDecimal")


def result_for(j: sq.Judgement, ctx: Optional[sq.MethodContext]) -> ValidatorResult:
    """The validator answer for one judgement, with a proof a reviewer can check."""
    tag = j.tag
    if tag == "second_order":
        return positive_fact("sql_second_order", (
            f"The SQL text executed at line {j.line} is built from `{j.parts[0].text}`, a string read "
            "back from the database: stored data is untrusted when it is reused as SQL text."
        ))
    if tag in ("dynamic_text", "misuse_dynamic"):
        reason = "sql_api_misuse_dynamic" if tag == "misuse_dynamic" else "sql_dynamic_text"
        if j.callee:
            return positive_fact(reason, (
                f"Line {j.line} passes {_describe(j.parts)} to `{j.callee}`, where it reaches the SQL text "
                f"({j.detail or 'dynamic SQL'})."
            ))
        source = _describe(j.parts) if j.parts else "its own SQL string"
        return positive_fact(reason, (
            f"The SQL text executed at line {j.line} is built from {source}; that text is part of the "
            "query grammar, not a bound value."
        ))
    if tag in ("unknown", "incomplete"):
        return evidence_gap(j.missing or f"the SQL text at line {j.line} is not resolved")
    if tag == "numeric_only":
        names = ", ".join(f"`{p.text[:40]}`" for p in j.parts[:2])
        note = ""
        if any(_is_bigdecimal(p, ctx) for p in j.parts):
            note = " BigDecimal may print in scientific notation (1E+3): still no grammar."
        # Proofs are cut at 200 characters; the note must survive the cut.
        return negative_proof("sql_numeric_only", (
            f"Parameterisation hygiene: numeric value concatenated; bind it. Line {j.line} adds only "
            f"numbers ({names}) to the SQL.{note}"
        ), issue_class="quality")
    if tag == "misuse_constant":
        return negative_proof("sql_api_misuse_constant", (
            f"Line {j.line} executes a PreparedStatement with a constant SQL string: an API "
            "misuse (the prepared query is ignored), not SQL injection."
        ), issue_class="quality")
    if tag == "statement_constant":
        return negative_proof("sql_fixed_template_bound", (
            f"Every execution of statement `{j.fact.var}` (line {j.line}) runs constant SQL text."
        ))
    if tag == "callee_no_sql":
        return negative_proof("sql_callee_no_sql", (
            f"The call at line {j.line} resolves to `{j.callee}`, which executes no SQL and returns no SQL text."
        ))
    if tag == "fixed_bound":
        if j.callee:
            return negative_proof("sql_fixed_template_bound", (
                f"The call at line {j.line} resolves to `{j.callee}`, which runs only fixed SQL text with "
                f"every placeholder bound ({j.detail})."
            ))
        if j.fact is not None and j.fact.scope == "field" and not j.fact.complete:
            return negative_proof("sql_fixed_template_bound", f"The {j.detail}; every placeholder is bound.")
        qc, execution = j.qc, j.execution
        placeholders = (
            "a placeholder list" if qc.placeholder_list
            else f"{qc.placeholders} placeholder{'s' if qc.placeholders != 1 else ''}"
        )
        return negative_proof("sql_fixed_template_bound", (
            f"The query at line {j.line} is fixed SQL text with {placeholders}, {j.detail}, "
            f"executed by {execution.method} at line {execution.line}."
        ))
    return no_opinion()


def _summaries(ctx: Any, path: str, text: str) -> sq.SqlSummaries:
    """The scan's summaries when it built a call graph holding this file, else
    summaries over this one file."""
    scan = getattr(ctx, "sql", None)
    if scan is not None and path in getattr(scan.graph, "_file_imports", {}):
        return scan
    return sq.SqlSummaries.for_file(path, text)


def candidate_statements(
    text: str, lines: List[int], summaries: Optional[sq.SqlSummaries] = None, path: str = "",
) -> Tuple[Optional[sq.MethodContext], Any, List[Tuple[sq.StatementFact, sq.QueryFolder]]]:
    """The statements an anchor is about: those whose allocation, binds or
    executions sit on an anchor line, or whose query text is built there.
    Returns (method context, graph method or None, [(fact, folder)])."""
    method = summaries.method_for(path, lines[0]) if summaries is not None else None
    ctx = summaries.context(method) if method is not None else None
    if ctx is None:
        method = None
        ctx = sq.method_at(text, lines[0])
    if ctx is None:
        return None, None, []
    facts = sq.statements_in_method(ctx.node, ctx.src, ctx)
    out: List[Tuple[sq.StatementFact, sq.QueryFolder]] = []
    wanted = set(lines)
    for fact in facts:
        folder = summaries.folder(method, ctx) if method is not None else sq.QueryFolder(ctx)
        touched = set(sq.fact_lines(fact))
        for expr in [fact.query_expr] + [e.sql_arg for e in fact.executions]:
            if expr is not None:
                folder.fold(expr)
        touched |= folder.touched
        folder.touched = set()
        if touched & wanted:
            out.append((fact, folder))
    return ctx, method, out


def _invocation_at(ctx: sq.MethodContext, lines: List[int], facts: Optional[Dict[str, Any]]) -> Optional[Any]:
    """The call the anchor points at: the facts' resolved call, else the first
    invocation starting on the anchor line."""
    call = (facts or {}).get("call") or {}
    want_line, want_col = call.get("start_line"), call.get("start_col")
    first = None
    stack = [ctx.node]
    while stack:
        n = stack.pop()
        if n.type == "method_invocation":
            line = n.start_point[0] + 1
            if want_line and line == want_line and (want_col is None or n.start_point[1] == want_col):
                return n
            if line == lines[0] and (first is None or n.start_byte < first.start_byte):
                first = n
        stack.extend(n.children)
    return first


def decide(finding: Dict[str, Any], facts: Optional[Dict[str, Any]], text: str,
           summaries: Optional[sq.SqlSummaries] = None) -> ValidatorResult:
    lines = _anchor_lines(finding, facts)
    if not lines:
        return no_opinion()
    path = str(finding.get("file_path") or "")
    summaries = summaries or sq.SqlSummaries.for_file(path, text)
    ctx, method, candidates = candidate_statements(text, lines, summaries, path)
    if ctx is None:
        return no_opinion()
    if not candidates:
        # A call into a project method: judge what the callee does with it.
        invocation = _invocation_at(ctx, lines, facts) if method is not None else None
        judgement = summaries.judge_call(method, ctx, invocation) if invocation is not None else None
        return result_for(judgement, ctx) if judgement is not None else no_opinion()
    results = [
        result_for(sq.judge_statement(fact, ctx, folder, fields=summaries.field_judgement), ctx)
        for fact, folder in candidates
    ]
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
    return decide(finding, facts, text, _summaries(ctx, path, text))

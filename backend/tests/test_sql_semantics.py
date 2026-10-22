"""SQL semantics (SAST-02-010, SAST-02-020): the JDBC statements a method
prepares, binds and executes, and what kind of text each query is.

Table-driven over small fixtures, one construct each (synthetic re-creations of
the accuracy review's shapes). Needs tree-sitter and the engine's pipeline
modules; skipped cleanly when they are absent.
"""

import sys
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_java")
pytest.importorskip("boto3", reason="pipeline modules import llm_client")

_ENGINE = Path(__file__).resolve().parents[1] / "sast_engine"
if str(_ENGINE) not in sys.path:
    sys.path.insert(0, str(_ENGINE))

from pipeline import sql_semantics as sq  # noqa: E402

pytestmark = pytest.mark.unit

FIXTURES = Path(__file__).parent / "fixtures" / "sql_semantics"


def _text(name: str) -> str:
    return (FIXTURES / name).read_text()


def _line_of(text: str, needle: str, nth: int = 1) -> int:
    seen = 0
    for number, content in enumerate(text.splitlines(), start=1):
        if needle in content:
            seen += 1
            if seen == nth:
                return number
    raise AssertionError(f"{needle!r} not in fixture")


def _statements(name: str, needle: str):
    text = _text(name)
    ctx, facts = sq.statements_at(text, _line_of(text, needle))
    assert ctx is not None, f"no method at {needle!r}"
    return ctx, facts


# --- SAST-02-010: statement model ----------------------------------------------

def test_setobject_bound_fixed_query_is_one_statement():
    ctx, facts = _statements("BoundSetObject.java", "ps.setObject")
    assert len(facts) == 1
    fact = facts[0]
    assert fact.alloc == "prepareStatement"
    assert fact.query_expr.type == "string_literal"
    assert [b.index for b in fact.binds] == [1]
    assert [e.method for e in fact.executions] == ["executeQuery"]
    assert not fact.executions[0].has_sql_arg
    assert not fact.api_misuse
    assert fact.complete


def test_reassignment_starts_a_second_statement_with_its_own_binds():
    ctx, facts = _statements("Reassigned.java", "executeUpdate")
    assert len(facts) == 2
    first, second = facts
    assert "a = ?" in ctx.text(first.query_expr)
    assert "b = ?" in ctx.text(second.query_expr)
    assert [ctx.text(b.value) for b in first.binds] == ["a"]
    assert [ctx.text(b.value) for b in second.binds] == ["b"]
    assert len(first.executions) == len(second.executions) == 1


def test_bind_only_in_else_branch_has_a_different_branch_than_the_execution():
    ctx, facts = _statements("ElseBind.java", "executeUpdate")
    (fact,) = facts
    (bind,) = fact.binds
    (execution,) = fact.executions
    assert bind.branch != execution.branch
    assert not sq.encloses(bind.branch, execution.branch)
    assert bind.branch[-1][1] == "else"


def test_prepared_statement_executed_with_a_string_is_api_misuse():
    ctx, facts = _statements("ApiMisuse.java", "executeQuery")
    (fact,) = facts
    assert fact.api_misuse
    assert fact.executions[0].has_sql_arg


def test_commented_out_concatenation_is_not_part_of_the_query():
    ctx, facts = _statements("CommentedConcat.java", "prepareStatement")
    (fact,) = facts
    assert fact.query_expr.type == "string_literal"
    assert "+" not in ctx.text(fact.query_expr)
    assert [b.kind for b in fact.binds] == ["numeric"]


def test_field_statement_bound_in_another_method_is_incomplete():
    ctx, facts = _statements("FieldStatement.java", "insert.setString")
    (fact,) = facts
    assert fact.scope == "field"
    assert not fact.complete
    assert fact.alloc is None
    assert [b.index for b in fact.binds] == [1]
    assert [e.method for e in fact.executions] == ["addBatch"]

    ctx, facts = _statements("FieldStatement.java", "insert = c.prepareStatement")
    (fact,) = facts
    assert fact.scope == "field" and not fact.complete and fact.alloc == "prepareStatement"


def test_jdbc_template_with_args_is_bound():
    ctx, facts = _statements("JdbcTemplateBound.java", "WHERE id = ?")
    (fact,) = facts
    assert fact.alloc == "jdbc_template"
    assert fact.bound_by_args
    assert ctx.text(fact.query_expr) == '"SELECT name FROM t WHERE id = ?"'

    ctx, facts = _statements("JdbcTemplateBound.java", '"SELECT name FROM t"')
    (fact,) = facts
    assert not fact.bound_by_args


def test_plain_statement_query_is_the_execute_argument():
    ctx, facts = _statements("PlainStatement.java", "executeQuery")
    (fact,) = facts
    assert fact.statement_type == "java.sql.Statement"
    assert fact.query_expr.type == "binary_expression"
    assert not fact.api_misuse


def test_numeric_bind_kind_comes_from_facts():
    ctx, facts = _statements("NumericBound.java", "setLong")
    assert [b.kind for b in facts[0].binds] == ["numeric"]


def test_exclusive_arms_of_one_if():
    a = ((1, "then"),)
    b = ((1, "else"),)
    assert sq.exclusive(a, b)
    assert not sq.exclusive(a, a + ((2, "loop"),))
    assert not sq.exclusive((), a)

"""Occurrence facts (SAST-01-010): the resolved AST facts of one finding.

Table-driven over small fixtures, one construct each. Needs tree-sitter and
the engine's pipeline modules (which import `llm_client` -> boto3); skipped
cleanly when they are absent.
"""

import sys
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_java")
pytest.importorskip("tree_sitter_typescript")
pytest.importorskip("boto3", reason="pipeline modules import llm_client")

_ENGINE = Path(__file__).resolve().parents[1] / "sast_engine"
if str(_ENGINE) not in sys.path:
    sys.path.insert(0, str(_ENGINE))

from pipeline import occurrence_facts as of  # noqa: E402

pytestmark = pytest.mark.unit

FIXTURES = Path(__file__).parent / "fixtures" / "occurrence_facts"


def _load(rel: str) -> tuple[str, str]:
    path = FIXTURES / rel
    return path.name, path.read_text()


def _line_of(text: str, needle: str, nth: int = 1) -> int:
    seen = 0
    for number, content in enumerate(text.splitlines(), start=1):
        if needle in content:
            seen += 1
            if seen == nth:
                return number
    raise AssertionError(f"{needle!r} not in fixture")


def _facts(rel: str, needle: str, nth: int = 1, span_of: str | None = None, **kw):
    name, text = _load(rel)
    line = _line_of(text, needle, nth)
    span = None
    if span_of is not None:
        start = text.splitlines()[line - 1].index(span_of)
        span = (start, start + len(span_of))
    return of.facts_for(name, text, line, span, **kw)


def _kinds(facts):
    return [a["kind"] for a in facts["args"]]


# --- argument kinds ------------------------------------------------------------

def test_string_plus_numeric_folds_to_constant_plus_numeric():
    f = _facts("java/LogCount.java", "log.info(")
    assert _kinds(f) == ["constant+numeric"]
    assert f.call["callee"] == "info"
    assert f.call["receiver_fqn"] == "org.slf4j.Logger"


def test_logger_error_with_a_caught_exception_has_a_throwable_argument():
    f = _facts("java/LogThrowable.java", "log.error(")
    assert _kinds(f) == ["string_literal", "throwable"]


def test_multiline_call_is_one_call_node_spanning_three_lines():
    f = _facts("java/MultiLineLog.java", "log.warn(")
    assert f.call["callee"] == "warn"
    assert (f.call["start_line"], f.call["end_line"]) == (11, 13)
    assert f.call["arity"] == 3
    assert _kinds(f) == ["string_literal", "call_result", "call_result"]


def test_the_call_is_the_outermost_one_that_starts_on_the_anchor_line():
    # Line 13 starts its own invocation (`ex.getMessage()`); the logger call
    # started on line 11, so a finding anchored on line 13 gets the inner call.
    name, text = _load("java/MultiLineLog.java")
    f = of.facts_for(name, text, 13)
    assert f.call["callee"] == "getMessage"
    assert f.call["start_line"] == 13


def test_numeric_is_the_value_used_not_the_value_parsed():
    # `n` is parsed from `s`, but the first query concatenates `s`.
    first = _facts("java/ParsedString.java", "executeQuery", 1)
    second = _facts("java/ParsedString.java", "executeQuery", 2)
    assert _kinds(first) == ["constant+string_var"]
    assert _kinds(second) == ["constant+numeric"]


def test_constants_fold_across_static_final_fields_and_final_locals():
    f = _facts("java/Constants.java", "executeQuery(QUERY")
    assert _kinds(f) == ["constant"]


def test_bigdecimal_is_numeric_only_when_it_comes_from_a_numeric_source():
    param = _facts("java/Constants.java", 'executeQuery("a" + price')
    made = _facts("java/Constants.java", 'executeQuery("a" + made')
    assert _kinds(param) == ["constant+object"]
    assert _kinds(made) == ["constant+numeric"]


# --- declaration / stub / comment ------------------------------------------------

def test_a_method_declaration_line_is_a_declaration_not_a_call():
    f = _facts("java/Declaration.java", "public int deleteJob", span_of="deleteJob")
    assert f.is_declaration is True
    assert f.call is None
    assert f.enclosing["method"] == "deleteJob"
    assert f.is_stub is False


def test_a_call_inside_the_method_is_not_a_declaration():
    f = _facts("java/Declaration.java", "return remove(id)", span_of="remove")
    assert f.is_declaration is False
    assert f.call["callee"] == "remove"


@pytest.mark.parametrize(
    "needle, stub",
    [("boolean isReady", True), ("void todo()", True), ("int remove(int id)", False),
     ("public int deleteJob", False)],
)
def test_stub_bodies(needle, stub):
    f = _facts("java/Declaration.java", needle)
    assert f.is_stub is stub


def test_a_match_inside_a_comment_is_flagged():
    block = _facts("java/CommentMatch.java", "/* stmt.executeQuery", span_of="stmt")
    line = _facts("java/CommentMatch.java", "// stmt.executeQuery", span_of="stmt")
    live = _facts("java/CommentMatch.java", 'executeQuery("SELECT 1")', span_of="stmt")
    assert block.in_comment and line.in_comment
    assert not live.in_comment
    assert live.call["callee"] == "executeQuery"


# --- receiver types --------------------------------------------------------------

def test_system_out_resolves_to_printstream():
    f = _facts("java/Stdout.java", "System.out.println")
    assert f.call["receiver_fqn"] == "java.io.PrintStream"


def test_a_renamed_logger_field_still_resolves_to_the_logging_framework():
    f = _facts("java/Renamed.java", "AUDIT.info")
    assert f.call["receiver"] == "AUDIT"
    assert f.call["receiver_fqn"] == "org.apache.logging.log4j.Logger"


def test_lombok_log_field_resolves_to_slf4j():
    f = _facts("java/Lombok.java", "log.info")
    assert f.call["receiver_fqn"] == "org.slf4j.Logger"


def test_typescript_constructor_injected_service_resolves_its_type():
    f = _facts("ts/translate.component.ts", "this.translate.instant")
    assert f.call["callee"] == "instant"
    assert f.call["receiver_fqn"] == "TranslateService"
    assert f.call["receiver_module"] == "@ngx-translate/core"
    assert f.enclosing["owner"] == "TranslateComponent"


def test_typescript_console_receiver():
    f = _facts("ts/translate.component.ts", "console.log")
    assert f.call["receiver_fqn"] == "console"
    assert _kinds(f) == ["constant+numeric"]


# --- degradation -----------------------------------------------------------------

def test_a_file_that_does_not_parse_has_no_facts():
    assert of.facts_for("Broken.java", "class { broken", 1) is None


def test_an_unsupported_language_has_no_facts():
    assert of.facts_for("config.yaml", "a: b", 1) is None


def test_facts_stay_small():
    import json

    f = _facts("java/MultiLineLog.java", "log.warn(")
    assert len(json.dumps(f)) < 2000


# --- signature --------------------------------------------------------------------

def test_semantic_signature_separates_unlike_calls_and_unresolved():
    a = of.semantic_signature(_facts("java/LogCount.java", "log.info("))
    b = of.semantic_signature(_facts("java/Renamed.java", "AUDIT.info"))
    assert a != b
    assert of.semantic_signature(None) == of.UNRESOLVED_SIGNATURE
    stub = of.semantic_signature(_facts("java/Declaration.java", "boolean isReady"))
    impl = of.semantic_signature(_facts("java/Declaration.java", "int remove(int id)"))
    assert stub.endswith("|stub") and impl.endswith("|impl")

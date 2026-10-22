"""The `sql_binding` validator (SAST-02-030, SAST-02-040): a SQL-injection
finding is decided from the statement it points at — fixed text with every
placeholder bound is a proof of no injection, string-built text is a fact of
one, and anything the method cannot see is a named evidence gap.

Unit tests over the `sql_semantics` fixtures, plus the precedence against a
model verdict through `finding_facts.prepare_findings` (the real hook path).
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

from pipeline import finding_facts  # noqa: E402
from pipeline.validators import ValidatorContext  # noqa: E402
from pipeline.validators import sql_binding as sb  # noqa: E402

pytestmark = pytest.mark.unit

FIXTURES = Path(__file__).parent / "fixtures" / "sql_semantics"


def _line_of(text: str, needle: str) -> int:
    for number, content in enumerate(text.splitlines(), start=1):
        if needle in content and not content.lstrip().startswith("//"):
            return number
    raise AssertionError(f"{needle!r} not in fixture")


def _finding(name: str, needle: str, **over):
    text = (FIXTURES / name).read_text()
    finding = {
        "file_path": f"src/main/java/com/acme/dao/{name}", "line": _line_of(text, needle),
        "rule_id": "java-jdbc-prepare-concat", "cwe": "CWE-89", "verdict": "true_positive",
        "confidence": 0.9, "verdict_reason": "The model says the query is injectable.",
        "issue_class": "security", "kind": "llm",
    }
    finding.update(over)
    return finding, text


def _decide(name: str, needle: str, **over):
    finding, text = _finding(name, needle, **over)
    ctx = ValidatorContext(file_text={finding["file_path"]: text})
    return sb.sql_binding(finding, None, ctx)


# --- decisions ----------------------------------------------------------------

@pytest.mark.parametrize("name, needle, outcome, tag", [
    ("BoundSetObject.java", "prepareStatement", "negative_proof", "sql_fixed_template_bound"),
    ("BoundSetObject.java", "ps.setObject", "negative_proof", "sql_fixed_template_bound"),
    ("BoundSetObject.java", "executeQuery", "negative_proof", "sql_fixed_template_bound"),
    ("NumericBound.java", "setLong", "negative_proof", "sql_fixed_template_bound"),
    ("CommentedConcat.java", "prepareStatement", "negative_proof", "sql_fixed_template_bound"),
    ("ConstantSelect.java", "prepareStatement", "negative_proof", "sql_fixed_template_bound"),
    ("JdbcTemplateBound.java", "WHERE id = ?", "negative_proof", "sql_fixed_template_bound"),
    ("Reassigned.java", "b = ?", "negative_proof", "sql_fixed_template_bound"),
    ("ApiMisuse.java", "ps.executeQuery(COUNT_SQL)", "negative_proof", "sql_api_misuse_constant"),
    ("PlainStatement.java", "executeQuery", "positive_fact", "sql_dynamic_text"),
    ("MixedBoundAndConcat.java", "prepareStatement", "positive_fact", "sql_dynamic_text"),
    ("WrongStatementBound.java", "ps2.executeQuery", "positive_fact", "sql_dynamic_text"),
    ("LiveConcatBelowComment.java", "prepareStatement", "positive_fact", "sql_dynamic_text"),
    ("Queries.java", "Q:order-by", "positive_fact", "sql_dynamic_text"),
    ("Queries.java", "Q:raw-csv", "positive_fact", "sql_dynamic_text"),
    ("Queries.java", "Q:placeholder-loop", "evidence_gap", None),  # prepared, never assigned
    ("ElseBind.java", "executeUpdate", "no_opinion", None),  # unbound on the `if` path
])
def test_decision(name, needle, outcome, tag):
    result = _decide(name, needle)
    assert result.outcome == outcome, result
    assert result.reason_tag == tag


def test_the_proof_names_query_binds_and_execution():
    result = _decide("BoundSetObject.java", "prepareStatement")
    assert "line 10" in result.proof and "setObject (line 11)" in result.proof
    assert "executeQuery at line 12" in result.proof


def test_constant_api_misuse_is_quality_not_injection():
    result = _decide("ApiMisuse.java", "ps.executeQuery(COUNT_SQL)")
    assert result.issue_class == "quality"


def test_a_helper_built_query_is_a_named_evidence_gap():
    result = _decide("Queries.java", "Q:helper")
    assert result.outcome == "evidence_gap"
    assert "QueryHelper.getDefaultWhere" in result.missing


def test_a_field_statement_is_a_named_evidence_gap():
    result = _decide("FieldStatement.java", "insert.setString")
    assert result.outcome == "evidence_gap"
    assert "`insert` is a field of FieldStatement" in result.missing


def test_the_concatenation_line_of_a_query_variable_finds_its_statement():
    # `java-sql-string-concat` anchors on where the text is built, not where
    # it is executed.
    result = _decide("Queries.java", 'sql += " AND name')
    assert result.outcome == "positive_fact"


def test_an_anchor_on_no_statement_has_no_opinion():
    assert _decide("Queries.java", "private static final String BASE").outcome == "no_opinion"


def test_a_match_inside_a_comment_is_ruled_out():
    finding, text = _finding("CommentedConcat.java", "prepareStatement")
    ctx = ValidatorContext(file_text={finding["file_path"]: text})
    result = sb.sql_binding(finding, {"in_comment": True}, ctx)
    assert result.outcome == "negative_proof" and result.reason_tag == "sql_in_comment"


def test_non_java_files_get_no_opinion():
    finding, text = _finding("BoundSetObject.java", "prepareStatement", file_path="query.py")
    assert sb.sql_binding(finding, None, ValidatorContext(file_text={"query.py": text})).outcome == "no_opinion"


# --- precedence against the model, through the hook ----------------------------

def _prepare(name: str, needle: str, **over):
    finding, text = _finding(name, needle, **over)
    finding_facts.prepare_findings([finding], text, file_path=finding["file_path"])
    return finding


def test_a_model_true_positive_on_a_bound_query_becomes_a_false_positive():
    finding = _prepare("BoundSetObject.java", "prepareStatement")
    assert finding["verdict"] == "false_positive"
    assert finding["reason_tag"] == "sql_fixed_template_bound"
    assert finding["decisions"][-1]["stage"] == "validator"


def test_a_model_false_positive_on_a_concatenated_query_is_a_conflict():
    finding = _prepare("MixedBoundAndConcat.java", "prepareStatement", verdict="false_positive",
                       verdict_reason="a is bound with setString.")
    assert finding["verdict"] == "unverified"
    assert finding["unresolved_reason"] == "conflict"
    assert "a is bound with setString" in finding["verdict_reason"]


def test_a_model_true_positive_on_concatenation_keeps_its_verdict_and_gains_the_fact():
    finding = _prepare("PlainStatement.java", "executeQuery")
    assert finding["verdict"] == "true_positive"
    (outcome,) = finding["facts"]["validators"]
    assert outcome["reason_tag"] == "sql_dynamic_text"


def test_api_misuse_with_constant_text_moves_to_the_quality_class():
    finding = _prepare("ApiMisuse.java", "ps.executeQuery(COUNT_SQL)")
    assert finding["verdict"] == "false_positive" and finding["issue_class"] == "quality"


def test_the_validator_runs_for_any_cwe_89_finding_whatever_its_rule():
    finding = _prepare("BoundSetObject.java", "prepareStatement", rule_id="llm-extra")
    assert finding["reason_tag"] == "sql_fixed_template_bound"


# --- SAST-02-040: numbers and stored strings --------------------------------------

@pytest.mark.parametrize("marker, outcome, tag", [
    ("numeric", "negative_proof", "sql_numeric_only"),
    ("inline-parse", "negative_proof", "sql_numeric_only"),
    ("parse-ignored", "positive_fact", "sql_dynamic_text"),
    ("stored-string", "positive_fact", "sql_second_order"),
    ("stored-inline", "positive_fact", "sql_second_order"),
    ("stored-field", "positive_fact", "sql_second_order"),
    ("stored-numeric", "negative_proof", "sql_numeric_only"),
    ("stored-int-inline", "negative_proof", "sql_numeric_only"),
    ("bigdecimal", "negative_proof", "sql_numeric_only"),
])
def test_numeric_and_stored_values(marker, outcome, tag):
    result = _decide("NumericAndStored.java", f"// N:{marker}")
    assert (result.outcome, result.reason_tag) == (outcome, tag), result


def test_a_numeric_only_query_is_quality_with_the_hygiene_reason():
    result = _decide("NumericAndStored.java", "// N:numeric")
    assert result.issue_class == "quality"
    assert result.proof.startswith("Parameterisation hygiene: numeric value concatenated; bind it.")


def test_the_bigdecimal_proof_notes_scientific_notation():
    assert "scientific notation" in _decide("NumericAndStored.java", "// N:bigdecimal").proof


def test_a_numeric_only_model_true_positive_moves_out_of_the_security_class():
    finding = _prepare("NumericAndStored.java", "// N:numeric")
    assert finding["verdict"] == "false_positive" and finding["issue_class"] == "quality"
    assert finding["reason_tag"] == "sql_numeric_only"

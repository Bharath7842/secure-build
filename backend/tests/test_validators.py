"""The occurrence validator hook and its precedence against a model verdict
(SAST-01-020). Needs tree-sitter and the engine's pipeline modules."""

import sys
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_java")
pytest.importorskip("boto3", reason="pipeline modules import llm_client")

_ENGINE = Path(__file__).resolve().parents[1] / "sast_engine"
if str(_ENGINE) not in sys.path:
    sys.path.insert(0, str(_ENGINE))

from pipeline import finding_facts, llm_file_scan, validators  # noqa: E402
from pipeline.regex_scan import RegexRule  # noqa: E402
from pipeline.validators import (  # noqa: E402
    Validator,
    ValidatorContext,
    evidence_gap,
    negative_proof,
    no_opinion,
    positive_fact,
)

pytestmark = pytest.mark.unit

FIXTURES = Path(__file__).parent / "fixtures" / "validators"


def _fake(name, result, *, version=1):
    return Validator(name=name, version=version, fn=lambda f, facts, ctx: result,
                     rule_prefixes=("runtime-sink-",))


def _finding(verdict="true_positive", reason="The model says so.", **extra):
    return {
        "rule_id": "runtime-sink-sql-deleteJob", "cwe": "CWE-89", "line": 4, "file_path": "x/Dao.java",
        "verdict": verdict, "confidence": 0.9 if verdict != "unverified" else None,
        "verdict_reason": reason, "kind": "llm", **extra,
    }


def _apply(finding, *fakes):
    results = validators.run_validators(finding, finding.get("facts"), ValidatorContext(), validators=list(fakes))
    validators.apply_precedence(finding, results)
    return finding


# --- the precedence table ----------------------------------------------------------

@pytest.mark.parametrize("verdict", ["true_positive", "false_positive", "unverified"])
def test_a_negative_proof_makes_any_verdict_a_false_positive(verdict):
    f = _apply(_finding(verdict), _fake("v", negative_proof("some_tag", "It is a declaration.")))
    assert f["verdict"] == "false_positive"
    assert f["verdict_reason"] == "It is a declaration."
    assert f["reason_tag"] == "some_tag"
    assert f["unresolved_reason"] is None
    assert f["decisions"][-1]["stage"] == "validator"
    assert f["decisions"][-1]["actor"] == "v@1"


def test_a_positive_fact_against_a_model_dismissal_is_a_conflict_keeping_both_reasons():
    f = _apply(_finding("false_positive", "Looks numeric."), _fake("v", positive_fact("t", "A string is concatenated.")))
    assert f["verdict"] == "unverified"
    assert f["unresolved_reason"] == "conflict"
    assert "Looks numeric." in f["verdict_reason"]
    assert "A string is concatenated." in f["verdict_reason"]


@pytest.mark.parametrize("verdict", ["true_positive", "unverified"])
def test_a_positive_fact_leaves_other_verdicts_unchanged_and_keeps_the_proof(verdict):
    f = _apply(_finding(verdict), _fake("v", positive_fact("t", "A string is concatenated.")))
    assert f["verdict"] == verdict
    assert f["facts"]["validators"][0]["proof"] == "A string is concatenated."


@pytest.mark.parametrize("verdict", ["true_positive", "false_positive", "unverified"])
def test_an_evidence_gap_makes_any_verdict_unresolved_naming_what_is_missing(verdict):
    f = _apply(_finding(verdict), _fake("v", evidence_gap("callee RequestsMgr.getCommMethod(String) body not resolved")))
    assert f["verdict"] == "unverified"
    assert f["unresolved_reason"] == "evidence_missing"
    assert "RequestsMgr.getCommMethod(String)" in f["verdict_reason"]


def test_no_opinion_changes_nothing():
    before = _finding()
    f = _apply(dict(before), _fake("v", no_opinion()))
    assert {k: f[k] for k in before} == before
    assert "decisions" not in f


def test_negative_outranks_positive_which_outranks_a_gap():
    f = _apply(_finding("false_positive"), _fake("a", evidence_gap("x")), _fake("b", positive_fact("t", "p")))
    assert f["unresolved_reason"] == "conflict"
    f = _apply(_finding("true_positive"), _fake("a", evidence_gap("x")), _fake("b", positive_fact("t", "p")),
               _fake("c", negative_proof("n", "no")))
    assert f["verdict"] == "false_positive"


def test_a_validator_that_raises_has_no_opinion():
    def boom(f, facts, ctx):
        raise RuntimeError("bug in a check")

    before = _finding()
    f = _apply(dict(before), Validator(name="boom", version=1, fn=boom, rule_prefixes=("runtime-sink-",)))
    assert f["verdict"] == "true_positive"


def test_a_validator_needs_a_selector():
    with pytest.raises(ValueError):
        validators.register("blind")(lambda f, facts, ctx: no_opinion())


def test_selectors_match_exact_ids_prefixes_and_cwes():
    v = Validator("v", 1, lambda *a: no_opinion(), rule_ids=("exact-rule",), rule_prefixes=("pre-",), cwes=(89,))
    assert v.matches({"rule_id": "exact-rule"})
    assert v.matches({"rule_id": "pre-anything"})
    assert v.matches({"rule_id": "other", "cwe": "CWE-089"})
    assert not v.matches({"rule_id": "other", "cwe": "CWE-79"})


def test_reapplying_after_a_later_stage_sets_a_model_verdict():
    f = _apply(_finding("unverified", unresolved_reason="not_reviewed_regex"),
               _fake("v", positive_fact("t", "A string is concatenated.")))
    f.update(verdict="false_positive", verdict_reason="The group looks safe.")
    assert validators.reapply_precedence(f) is True
    assert f["verdict"] == "unverified" and f["unresolved_reason"] == "conflict"


# --- the shipped validators ----------------------------------------------------------

_RULE = RegexRule({
    "id": "runtime-sink-sql-deleteJob", "title": "Project wrapper deleteJob reaches a sql sink",
    "cwe": "CWE-89", "severity": "HIGH", "pattern": r"\bdeleteJob\s*\(", "languages": ["java"],
    "group_by_rule": True, "derived": True,
})


def _hits(text):
    from pipeline import regex_scan

    return regex_scan.scan_text_by_rule(text, _RULE)


def _regex_findings(name):
    text = (FIXTURES / name).read_text()
    findings = llm_file_scan.findings_from_hits(
        file_path=f"src/{name}", source_text=text, hits=_hits(text), rules_by_id={_RULE.id: _RULE},
    )
    return text, findings


def test_declaration_not_call_dismisses_the_declaration_and_leaves_the_call_site():
    text, findings = _regex_findings("JobDao.java")
    by_line = {f["line"]: f for f in findings}
    declaration = by_line[4]
    assert declaration["verdict"] == "false_positive"
    assert declaration["reason_tag"] == "match_is_declaration"
    assert declaration["kind"] == "regex"
    assert "deleteJob" in declaration["verdict_reason"]
    call_site = by_line[9]
    # Not dismissed as a declaration. (Since EPIC-02 the SQL check judges it from
    # deleteJob's own body, which hands only constant SQL and a number on.)
    assert call_site.get("reason_tag") != "match_is_declaration"
    assert call_site["reason_tag"] == "sql_fixed_template_bound"


def test_stub_method_dismisses_the_stub_but_not_the_real_implementation():
    _text, stub = _regex_findings("JobStub.java")
    _text, impl = _regex_findings("JobDao.java")
    assert stub[0]["verdict"] == "false_positive" and stub[0]["reason_tag"] == "stub_no_sink"
    # JobDao's call site (a real method body) is untouched by the stub check.
    call_site = [f for f in impl if f["line"] == 9][0]
    assert call_site.get("reason_tag") != "stub_no_sink"


def test_the_toggle_off_skips_facts_and_validators_entirely():
    text = (FIXTURES / "JobDao.java").read_text()
    findings = llm_file_scan.findings_from_hits(
        file_path="src/JobDao.java", source_text=text, hits=_hits(text),
        rules_by_id={_RULE.id: _RULE}, occurrence_validators=False,
    )
    assert all(f["verdict"] == "unverified" for f in findings)
    assert all("reason_tag" not in f for f in findings)


def test_findings_without_facts_are_judged_exactly_as_before():
    # An unsupported language has no facts; the validators have no opinion.
    f = _finding("unverified", unresolved_reason="not_reviewed_regex", file_path="conf/app.properties")
    finding_facts.prepare_findings([f], "a=b\n", file_path="conf/app.properties")
    assert f["verdict"] == "unverified" and "facts" not in f


def test_validators_register_stub_before_declaration():
    names = [v.name for v in validators.registered()]
    assert names.index("stub_method") < names.index("declaration_not_call")


def test_counts_each_outcome_in_usage():
    usage = {}
    text, _ = _regex_findings("JobDao.java")
    llm_file_scan.findings_from_hits(
        file_path="src/JobDao.java", source_text=text, hits=_hits(text),
        rules_by_id={_RULE.id: _RULE}, usage=usage,
    )
    counters = usage["_counters"]["validators"]
    assert counters["declaration_not_call.negative_proof"] == 1
    assert counters["declaration_not_call.no_opinion"] == 1

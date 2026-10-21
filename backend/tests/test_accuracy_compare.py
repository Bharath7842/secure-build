"""The pure parts of the accuracy harness: case loading and finding comparison.
No scan runs here, so this is part of the default suite."""

from pathlib import Path

import pytest

from accuracy.case import CaseError, Expected, discover_cases, load_case
from accuracy.case import Case
from accuracy.runner import compare

CORPUS = Path(__file__).parent / "accuracy_corpus"
F = "src/A.java"


def _case(*expected, allow_absent=False):
    return Case(
        id="c", area="a", polarity="positive", adjudication="dev_label_only",
        directory=Path("."), expected=list(expected), allow_absent=allow_absent,
    )


def _finding(line, verdict="true_positive", rule="r1", cwe="CWE-89", path=F, **extra):
    return {
        "file_path": path, "line": line, "rule_id": rule, "cwe": cwe, "verdict": verdict,
        "issue_class": "security", "unresolved_reason": None, "verdict_reason": "because", **extra,
    }


def test_a_matching_finding_passes():
    expected = Expected(file=F, sink_line=10, verdict="true_positive", rule_id="r1")
    assert compare(_case(expected), [_finding(11)]) == ([], [], [])


def test_the_sink_line_has_a_two_line_tolerance():
    expected = Expected(file=F, sink_line=10, verdict="true_positive", rule_id="r1")
    assert compare(_case(expected), [_finding(13)])[0]  # outside it: missing
    assert compare(_case(expected), [_finding(12)]) == ([], [], [])


def test_a_cwe_can_identify_a_finding_instead_of_a_rule():
    expected = Expected(file=F, sink_line=10, verdict="true_positive", cwe="cwe-89")
    assert compare(_case(expected), [_finding(10, rule="llm-extra")]) == ([], [], [])


def test_missing_unexpected_and_mismatched_are_told_apart():
    expected = [
        Expected(file=F, sink_line=10, verdict="true_positive", rule_id="r1"),
        Expected(file=F, sink_line=50, verdict="true_positive", rule_id="r2"),
    ]
    findings = [_finding(10, verdict="false_positive"), _finding(90, rule="r9", cwe="CWE-1")]
    missing, unexpected, mismatches = compare(_case(*expected), findings)
    assert len(missing) == 1 and "r2" in missing[0]
    assert len(unexpected) == 1 and "r9" in unexpected[0]
    assert len(mismatches) == 1 and "expected true_positive, got false_positive" in mismatches[0]


def test_the_candidate_naming_the_expected_rule_wins_over_a_near_one():
    expected = Expected(file=F, sink_line=13, verdict="true_positive", rule_id="exec")
    findings = [
        _finding(11, rule="concat"),  # same CWE, two lines away
        _finding(13, rule="exec", verdict="false_positive"),
    ]
    missing, unexpected, mismatches = compare(_case(expected), findings)
    assert missing == [] and len(mismatches) == 1
    assert [u for u in unexpected if "concat" in u]  # the other one stays unexpected


def test_a_negative_may_be_absent_only_when_allowed():
    expected = Expected(file=F, sink_line=10, verdict="false_positive", rule_id="r1")
    assert compare(_case(expected), [])[0]
    assert compare(_case(expected, allow_absent=True), []) == ([], [], [])


def test_issue_class_unresolved_reason_and_reason_tag_are_checked():
    expected = Expected(
        file=F, sink_line=10, verdict="unverified", rule_id="r1", issue_class="quality",
        unresolved_reason="llm_missing_verdict", reason_tag="setString",
    )
    finding = _finding(10, verdict="unverified")
    _missing, _unexpected, mismatches = compare(_case(expected), [finding])
    assert len(mismatches) == 3
    ok = _finding(
        10, verdict="unverified", issue_class="quality", unresolved_reason="llm_missing_verdict",
        verdict_reason="binds with SETSTRING",
    )
    assert compare(_case(expected), [ok]) == ([], [], [])


# --- loading ---------------------------------------------------------------

def test_every_committed_case_loads():
    cases = discover_cases(CORPUS)
    assert len(cases) >= 8
    assert {c.polarity for c in cases} == {"positive", "negative", "uncertain"}
    for case in cases:
        assert case.source_dir.is_dir()
        assert case.limitations["parallel-scan-stages"] is False


def _write_case(tmp_path, body):
    directory = tmp_path / "c1"
    (directory / "repo").mkdir(parents=True)
    (directory / "case.yaml").write_text(body, encoding="utf-8")
    return directory


GOOD = """
id: c1
area: demo
polarity: positive
adjudication: dev_label_only
expected:
  - {rule_id: r, file: A.java, sink_line: 3, verdict: true_positive}
"""


def test_a_valid_case_loads(tmp_path):
    case = load_case(_write_case(tmp_path, GOOD))
    assert case.expected[0].rule_id == "r" and case.adjudication == "dev_label_only"


@pytest.mark.parametrize("old,new,message", [
    ("polarity: positive", "polarity: maybe", "polarity"),
    ("adjudication: dev_label_only", "adjudication: sure", "adjudication"),
    ("id: c1", "id: other", "directory name"),
    ("verdict: true_positive", "verdict: tp", "verdict"),
    ("{rule_id: r, file", "{file", "rule_id"),
])
def test_an_invalid_case_is_rejected(tmp_path, old, new, message):
    with pytest.raises(CaseError, match=message):
        load_case(_write_case(tmp_path, GOOD.replace(old, new)))

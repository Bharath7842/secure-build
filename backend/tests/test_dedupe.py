"""De-duplication keeps distinct sinks and records conflicts (SAST-01-050)."""

import sys
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_java")
pytest.importorskip("boto3", reason="pipeline modules import llm_client")

_ENGINE = Path(__file__).resolve().parents[1] / "sast_engine"
if str(_ENGINE) not in sys.path:
    sys.path.insert(0, str(_ENGINE))

from pipeline import finding_facts, llm_file_scan as lfs  # noqa: E402

pytestmark = pytest.mark.unit

JAVA = """\
package com.acme;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Report {
    private static final Logger log = LoggerFactory.getLogger(Report.class);

    void run(int count, Exception ex) {
        log.info("rows " + count);
        log.warn("failed {}", ex.getMessage());
        log.error("again {}", ex.getMessage());
    }
}
"""
COUNT_LINE, MESSAGE_LINE, AGAIN_LINE = 10, 11, 12


def _f(line, verdict="true_positive", **extra):
    f = {
        "rule_id": "java-log-injection-unsanitized-input", "cwe": "CWE-117", "line": line,
        "file_path": "Report.java", "title": "Log injection", "verdict": verdict,
        "severity": "MEDIUM", "confidence": 0.8, "verdict_reason": f"reason for {verdict}",
        "kind": "llm", **extra,
    }
    finding_facts.attach_facts(f, JAVA, file_path="Report.java")
    return f


def test_adjacent_calls_stay_separate_findings():
    merged = lfs.merge_dedupe([_f(COUNT_LINE), _f(MESSAGE_LINE)])
    assert [f["line"] for f in merged] == [COUNT_LINE, MESSAGE_LINE]


def test_the_same_call_reported_twice_is_one_finding_and_remembers_the_duplicate():
    merged = lfs.merge_dedupe([_f(MESSAGE_LINE, severity="LOW"), _f(MESSAGE_LINE, severity="HIGH")])
    assert len(merged) == 1 and merged[0]["severity"] == "HIGH"
    step = merged[0]["decisions"][-1]
    assert step["stage"] == "dedupe" and step["detail"]["discarded_verdict"] == "true_positive"


def test_a_validator_proof_beats_a_bare_model_confirmation():
    proven = _f(MESSAGE_LINE, "false_positive")
    proven["facts"]["validators"] = [{"validator": "v", "version": 1, "outcome": "negative_proof",
                                      "reason_tag": "t", "proof": "p"}]
    proven["reason_tag"] = "t"
    merged = lfs.merge_dedupe([_f(MESSAGE_LINE, "true_positive"), proven])
    assert len(merged) == 1 and merged[0]["verdict"] == "false_positive"


def test_more_evidence_wins_between_a_confirmation_and_a_dismissal():
    full = _f(MESSAGE_LINE, "true_positive", source="ex (parameter)", sink="log.warn",
              data_flow="ex message reaches the log")
    bare = _f(MESSAGE_LINE, "false_positive")
    for pair in ([full, bare], [bare, full]):
        merged = lfs.merge_dedupe([dict(p) for p in pair])
        assert len(merged) == 1 and merged[0]["verdict"] == "true_positive"


def test_equal_evidence_is_an_unresolved_conflict_keeping_both_reasons():
    usage = {}
    merged = lfs.merge_dedupe([_f(MESSAGE_LINE, "true_positive"), _f(MESSAGE_LINE, "false_positive")], usage=usage)
    assert len(merged) == 1
    assert merged[0]["verdict"] == "unverified" and merged[0]["unresolved_reason"] == "conflict"
    assert "reason for true_positive" in merged[0]["verdict_reason"]
    assert "reason for false_positive" in merged[0]["verdict_reason"]
    assert merged[0]["decisions"][-1]["detail"]["conflict"] is True
    assert usage["_counters"]["dedupe_conflicts"]["total"] == 1


def test_the_same_verdict_at_different_severities_keeps_the_higher_one():
    merged = lfs.merge_dedupe([_f(AGAIN_LINE, severity="LOW"), _f(AGAIN_LINE, severity="CRITICAL")])
    assert merged[0]["severity"] == "CRITICAL"


def test_without_facts_merging_falls_back_to_the_line_window():
    a = {"rule_id": "a", "line": 10, "cwe": "CWE-89", "verdict": "true_positive", "severity": "LOW", "title": "x"}
    b = {"rule_id": "b", "line": 12, "cwe": "CWE-89", "verdict": "true_positive", "severity": "HIGH", "title": "y"}
    assert len(lfs.merge_dedupe([a, b])) == 1


def test_an_undecided_answer_is_still_never_replaced_by_a_dismissal():
    merged = lfs.merge_dedupe([_f(MESSAGE_LINE, "false_positive"), _f(MESSAGE_LINE, "unverified", confidence=None)])
    assert merged[0]["verdict"] == "unverified"


def test_output_order_is_by_line_then_rule():
    merged = lfs.merge_dedupe([_f(AGAIN_LINE), _f(COUNT_LINE), _f(MESSAGE_LINE)])
    assert [f["line"] for f in merged] == [COUNT_LINE, MESSAGE_LINE, AGAIN_LINE]

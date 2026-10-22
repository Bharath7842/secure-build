"""Pre-publication explanation consistency check (SAST-01-090): each check, the
single targeted retry, and the rule that a contradiction is never a dismissal."""

import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_java")
pytest.importorskip("boto3", reason="pipeline modules import llm_client")

_ENGINE = Path(__file__).resolve().parents[1] / "sast_engine"
if str(_ENGINE) not in sys.path:
    sys.path.insert(0, str(_ENGINE))

from pipeline import explanation_check as ec, finding_facts, llm_file_scan as lfs  # noqa: E402

pytestmark = pytest.mark.unit

JAVA = """\
package com.acme.dao;

import java.sql.Statement;

public class OrderDao {
    public void find(Statement stmt, String name, Exception ex) throws Exception {
        stmt.executeQuery("SELECT * FROM t WHERE n = '" + name + "'");
        logger.error(msg, ex);
    }
}
"""
QUERY_LINE, LOG_LINE = 7, 8


def _finding(line=QUERY_LINE, **extra):
    f = {
        "rule_id": "llm-extra", "cwe": "CWE-89", "line": line, "file_path": "OrderDao.java",
        "title": "SQL injection", "severity": "HIGH", "verdict": "true_positive", "confidence": 0.9,
        "sink": "stmt.executeQuery", "source": "name (method parameter)",
        "verdict_reason": "The name is concatenated into the query text.", "ai_fix": "Bind the name.",
        "kind": "llm", **extra,
    }
    finding_facts.attach_facts(f, JAVA, file_path="OrderDao.java")
    return f


def _checks(finding):
    return {c["check"] for c in ec.check_explanation(finding, finding.get("facts"), JAVA)}


# --- one test per check ---------------------------------------------------------------

def test_a_consistent_finding_has_no_contradictions():
    assert _checks(_finding()) == set()


def test_1_the_named_sink_is_not_in_the_anchored_call():
    assert _checks(_finding(sink="log.warn(message)")) == {ec.CHECK_SINK}
    assert _checks(_finding(line=LOG_LINE, sink="stmt.executeQuery")) == {ec.CHECK_SINK}


def test_1_a_prose_sink_cannot_be_judged_and_is_left_alone():
    assert _checks(_finding(sink="the database call in OrderDao.find")) == set()


def test_2_the_named_source_is_not_in_the_method():
    assert _checks(_finding(source='request.getParameter("id")')) == {ec.CHECK_SOURCE}
    assert _checks(_finding(source="name (method parameter)")) == set()


def test_3_a_true_positive_whose_reason_says_it_is_safe():
    f = _finding(verdict_reason="The query is parameterized, so there is no injection risk.")
    assert _checks(f) == {ec.CHECK_REASON}


def test_3_a_negated_phrase_is_not_a_contradiction():
    assert _checks(_finding(verdict_reason="The query is not parameterized.")) == set()


def test_3_a_false_positive_whose_reason_asserts_exploitation():
    f = _finding(verdict="false_positive", verdict_reason="An attacker can control the name.")
    assert _checks(f) == {ec.CHECK_REASON}
    assert _checks(_finding(verdict="false_positive", verdict_reason="An attacker cannot reach it.")) == set()


def test_4_the_suggested_fix_is_already_the_code():
    f = _finding(line=LOG_LINE, sink="logger.error", source="",
                 ai_fix="Pass the exception: `logger.error(msg, ex)`.", cwe="CWE-532")
    assert _checks(f) == {ec.CHECK_FIX}
    assert _checks(_finding(line=LOG_LINE, sink="logger.error", source="", cwe="CWE-532",
                            ai_fix="Use `logger.error(sanitize(msg), ex)`.")) == set()


def test_5_a_no_callers_claim_is_unproven_while_the_call_graph_is_incomplete():
    f = _finding(verdict="false_positive", verdict_reason="The method has no callers, so it is dead code.")
    assert _checks(f) == {ec.CHECK_CALLERS}
    assert ec.check_explanation(f, f["facts"], JAVA, call_graph_complete=True) == []


def test_an_undecided_finding_has_no_explanation_to_check():
    assert _checks(_finding(verdict="unverified", sink="log.warn(x)")) == set()


def test_marking_a_contradiction_is_unresolved_never_a_dismissal():
    f = _finding(sink="log.warn(message)")
    ec.annotate([f], JAVA)
    ec.mark_contradicted(f)
    assert f["verdict"] == "unverified" and f["unresolved_reason"] == "explanation_contradiction"
    assert "does not contain it" in f["verdict_reason"]
    assert f["decisions"][-1]["stage"] == "explanation_retry"


# --- the retry, through scan_file --------------------------------------------------------

def _raw(**over):
    base = {
        "line": QUERY_LINE, "verdict": "true_positive", "confidence": 0.9, "rule_id": "llm-extra",
        "severity": "HIGH", "cwe": "CWE-89", "title": "SQL injection",
        "owasp_category": "A03:2021-Injection", "source": "name (method parameter)",
        "sink": "stmt.executeQuery", "data_flow": "name reaches the query",
        "snippet": 'stmt.executeQuery("SELECT * FROM t WHERE n = \'" + name + "\'");',
        "verdict_reason": "The name is concatenated into the query text.", "ai_fix": "Bind the name.",
    }
    return {**base, **over}


class Provider:
    def __init__(self, *answers):
        self.answers, self.users = list(answers), []

    def __call__(self, system, user, **kwargs):
        self.users.append(user)
        return json.dumps({"findings": [self.answers[min(len(self.users) - 1, len(self.answers) - 1)]]})


def _scan(tmp_path, provider, usage=None):
    path = tmp_path / "src/main/java/com/acme/dao/OrderDao.java"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(JAVA, encoding="utf-8")
    return lfs.scan_file(
        repo_root=tmp_path, rel_path="src/main/java/com/acme/dao/OrderDao.java", rules=[],
        call_llm_fn=provider, usage=usage if usage is not None else {},
    )


BAD = {"sink": "log.warn(message)"}


def test_a_consistent_response_costs_no_retry(tmp_path):
    provider = Provider(_raw())
    result = _scan(tmp_path, provider)
    assert len(provider.users) == 1
    assert result["findings"][0]["verdict"] == "true_positive"


def test_a_contradiction_gets_one_retry_naming_it_and_a_consistent_answer_is_published(tmp_path):
    usage = {}
    provider = Provider(_raw(**BAD), _raw())
    result = _scan(tmp_path, provider, usage)
    assert len(provider.users) == 2
    assert "Deterministic facts:" in provider.users[1]
    assert "does not contain it" in provider.users[1] and "Deterministic facts:" not in provider.users[0]
    (finding,) = result["findings"]
    assert finding["verdict"] == "true_positive" and finding["sink"] == "stmt.executeQuery"
    # The query really is concatenated, so the SQL validator records its fact
    # first (EPIC-02); the explanation retry follows it.
    assert [d["stage"] for d in finding["decisions"]] == ["validator", "explanation_retry"]
    counters = usage["_counters"]["explanation_contradictions"]
    assert counters["retries"] == 1 and counters["retry_resolved"] == 1 and counters["sink_not_on_line"] >= 1


def test_a_retry_that_still_contradicts_leaves_the_finding_unresolved(tmp_path):
    provider = Provider(_raw(**BAD), _raw(**BAD))
    result = _scan(tmp_path, provider)
    assert len(provider.users) == 2  # one retry, no more
    (finding,) = result["findings"]
    assert finding["verdict"] == "unverified"
    assert finding["unresolved_reason"] == "explanation_contradiction"


def test_a_contradicted_false_positive_is_never_made_a_true_positive_or_dropped(tmp_path):
    provider = Provider(_raw(verdict="false_positive", confidence=0.9,
                             verdict_reason="An attacker can control the name, but it is escaped.", ai_fix=None))
    result = _scan(tmp_path, provider)
    (finding,) = result["findings"]
    # Undecided, never a true positive and never dropped. The reason is the
    # stronger one: a deterministic fact (the query is concatenated) disagrees
    # with the dismissal, which outranks the contradicted explanation.
    assert finding["verdict"] == "unverified" and finding["unresolved_reason"] == "conflict"


def test_without_budget_there_is_no_retry_and_the_finding_is_unresolved(tmp_path, monkeypatch):
    monkeypatch.setattr(lfs, "stage_has_budget", lambda usage, step: False)
    provider = Provider(_raw(**BAD), _raw())
    result = _scan(tmp_path, provider)
    assert len(provider.users) == 1
    (finding,) = result["findings"]
    assert finding["verdict"] == "unverified" and finding["unresolved_reason"] == "explanation_contradiction"


def test_with_the_validators_off_nothing_is_checked(tmp_path):
    path = tmp_path / "src/main/java/com/acme/dao/OrderDao.java"
    path.parent.mkdir(parents=True)
    path.write_text(JAVA, encoding="utf-8")
    provider = Provider(_raw(**BAD))
    result = lfs.scan_file(
        repo_root=tmp_path, rel_path="src/main/java/com/acme/dao/OrderDao.java", rules=[],
        call_llm_fn=provider, usage={}, occurrence_validators=False,
    )
    assert len(provider.users) == 1 and result["findings"][0]["verdict"] == "true_positive"

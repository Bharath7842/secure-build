"""The publication filters (SAST-01-030, SAST-01-040): a logger-line check
decided by CWE and resolved receiver type, and noisy-rule publication that
needs evidence instead of confidence."""

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

LOGGER_JAVA = """\
package com.acme;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Auth {
    private static final Logger AUDIT = LoggerFactory.getLogger(Auth.class);

    void login(String user, String pwd) {
        AUDIT.info("login " + user + " password=" + pwd);
    }
}
"""
LOGGER_LINE = 10


def _finding(cwe, line=LOGGER_LINE, verdict="true_positive", **extra):
    return {
        "rule_id": "llm-extra", "cwe": cwe, "line": line, "file_path": "src/Auth.java",
        "title": "x", "verdict": verdict, "confidence": 0.9, "snippet": "placeholder",
        "severity": "HIGH", "kind": "llm", **extra,
    }


def _decide(finding, text=LOGGER_JAVA, *, with_facts=True, usage=None):
    if with_facts:
        finding_facts.attach_facts(finding, text, file_path="src/Auth.java")
    context = lfs.build_code_context(text, finding["line"], finding["snippet"])
    return lfs.publish_decision(finding, context, usage=usage)


# --- SAST-01-030 ------------------------------------------------------------------

@pytest.mark.parametrize("cwe", ["CWE-532", "CWE-117", "CWE-312", "CWE-313", "CWE-359",
                                 "CWE-200", "CWE-209", "CWE-497", "CWE-798"])
def test_secret_and_log_forging_classes_are_published_on_a_log_line(cwe):
    assert _decide(_finding(cwe)) == lfs.PUBLISH


def test_a_renamed_logger_is_recognised_by_its_resolved_type():
    # AUDIT is not called "logger"/"log"; the SQLi blamed on it is still a log line.
    usage = {}
    assert _decide(_finding("CWE-89"), usage=usage) == lfs.DROP
    assert usage["_counters"]["publish_filter"]["logging_line_dropped.CWE-89"] == 1
    assert usage["_records"]["publish_filter_drops"][0]["cwe"] == "CWE-89"


@pytest.mark.parametrize("cwe", ["CWE-89", "CWE-79", "CWE-78", "CWE-22", "CWE-611", "CWE-918", "CWE-502", "CWE-90"])
def test_sink_classes_a_log_call_cannot_be_are_dropped(cwe):
    assert _decide(_finding(cwe)) == lfs.DROP


def test_a_finding_with_no_cwe_is_not_dropped_by_the_logging_check():
    f = _finding(None)
    finding_facts.attach_facts(f, LOGGER_JAVA, file_path="src/Auth.java")
    context = lfs.build_code_context(LOGGER_JAVA, f["line"], "placeholder")
    assert lfs.publish_decision(f, context, suppress_no_cwe=False) == lfs.PUBLISH


def test_without_facts_the_spelling_regex_is_the_fallback_and_cwe_still_gates():
    src = 'x\nlogger.error("pwd=" + pwd);\n'
    sqli = _finding("CWE-89", line=2, snippet='logger.error("pwd=" + pwd);')
    secret = _finding("CWE-532", line=2, snippet='logger.error("pwd=" + pwd);')
    assert _decide(sqli, src, with_facts=False) == lfs.DROP
    assert _decide(secret, src, with_facts=False) == lfs.PUBLISH


def test_a_non_logger_receiver_with_a_logger_like_name_is_not_a_log_call():
    src = LOGGER_JAVA.replace("AUDIT.info(", "audit.info(").replace(
        "private static final Logger AUDIT = LoggerFactory.getLogger(Auth.class);",
        "private Auditor audit;",
    )
    assert _decide(_finding("CWE-89"), src) == lfs.PUBLISH


# --- SAST-01-040 ------------------------------------------------------------------

SQL_JAVA = """\
package com.acme;

public class Orders {
    void find(java.sql.Statement stmt, javax.servlet.http.HttpServletRequest req, String id) throws Exception {
        String sql = "SELECT * FROM orders WHERE id = " + id;
        stmt.executeQuery(sql);
        stmt.executeQuery("SELECT * FROM orders WHERE id = " + id);
        String name = req.getParameter("name");
        stmt.executeQuery(build(name));
    }
}
"""


def _sql(line, **extra):
    return _finding("CWE-89", line=line, rule_id="sql-query-string-concat", **extra)


def test_a_confident_noisy_true_positive_with_no_evidence_is_demoted_not_published():
    usage = {}
    f = _sql(6, confidence=0.95, source="")
    assert _decide(f, SQL_JAVA, usage=usage) == lfs.DEMOTE
    out = lfs.apply_publish_decision(f, lfs.DEMOTE)
    assert out["verdict"] == "unverified" and out["unresolved_reason"] == "evidence_missing"
    assert out["confidence"] is None
    assert out["decisions"][-1]["stage"] == "publish_filter"
    assert usage["_counters"]["publish_filter"]["noisy_tp_demoted_unverified"] == 1


def test_query_construction_in_the_findings_own_statement_publishes_it():
    assert _decide(_sql(7, source=""), SQL_JAVA) == lfs.PUBLISH


def test_a_concatenation_in_an_earlier_statement_no_longer_counts():
    # Line 5 builds the query, line 6 executes it: the executing statement itself
    # shows no construction, and no source is named.
    assert _decide(_sql(6, source=""), SQL_JAVA) == lfs.DEMOTE


def test_a_named_source_that_is_in_the_method_publishes_it():
    assert _decide(_sql(9, source='req.getParameter("name")'), SQL_JAVA) == lfs.PUBLISH
    assert _decide(_sql(9, source="name (local variable)"), SQL_JAVA) == lfs.PUBLISH


def test_a_named_source_that_is_not_in_the_method_does_not_count():
    assert _decide(_sql(9, source='request.getParameter("id")'), SQL_JAVA) == lfs.DEMOTE


def test_a_noisy_false_positive_is_still_dropped_and_counted():
    usage = {}
    assert _decide(_sql(7, verdict="false_positive"), SQL_JAVA, usage=usage) == lfs.DROP
    assert usage["_counters"]["publish_filter"]["noisy_fp_dropped"] == 1


def test_without_facts_the_window_check_and_a_named_source_still_publish():
    f = _sql(7, source="x")
    assert _decide(f, SQL_JAVA, with_facts=False) == lfs.PUBLISH


def test_unevidenced_confidence_floor_is_gone():
    assert not hasattr(lfs, "UNEVIDENCED_CONFIDENCE_FLOOR")


def test_flow_findings_find_their_source_on_the_flow_path():
    f = _sql(6, kind="flow", source="id (request parameter)", flow_path=[
        {"role": "source", "label": "id", "snippet": "4: String id = req.getParameter(\"id\")"},
        {"role": "sink", "label": "stmt.executeQuery", "snippet": "6: stmt.executeQuery(sql);"},
    ])
    assert _decide(f, SQL_JAVA) == lfs.PUBLISH
    f2 = _sql(6, kind="flow", source="other", flow_path=f["flow_path"])
    assert _decide(f2, SQL_JAVA) == lfs.DEMOTE

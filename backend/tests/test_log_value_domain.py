"""`log_value_domain` (SAST-03-030): a log call whose every non-literal argument
is a constant, number, boolean or enum cannot forge a log line."""

import sys
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_java")
pytest.importorskip("boto3", reason="pipeline modules import llm_client")

_ENGINE = Path(__file__).resolve().parents[1] / "sast_engine"
if str(_ENGINE) not in sys.path:
    sys.path.insert(0, str(_ENGINE))

from pipeline import call_graph, finding_facts  # noqa: E402
from pipeline.validators import ValidatorContext, VALIDATOR_CONTEXT_USAGE_KEY  # noqa: E402

pytestmark = pytest.mark.unit

RESULT = """package com.acme.model;

import java.math.BigInteger;

public class Result {
    public BigInteger getResultCode() { return null; }
    public String getResultDesc() { return null; }
    public int size() { return 0; }
}
"""
SVC_HEAD = """package com.acme.service;

import com.acme.model.Result;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.sql.PreparedStatement;
import javax.servlet.http.HttpServletRequest;

public class Svc {
    private static final Logger log = LoggerFactory.getLogger(Svc.class);
    private static final String CLASS_NAME = "Svc";

    void run(HttpServletRequest request, Result result, PreparedStatement ps, String s, int count, Exception ex) throws Exception {
"""


@pytest.fixture()
def project(tmp_path):
    (tmp_path / "com/acme/model").mkdir(parents=True)
    (tmp_path / "com/acme/service").mkdir(parents=True)
    (tmp_path / "com/acme/model/Result.java").write_text(RESULT)
    return tmp_path


def _decide(project, body, *, cwe="CWE-117", kind="llm", needle=None):
    text = SVC_HEAD + body + "\n    }\n}\n"
    (project / "com/acme/service/Svc.java").write_text(text)
    graph = call_graph.build_call_graph(project, ["com/acme/model/Result.java", "com/acme/service/Svc.java"])
    ctx = ValidatorContext(repo_root=project, call_graph=graph)
    needle = needle or body.strip().splitlines()[-1].strip()
    line = next(i for i, l in enumerate(text.splitlines(), 1) if needle in l)
    f = {"file_path": "com/acme/service/Svc.java", "line": line, "rule_id": "java-log-injection-unsanitized-input",
         "cwe": cwe, "kind": kind, "verdict": "true_positive", "verdict_reason": "The model says so.",
         "issue_class": "security", "confidence": 0.8}
    usage = {VALIDATOR_CONTEXT_USAGE_KEY: ctx}
    finding_facts.prepare_findings([f], text, file_path=f["file_path"], usage=usage)
    mine = [(o["outcome"], o.get("reason_tag")) for o in (f.get("facts") or {}).get("validators", [])
            if o["validator"] == "log_value_domain"]
    return f, mine


@pytest.mark.parametrize("body", [
    '        log.info("rows " + count);',
    '        log.info(CLASS_NAME + ": no connection");',
    '        int jobId = Integer.parseInt(s);\n        log.info("job " + jobId);',
    '        log.info("code {}", result.getResultCode());',
    '        log.info("updated {}", ps.executeUpdate());',
    '        log.info("size {}", result.size());',
    '        log.info("count {}", s.length());',
])
def test_constrained_arguments_are_a_proof(project, body):
    f, mine = _decide(project, body)
    assert mine == [("negative_proof", "log_arg_constrained")], body
    assert f["verdict"] == "false_positive"


@pytest.mark.parametrize("body", [
    '        log.info("job " + s);',
    '        long parsed = Long.parseLong(s);\n        log.info("job " + s);',
    '        log.info("desc {}", result.getResultDesc());',
    '        log.info("failed {}", ex.getMessage());',
    '        log.info("failed", ex);',
    '        log.info("unknown {}", result.getMissing());',
])
def test_a_string_exception_or_unresolved_argument_is_left_alone(project, body):
    f, mine = _decide(project, body)
    assert mine == [], body
    assert f["verdict"] == "true_positive"


def test_the_request_locale_is_an_evidence_gap_not_a_proof(project):
    f, mine = _decide(project, '        log.info("locale {}", request.getLocale());')
    assert mine == [("evidence_gap", None)]
    assert f["verdict"] == "unverified" and f["unresolved_reason"] == "evidence_missing"
    assert "Accept-Language" in f["verdict_reason"]


def test_a_constrained_value_is_still_a_leak_when_it_is_sensitive(project):
    f, mine = _decide(project, '        log.info("account {}", count);', cwe="CWE-532")
    f["rule_id"] = "java-sensitive-data-in-logs"
    # The validator is not selected for a CWE-532 finding on another rule at all.
    assert f["verdict"] == "true_positive"


def test_call_graph_records_return_types_and_declared_throws(project):
    graph = call_graph.build_call_graph(project, ["com/acme/model/Result.java"])
    by_name = {m.name: m for m in graph.methods.values()}
    assert by_name["getResultCode"].return_type == "BigInteger"
    assert by_name["getResultDesc"].return_type == "String"

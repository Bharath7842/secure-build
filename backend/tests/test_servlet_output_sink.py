"""`servlet_output_sink` (SAST-03-070): reflected XSS needs request data written
to a real HTTP response writer. A `System.out` line is never one."""

import sys
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_java")
pytest.importorskip("boto3", reason="pipeline modules import llm_client")

_ENGINE = Path(__file__).resolve().parents[1] / "sast_engine"
if str(_ENGINE) not in sys.path:
    sys.path.insert(0, str(_ENGINE))

from pipeline import finding_facts, regex_scan  # noqa: E402

pytestmark = pytest.mark.unit

RULE = {r.id: r for r in regex_scan.load_rules(_ENGINE / "rules")}["java-xss-jsp-servlet"]
FIXTURES = Path(__file__).parent / "fixtures" / "output_sinks"
PATH = "src/main/java/com/acme/web/Page.java"

HEAD = """package com.acme.web;

import java.io.PrintWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Page {
    void run(HttpServletRequest request, HttpServletResponse response, int count, String name) throws Exception {
"""


def _source(body: str) -> str:
    return HEAD + body + "\n    }\n}\n"


def _finding(text, needle, *, kind="llm", cwe="CWE-79", verdict="true_positive", path=PATH):
    line = next(i for i, l in enumerate(text.splitlines(), 1) if needle in l)
    f = {"file_path": path, "line": line, "rule_id": RULE.id, "cwe": cwe, "kind": kind,
         "verdict": verdict, "verdict_reason": "The model says so.", "issue_class": "security",
         "confidence": 0.8}
    if kind == "regex":
        hit = next(h for h in regex_scan.scan_text_by_rule(text, RULE) if h["line"] == line)
        f.update(col_start=hit.get("col_start"), col_end=hit.get("col_end"), verdict="unverified",
                 verdict_reason="Regex hit.", confidence=None, unresolved_reason="not_reviewed_regex")
    return f


def _decide(text, needle, **kw):
    f = _finding(text, needle, **kw)
    finding_facts.prepare_findings([f], text, file_path=f["file_path"], usage={})
    outcomes = [(o["validator"], o["outcome"], o.get("reason_tag")) for o in (f.get("facts") or {}).get("validators", [])
                if o["validator"] == "servlet_output_sink"]
    return f, outcomes


def test_a_model_xss_on_a_stdout_line_is_a_false_positive_by_proof():
    text = _source('        System.out.println("requests handled: " + count);')
    f, outcomes = _decide(text, "System.out")
    assert outcomes == [("servlet_output_sink", "negative_proof", "xss_sink_not_http_response")]
    assert f["verdict"] == "false_positive" and f["reason_tag"] == "xss_sink_not_http_response"


def test_the_word_request_in_a_string_literal_is_not_a_source():
    text = _source('        System.out.println("handling request " + name);')
    f, outcomes = _decide(text, "System.out")
    assert outcomes == [("servlet_output_sink", "negative_proof", "xss_sink_not_http_response")]


def test_request_data_written_to_the_response_is_a_fact_and_beats_a_model_dismissal():
    text = _source('        response.getWriter().write(request.getParameter("q"));')
    f, outcomes = _decide(text, "getWriter", verdict="false_positive")
    assert outcomes == [("servlet_output_sink", "positive_fact", "xss_request_in_response")]
    assert f["verdict"] == "unverified" and f["unresolved_reason"] == "conflict"


def test_a_value_assigned_from_the_request_is_followed_through_a_local():
    text = _source('        String q = request.getParameter("q");\n        response.getWriter().write("<b>" + q + "</b>");')
    f, outcomes = _decide(text, "getWriter")
    assert outcomes == [("servlet_output_sink", "positive_fact", "xss_request_in_response")]
    assert f["verdict"] == "true_positive"


def test_a_writer_variable_taken_from_the_response_is_still_the_response():
    text = _source('        PrintWriter w = response.getWriter();\n        w.println(request.getParameter("q"));')
    f, outcomes = _decide(text, "w.println")
    assert outcomes == [("servlet_output_sink", "positive_fact", "xss_request_in_response")]


def test_only_constants_and_numbers_are_written_by_the_response_is_a_proof():
    text = _source('        response.getWriter().println("total: " + count);')
    f, outcomes = _decide(text, "getWriter")
    assert outcomes == [("servlet_output_sink", "negative_proof", "xss_arg_constrained")]
    assert f["verdict"] == "false_positive"


def test_a_regex_hit_with_no_request_argument_is_dismissed_but_a_model_finding_is_not():
    text = _source('        response.getWriter().write(name);\n        String s = request.getParameter("x");')
    # The (tightened) pattern no longer produces this hit, so build the candidate directly.
    for kind, expected in (("regex", [("servlet_output_sink", "negative_proof", "xss_no_request_source")]),
                           ("llm", [])):
        f = _finding(text, "getWriter")
        f["kind"] = kind
        if kind == "regex":
            f.update(verdict="unverified", unresolved_reason="not_reviewed_regex", confidence=None)
        finding_facts.prepare_findings([f], text, file_path=PATH, usage={})
        got = [(o["validator"], o["outcome"], o.get("reason_tag")) for o in (f.get("facts") or {}).get("validators", [])
               if o["validator"] == "servlet_output_sink"]
        assert got == expected, kind


def test_an_unresolved_receiver_gives_no_opinion():
    text = _source('        out.println(request.getParameter("q"));')
    f, outcomes = _decide(text, "out.println")
    assert outcomes == []
    assert f["verdict"] == "true_positive"


def test_a_cwe_532_finding_on_a_stdout_line_is_untouched():
    text = _source('        System.out.println("password=" + name);')
    f, outcomes = _decide(text, "System.out", cwe="CWE-532")
    # Even where the validator runs (the finding cites the XSS rule) its CWE-79 answer
    # does not settle a CWE-532 finding.
    assert f["verdict"] == "true_positive"
    other = _finding(text, "System.out", cwe="CWE-532")
    other["rule_id"] = "java-sensitive-data-in-logs"
    finding_facts.prepare_findings([other], text, file_path=PATH, usage={})
    assert not (other.get("facts") or {}).get("validators")


def test_jsp_scriptlet_writing_a_request_parameter_is_a_fact():
    text = (FIXTURES / "page.jsp").read_text()
    f, outcomes = _decide(text, "out.println(q)", path="src/main/webapp/page.jsp")
    assert outcomes == [("servlet_output_sink", "positive_fact", "xss_request_in_response")]


def test_the_tightened_pattern_keeps_the_real_forms_and_drops_stdout():
    def hit(code):
        return bool(regex_scan.scan_text_by_rule(code, RULE))
    assert hit('response.getWriter().write(request.getParameter("q"));')
    assert hit('out.println(request.getParameter("q"));')
    assert not hit('System.out.println("x request y");')
    assert not hit('System.out.println("requests: " + count);')

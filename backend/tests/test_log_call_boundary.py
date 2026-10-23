"""`log_call_boundary` (SAST-03-020) and the CWE scoping it relies on.

The regex stays the candidate generator; the validator decides from the parsed
logger call whether the text the rule blamed on it is really one of its
arguments. Hits come from the real rule (so the 200-character window that
crosses statements is exercised), findings go through the real hook.
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

from pipeline import finding_facts, regex_scan  # noqa: E402
from pipeline.validators import (  # noqa: E402
    ValidatorContext, _settle, apply_validators, evidence_gap, negative_proof, positive_fact,
)

pytestmark = pytest.mark.unit

RULES = {r.id: r for r in regex_scan.load_rules(_ENGINE / "rules")}
RULE = RULES["java-log-injection-unsanitized-input"]
PATH = "src/main/java/com/acme/service/Svc.java"

HEADER = """package com.acme.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Properties;

public class Svc {
    private static final Logger log = LoggerFactory.getLogger(Svc.class);
"""


def _source(body: str) -> str:
    return HEADER + "    void run(javax.servlet.http.HttpServletRequest request, String name) {\n" + body + "\n    }\n}\n"


def _findings(body: str, *, verdict: str = "true_positive", kind: str = "regex"):
    text = _source(body)
    out = []
    for hit in regex_scan.scan_text_by_rule(text, RULE):
        out.append({
            "file_path": PATH, "line": hit["line"], "col_start": hit.get("col_start"),
            "col_end": hit.get("col_end"), "rule_id": RULE.id, "cwe": "CWE-117", "kind": kind,
            "verdict": verdict, "verdict_reason": "Regex hit." if verdict == "unverified" else "Model says so.",
            "issue_class": "security", "matched_text": hit.get("matched_text"),
            "confidence": None if verdict == "unverified" else 0.8,
            "unresolved_reason": "not_reviewed_regex" if verdict == "unverified" else None,
        })
    return text, out


def _decide(body: str, **kw):
    text, findings = _findings(body, **kw)
    assert findings, "the rule should have produced a candidate"
    usage = {}
    finding_facts.prepare_findings(findings, text, file_path=PATH, usage=usage)
    return findings, usage


def _outcome(finding):
    return [(o["validator"], o["outcome"], o.get("reason_tag")) for o in (finding.get("facts") or {}).get("validators", [])
            if o["validator"] == "log_call_boundary"]


def test_a_constant_log_followed_by_a_throw_is_not_a_log_forging_sink():
    findings, usage = _decide(
        '        log.info("rows deleted");\n'
        '        throw new IllegalStateException(request.getParameter("x"));'
    )
    [f] = findings
    assert _outcome(f) == [("log_call_boundary", "negative_proof", "log_source_outside_call")]
    assert f["verdict"] == "false_positive" and f["reason_tag"] == "log_source_outside_call"
    assert "line 12" in f["verdict_reason"] or "later statement" in f["verdict_reason"]
    assert usage["_counters"]["validators"]["log_call_boundary.log_source_outside_call"] == 1


def test_the_source_in_the_calls_own_arguments_is_a_fact():
    [f], _ = _decide('        log.error("failed {}", name, request.getParameter("x"));')
    assert _outcome(f) == [("log_call_boundary", "positive_fact", "log_source_in_call")]
    assert f["verdict"] == "true_positive"


def test_a_multi_line_parameterised_call_is_judged_on_its_own_arguments():
    [f], _ = _decide(
        '        log.warn("{} {} {}",\n'
        '                name,\n'
        '                request.getRequestURI());'
    )
    assert _outcome(f) == [("log_call_boundary", "positive_fact", "log_source_in_call")]
    assert f["line"] == 10  # the call's first line


def test_a_source_reaching_the_call_through_a_local_is_a_fact():
    # The rule's pattern cannot see this idiom (the model finds it), so build the
    # candidate the way a model finding would arrive: on the log call's line.
    text = _source('        String m = request.getParameter("x");\n        log.info(m);')
    line = next(i for i, l in enumerate(text.splitlines(), 1) if "log.info(m)" in l)
    f = {"file_path": PATH, "line": line, "rule_id": RULE.id, "cwe": "CWE-117", "kind": "regex",
         "verdict": "unverified", "verdict_reason": "Regex hit.", "issue_class": "security",
         "unresolved_reason": "not_reviewed_regex"}
    finding_facts.prepare_findings([f], text, file_path=PATH, usage={})
    assert _outcome(f) == [("log_call_boundary", "positive_fact", "log_source_via_local")]
    assert f["verdict"] == "unverified"  # a positive fact alone does not decide a regex hit


def test_a_throwable_argument_is_left_to_the_exception_provenance_check():
    text = _source('        try { run(request, name); } catch (Exception e) {\n'
                   '            log.error("failed", e);\n'
                   '            throw new IllegalStateException(e.getMessage());\n'
                   '        }')
    hits = regex_scan.scan_text_by_rule(text, RULE)
    assert hits
    f = {"file_path": PATH, "line": next(h["line"] for h in hits if "failed" in text.splitlines()[h["line"] - 1]),
         "rule_id": RULE.id, "cwe": "CWE-117", "kind": "regex", "verdict": "unverified",
         "verdict_reason": "Regex hit.", "issue_class": "security", "unresolved_reason": "not_reviewed_regex"}
    hit = next(h for h in hits if h["line"] == f["line"])
    f.update(col_start=hit.get("col_start"), col_end=hit.get("col_end"))
    finding_facts.prepare_findings([f], text, file_path=PATH, usage={})
    assert _outcome(f) == []  # no opinion: the throwable's text is SAST-03-040's question
    assert f["verdict"] == "unverified"


def test_a_model_finding_is_never_dismissed_on_the_source_window():
    findings, _ = _decide(
        '        log.info("rows deleted: " + name);\n'
        '        throw new IllegalStateException(request.getParameter("x"));',
        kind="llm",
    )
    [f] = findings
    assert _outcome(f) == []  # the model's source may be `name`
    assert f["verdict"] == "true_positive"


def test_a_hit_on_a_receiver_that_is_not_a_logger_is_dismissed_with_the_reason():
    # `catalog.setProperty(` matches `log(ger)?\.` only through `catalog`'s last three letters.
    text = _source('        Properties catalog = new Properties();\n'
                   '        catalog.setProperty("k", request.getParameter("x"));')
    # The rule's pattern wants info|warn|error|debug, so build the hit as the pattern would.
    line = next(i for i, l in enumerate(text.splitlines(), 1) if "catalog.setProperty" in l)
    col = text.splitlines()[line - 1].index("catalog") + 4  # starts inside `catalog`
    f = {"file_path": PATH, "line": line, "col_start": col, "col_end": col + 20, "rule_id": RULE.id,
         "cwe": "CWE-117", "kind": "regex", "verdict": "unverified", "verdict_reason": "Regex hit.",
         "issue_class": "security", "unresolved_reason": "not_reviewed_regex"}
    finding_facts.prepare_findings([f], text, file_path=PATH, usage={})
    assert _outcome(f) == [("log_call_boundary", "negative_proof", "not_a_logger_call")]
    assert f["verdict"] == "false_positive"


def test_stdout_is_an_evidence_gap_not_a_dismissal():
    text = _source('        System.out.println("x " + request.getParameter("x"));')
    line = next(i for i, l in enumerate(text.splitlines(), 1) if "System.out" in l)
    f = {"file_path": PATH, "line": line, "rule_id": "llm", "cwe": "CWE-117", "kind": "llm",
         "verdict": "true_positive", "verdict_reason": "x", "issue_class": "security",
         "sink": "System.out.println"}
    finding_facts.prepare_findings([f], text, file_path=PATH, usage={})
    assert _outcome(f) == [("log_call_boundary", "evidence_gap", None)]


# --- CWE scoping (the hook) -------------------------------------------------------

def _finding(cwe, verdict="true_positive"):
    return {"cwe": cwe, "verdict": verdict, "verdict_reason": "r", "issue_class": "security"}


def _outcomes(result):
    from pipeline.validators import _outcome_dict, Validator
    v = Validator(name="t", version=1, fn=lambda *a: None, rule_ids=(), rule_prefixes=(), cwes=())
    return [_outcome_dict(v, result)]


def test_a_cwe_117_proof_does_not_touch_a_cwe_532_finding():
    proof = negative_proof("log_arg_constrained", "only a number is logged", applies_to_cwe=("CWE-117",))
    secret = _finding("CWE-532")
    assert _settle(secret, _outcomes(proof), record=False) is False
    assert secret["verdict"] == "true_positive"
    forging = _finding("CWE-117")
    assert _settle(forging, _outcomes(proof), record=False) is True
    assert forging["verdict"] == "false_positive"


def test_an_unscoped_proof_still_applies_to_every_cwe():
    proof = negative_proof("match_is_declaration", "it is a declaration")
    f = _finding("CWE-532")
    _settle(f, _outcomes(proof), record=False)
    assert f["verdict"] == "false_positive"


def test_a_scoped_gap_or_fact_is_ignored_for_other_cwes():
    for result in (evidence_gap("something", applies_to_cwe=("CWE-117",)),
                   positive_fact("t", "p", applies_to_cwe=("CWE-117",))):
        f = _finding("CWE-532", verdict="false_positive")
        _settle(f, _outcomes(result), record=False)
        assert f["verdict"] == "false_positive"


def test_adjacent_log_calls_each_get_their_own_candidate():
    # The pattern looks ahead without consuming, so the first call's window does not
    # swallow the second call's own hit.
    text = _source('        log.info("rows " + name);\n        log.warn("failed {}", name, new Exception().getMessage());')
    hits = regex_scan.scan_text_by_rule(text, RULE)
    assert [h["line"] for h in hits] == [10, 11]

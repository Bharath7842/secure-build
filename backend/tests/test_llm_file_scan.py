"""Tests for pipeline/llm_file_scan.py — LLM-primary detect+triage of
CRITICAL-risk files. All LLM calls are stubbed via `call_llm_fn` so these
run fully offline.
"""

from pathlib import Path

import pytest

pytest.importorskip("langgraph")

from app.config import settings  # noqa: E402
from app.services.agent_bridge import _load_agent_module  # noqa: E402

_ENGINE_DIR = Path(__file__).resolve().parents[1] / "sast_engine"


@pytest.fixture()
def agent(monkeypatch):
    import sys

    monkeypatch.setattr(settings, "sast_framework_path", str(_ENGINE_DIR))
    sys.modules.pop("sast_scan_agent", None)
    return _load_agent_module()


@pytest.fixture()
def llm_file_scan(agent):
    import sys

    return sys.modules["pipeline.llm_file_scan"]


@pytest.fixture()
def regex_scan(agent):
    import sys

    return sys.modules["pipeline.regex_scan"]


@pytest.fixture()
def rules(regex_scan):
    return regex_scan.load_rules(_ENGINE_DIR / "rules")


# --- rule catalog for the prompt --------------------------------------------

def test_rules_for_prompt_includes_owasp_and_catalog_fields(regex_scan, rules):
    catalog = regex_scan.rules_for_prompt(rules, "python", set())
    assert catalog, "expected at least one applicable rule for python"
    for entry in catalog:
        assert entry["owasp"], f"rule {entry['id']} missing owasp label"
        assert entry["id"] and entry["cwe"] is not None and entry["severity"] and entry["description"]
        # the raw regex is a scan-time construct, not LLM prompt guidance —
        # must not leak into the prompt catalog.
        assert "pattern" not in entry


def test_rules_for_prompt_filters_by_language(regex_scan, rules):
    catalog = regex_scan.rules_for_prompt(rules, "python", set())
    ids = {r["id"] for r in catalog}
    assert "java-runtime-exec" not in ids  # java-only rule must not leak into python catalog
    assert "exec-call" in ids  # python-tagged rule should be present


def test_system_prompt_steers_deep_scan_toward_response_body_and_log_injection(llm_file_scan):
    """Regression guard: the deep-scan LLM tier used to have no explicit reason
    to flag a Java/Spring backend reflecting an exception message into an HTTP
    response body, or unsanitized input reaching a log call — its only
    XSS-adjacent sink was "the DOM" (read as client-side). A real comparison
    against GitLab's taint-flow SAST on the same repo found several
    reflected-XSS and log-injection findings ours missed for exactly this
    reason, so the base prompt must name both sinks explicitly."""
    prompt = llm_file_scan.build_system_prompt(catalog=[], stack_context="")
    assert "HTTP response body" in prompt
    assert "log statement" in prompt
    assert "CSRF" in prompt


def test_system_prompt_steers_deep_scan_toward_underflow_indirection_and_request_echo(llm_file_scan):
    """Regression guard for a second gap comparison: the prompt's response-body
    sink was broad enough in principle ("other user-controlled text") to imply
    a raw @RequestParam echo or a variable-indirected exception message, but
    never named either explicitly — and had no mention of integer underflow
    (CWE-191) at all. All three must be named so the LLM treats them as
    first-class targets instead of inferring them from a catch-all phrase."""
    prompt = llm_file_scan.build_system_prompt(catalog=[], stack_context="")
    assert "@RequestParam" in prompt
    assert "assigned to a local variable" in prompt
    assert "integer underflow" in prompt
    assert "CWE-191" in prompt


def test_system_prompt_steers_deep_scan_toward_constructor_sink_and_request_uri(llm_file_scan):
    """Regression guard for real code found by checking a target repo directly:
    a GlobalExceptionHandler that returns new ResponseEntity<>(dto, status)
    (the constructor form) rather than .ok()/.body(), and logs
    request.getRequestURI() (not just getParameter()/getHeader()) alongside
    the exception message in a multi-argument parameterized log call. Neither
    was named, so the model had no explicit reason to treat the constructor
    form as the same sink as .body()/.ok(), or getRequestURI() as a log-
    injection source."""
    prompt = llm_file_scan.build_system_prompt(catalog=[], stack_context="")
    assert "new ResponseEntity<>(dto, status)" in prompt
    assert "getRequestURI()" in prompt


# --- chunking ----------------------------------------------------------------

def test_chunk_file_single_chunk_for_small_file(llm_file_scan):
    text = "line1\nline2\nline3\n"
    chunks = llm_file_scan.chunk_file(text, "python")
    assert len(chunks) == 1
    assert chunks[0]["start_line"] == 1
    assert chunks[0]["end_line"] == 3


def test_chunk_file_splits_large_file_with_overlap(llm_file_scan):
    lines = [f"value_{i} = 'padding_padding_padding_padding_padding'" for i in range(700)]
    text = "\n".join(lines)
    assert len(text) > llm_file_scan.SINGLE_CALL_CHAR_BUDGET

    chunks = llm_file_scan.chunk_file(text, "python")
    assert len(chunks) > 1
    assert chunks[0]["start_line"] == 1
    assert chunks[-1]["end_line"] == len(lines)
    # consecutive chunks overlap by a few lines
    assert chunks[1]["start_line"] <= chunks[0]["end_line"]


def test_chunk_file_empty_text_returns_no_chunks(llm_file_scan):
    assert llm_file_scan.chunk_file("", "python") == []


# --- normalization / dedupe ---------------------------------------------------

def test_normalize_finding_defaults_owasp_from_cwe_when_missing(llm_file_scan):
    raw = {
        "verdict": "true_positive", "severity": "HIGH", "cwe": "CWE-89", "line": 12,
        "rule_id": "sql-x", "title": "SQLi", "verdict_reason": "concatenated query",
    }
    norm = llm_file_scan.normalize_finding(raw, file_path="a.py", chunk_start=1, chunk_end=20)
    assert norm["owasp_category"] == "A03:2021-Injection"


def test_normalize_finding_defaults_reason_when_blank(llm_file_scan):
    raw = {"verdict": "false_positive", "severity": "LOW", "line": 3}
    norm = llm_file_scan.normalize_finding(raw, file_path="a.py", chunk_start=1, chunk_end=10)
    assert norm["verdict_reason"]


def test_normalize_finding_clamps_line_into_chunk_range(llm_file_scan):
    raw = {"verdict": "true_positive", "severity": "HIGH", "line": 9999}
    norm = llm_file_scan.normalize_finding(raw, file_path="a.py", chunk_start=1, chunk_end=50)
    assert norm["line"] == 50


def test_merge_dedupe_prefers_true_positive_over_false_positive(llm_file_scan):
    findings = [
        {"rule_id": "r1", "line": 10, "verdict": "false_positive", "severity": "LOW", "title": "SQL injection"},
        {"rule_id": "r1", "line": 10, "verdict": "true_positive", "severity": "HIGH", "title": "SQL injection"},
    ]
    merged = llm_file_scan.merge_dedupe(findings)
    assert len(merged) == 1
    assert merged[0]["verdict"] == "true_positive"


def test_merge_dedupe_prefers_higher_severity_when_same_verdict(llm_file_scan):
    findings = [
        {"rule_id": "r1", "line": 5, "verdict": "true_positive", "severity": "LOW", "title": "SQL injection"},
        {"rule_id": "r1", "line": 5, "verdict": "true_positive", "severity": "CRITICAL", "title": "SQL injection"},
    ]
    merged = llm_file_scan.merge_dedupe(findings)
    assert len(merged) == 1
    assert merged[0]["severity"] == "CRITICAL"


def test_merge_dedupe_keeps_distinct_line_topic_pairs(llm_file_scan):
    """Dedupe key is (line, cwe-or-title-topic), not rule_id — distinct issues on
    the same line survive when their titles differ."""
    findings = [
        {"rule_id": "r1", "line": 5, "verdict": "true_positive", "severity": "HIGH", "title": "SQL injection"},
        {"rule_id": "r2", "line": 5, "verdict": "true_positive", "severity": "HIGH", "title": "XSS reflected"},
        {"rule_id": "r1", "line": 6, "verdict": "true_positive", "severity": "HIGH", "title": "SQL injection"},
    ]
    merged = llm_file_scan.merge_dedupe(findings)
    assert len(merged) == 3


def test_should_publish_finding_drops_unevidenced_sql_concat_catalog_echo(llm_file_scan):
    finding = {
        "rule_id": "sql-query-string-concat",
        "title": "SQL query string concatenation",
        "snippet": "some unrelated line",
        "line": 10,
        "verdict": "true_positive",
        "confidence": 0.3,
    }
    assert llm_file_scan.should_publish_finding(finding, context_text="unrelated context") is False


def test_should_publish_finding_keeps_evidenced_sql_concat_true_positive(llm_file_scan):
    finding = {
        "rule_id": "sql-query-string-concat",
        "title": "SQL query string concatenation",
        "cwe": "CWE-89",
        "snippet": 'stmt.executeQuery(sql)',
        "line": 60,
        "verdict": "true_positive",
        "source": 'request.getParameter("id")',
        "confidence": 0.85,
    }
    context = (
        '40: String sql = "SELECT * FROM users WHERE id=" + request.getParameter("id");\n'
        "60: stmt.executeQuery(sql)  <--"
    )
    assert llm_file_scan.should_publish_finding(finding, context) is True


def test_should_publish_finding_drops_resultset_read_false_positive(llm_file_scan):
    finding = {
        "rule_id": "llm-extra",
        "title": "Potential SQL injection",
        "snippet": 'tb.setParticipant_id(rs.getString(1));',
        "line": 81,
    }
    assert llm_file_scan.should_publish_finding(finding) is False


def test_should_publish_finding_drops_unanalyzable_bytecode_meta_finding(llm_file_scan):
    finding = {
        "file_path": "NPG/security/SecurityMgrEJB.class",
        "confidence": 0.0,
        "title": "Bytecode file cannot be analyzed for injection vulnerabilities",
        "verdict_reason": "The file is compiled Java bytecode and does not represent actual source code.",
        "line": 1,
    }
    assert llm_file_scan.should_publish_finding(finding) is False


def test_should_publish_finding_drops_console_log_call(llm_file_scan):
    finding = {
        "rule_id": "llm-extra",
        "verdict": "true_positive",
        "confidence": 0.95,
        "snippet": "console.log('user password:', password);",
        "line": 12,
    }
    assert llm_file_scan.should_publish_finding(finding) is False


def test_should_publish_finding_drops_this_logger_call_even_true_positive(llm_file_scan):
    finding = {
        "rule_id": "java-sensitive-data-in-logs",
        "verdict": "true_positive",
        "confidence": 0.97,
        "source": 'req.getParameter("password")',
        "snippet": 'this.logger.error("login failed for password=" + password);',
        "line": 40,
    }
    assert llm_file_scan.should_publish_finding(finding) is False


@pytest.mark.parametrize("method", ["log", "trace", "debug", "info", "warn", "error", "fatal"])
def test_should_publish_finding_drops_bare_logger_calls(llm_file_scan, method):
    finding = {
        "rule_id": "llm-extra",
        "verdict": "true_positive",
        "confidence": 0.9,
        "snippet": f'logger.{method}("token=" + token);',
        "line": 5,
    }
    assert llm_file_scan.should_publish_finding(finding) is False


def test_should_publish_finding_keeps_non_logger_named_call(llm_file_scan):
    finding = {
        "rule_id": "llm-extra",
        "cwe": "CWE-532",
        "verdict": "true_positive",
        "confidence": 0.9,
        "snippet": 'auditLogger.info("token=" + token);',
        "line": 5,
    }
    assert llm_file_scan.should_publish_finding(finding) is True


# --- suppress_no_cwe / suppress_http_findings --------------------------------

def test_should_publish_finding_drops_no_cwe_finding_by_default(llm_file_scan):
    finding = {
        "rule_id": "llm-extra", "verdict": "true_positive", "confidence": 0.9,
        "snippet": "x = 1;", "line": 5, "cwe": "",
    }
    assert llm_file_scan.should_publish_finding(finding) is False


def test_should_publish_finding_keeps_no_cwe_finding_when_disabled(llm_file_scan):
    finding = {
        "rule_id": "llm-extra", "verdict": "true_positive", "confidence": 0.9,
        "snippet": "x = 1;", "line": 5, "cwe": "",
    }
    assert llm_file_scan.should_publish_finding(finding, suppress_no_cwe=False) is True


@pytest.mark.parametrize("cwe,title,reason", [
    ("CWE-319", "Some finding", ""),
    ("", "Cleartext HTTP transmission of credentials", ""),
    ("", "Endpoint", "Missing HTTPS enforcement on the login endpoint"),
    ("", "API call", "Uses HTTP instead of HTTPS for the payment callback"),
])
def test_should_publish_finding_drops_http_finding_when_enabled(llm_file_scan, cwe, title, reason):
    finding = {
        "rule_id": "llm-extra", "verdict": "true_positive", "confidence": 0.9,
        "snippet": "x = 1;", "line": 5, "cwe": cwe or "CWE-319", "title": title,
        "verdict_reason": reason,
    }
    assert llm_file_scan.should_publish_finding(finding, suppress_http_findings=True) is False


def test_should_publish_finding_keeps_http_finding_by_default(llm_file_scan):
    """suppress_http_findings defaults False — opt-in per project only."""
    finding = {
        "rule_id": "llm-extra", "verdict": "true_positive", "confidence": 0.9,
        "snippet": "x = 1;", "line": 5, "cwe": "CWE-319", "title": "Cleartext HTTP",
    }
    assert llm_file_scan.should_publish_finding(finding) is True


def test_should_publish_finding_keeps_unrelated_http_mention_even_when_enabled(llm_file_scan):
    """A finding that merely mentions 'HTTP' (status code handling, an HTTP
    client call) must not be caught by the narrow HTTP-vs-HTTPS keyword match."""
    finding = {
        "rule_id": "llm-extra", "verdict": "true_positive", "confidence": 0.9,
        "cwe": "CWE-20", "snippet": "x = 1;", "line": 5,
        "title": "Improper handling of HTTP 500 error responses",
        "verdict_reason": "The client does not retry on an HTTP 500 response.",
    }
    assert llm_file_scan.should_publish_finding(finding, suppress_http_findings=True) is True


# --- suppress_low_confidence_false_positives ---------------------------------

def test_should_publish_finding_drops_low_confidence_self_dismissed_fp(llm_file_scan):
    finding = {
        "rule_id": "llm-extra", "verdict": "false_positive", "confidence": 0.1,
        "cwe": "CWE-79", "snippet": "x = 1;", "line": 5,
        "verdict_reason": "Not a vulnerability — no injection vector exists here.",
    }
    assert llm_file_scan.should_publish_finding(
        finding, suppress_low_confidence_false_positives=True
    ) is False


def test_should_publish_finding_keeps_low_confidence_fp_by_default(llm_file_scan):
    """suppress_low_confidence_false_positives defaults False on the function
    itself — real scans opt in via agent_bridge/scan_limitations."""
    finding = {
        "rule_id": "llm-extra", "verdict": "false_positive", "confidence": 0.1,
        "cwe": "CWE-79", "snippet": "x = 1;", "line": 5,
    }
    assert llm_file_scan.should_publish_finding(finding) is True


def test_should_publish_finding_keeps_fp_above_confidence_ceiling(llm_file_scan):
    finding = {
        "rule_id": "llm-extra", "verdict": "false_positive", "confidence": 0.4,
        "cwe": "CWE-79", "snippet": "x = 1;", "line": 5,
    }
    assert llm_file_scan.should_publish_finding(
        finding, suppress_low_confidence_false_positives=True
    ) is True


def test_should_publish_finding_keeps_true_positive_at_zero_confidence(llm_file_scan):
    """The confidence ceiling only ever applies to false_positive verdicts."""
    finding = {
        "rule_id": "llm-extra", "verdict": "true_positive", "confidence": 0.0,
        "cwe": "CWE-79", "snippet": "x = 1;", "line": 5,
    }
    assert llm_file_scan.should_publish_finding(
        finding, suppress_low_confidence_false_positives=True
    ) is True


# --- looks_vendored_or_minified / is_non_analyzable_file ---------------------

def test_looks_vendored_or_minified_true_for_min_js_filename(llm_file_scan):
    assert llm_file_scan.looks_vendored_or_minified("assets/libraries/jquery.min.js", "x") is True


def test_looks_vendored_or_minified_true_for_long_line_content_without_min_name(llm_file_scan):
    text = "var x=1;" * 500  # one very long line, no newlines
    assert llm_file_scan.looks_vendored_or_minified("assets/libraries/bundle.js", text) is True


def test_looks_vendored_or_minified_false_for_normal_source(llm_file_scan):
    text = "\n".join(f"line {i} of normal hand-written code" for i in range(50))
    assert llm_file_scan.looks_vendored_or_minified("src/app/foo.component.ts", text) is False


def test_is_non_analyzable_file_flags_minified_js(tmp_path, llm_file_scan):
    rel = "assets/libraries/jquery.min.js"
    (tmp_path / "assets" / "libraries").mkdir(parents=True)
    (tmp_path / rel).write_text("var $=function(){};")
    reason = llm_file_scan.is_non_analyzable_file(tmp_path, rel, "var $=function(){};")
    assert reason == "vendored/minified third-party code"


def test_scan_file_skips_java_class_without_calling_llm(tmp_path, llm_file_scan, rules):
    rel = "security/SecurityMgrEJB.class"
    path = tmp_path / rel
    path.parent.mkdir(parents=True)
    path.write_bytes(b"\xca\xfe\xba\xbe" + b"\x00" * 200)

    calls: list[int] = []

    def fake_call_llm(*_args, **_kwargs):
        calls.append(1)
        return "[]"

    result = llm_file_scan.scan_file(
        repo_root=tmp_path,
        rel_path=rel,
        rules=rules,
        call_llm_fn=fake_call_llm,
    )
    assert result["skipped_non_source"] is True
    assert result["findings"] == []
    assert calls == []


def test_is_excluded_from_finding_scan_matches_schema_cvs_log4j(llm_file_scan):
    assert llm_file_scan.is_excluded_from_finding_scan("schema.xsd")
    assert llm_file_scan.is_excluded_from_finding_scan("svc.WSDL")
    assert llm_file_scan.is_excluded_from_finding_scan("xsd/foo.xml")
    assert llm_file_scan.is_excluded_from_finding_scan("configuration/app.xml")
    assert llm_file_scan.is_excluded_from_finding_scan("NPG/config/NPG.xml")
    assert llm_file_scan.is_excluded_from_finding_scan(
        "NPG/config/ApplicationResources.properties",
    )
    assert llm_file_scan.is_excluded_from_finding_scan("NPG/config/Start_EMASim")
    assert llm_file_scan.is_excluded_from_finding_scan(
        "NPG/config/MsgHandler_11_log4j.xml",
    )
    assert llm_file_scan.is_excluded_from_finding_scan(
        "NPG/config/NPC_11_sc_log4j.xml",
    )
    assert llm_file_scan.is_excluded_from_finding_scan("log4j.xml")
    assert llm_file_scan.is_excluded_from_finding_scan("src/CVS/Tag")
    assert llm_file_scan.is_excluded_from_finding_scan("log4j.xml")
    assert llm_file_scan.is_excluded_from_finding_scan("src/main/resources/log4j2.xml")
    assert llm_file_scan.is_excluded_from_finding_scan("a.compose")
    assert llm_file_scan.is_excluded_from_finding_scan("a.parse")
    assert llm_file_scan.is_excluded_from_finding_scan("a.dtd")
    assert llm_file_scan.is_excluded_from_finding_scan("foo.library")
    assert llm_file_scan.is_excluded_from_finding_scan(".prefs")
    assert llm_file_scan.is_excluded_from_finding_scan(".project")
    assert llm_file_scan.is_excluded_from_finding_scan("app.classpath")
    assert llm_file_scan.is_excluded_from_finding_scan("a.jpx")
    assert llm_file_scan.is_excluded_from_finding_scan("a.map")
    assert llm_file_scan.is_excluded_from_finding_scan("a.csv")
    assert llm_file_scan.is_excluded_from_finding_scan("META-INF/MANIFEST.MF")
    assert llm_file_scan.is_excluded_from_finding_scan("log4j_origJB1.xml")
    assert llm_file_scan.is_excluded_from_finding_scan(".cvsignore")
    assert llm_file_scan.is_excluded_from_finding_scan("node_modules/left-pad/index.js")
    assert llm_file_scan.is_excluded_from_finding_scan(".settings/org.eclipse.core.prefs")
    assert llm_file_scan.is_excluded_from_finding_scan("scripts/ModifyNPGDBPassword.sh")
    assert llm_file_scan.is_excluded_from_finding_scan("setup.sh")
    assert not llm_file_scan.is_excluded_from_finding_scan("app/auth.py")
    assert not llm_file_scan.is_excluded_from_finding_scan("app/config.py")
    assert not llm_file_scan.is_excluded_from_finding_scan(
        "src/main/java/com/foo/target/X.java",
    )


def test_files_for_risk_levels_drops_schema_cvs_log4j(llm_file_scan):
    module_plan = {
        "files": [
            {"path": "app/auth.py", "risk_level": "CRITICAL"},
            {"path": "schema.xsd", "risk_level": "CRITICAL"},
            {"path": "svc.wsdl", "risk_level": "CRITICAL"},
            {"path": "xsd/foo.xml", "risk_level": "CRITICAL"},
            {"path": "configuration/app.xml", "risk_level": "CRITICAL"},
            {"path": "NPG/config/MsgHandler_11_log4j.xml", "risk_level": "CRITICAL"},
            {"path": "NPG/config/ApplicationResources.properties", "risk_level": "CRITICAL"},
            {"path": "NPG/config/NPG.xml", "risk_level": "CRITICAL"},
            {"path": "CVS/Repository", "risk_level": "CRITICAL"},
            {"path": "src/CVS/Tag", "risk_level": "CRITICAL"},
            {"path": "log4j.xml", "risk_level": "CRITICAL"},
            {"path": "a.compose", "risk_level": "CRITICAL"},
            {"path": "a.parse", "risk_level": "CRITICAL"},
            {"path": "a.dtd", "risk_level": "CRITICAL"},
            {"path": "foo.library", "risk_level": "CRITICAL"},
            {"path": ".prefs", "risk_level": "CRITICAL"},
            {"path": ".project", "risk_level": "CRITICAL"},
            {"path": "app.classpath", "risk_level": "CRITICAL"},
            {"path": "a.jpx", "risk_level": "CRITICAL"},
            {"path": "a.map", "risk_level": "CRITICAL"},
            {"path": "a.csv", "risk_level": "CRITICAL"},
            {"path": "META-INF/MANIFEST.MF", "risk_level": "CRITICAL"},
            {"path": "log4j_origJB1.xml", "risk_level": "CRITICAL"},
            {"path": ".cvsignore", "risk_level": "CRITICAL"},
            {"path": "src/main/java/com/foo/target/X.java", "risk_level": "CRITICAL"},
            {"path": "scripts/ModifyNPGDBPassword.sh", "risk_level": "MEDIUM"},
            {"path": "app/util.py", "risk_level": "LOW"},
            {"path": "configuration/logging.xml", "risk_level": "LOW"},
        ]
    }
    selected = llm_file_scan.files_for_risk_levels(
        module_plan, llm_file_scan.LLM_RISK_LEVELS,
    )
    assert [e["path"] for e in selected] == [
        "app/auth.py", "src/main/java/com/foo/target/X.java",
    ]
    triage = llm_file_scan.files_for_risk_levels(
        module_plan, llm_file_scan.TRIAGE_RISK_LEVELS,
    )
    assert [e["path"] for e in triage] == ["app/util.py"]


def test_files_for_paths_resolves_in_given_order(llm_file_scan):
    module_plan = {
        "files": [
            {"path": "a.py", "risk_level": "CRITICAL"},
            {"path": "b.py", "risk_level": "HIGH"},
            {"path": "c.py", "risk_level": "MEDIUM"},
        ]
    }
    resolved = llm_file_scan.files_for_paths(module_plan, ["c.py", "a.py"])
    assert [e["path"] for e in resolved] == ["c.py", "a.py"]


def test_files_for_paths_skips_unknown_paths(llm_file_scan):
    module_plan = {"files": [{"path": "a.py", "risk_level": "CRITICAL"}]}
    resolved = llm_file_scan.files_for_paths(module_plan, ["a.py", "missing.py"])
    assert [e["path"] for e in resolved] == ["a.py"]


def test_scan_file_skips_xsd_without_calling_llm(tmp_path, llm_file_scan, rules):
    (tmp_path / "schema.xsd").write_text("<schema/>\n", encoding="utf-8")
    calls: list[int] = []

    def fake_call_llm(*_args, **_kwargs):
        calls.append(1)
        return "[]"

    result = llm_file_scan.scan_file(
        repo_root=tmp_path, rel_path="schema.xsd", rules=rules,
        call_llm_fn=fake_call_llm,
    )
    assert result["skipped_non_source"] is True
    assert calls == []


def test_build_code_context_includes_surrounding_lines(llm_file_scan):
    source = "\n".join(f"line {i}" for i in range(1, 21))
    block = llm_file_scan.build_code_context(source, 10)
    assert "5: line 5" in block
    assert "10: line 10  <--" in block
    assert "15: line 15" in block


def test_finalize_findings_enriches_before_suppression(llm_file_scan):
    source = "\n".join(f"line {i}" for i in range(1, 6))
    findings = [
        {
            "rule_id": "llm-extra",
            "cwe": "CWE-79",
            "line": 3,
            "snippet": "line 3",
            "title": "Real issue",
            "verdict": "true_positive",
            "severity": "HIGH",
        },
        {
            "rule_id": "sql-query-string-concat",
            "cwe": "CWE-89",
            "line": 4,
            "snippet": "ignored",
            "title": "concat",
            "verdict": "true_positive",
            "severity": "HIGH",
            "confidence": 0.2,
        },
    ]
    out = llm_file_scan.finalize_findings(findings, source)
    assert len(out) == 1
    assert "3: line 3  <--" in out[0]["snippet"]


def test_finalize_findings_drops_logging_call_after_enrichment(llm_file_scan):
    """Logging-call findings are dropped after enrichment, and nearby (non-anchored) logger calls don't false-suppress."""
    source = "\n".join([
        "line1",
        'logger.info("unrelated line above");',
        'stmt.executeQuery(sql);',
        'logger.info("password=" + password);',
        "line5",
    ])
    findings = [
        {  # anchored on the real SQLi line — must survive despite a logger call one line above
            "rule_id": "llm-extra", "cwe": "CWE-89", "line": 3, "snippet": "placeholder",
            "title": "SQLi", "verdict": "true_positive", "confidence": 0.9,
        },
        {  # anchored on the logger.info line itself — must be dropped
            "rule_id": "java-sensitive-data-in-logs", "cwe": "CWE-532", "line": 4, "snippet": "placeholder",
            "title": "Sensitive data in logs", "verdict": "true_positive", "confidence": 0.95,
        },
    ]
    out = llm_file_scan.finalize_findings(findings, source)
    assert len(out) == 1
    assert out[0]["line"] == 3
    assert "3: stmt.executeQuery(sql);  <--" in out[0]["snippet"]


def test_normalize_finding_reanchors_by_snippet(llm_file_scan):
    source_lines = [f"line {i} is vulnerable here" if i == 42 else f"line {i}" for i in range(1, 101)]
    raw = {
        "verdict": "true_positive",
        "severity": "HIGH",
        "line": 9999,
        "snippet": "42: line 42 is vulnerable here",
        "title": "off-by-chunk report",
    }
    norm = llm_file_scan.normalize_finding(
        raw, file_path="a.py", chunk_start=1, chunk_end=50, source_lines=source_lines,
    )
    assert norm["line"] == 42


def test_normalize_verdict_treats_negation_as_false_positive(llm_file_scan):
    assert llm_file_scan._normalize_verdict("not a true positive") == "false_positive"


# --- scan_file: LLM-primary, no zero-regex-hit skip gate ---------------------

def test_scan_file_calls_llm_even_when_content_matches_no_catalog_rule(tmp_path, llm_file_scan, rules):
    """LLM-primary: `add()` matches none of the regex catalog patterns, but
    scan_file must still call the LLM — there is no zero-regex-hit skip gate."""
    f = tmp_path / "clean.py"
    f.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

    calls = []

    def fake_call_llm(system, user, **kwargs):
        calls.append(user)
        return (
            '[{"verdict": "true_positive", "owasp_category": "A03:2021-Injection", '
            '"severity": "HIGH", "cwe": "CWE-89", "rule_id": "llm-extra", '
            '"title": "made up finding", "line": 1, "snippet": "def add", '
            '"verdict_reason": "test finding"}]'
        )

    result = llm_file_scan.scan_file(
        repo_root=tmp_path, rel_path="clean.py", rules=rules,
        active_frameworks=set(), stack_context="Flask",
        call_llm_fn=fake_call_llm,
    )
    assert len(calls) == 1
    assert result["tp_count"] == 1
    assert result["findings"][0]["title"] == "made up finding"


def test_scan_file_missing_file_short_circuits_without_llm_call(tmp_path, llm_file_scan, rules):
    calls = []

    def fake_call_llm(system, user, **kwargs):
        calls.append(user)
        return "[]"

    result = llm_file_scan.scan_file(
        repo_root=tmp_path, rel_path="does_not_exist.py", rules=rules,
        call_llm_fn=fake_call_llm,
    )
    assert result["read_error"] is True
    assert calls == []


# --- scan_deep_files: per-file writer, mixed TP/FP -----------------------

def test_build_report_from_file_results_counts_tp_fp(llm_file_scan):
    files = [
        {
            "findings": [
                {"verdict": "true_positive", "owasp_category": "A03:2021-Injection"},
                {"verdict": "false_positive", "owasp_category": "A03:2021-Injection"},
            ],
        },
    ]
    report = llm_file_scan.build_report_from_file_results(files)
    assert report["files_scanned"] == 1
    assert report["tp_count"] == 1
    assert report["fp_count"] == 1
    assert report["unverified_count"] == 0
    assert report["by_owasp_category"]["A03:2021-Injection"] == {
        "true_positive": 1, "false_positive": 1, "unverified": 0,
    }


def test_build_report_from_file_results_counts_unverified_separately(llm_file_scan):
    """Regex-only findings must not be swept into the false-positive total —
    nobody dismissed them, they were simply never reviewed."""
    files = [
        {
            "findings": [
                {"verdict": "true_positive", "owasp_category": "A03:2021-Injection"},
                {"verdict": "unverified", "owasp_category": "A03:2021-Injection"},
                {"verdict": "unverified", "owasp_category": "A01:2021-Broken-Access-Control"},
            ],
        },
    ]
    report = llm_file_scan.build_report_from_file_results(files)
    assert report["tp_count"] == 1
    assert report["fp_count"] == 0
    assert report["unverified_count"] == 2
    assert report["by_owasp_category"]["A03:2021-Injection"] == {
        "true_positive": 1, "false_positive": 0, "unverified": 1,
    }


def test_scan_deep_files_writes_once_per_file_with_mixed_tp_fp(tmp_path, llm_file_scan, rules):
    (tmp_path / "a.py").write_text("password = 'hunter2'\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("x = 1\n", encoding="utf-8")

    module_plan = {
        "files": [
            {"path": "a.py", "risk_level": "CRITICAL"},
            {"path": "b.py", "risk_level": "CRITICAL"},
            {"path": "c.py", "risk_level": "LOW"},
        ]
    }

    def fake_call_llm(system, user, **kwargs):
        if "File: a.py" in user:
            return (
                '[{"verdict": "true_positive", '
                '"owasp_category": "A07:2021-Identification-and-Authentication-Failures", '
                '"severity": "HIGH", "cwe": "CWE-798", "rule_id": "secret-password-assign", '
                '"title": "hardcoded password", "line": 1, "snippet": "password = ...", '
                '"verdict_reason": "real secret"}]'
            )
        return (
            '[{"verdict": "false_positive", "owasp_category": "A04:2021-Insecure-Design", '
            '"severity": "LOW", "cwe": "CWE-1188", "rule_id": "llm-extra", '
            '"title": "not an issue", "line": 1, "snippet": "x = 1", '
            '"verdict_reason": "just a constant"}]'
        )

    writer_calls: list[tuple[str, list]] = []

    def writer(file_path, findings):
        writer_calls.append((file_path, findings))

    result = llm_file_scan.scan_deep_files(
        module_plan=module_plan, repo_root=tmp_path, rules=rules,
        findings_writer=writer, call_llm_fn=fake_call_llm,
    )

    assert result["files_scanned"] == 2  # CRITICAL files — LOW is a different pass
    assert len(writer_calls) == 2  # one writer call per LLM-tier file
    by_path = dict(writer_calls)
    assert set(by_path) == {"a.py", "b.py"}
    assert by_path["a.py"][0]["verdict"] == "true_positive"
    assert by_path["b.py"][0]["verdict"] == "false_positive"
    assert result["tp_count"] == 1
    assert result["fp_count"] == 1


def test_scan_deep_files_still_calls_writer_with_empty_findings(tmp_path, llm_file_scan, rules):
    """scan_deep_files calls the writer once per CRITICAL file regardless
    of whether that file produced any findings — an empty-findings guard (if
    wanted) is the writer's own responsibility, e.g. scan_runner's
    `_make_findings_writer` no-ops on an empty list rather than this layer
    silently skipping the call."""
    (tmp_path / "clean.py").write_text("x = 1\n", encoding="utf-8")
    module_plan = {"files": [{"path": "clean.py", "risk_level": "CRITICAL"}]}

    writer_calls = []

    def writer(file_path, findings):
        writer_calls.append((file_path, findings))

    def fake_call_llm(system, user, **kwargs):
        return "[]"

    result = llm_file_scan.scan_deep_files(
        module_plan=module_plan, repo_root=tmp_path, rules=rules,
        findings_writer=writer, call_llm_fn=fake_call_llm,
    )
    assert result["files_scanned"] == 1
    assert writer_calls == [("clean.py", [])]


def test_scan_deep_files_includes_high_skips_medium_and_low(tmp_path, llm_file_scan, rules):
    """The deep (full-file, no-gate) LLM pass covers CRITICAL and HIGH only.
    MEDIUM joined LOW in the regex-gated triage pass, so neither may appear
    here — MEDIUM is the highest-volume tier, and keeping it out of the full
    scan is exactly the cost this split removes."""
    (tmp_path / "crit.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "high.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "med.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "low.py").write_text("password = 'hunter2'\n", encoding="utf-8")

    module_plan = {
        "files": [
            {"path": "crit.py", "risk_level": "CRITICAL"},
            {"path": "high.py", "risk_level": "HIGH"},
            {"path": "med.py", "risk_level": "MEDIUM"},
            {"path": "low.py", "risk_level": "LOW"},
        ]
    }
    seen: list[str] = []

    def fake_call_llm(system, user, **kwargs):
        for name in ("crit.py", "high.py", "med.py", "low.py"):
            if f"File: {name}" in user:
                seen.append(name)
        return "[]"

    result = llm_file_scan.scan_deep_files(
        module_plan=module_plan, repo_root=tmp_path, rules=rules,
        call_llm_fn=fake_call_llm, file_workers=1, chunk_workers=1,
    )
    assert result["files_scanned"] == 2
    assert set(seen) == {"crit.py", "high.py"}


def test_scan_deep_files_entries_override_ignores_module_plan(tmp_path, llm_file_scan, rules):
    """When `entries` is given, it is the exact working set — module_plan's
    own files (even ones that would otherwise qualify) are not consulted."""
    (tmp_path / "crit.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "only_this.py").write_text("x = 1\n", encoding="utf-8")

    # module_plan claims crit.py is the only CRITICAL/HIGH file...
    module_plan = {"files": [{"path": "crit.py", "risk_level": "CRITICAL"}]}
    # ...but entries names a different file entirely.
    entries = [{"path": "only_this.py", "risk_level": "CRITICAL"}]

    seen: set[str] = set()

    def fake_call_llm(system, user, **kwargs):
        # "[]" triggers a parse-failure retry (empty array), so this may be
        # called more than once for the same file — a set absorbs that.
        for name in ("crit.py", "only_this.py"):
            if f"File: {name}" in user:
                seen.add(name)
        return "[]"

    result = llm_file_scan.scan_deep_files(
        module_plan=module_plan, entries=entries, repo_root=tmp_path, rules=rules,
        call_llm_fn=fake_call_llm, file_workers=1, chunk_workers=1,
    )
    assert result["files_scanned"] == 1
    assert seen == {"only_this.py"}


def test_scan_file_passes_shared_usage_to_llm(tmp_path, llm_file_scan, rules):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    usage = {"cost_usd": 2.0, "cost_cutoff_usd": 2.0, "calls": []}
    seen = []

    def fake_call_llm(system, user, **kwargs):
        seen.append(kwargs.get("usage"))
        assert kwargs.get("step") == "scan_deep_files"
        return "[]"

    llm_file_scan.scan_file(
        repo_root=tmp_path, rel_path="a.py", rules=rules,
        usage=usage, call_llm_fn=fake_call_llm,
    )
    assert seen and seen[0] is usage


def test_scan_triage_files_skips_zero_hit_files(tmp_path, llm_file_scan, rules):
    (tmp_path / "clean.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    (tmp_path / "secret.py").write_text("password = 'hunter2'\n", encoding="utf-8")
    module_plan = {
        "files": [
            {"path": "clean.py", "risk_level": "LOW", "lang": "python"},
            {"path": "secret.py", "risk_level": "LOW", "lang": "python"},
        ]
    }
    llm_calls = []
    writer_calls = []

    def fake_call_llm(system, user, **kwargs):
        llm_calls.append(user)
        assert "secret-password-assign" in user
        assert kwargs.get("step") == "scan_triage_files"
        return (
            '[{"verdict": "true_positive", '
            '"owasp_category": "A07:2021-Identification-and-Authentication-Failures", '
            '"severity": "HIGH", "cwe": "CWE-798", "rule_id": "secret-password-assign", '
            '"title": "hardcoded password", "line": 1, "snippet": "password = \'hunter2\'", '
            '"verdict_reason": "literal password"}]'
        )

    def writer(file_path, findings):
        writer_calls.append((file_path, findings))

    result = llm_file_scan.scan_triage_files(
        triage_mode=llm_file_scan.TRIAGE_MODE_LLM,
        module_plan=module_plan, repo_root=tmp_path, rules=rules,
        findings_writer=writer, call_llm_fn=fake_call_llm, file_workers=1,
    )
    assert result["files_regex_scanned"] == 2
    assert result["files_scanned"] == 1
    assert len(llm_calls) == 1
    assert [p for p, _ in writer_calls] == ["secret.py"]
    assert writer_calls[0][1][0]["kind"] == "regex"
    assert writer_calls[0][1][0]["verdict"] == "true_positive"
    assert writer_calls[0][1][0]["rule_id"] == "secret-password-assign"


# --- regex-only triage (the default mode) ------------------------------------

def test_scan_triage_files_regex_only_makes_no_llm_calls(tmp_path, llm_file_scan, rules):
    """The whole point of the default mode: thousands of MEDIUM/LOW files cost
    zero LLM round trips. If this ever regresses, scans go from minutes back to
    hours, so assert the stub is never invoked at all."""
    (tmp_path / "clean.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    (tmp_path / "secret.py").write_text("password = 'hunter2'\n", encoding="utf-8")
    module_plan = {
        "files": [
            {"path": "clean.py", "risk_level": "LOW", "lang": "python"},
            {"path": "secret.py", "risk_level": "MEDIUM", "lang": "python"},
        ]
    }
    writer_calls = []

    def exploding_llm(*_args, **_kwargs):
        raise AssertionError("regex-only triage must never call the LLM")

    result = llm_file_scan.scan_triage_files(
        module_plan=module_plan, repo_root=tmp_path, rules=rules,
        findings_writer=lambda p, f: writer_calls.append((p, f)),
        call_llm_fn=exploding_llm, file_workers=1,
    )
    assert result["files_regex_scanned"] == 2
    assert result["files_scanned"] == 1          # only the file with a hit
    assert result["unverified_count"] == 1
    assert result["tp_count"] == 0 and result["fp_count"] == 0
    assert [p for p, _ in writer_calls] == ["secret.py"]

    finding = writer_calls[0][1][0]
    assert finding["verdict"] == "unverified"
    assert finding["kind"] == "regex"
    assert finding["rule_id"] == "secret-password-assign"
    assert finding["confidence"] is None          # no model judged this
    assert finding["matched_text"]                # bare match kept for grouping
    assert finding["severity"] and finding["owasp_category"]


def test_regex_only_is_the_default_mode(tmp_path, llm_file_scan, rules):
    """Callers that pass no triage_mode get regex_only — the default is what
    every production scan actually runs."""
    (tmp_path / "secret.py").write_text("password = 'hunter2'\n", encoding="utf-8")

    def exploding_llm(*_args, **_kwargs):
        raise AssertionError("default mode must not call the LLM")

    result = llm_file_scan.scan_triage_files(
        module_plan={"files": [{"path": "secret.py", "risk_level": "LOW", "lang": "python"}]},
        repo_root=tmp_path, rules=rules, call_llm_fn=exploding_llm, file_workers=1,
    )
    assert result["unverified_count"] == 1


def test_unverified_verdict_survives_normalization(llm_file_scan):
    """_normalize_verdict falls through to false_positive for anything it does
    not recognize. If "unverified" were not in _VALID_VERDICTS, every
    regex-only finding would be silently rewritten to false_positive and
    disappear from the report."""
    assert llm_file_scan._normalize_verdict("unverified") == "unverified"
    assert llm_file_scan.VERDICT_UNVERIFIED in llm_file_scan._VALID_VERDICTS


def test_findings_from_hits_dedupes_same_rule_same_line(tmp_path, llm_file_scan, rules):
    """Repeat hits of one rule on one line collapse; two different rules on the
    same line stay separate, because they describe different problems."""
    rules_by_id = {r.id: r for r in rules}
    hits = [
        {"line": 1, "rule": "secret-password-assign", "matched_text": "password = 'a'", "severity": "HIGH"},
        {"line": 1, "rule": "secret-password-assign", "matched_text": "password = 'a'", "severity": "HIGH"},
        {"line": 1, "rule": "md5-hash", "matched_text": "md5(", "severity": "MEDIUM"},
        {"line": 9, "rule": "secret-password-assign", "matched_text": "password = 'b'", "severity": "HIGH"},
    ]
    out = llm_file_scan.findings_from_hits(
        file_path="a.py", source_text="x\n" * 20, hits=hits, rules_by_id=rules_by_id,
    )
    assert len(out) == 3
    assert {(f["rule_id"], f["line"]) for f in out} == {
        ("secret-password-assign", 1), ("md5-hash", 1), ("secret-password-assign", 9),
    }


def test_findings_from_hits_sets_group_by_rule_from_catalog(tmp_path, llm_file_scan, rules):
    """The finding dict denormalizes RegexRule.group_by_rule so downstream
    grouping (group_key_for_finding, and later the DB row) never needs the
    rule catalog again."""
    rules_by_id = {r.id: r for r in rules}
    hits = [
        {"line": 1, "rule": "serializable-missing-svuid",
         "matched_text": "class Foo implements Serializable", "severity": "INFO"},
        {"line": 9, "rule": "secret-password-assign", "matched_text": "password = 'a'", "severity": "HIGH"},
    ]
    out = llm_file_scan.findings_from_hits(
        file_path="a.py", source_text="x\n" * 20, hits=hits, rules_by_id=rules_by_id,
    )
    by_rule = {f["rule_id"]: f for f in out}
    assert by_rule["serializable-missing-svuid"]["group_by_rule"] is True
    assert by_rule["secret-password-assign"]["group_by_rule"] is False


def test_scan_triage_files_skips_generated_files(tmp_path, llm_file_scan, rules):
    """Generated code is skipped even when it has hits — its findings are not
    actionable (you would fix the generator, not the output) and a legacy repo
    can carry thousands of near-identical generated files."""
    (tmp_path / "handwritten.py").write_text("password = 'hunter2'\n", encoding="utf-8")
    (tmp_path / "generated.py").write_text(
        "# This file was automatically generated by castor. DO NOT EDIT.\n"
        "password = 'hunter2'\n",
        encoding="utf-8",
    )
    module_plan = {
        "files": [
            {"path": "handwritten.py", "risk_level": "MEDIUM", "lang": "python"},
            {"path": "generated.py", "risk_level": "MEDIUM", "lang": "python"},
        ]
    }
    writer_calls = []
    result = llm_file_scan.scan_triage_files(
        module_plan=module_plan, repo_root=tmp_path, rules=rules,
        findings_writer=lambda p, f: writer_calls.append(p), file_workers=1,
    )
    assert result["files_skipped_generated"] == 1
    assert result["files_scanned"] == 1
    assert [p for p in writer_calls] == ["handwritten.py"]


def test_scan_triage_files_skips_vendored_minified_files(tmp_path, llm_file_scan, rules):
    """A vendored/minified library file (e.g. a bundled *.min.js) is skipped
    even when its regex hits fire — nobody can act on a finding inside a
    third-party dependency's own minified source."""
    (tmp_path / "handwritten.py").write_text("password = 'hunter2'\n", encoding="utf-8")
    (tmp_path / "vendor.min.js").write_text("password = 'hunter2'\n", encoding="utf-8")
    module_plan = {
        "files": [
            {"path": "handwritten.py", "risk_level": "MEDIUM", "lang": "python"},
            {"path": "vendor.min.js", "risk_level": "MEDIUM", "lang": "python"},
        ]
    }
    writer_calls = []
    result = llm_file_scan.scan_triage_files(
        module_plan=module_plan, repo_root=tmp_path, rules=rules,
        findings_writer=lambda p, f: writer_calls.append(p), file_workers=1,
    )
    assert result["files_skipped_vendored"] == 1
    assert result["files_scanned"] == 1
    assert [p for p in writer_calls] == ["handwritten.py"]


@pytest.mark.parametrize("header", [
    "// @Generated(\"com.example.Gen\")",
    "/* DO NOT EDIT - generated by wsdl2java */",
    "# This file was automatically generated.",
    "// Auto-generated by protoc",
    "<!-- generated from schema.xsd -->",
])
def test_looks_generated_detects_common_markers(llm_file_scan, header):
    assert llm_file_scan.looks_generated(header + "\nclass Foo {}\n") is True


@pytest.mark.parametrize("text", [
    "public class UserDao { }",
    "",
    "# a normal comment about the generated report feature",
])
def test_looks_generated_ignores_handwritten_source(llm_file_scan, text):
    # "generated report" prose must not trip it — only generation markers do.
    assert llm_file_scan.looks_generated(text) is False


def test_looks_generated_only_inspects_the_header(llm_file_scan):
    """A marker deep in the file is a comment *about* generation, not a
    declaration that this file is generated."""
    body = "x = 1\n" * 2000 + "# this file was generated\n"
    assert len(body) > llm_file_scan.GENERATED_HEADER_SCAN_CHARS
    assert llm_file_scan.looks_generated(body) is False


def test_scan_triage_files_entries_override_routes_overflow_critical_files(tmp_path, llm_file_scan, rules):
    """This is what deep-scan-cap overflow relies on: an entry that still
    carries risk_level="CRITICAL" (it fails the TRIAGE_RISK_LEVELS membership
    check) still gets regex-gated triage — hit-context only, kind=regex, not
    a full-file kind=llm deep scan — when passed explicitly via `entries`."""
    (tmp_path / "overflow.py").write_text("password = 'hunter2'\n", encoding="utf-8")
    # module_plan doesn't even list this file under "files" — proves the
    # working set comes entirely from `entries`, not from risk_level lookup.
    module_plan = {"files": []}
    overflow_entry = {"path": "overflow.py", "risk_level": "CRITICAL", "lang": "python"}

    def fake_call_llm(system, user, **kwargs):
        assert kwargs.get("step") == "scan_triage_files"
        # Only the hit + context window, never a whole-file deep-scan prompt.
        assert "secret-password-assign" in user
        return (
            '[{"verdict": "true_positive", '
            '"owasp_category": "A07:2021-Identification-and-Authentication-Failures", '
            '"severity": "HIGH", "cwe": "CWE-798", "rule_id": "secret-password-assign", '
            '"title": "hardcoded password", "line": 1, "snippet": "password = \'hunter2\'", '
            '"verdict_reason": "literal password"}]'
        )

    result = llm_file_scan.scan_triage_files(
        triage_mode=llm_file_scan.TRIAGE_MODE_LLM,
        module_plan=module_plan, entries=[overflow_entry], repo_root=tmp_path, rules=rules,
        call_llm_fn=fake_call_llm, file_workers=1,
    )
    assert result["files_scanned"] == 1
    assert result["files"][0]["findings"][0]["kind"] == "regex"


def test_scan_triage_files_drops_invented_findings(tmp_path, llm_file_scan, rules):
    (tmp_path / "secret.py").write_text("password = 'hunter2'\n", encoding="utf-8")
    module_plan = {"files": [{"path": "secret.py", "risk_level": "LOW", "lang": "python"}]}

    def fake_call_llm(system, user, **kwargs):
        return (
            '['
            '{"verdict": "true_positive", "owasp_category": "A07:2021-Identification-and-Authentication-Failures", '
            '"severity": "HIGH", "cwe": "CWE-798", "rule_id": "secret-password-assign", '
            '"title": "hardcoded password", "line": 1, "snippet": "password = \'hunter2\'", '
            '"verdict_reason": "literal password"},'
            '{"verdict": "true_positive", "owasp_category": "A03:2021-Injection", '
            '"severity": "HIGH", "cwe": "CWE-89", "rule_id": "llm-extra", '
            '"title": "invented SQLi", "line": 1, "snippet": "password = \'hunter2\'", '
            '"verdict_reason": "should be dropped"}'
            ']'
        )

    result = llm_file_scan.scan_triage_files(
        triage_mode=llm_file_scan.TRIAGE_MODE_LLM,
        module_plan=module_plan, repo_root=tmp_path, rules=rules,
        call_llm_fn=fake_call_llm, file_workers=1,
    )
    assert result["files_scanned"] == 1
    ids = {f["rule_id"] for f in result["files"][0]["findings"]}
    assert ids == {"secret-password-assign"}


# A valid triage response for the `secret-password-assign` hit. Returning a
# real finding (rather than "[]") keeps these tests on the single-call path —
# an empty array is treated as a parse failure and triggers one retry.
_TRIAGE_PASSWORD_FINDING = (
    '[{"verdict": "true_positive", '
    '"owasp_category": "A07:2021-Identification-and-Authentication-Failures", '
    '"severity": "HIGH", "cwe": "CWE-798", "rule_id": "secret-password-assign", '
    '"title": "hardcoded password", "line": 1, "snippet": "password = \'hunter2\'", '
    '"verdict_reason": "literal password"}]'
)


def test_scan_triage_files_covers_medium_and_skips_zero_hit_medium(tmp_path, llm_file_scan, rules):
    """MEDIUM is regex-gated exactly like LOW: a MEDIUM file with no regex hit
    costs no LLM call and no writer call at all."""
    (tmp_path / "med_clean.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    (tmp_path / "med_hit.py").write_text("password = 'hunter2'\n", encoding="utf-8")
    module_plan = {
        "files": [
            {"path": "med_clean.py", "risk_level": "MEDIUM", "lang": "python"},
            {"path": "med_hit.py", "risk_level": "MEDIUM", "lang": "python"},
        ]
    }
    prompts = []
    writer_calls = []

    def fake_call_llm(system, user, **kwargs):
        prompts.append(user)
        return _TRIAGE_PASSWORD_FINDING

    result = llm_file_scan.scan_triage_files(
        triage_mode=llm_file_scan.TRIAGE_MODE_LLM,
        module_plan=module_plan, repo_root=tmp_path, rules=rules,
        findings_writer=lambda p, f: writer_calls.append(p),
        call_llm_fn=fake_call_llm, file_workers=1,
    )
    assert result["files_regex_scanned"] == 2
    assert result["files_scanned"] == 1
    # The clean MEDIUM file never reached the LLM or the writer.
    assert all("med_clean.py" not in p for p in prompts)
    assert prompts and "med_hit.py" in prompts[0]
    assert writer_calls == ["med_hit.py"]


def test_scan_triage_files_sends_only_hit_context_not_whole_file(tmp_path, llm_file_scan, rules):
    """The triage prompt carries the hit candidates plus a context window each —
    never the entire file. A hit near the top of a long file must not drag the
    rest of the file into the prompt."""
    body = "\n".join(
        ["password = 'hunter2'"] + [f"UNIQUE_FAR_AWAY_MARKER_{i} = {i}" for i in range(400)]
    )
    (tmp_path / "big.py").write_text(body + "\n", encoding="utf-8")
    module_plan = {"files": [{"path": "big.py", "risk_level": "MEDIUM", "lang": "python"}]}
    prompts = []

    def fake_call_llm(system, user, **kwargs):
        prompts.append(user)
        return _TRIAGE_PASSWORD_FINDING

    llm_file_scan.scan_triage_files(
        triage_mode=llm_file_scan.TRIAGE_MODE_LLM,
        module_plan=module_plan, repo_root=tmp_path, rules=rules,
        call_llm_fn=fake_call_llm, file_workers=1,
    )
    assert len(prompts) == 1
    prompt = prompts[0]
    assert "password = 'hunter2'" in prompt        # the hit itself
    assert "UNIQUE_FAR_AWAY_MARKER_0" in prompt    # its immediate context
    # Everything past the context window stays out of the prompt.
    assert "UNIQUE_FAR_AWAY_MARKER_399" not in prompt
    assert "UNIQUE_FAR_AWAY_MARKER_200" not in prompt
    assert len(prompt) < len(body)


def test_scan_triage_files_passes_shared_usage_to_llm(tmp_path, llm_file_scan, rules):
    (tmp_path / "secret.py").write_text("password = 'hunter2'\n", encoding="utf-8")
    usage = {"cost_usd": 2.0, "cost_cutoff_usd": 2.0, "calls": []}
    seen = []

    def fake_call_llm(system, user, **kwargs):
        seen.append(kwargs.get("usage"))
        return "[]"

    llm_file_scan.scan_triage_files(
        triage_mode=llm_file_scan.TRIAGE_MODE_LLM,
        module_plan={"files": [{"path": "secret.py", "risk_level": "LOW", "lang": "python"}]},
        repo_root=tmp_path, rules=rules, usage=usage,
        call_llm_fn=fake_call_llm, file_workers=1,
    )
    assert seen and seen[0] is usage


def test_scan_file_cutoff_routes_shared_usage_to_ollama(tmp_path, llm_file_scan, rules, monkeypatch):
    """Passing the scan usage dict (not an empty local copy) lets the $2 cutoff fire."""
    import sys

    llm = sys.modules["llm_client"]
    routes: list[str] = []

    def fake_bedrock(*_a, **_k):
        routes.append("bedrock")
        return "[]"

    def fake_ollama(*_a, **kwargs):
        routes.append("ollama")
        usage = kwargs.get("usage")
        if usage is not None:
            llm.record_llm_usage(usage, "scan_deep_files", 10, 5, provider="ollama")
        return "[]"

    monkeypatch.setattr(llm, "_call_bedrock", fake_bedrock)
    monkeypatch.setattr(llm, "_call_ollama", fake_ollama)

    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    usage = llm.init_usage(
        "bedrock",
        llm.BEDROCK_MODEL_ID,
        fallback_provider="ollama",
        fallback_model="granite-code:3b",
        cost_cutoff_usd=2.0,
    )
    usage["cost_usd"] = 2.0
    llm_file_scan.scan_file(
        repo_root=tmp_path, rel_path="a.py", rules=rules,
        usage=usage, call_llm_fn=llm.call_llm,
    )
    assert routes
    assert all(r == "ollama" for r in routes)
    assert "bedrock" not in routes
    assert usage["fallback_switched"] is True


def test_scan_triage_files_skips_shell_scripts(tmp_path, llm_file_scan, rules):
    """`.sh` stays in Discovery but is never regex-scanned — a sed substitution
    that looks like `password = '...'` is not a finding."""
    (tmp_path / "ModifyNPGDBPassword.sh").write_text(
        "sed -i 's/password = \"old\"/password = \"new\"/' cfg\n",
        encoding="utf-8",
    )

    def exploding_llm(*_args, **_kwargs):
        raise AssertionError("regex-only triage must never call the LLM")

    result = llm_file_scan.scan_triage_files(
        module_plan={"files": [
            {"path": "ModifyNPGDBPassword.sh", "risk_level": "MEDIUM", "lang": "shell"},
        ]},
        repo_root=tmp_path, rules=rules,
        call_llm_fn=exploding_llm, file_workers=1,
    )
    assert result["files_regex_scanned"] == 0
    assert result["unverified_count"] == 0
    assert result["files_scanned"] == 0


# --- grouped confirmation of unverified MEDIUM/LOW findings ------------------

def _unverified_finding(*, file_path, rule_id="secret-password-assign", line=1,
                         matched_text="password = 'hunter2'", severity="MEDIUM"):
    return {
        "rule_id": rule_id,
        "title": "hardcoded password",
        "severity": severity,
        "cwe": "CWE-798",
        "owasp_category": "A07:2021-Identification-and-Authentication-Failures",
        "line": line,
        "snippet": matched_text,
        "matched_text": matched_text,
        "verdict": "unverified",
        "verdict_reason": "Regex pattern match, not reviewed by an LLM — confirm before acting on it.",
        "kind": "regex",
        "confidence": None,
        "file_path": file_path,
    }


def test_group_key_for_finding_groups_by_rule_and_matched_text(llm_file_scan):
    a = _unverified_finding(file_path="a.py")
    b = _unverified_finding(file_path="b.py")  # same rule + matched text
    c = _unverified_finding(file_path="c.py", matched_text="password = 'different'")
    assert llm_file_scan.group_key_for_finding(a) == llm_file_scan.group_key_for_finding(b)
    assert llm_file_scan.group_key_for_finding(a) != llm_file_scan.group_key_for_finding(c)


def test_group_key_for_finding_ignores_matched_text_when_group_by_rule(llm_file_scan):
    """A rule opted into group_by_rule collapses by rule_id alone — two
    findings from the same rule but with different matched text (e.g. two
    different class names) must still land in the same group."""
    a = _unverified_finding(file_path="a.py", rule_id="serializable-missing-svuid",
                             matched_text="class Foo implements Serializable")
    a["group_by_rule"] = True
    b = _unverified_finding(file_path="b.py", rule_id="serializable-missing-svuid",
                             matched_text="class Bar implements Serializable")
    b["group_by_rule"] = True
    assert llm_file_scan.group_key_for_finding(a) == llm_file_scan.group_key_for_finding(b)


# --- pure grouping (no LLM call) ---------------------------------------------

def test_group_unverified_findings_collapses_same_construct_no_llm_call(llm_file_scan):
    """The whole point of the standalone grouping step: three occurrences of
    the same construct across three files collapse into one group, and this
    function takes no call_llm_fn at all — it is structurally incapable of
    making an LLM call."""
    file_results = [
        {"file_path": "a.py", "findings": [_unverified_finding(file_path="a.py")]},
        {"file_path": "b.py", "findings": [_unverified_finding(file_path="b.py")]},
        {"file_path": "c.py", "findings": [_unverified_finding(file_path="c.py")]},
    ]

    summary = llm_file_scan.group_unverified_findings(file_results)

    assert summary["candidate_count"] == 3
    assert summary["group_count"] == 1
    assert len(summary["groups"]) == 1
    group = summary["groups"][0]
    assert group["rule_id"] == "secret-password-assign"
    assert group["occurrence_count"] == 3
    assert set(group["sample_files"]) == {"a.py", "b.py", "c.py"}
    assert group["owasp_category"] == "A07:2021-Identification-and-Authentication-Failures"

    # verdicts are never touched by this function
    for file_result in file_results:
        assert file_result["findings"][0]["verdict"] == "unverified"


def test_group_unverified_findings_keeps_distinct_constructs_separate(llm_file_scan):
    file_results = [
        {"file_path": "a.py", "findings": [_unverified_finding(file_path="a.py")]},
        {"file_path": "b.py", "findings": [
            _unverified_finding(file_path="b.py", matched_text="password = 'different'"),
        ]},
    ]
    summary = llm_file_scan.group_unverified_findings(file_results)
    assert summary["group_count"] == 2
    assert summary["candidate_count"] == 2


def test_group_unverified_findings_sorted_by_occurrence_count_descending(llm_file_scan):
    file_results = [
        {"file_path": "a.py", "findings": [_unverified_finding(file_path="a.py", rule_id="rule-a")]},
        {"file_path": "b.py", "findings": [_unverified_finding(file_path="b.py", rule_id="rule-b")]},
        {"file_path": "c.py", "findings": [_unverified_finding(file_path="c.py", rule_id="rule-b")]},
        {"file_path": "d.py", "findings": [_unverified_finding(file_path="d.py", rule_id="rule-b")]},
    ]
    summary = llm_file_scan.group_unverified_findings(file_results)
    assert summary["group_count"] == 2
    assert summary["groups"][0]["rule_id"] == "rule-b"
    assert summary["groups"][0]["occurrence_count"] == 3
    assert summary["groups"][1]["rule_id"] == "rule-a"
    assert summary["groups"][1]["occurrence_count"] == 1


def test_group_unverified_findings_ignores_confirmed_but_includes_overflow_severities(llm_file_scan):
    """Regression guard: CRITICAL/HIGH files that overflowed DEEP_SCAN_FILE_CAP
    into this tier still get grouped — only already-confirmed (non-unverified)
    findings are excluded. Excluding overflow severities by default used to
    strand those findings at verdict=unverified forever, since nothing else
    in the pipeline ever revisits them."""
    already_confirmed = _unverified_finding(file_path="a.py", line=2)
    already_confirmed["verdict"] = "true_positive"
    critical_overflow = _unverified_finding(file_path="a.py", line=3, severity="CRITICAL")

    file_results = [{"file_path": "a.py", "findings": [
        _unverified_finding(file_path="a.py", line=1),
        already_confirmed,
        critical_overflow,
    ]}]

    summary = llm_file_scan.group_unverified_findings(file_results)
    # Same rule_id + matched_text as the plain MEDIUM finding, so both land in
    # one group of 2 candidates — the already-confirmed finding is excluded.
    assert summary["candidate_count"] == 2
    assert summary["group_count"] == 1


def test_group_confirm_unverified_findings_one_call_per_group(tmp_path, llm_file_scan, rules):
    """Three occurrences of the same construct across three files must cost
    exactly one LLM call, and that one verdict must land on all three."""
    for name in ("a.py", "b.py", "c.py"):
        (tmp_path / name).write_text("password = 'hunter2'\n", encoding="utf-8")

    file_results = [
        {"file_path": "a.py", "findings": [_unverified_finding(file_path="a.py")]},
        {"file_path": "b.py", "findings": [_unverified_finding(file_path="b.py")]},
        {"file_path": "c.py", "findings": [_unverified_finding(file_path="c.py")]},
    ]

    calls = []

    def fake_call_llm(system, user, **kwargs):
        calls.append(user)
        assert kwargs.get("step") == "group_confirm_triage_findings"
        assert "occurrence_count" in user
        return (
            '[{"verdict": "true_positive", "confidence": 0.9, '
            '"verdict_reason": "real hardcoded credential"}]'
        )

    writer_calls = []

    def writer(file_path, updates):
        writer_calls.append((file_path, updates))

    result = llm_file_scan.group_confirm_unverified_findings(
        file_results=file_results, repo_root=tmp_path, rules=rules,
        call_llm_fn=fake_call_llm, group_workers=1,
        verdict_updates_writer=writer,
    )

    assert len(calls) == 1  # one call for the whole group, not one per file
    assert result["group_count"] == 1
    assert result["confirmed_finding_count"] == 3
    assert result["tp_group_count"] == 1

    for file_result in file_results:
        finding = file_result["findings"][0]
        assert finding["verdict"] == "true_positive"
        assert finding["confidence"] == 0.9
        assert "confirmed via grouped review of 3 occurrence(s)" in finding["verdict_reason"]

    assert {p for p, _ in writer_calls} == {"a.py", "b.py", "c.py"}
    for _path, updates in writer_calls:
        assert updates[0]["verdict"] == "true_positive"
        assert updates[0]["rule_id"] == "secret-password-assign"
        assert updates[0]["line"] == 1


def test_group_confirm_unverified_findings_confirms_overflow_severities_too(tmp_path, llm_file_scan, rules):
    """Already-confirmed findings are left alone, but a CRITICAL/HIGH-overflow
    unverified finding sharing the same construct as a MEDIUM one is confirmed
    right along with it — this is the fix for scans that used to finish with
    findings permanently stuck at verdict=unverified because the confirm step
    only ever looked at MEDIUM/LOW severities."""
    (tmp_path / "a.py").write_text("password = 'hunter2'\n", encoding="utf-8")

    already_confirmed = _unverified_finding(file_path="a.py", line=2)
    already_confirmed["verdict"] = "true_positive"
    critical_overflow = _unverified_finding(file_path="a.py", line=3, severity="CRITICAL")

    file_results = [{"file_path": "a.py", "findings": [
        _unverified_finding(file_path="a.py", line=1),
        already_confirmed,
        critical_overflow,
    ]}]

    calls = []

    def fake_call_llm(system, user, **kwargs):
        calls.append(user)
        return '[{"verdict": "false_positive", "confidence": 0.2, "verdict_reason": "test fixture"}]'

    result = llm_file_scan.group_confirm_unverified_findings(
        file_results=file_results, repo_root=tmp_path, rules=rules,
        call_llm_fn=fake_call_llm, group_workers=1,
    )

    # Same rule_id + matched_text as the plain MEDIUM finding -> one group,
    # one LLM call, applied to both members.
    assert result["candidate_count"] == 2
    assert len(calls) == 1
    assert already_confirmed["verdict"] == "true_positive"  # untouched
    assert critical_overflow["verdict"] == "false_positive"  # confirmed, not stranded


def test_confirm_finding_group_llm_error_leaves_unverified(tmp_path, llm_file_scan, rules):
    (tmp_path / "a.py").write_text("password = 'hunter2'\n", encoding="utf-8")
    file_results = [{"file_path": "a.py", "findings": [_unverified_finding(file_path="a.py")]}]

    def broken_llm(*_args, **_kwargs):
        raise RuntimeError("provider unavailable")

    result = llm_file_scan.group_confirm_unverified_findings(
        file_results=file_results, repo_root=tmp_path, rules=rules,
        call_llm_fn=broken_llm, group_workers=1,
    )

    assert result["error_group_count"] == 1
    assert result["confirmed_finding_count"] == 0
    finding = file_results[0]["findings"][0]
    assert finding["verdict"] == "unverified"  # left untouched on error


# --- batched grouped confirmation (multiple groups per LLM call) ------------

import json as _json
import re as _re


def _pattern_indices(user_prompt):
    """Local group_index values present in a batch prompt, in the order the
    batch built them (matches build_group_confirm_batch_prompt's block
    labels: 'Pattern <group_index> — <file_path>:')."""
    return [int(i) for i in _re.findall(r"Pattern (\d+) —", user_prompt)]


def test_group_confirm_unverified_findings_default_groups_per_call_is_backcompat(tmp_path, llm_file_scan, rules):
    """With no groups_per_call/group_cap passed, 3 distinct groups still cost
    3 separate LLM calls — the default must reproduce today's behavior."""
    for i, name in enumerate(("a.py", "b.py", "c.py")):
        (tmp_path / name).write_text(f"password = 'secret{i}'\n", encoding="utf-8")

    file_results = [
        {"file_path": name, "findings": [
            _unverified_finding(file_path=name, rule_id=f"rule-{i}", matched_text=f"password = 'secret{i}'")
        ]}
        for i, name in enumerate(("a.py", "b.py", "c.py"))
    ]

    calls = []

    def fake_call_llm(system, user, **kwargs):
        calls.append(user)
        return '[{"verdict": "true_positive", "confidence": 0.8, "verdict_reason": "real"}]'

    result = llm_file_scan.group_confirm_unverified_findings(
        file_results=file_results, repo_root=tmp_path, rules=rules,
        call_llm_fn=fake_call_llm, group_workers=1,
    )

    assert len(calls) == 3
    assert result["group_count"] == 3
    assert result["confirm_group_count"] == 3
    assert result["skipped_group_count"] == 0


def test_confirm_finding_group_batch_one_call_for_multiple_groups(tmp_path, llm_file_scan, rules):
    """3 distinct groups with groups_per_call=3 must cost exactly one LLM call."""
    for i, name in enumerate(("a.py", "b.py", "c.py")):
        (tmp_path / name).write_text(f"password = 'secret{i}'\n", encoding="utf-8")

    file_results = [
        {"file_path": name, "findings": [
            _unverified_finding(file_path=name, rule_id=f"rule-{i}", matched_text=f"password = 'secret{i}'")
        ]}
        for i, name in enumerate(("a.py", "b.py", "c.py"))
    ]

    calls = []

    def fake_call_llm(system, user, **kwargs):
        calls.append(user)
        assert kwargs.get("step") == "group_confirm_triage_findings"
        indices = _pattern_indices(user)
        return _json.dumps([
            {"group_index": idx, "verdict": "true_positive", "confidence": 0.7 + idx * 0.01,
             "verdict_reason": f"reason {idx}"}
            for idx in indices
        ])

    result = llm_file_scan.group_confirm_unverified_findings(
        file_results=file_results, repo_root=tmp_path, rules=rules,
        call_llm_fn=fake_call_llm, group_workers=1, groups_per_call=3,
    )

    assert len(calls) == 1
    assert result["confirm_group_count"] == 3
    assert result["tp_group_count"] == 3
    for file_result in file_results:
        assert file_result["findings"][0]["verdict"] == "true_positive"


def test_group_confirm_unverified_findings_batches_across_multiple_calls(tmp_path, llm_file_scan, rules):
    """12 distinct groups with groups_per_call=5 must batch into 3 calls (5+5+2),
    and every group must get the verdict from its own batch's response."""
    names = [f"f{i}.py" for i in range(12)]
    for i, name in enumerate(names):
        (tmp_path / name).write_text(f"password = 'secret{i}'\n", encoding="utf-8")

    file_results = [
        {"file_path": name, "findings": [
            _unverified_finding(file_path=name, rule_id=f"rule-{i}", matched_text=f"password = 'secret{i}'")
        ]}
        for i, name in enumerate(names)
    ]

    calls = []

    def fake_call_llm(system, user, **kwargs):
        calls.append(user)
        indices = _pattern_indices(user)
        return _json.dumps([
            {"group_index": idx, "verdict": "true_positive", "confidence": 0.9, "verdict_reason": "real"}
            for idx in indices
        ])

    result = llm_file_scan.group_confirm_unverified_findings(
        file_results=file_results, repo_root=tmp_path, rules=rules,
        call_llm_fn=fake_call_llm, group_workers=1, groups_per_call=5,
    )

    assert len(calls) == 3  # 5 + 5 + 2
    assert result["confirm_group_count"] == 12
    assert result["tp_group_count"] == 12
    for file_result in file_results:
        assert file_result["findings"][0]["verdict"] == "true_positive"


def test_confirm_finding_group_batch_salvages_partial_response_via_fallback(tmp_path, llm_file_scan, rules):
    """A batch of 3 whose response only covers 2 group_index values falls back
    to a per-group call for the missing one, rather than leaving it unverified."""
    for i, name in enumerate(("a.py", "b.py", "c.py")):
        (tmp_path / name).write_text(f"password = 'secret{i}'\n", encoding="utf-8")

    file_results = [
        {"file_path": name, "findings": [
            _unverified_finding(file_path=name, rule_id=f"rule-{i}", matched_text=f"password = 'secret{i}'")
        ]}
        for i, name in enumerate(("a.py", "b.py", "c.py"))
    ]

    calls = []

    def fake_call_llm(system, user, **kwargs):
        calls.append(user)
        if "group_index" in user:  # the batched call
            # Only respond for group_index 0 and 2 — index 1 is dropped.
            return _json.dumps([
                {"group_index": 0, "verdict": "true_positive", "confidence": 0.9, "verdict_reason": "real"},
                {"group_index": 2, "verdict": "false_positive", "confidence": 0.1, "verdict_reason": "fixture"},
            ])
        # the per-group fallback call for the missing group_index 1
        return '[{"verdict": "false_positive", "confidence": 0.2, "verdict_reason": "resolved via fallback"}]'

    result = llm_file_scan.group_confirm_unverified_findings(
        file_results=file_results, repo_root=tmp_path, rules=rules,
        call_llm_fn=fake_call_llm, group_workers=1, groups_per_call=3,
    )

    assert len(calls) == 2  # 1 batch call + 1 fallback call for the missing group
    assert result["tp_group_count"] == 1
    assert result["fp_group_count"] == 2
    assert result["error_group_count"] == 0
    verdicts = {fr["findings"][0]["file_path"]: fr["findings"][0]["verdict"] for fr in file_results}
    assert verdicts["a.py"] == "true_positive"
    assert verdicts["b.py"] == "false_positive"  # resolved via fallback, not left unverified
    assert verdicts["c.py"] == "false_positive"


def test_confirm_finding_group_batch_llm_error_falls_back_to_per_group_calls(tmp_path, llm_file_scan, rules):
    """A batch call that raises falls back to a per-group call for every
    member instead of leaving the whole batch unverified."""
    for i, name in enumerate(("a.py", "b.py")):
        (tmp_path / name).write_text(f"password = 'secret{i}'\n", encoding="utf-8")

    file_results = [
        {"file_path": name, "findings": [
            _unverified_finding(file_path=name, rule_id=f"rule-{i}", matched_text=f"password = 'secret{i}'")
        ]}
        for i, name in enumerate(("a.py", "b.py"))
    ]

    calls = []

    def flaky_llm(system, user, **kwargs):
        calls.append(user)
        if "group_index" in user:  # the batched call fails outright
            raise RuntimeError("provider unavailable")
        return '[{"verdict": "true_positive", "confidence": 0.8, "verdict_reason": "resolved via fallback"}]'

    result = llm_file_scan.group_confirm_unverified_findings(
        file_results=file_results, repo_root=tmp_path, rules=rules,
        call_llm_fn=flaky_llm, group_workers=1, groups_per_call=2,
    )

    assert len(calls) == 3  # 1 failed batch call + 2 per-group fallback calls
    assert result["error_group_count"] == 0
    assert result["confirmed_finding_count"] == 2
    for file_result in file_results:
        assert file_result["findings"][0]["verdict"] == "true_positive"


def test_confirm_finding_group_batch_leaves_unverified_only_if_fallback_also_fails(tmp_path, llm_file_scan, rules):
    """Worst case: the batch call AND every per-group fallback call fail —
    only then do groups stay unverified."""
    for i, name in enumerate(("a.py", "b.py")):
        (tmp_path / name).write_text(f"password = 'secret{i}'\n", encoding="utf-8")

    file_results = [
        {"file_path": name, "findings": [
            _unverified_finding(file_path=name, rule_id=f"rule-{i}", matched_text=f"password = 'secret{i}'")
        ]}
        for i, name in enumerate(("a.py", "b.py"))
    ]

    def broken_llm(*_args, **_kwargs):
        raise RuntimeError("provider unavailable")

    result = llm_file_scan.group_confirm_unverified_findings(
        file_results=file_results, repo_root=tmp_path, rules=rules,
        call_llm_fn=broken_llm, group_workers=1, groups_per_call=2,
    )

    assert result["error_group_count"] == 2
    assert result["confirmed_finding_count"] == 0
    for file_result in file_results:
        assert file_result["findings"][0]["verdict"] == "unverified"


def test_group_confirm_unverified_findings_group_cap_selects_top_n_by_occurrence(tmp_path, llm_file_scan, rules):
    """With group_cap=2, only the two highest-occurrence groups are sent to
    the LLM; the rest stay unverified and never trigger a call."""
    # Group "high" occurs 5 times, "mid" occurs 3 times, "low" occurs once.
    file_results = []
    for i in range(5):
        name = f"high{i}.py"
        (tmp_path / name).write_text("password = 'high'\n", encoding="utf-8")
        file_results.append({"file_path": name, "findings": [
            _unverified_finding(file_path=name, rule_id="rule-high", matched_text="password = 'high'")
        ]})
    for i in range(3):
        name = f"mid{i}.py"
        (tmp_path / name).write_text("password = 'mid'\n", encoding="utf-8")
        file_results.append({"file_path": name, "findings": [
            _unverified_finding(file_path=name, rule_id="rule-mid", matched_text="password = 'mid'")
        ]})
    (tmp_path / "low.py").write_text("password = 'low'\n", encoding="utf-8")
    file_results.append({"file_path": "low.py", "findings": [
        _unverified_finding(file_path="low.py", rule_id="rule-low", matched_text="password = 'low'")
    ]})

    seen_rule_ids = []

    def fake_call_llm(system, user, **kwargs):
        seen_rule_ids.append(_re.search(r'"rule_id":\s*"([^"]+)"', user).group(1))
        return '[{"verdict": "true_positive", "confidence": 0.9, "verdict_reason": "real"}]'

    result = llm_file_scan.group_confirm_unverified_findings(
        file_results=file_results, repo_root=tmp_path, rules=rules,
        call_llm_fn=fake_call_llm, group_workers=1, group_cap=2,
    )

    assert result["group_count"] == 3
    assert result["confirm_group_count"] == 2
    assert result["skipped_group_count"] == 1
    assert set(seen_rule_ids) == {"rule-high", "rule-mid"}  # "rule-low" never confirmed

    low_finding = file_results[-1]["findings"][0]
    assert low_finding["verdict"] == "unverified"

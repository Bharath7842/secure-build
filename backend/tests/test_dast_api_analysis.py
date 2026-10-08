"""Unit tests for the DAST per-API analysis pure helpers (no browser/LLM)."""

from app.dast import api_analysis as aa


def test_build_api_target_parses_query_and_related_forms():
    api_call = {
        "method": "get",
        "url": "http://t/api/search?q=shoes&page=2",
        "content_type": "application/json",
        "status_code": 200,
    }
    pages = [{"forms": [{"action": "http://t/api/search", "method": "get", "inputs": [{"name": "q", "type": "text"}]}]}]
    target = aa.build_api_target(api_call, pages)
    assert target["method"] == "GET"
    assert target["path"] == "/api/search"
    assert target["query_params"] == ["q", "page"]
    assert target["related_forms"] and target["related_forms"][0]["inputs"][0]["name"] == "q"


def test_target_label_uses_the_full_http_url():
    assert aa.target_label({"method": "GET", "url": "http://t.test/api/Challenges"}) == "GET http://t.test/api/Challenges"
    assert aa.target_label({"method": "POST", "url": "https://app.example/login#frag"}) == "POST https://app.example/login"
    assert aa.target_label({"method": "GET", "url": "/api/x"}) == "GET /api/x"


def test_overall_verdict_rollup():
    def checks(*verdicts):
        return [{"verdict": v} for v in verdicts]

    assert aa.overall_verdict(checks("PASS", "FAIL", "INCONCLUSIVE")) == "FAIL"
    assert aa.overall_verdict(checks("INCONCLUSIVE", "INCONCLUSIVE")) == "PASS"
    assert aa.overall_verdict(checks("PASS", "INCONCLUSIVE")) == "PASS"
    assert aa.overall_verdict(checks("PASS")) == "PASS"
    assert aa.overall_verdict([]) == "PASS"


def test_finding_rows_only_for_fail():
    api_result = {
        "label": "POST /api/login",
        "url": "http://t/api/login",
        "checks": [
            {
                "check_id": "dast-sqli", "check": "SQL Injection", "cwe": "CWE-89",
                "owasp_category": "A03:2021-Injection", "target": "username", "location": "body",
                "payload": "x", "verdict": "FAIL", "severity": "HIGH", "confidence": "HIGH",
                "finding": "reflected sql error", "evidence": "500", "response": {"status_code": 500},
            },
            {
                "check_id": "dast-misconfig", "check": "Security Misconfiguration", "cwe": "CWE-16",
                "owasp_category": "A05", "target": "headers", "location": "header",
                "payload": "y", "verdict": "PASS", "severity": "INFO", "confidence": "MEDIUM",
                "finding": "ok", "evidence": "", "response": {"status_code": 200},
            },
            {
                "check_id": "dast-xss", "check": "XSS", "cwe": "CWE-79",
                "owasp_category": "A03", "target": "q", "location": "query",
                "payload": "z", "verdict": "INCONCLUSIVE", "severity": "MEDIUM", "confidence": "LOW",
                "finding": "unclear", "evidence": "", "response": {"status_code": 200},
            },
        ],
    }
    rows = aa.finding_rows_from_analysis(api_result)
    by_rule = {r["rule_id"]: r for r in rows}
    assert set(by_rule) == {"dast-sqli"}  # PASS and leftover INCONCLUSIVE dropped
    assert by_rule["dast-sqli"]["verdict"] == "true_positive"
    assert by_rule["dast-sqli"]["kind"] == "dast"
    assert by_rule["dast-sqli"]["confidence"] == 0.9

"""Deterministic mock DAST engine: the full result shape with no browser, model or network.

`engine_adapter.run_dast_scan` returns this under `USE_MOCK_ENGINE`, so every API
and UI story can be built and tested offline. Identical input yields identical
output (no clocks, randomness or I/O). The result carries:

* discovery: pages, API calls, per-API analysis tree (one failing, one clean and
  one passing check), a passive-analysis summary, the identity set and a
  two-role authorization matrix, and a request-audit summary;
* finding rows (`mock_finding_batches`): active findings with evidence,
  passive findings and an authorization finding;
* a usage summary.

Every rule id here is a check id from the catalog (`app/data/dast/check_catalog.yaml`);
`tests/test_dast_mock_engine.py` pins that, and that each remediation ref resolves.
"""

from __future__ import annotations

from typing import Any

from . import api_analysis
from .contract import validate_result
from .domain.usage import UsageRecord, summarize

MOCK_MODEL_PROVIDER = "ollama"
MOCK_MODEL = "gpt-oss:20b"

# Evidence per mock active check, keyed by check id. `audit_ref` is the request-audit
# sequence number the mock "sent" the test request as.
_ACTIVE_EVIDENCE: dict[str, dict[str, Any]] = {
    "dast-sqli": {
        "baseline_excerpt": '{"token":"<redacted>","user":"demo"}',
        "test_excerpt": '{"error":"SQLSyntaxErrorException near \'--\'"}',
        "signals": [
            {"name": "sql_error_text", "detail": "SQLSyntaxErrorException in response body"},
            {"name": "status_changed", "detail": "baseline 200, test 500"},
        ],
        "audit_ref": "5",
    },
}

_STANDARDS = {
    "dast-sqli": ["OWASP A03:2021", "OWASP API8:2023", "WSTG-INPV-05", "CWE-89"],
    "dast-xss": ["OWASP A03:2021", "WSTG-INPV-01", "CWE-79"],
    "dast-misconfig": ["OWASP A05:2021", "WSTG-CONF-07", "CWE-16"],
}


def _mock_api_analysis(base: str) -> list[dict[str, Any]]:
    """Deterministic per-API analysis tree for the mock engine — one failing
    check and one clean check across two endpoints, so the UI drill-down and
    the findings mapping both have data without a browser, an LLM, or any
    payload sent anywhere."""
    return [
        {
            "method": "POST",
            "url": f"{base}/api/login",
            "path": "/api/login",
            "label": f"POST {base}/api/login",
            "overall_verdict": "FAIL",
            "summary": "The login endpoint reflected a database error on a crafted username.",
            "counts": {"fail": 1, "pass": 1, "inconclusive": 0},
            "kind": "api",
            "recorded": {
                "method": "POST",
                "url": f"{base}/api/login",
                "path": "/api/login",
                "status_code": 200,
                "content_type": "application/json",
                "kind": "api",
                "parameters": [
                    {"name": "username", "location": "body", "values": []},
                    {"name": "password", "location": "body", "values": []},
                ],
            },
            "checks": [
                {
                    "check_id": "dast-sqli",
                    "check": "SQL Injection",
                    "cwe": "CWE-89",
                    "owasp_category": "A03:2021-Injection",
                    "target": "username",
                    "location": "body",
                    "payload": "<mock-sqli-probe>",
                    "expected_signal": "SQL error text or altered authentication behaviour.",
                    "response": {
                        "status_code": 500,
                        "content_type": "application/json",
                        "security_headers": {},
                        "evidence": '{"error":"SQLSyntaxErrorException near \'--\'"}',
                        "error": "",
                    },
                    "finding": "A crafted username returned a 500 with a raw SQL syntax error, indicating the input reaches a query unsanitized.",
                    "severity": "HIGH",
                    "verdict": "FAIL",
                    "confidence": "HIGH",
                    "evidence": "HTTP 500 with SQLSyntaxErrorException in the body.",
                },
                {
                    "check_id": "dast-misconfig",
                    "check": "Security Misconfiguration",
                    "cwe": "CWE-16",
                    "owasp_category": "A05:2021-Security-Misconfiguration",
                    "target": "response headers",
                    "location": "header",
                    "payload": "<mock-options-probe>",
                    "expected_signal": "Missing security headers or dangerous methods allowed.",
                    "response": {
                        "status_code": 200,
                        "content_type": "application/json",
                        "security_headers": {"x-content-type-options": "nosniff"},
                        "evidence": "",
                        "error": "",
                    },
                    "finding": "Expected security headers were present and no dangerous methods were accepted.",
                    "severity": "INFO",
                    "verdict": "PASS",
                    "confidence": "MEDIUM",
                    "evidence": "x-content-type-options: nosniff present; OPTIONS rejected.",
                },
            ],
        },
        {
            "method": "GET",
            "url": f"{base}/api/products",
            "path": "/api/products",
            "label": f"GET {base}/api/products",
            "overall_verdict": "PASS",
            "summary": "The reflected-input check did not find an issue.",
            "counts": {"fail": 0, "pass": 1, "inconclusive": 0},
            "kind": "api",
            "recorded": {
                "method": "GET",
                "url": f"{base}/api/products",
                "path": "/api/products",
                "status_code": 200,
                "content_type": "application/json",
                "kind": "api",
                "parameters": [{"name": "q", "location": "query", "values": []}],
            },
            "checks": [
                {
                    "check_id": "dast-xss",
                    "check": "Cross-Site Scripting",
                    "cwe": "CWE-79",
                    "owasp_category": "A03:2021-Injection",
                    "target": "q",
                    "location": "query",
                    "payload": "<mock-xss-probe>",
                    "expected_signal": "Supplied markup reflected unescaped in the response.",
                    "response": {
                        "status_code": 200,
                        "content_type": "application/json",
                        "security_headers": {},
                        "evidence": '{"results":[]}',
                        "error": "",
                    },
                    "finding": "The probe was not reflected in the response.",
                    "severity": "INFO",
                    "verdict": "PASS",
                    "confidence": "HIGH",
                    "evidence": "Payload absent from the JSON body.",
                },
            ],
        },
    ]


def _mock_pages(base: str) -> list[dict[str, Any]]:
    return [
        {"url": f"{base}/", "depth": 0, "title": "Home", "forms": [], "links_count": 4, "new_link_count": 3},
        {"url": f"{base}/account", "depth": 1, "title": "Account", "forms": [{"action": f"{base}/account", "method": "post"}], "links_count": 2, "new_link_count": 1},
        {"url": f"{base}/search?q={{}}", "depth": 1, "title": "Search", "forms": [{"action": f"{base}/search", "method": "get"}], "links_count": 1, "new_link_count": 0},
    ]


def _mock_api_calls(base: str) -> list[dict[str, Any]]:
    return [
        {"method": "GET", "url": f"{base}/api/products", "status_code": 200, "content_type": "application/json"},
        {"method": "POST", "url": f"{base}/api/login", "status_code": 200, "content_type": "application/json"},
        {"method": "GET", "url": f"{base}/api/admin/users", "status_code": 200, "content_type": "application/json"},
    ]


def _mock_passive_rows(base: str) -> list[dict[str, Any]]:
    """Findings from analysing responses already seen — no extra requests sent."""
    home = f"GET {base}/"
    login = f"POST {base}/api/login"
    return [
        {
            "severity": "MEDIUM",
            "cwe": "CWE-693",
            "owasp_category": "A05:2021-Security-Misconfiguration",
            "rule_id": "dast-passive-missing-csp",
            "title": f"Missing Content-Security-Policy header — {home}",
            "file_path": home,
            "line": None,
            "snippet": "Check: Missing Content-Security-Policy\nTarget: response headers (header)\nEvidence: no Content-Security-Policy header on the HTML response",
            "kind": "dast",
            "verdict": "true_positive",
            "confidence": 0.9,
            "confidence_label": "HIGH",
            "source": "response headers",
            "sink": f"{base}/",
            "verdict_reason": "The home page response carries no Content-Security-Policy header.",
            "target": home,
            "param": "Content-Security-Policy",
            "location": "header",
            "remediation_ref": "rem-csp",
            "standards": ["OWASP A05:2021", "WSTG-CONF-12", "CWE-693"],
            "evidence": {
                "baseline_excerpt": "",
                "test_excerpt": "HTTP/1.1 200 OK; headers: content-type, x-content-type-options",
                "signals": [{"name": "header_absent", "detail": "content-security-policy"}],
                "audit_ref": "1",
            },
        },
        {
            "severity": "LOW",
            "cwe": "CWE-1004",
            "owasp_category": "A05:2021-Security-Misconfiguration",
            "rule_id": "dast-passive-cookie-flags",
            "title": f"Session cookie without HttpOnly — {login}",
            "file_path": login,
            "line": None,
            "snippet": "Check: Cookie flags\nTarget: Set-Cookie (header)\nEvidence: session=<redacted>; Path=/; Secure",
            "kind": "dast",
            "verdict": "true_positive",
            "confidence": 0.9,
            "confidence_label": "HIGH",
            "source": "Set-Cookie",
            "sink": f"{base}/api/login",
            "verdict_reason": "The session cookie is set without the HttpOnly attribute.",
            "target": login,
            "param": "session",
            "location": "header",
            "remediation_ref": "rem-cookie-flags",
            "standards": ["OWASP A05:2021", "WSTG-SESS-02", "CWE-1004"],
            "evidence": {
                "baseline_excerpt": "",
                "test_excerpt": "Set-Cookie: session=<redacted>; Path=/; Secure",
                "signals": [{"name": "cookie_flag_missing", "detail": "HttpOnly"}],
                "audit_ref": "2",
            },
        },
    ]


def _mock_authorization(base: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Two identities (admin, user) plus the always-added anonymous baseline. The user
    can reach an admin-only endpoint (a broken-function-level-authorization finding);
    nothing user-owned was discovered, so those cells are untested."""
    identities = [
        {"identity_id": "mock-admin", "label": "admin", "role": "admin"},
        {"identity_id": "mock-user", "label": "user", "role": "user"},
    ]
    matrix = [
        {"owner": "admin", "actor": "user", "result": "FAIL", "failures": 1, "reason": "",
         "finding_keys": [f"dast-bfla|GET {base}/api/admin/users"]},
        {"owner": "admin", "actor": "anonymous", "result": "OK", "failures": 0, "reason": "", "finding_keys": []},
        {"owner": "user", "actor": "admin", "result": "untested", "failures": 0,
         "reason": "no user-owned resource was discovered", "finding_keys": []},
        {"owner": "user", "actor": "anonymous", "result": "untested", "failures": 0,
         "reason": "no user-owned resource was discovered", "finding_keys": []},
    ]
    replays = [
        {"owner": "admin", "actor": "user", "replays": 1, "denied": 0, "crossed": 1, "owned": 1, "truncated": False},
        {"owner": "admin", "actor": "anonymous", "replays": 1, "denied": 1, "crossed": 0, "owned": 1, "truncated": False},
        {"owner": "user", "actor": "admin", "replays": 0, "denied": 0, "crossed": 0, "owned": 0, "truncated": False},
        {"owner": "user", "actor": "anonymous", "replays": 0, "denied": 0, "crossed": 0, "owned": 0, "truncated": False},
    ]
    summary = {
        "ran": True,
        "identities": identities,
        "baseline_identity": "anonymous",
        "matrix": matrix,  # the contract check reads it; the API derives its own from `replays` and the findings
        "replays": replays,
        "total_replays": 2,
        "findings": 1,
        "degraded": False,
        "degraded_reason": "",
    }
    rows = [
        {
            "severity": "HIGH",
            "cwe": "CWE-285",
            "owasp_category": "A01:2021-Broken-Access-Control",
            "rule_id": "dast-bfla",
            "title": f"Admin endpoint reachable as user — GET {base}/api/admin/users",
            "file_path": f"GET {base}/api/admin/users",
            "line": None,
            "snippet": "Check: Broken function level authorization\nTarget: identity (header)\nEvidence: user role received HTTP 200 with the admin response body",
            "kind": "dast",
            "verdict": "true_positive",
            "confidence": 0.9,
            "confidence_label": "HIGH",
            "source": "user",
            "sink": f"{base}/api/admin/users",
            "verdict_reason": "The user identity received the same successful response as admin on an admin-only endpoint.",
            "target": f"GET {base}/api/admin/users",
            "param": None,
            "location": "response",
            "roles": ["admin", "user"],
            "remediation_ref": "rem-bfla",
            "standards": ["OWASP A01:2021", "OWASP API5:2023", "WSTG-ATHZ-02", "CWE-285"],
            "evidence": {
                "baseline_excerpt": "admin: HTTP 200, 1432 bytes",
                "test_excerpt": "user: HTTP 200, 1432 bytes",
                "signals": [
                    {"name": "status_same_across_roles", "detail": "200 for admin and user"},
                    {"name": "body_same_across_roles", "detail": "identical length"},
                ],
                "audit_ref": "11",
            },
        },
    ]
    return summary, rows


def _mock_active_rows(analysis: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Active findings (FAIL -> true_positive) with evidence."""
    rows: list[dict[str, Any]] = []
    for api_result in analysis:
        for row in api_analysis.finding_rows_from_analysis(api_result):
            check_id = row["rule_id"]
            row["standards"] = list(_STANDARDS.get(check_id, row.get("standards") or []))
            row["remediation_ref"] = f"rem-{check_id.removeprefix('dast-')}"
            row["evidence"] = dict(_ACTIVE_EVIDENCE[check_id])
            rows.append(row)
    return rows


def mock_usage_summary() -> dict[str, Any]:
    """Fixed token accounting in the gateway's usage-summary shape (`domain.usage.summarize`)."""
    calls = {
        "construct": (3, 2400, 900),
        "rule": (3, 1800, 450),
        "narrate": (5, 2000, 700),
    }
    records = []
    for task, (count, input_tokens, output_tokens) in calls.items():
        for i in range(count):  # spread the step totals over its calls; remainders land on the first
            records.append(
                UsageRecord(
                    task, MOCK_MODEL_PROVIDER, MOCK_MODEL,
                    input_tokens // count + (input_tokens % count if i == 0 else 0),
                    output_tokens // count + (output_tokens % count if i == 0 else 0),
                    estimated=True,
                )
            )
    return summarize(records)


def mock_finding_batches(base: str, discovery: dict[str, Any]) -> list[tuple[str, list[dict[str, Any]]]]:
    """(label, rows) batches in the order the stages would write them."""
    _, authz_rows = _mock_authorization(base)
    active = _mock_active_rows(discovery.get("api_analysis") or [])
    batches: list[tuple[str, list[dict[str, Any]]]] = []
    batches.append(("passive analysis", _mock_passive_rows(base)))
    for label in dict.fromkeys(row["file_path"] for row in active):
        batches.append((label, [row for row in active if row["file_path"] == label]))
    batches.append(("authorization", authz_rows))
    return batches


def mock_discovery(dast_input: dict[str, Any]) -> dict[str, Any]:
    """Deterministic fake crawl + analysis result — no browser, model or network."""
    base = (dast_input.get("target_url") or "http://localhost:3000").rstrip("/")
    print("### DAST: checking connection")
    print(f"[1/4] Connected to {base}")
    print("### DAST: classifying login")
    print("[2/4] Login type: simple_form")
    print("### DAST: logging in")
    print("[3/4] Login succeeded (mock)")
    print("### DAST: crawling")
    pages = _mock_pages(base)
    api_calls = _mock_api_calls(base)
    for p in pages:
        print(f"  [depth {p['depth']}] {p['url']}")
    passive_rows = _mock_passive_rows(base)
    print("### DAST: passive analysis")
    print(f"  passive analysis: {len(passive_rows)} finding(s)")
    print("### DAST: testing apis")
    analysis = _mock_api_analysis(base)
    for api in analysis:
        print(f"  {api['label']}: overall {api['overall_verdict']}")
    authorization, authz_rows = _mock_authorization(base)
    print("### DAST: checking authorization")
    print(f"  authorization: {len(authorization['identities'])} identities + anonymous, "
          f"{sum(1 for c in authorization['matrix'] if c['result'] == 'FAIL')} failing cell(s)")
    summary = {
        "apis_tested": len(analysis),
        "fail": sum(a["counts"]["fail"] for a in analysis),
        "pass": sum(a["counts"]["pass"] for a in analysis),
        "inconclusive": sum(a["counts"]["inconclusive"] for a in analysis),
        "apis_failing": sum(1 for a in analysis if a["overall_verdict"] == "FAIL"),
    }
    print("### DAST: finishing")
    print(
        f"Pages: {len(pages)}, forms: 2, API endpoints: {len(api_calls)}, "
        f"APIs tested: {summary['apis_tested']} ({summary['fail']} failing checks)"
    )
    return {
        "target_url": dast_input.get("target_url") or base,
        "connection_ok": True,
        "connection_error": "",
        "login_type": "simple_form",
        "login_success": True,
        "login_error": "",
        "stop_reason": "",
        "crawl_stop_reason": "queue_empty",
        "pages": pages,
        "api_calls": api_calls,
        "forms_count": 2,
        "skipped_duplicate_patterns": [],
        "failed_urls": [],
        "warnings": [],
        "api_analysis": analysis,
        "analysis_summary": summary,
        "passive_analysis": {
            "checks_run": 6,
            "exchanges": 5,
            "findings": len(passive_rows),
            "unverified": 0,
            "finding_keys": [f"{r['rule_id']}|{r['target']}" for r in passive_rows],
            "cors": {"assessable": False, "note": "not assessable: no request carried an Origin header, so reflected-origin behaviour cannot be judged without sending probes"},
        },
        "active_testing": {
            "targets_total": 3, "targets_tested": len(analysis), "targets_capped": 0, "tests_sent": 3, "dropped_unknown_check": 0, "dropped_unsafe": 1,
            "dropped_malformed": 0, "over_cap": 0, "fallback_targets": 0, "guardrail_downgrades": 1, "guardrail_overrides": 0,
            "not_tested": [{"label": f"POST {base}/api/account", "reason": "not tested: safe mode"}], "cancelled": False, "review_items": 0,
        },
        "authorization": authorization,
        "request_audit_summary": {"sent": 12, "denied": 1},
    }


def run_mock_dast(dast_input: dict[str, Any]) -> tuple[dict[str, Any], list[tuple[str, list[dict[str, Any]]]]]:
    """Return `(engine_result, finding_batches)`; the result validates against the domain entities."""
    discovery = mock_discovery(dast_input)
    base = (dast_input.get("target_url") or "http://localhost:3000").rstrip("/")
    batches = mock_finding_batches(base, discovery)
    validate_result(discovery, [row for _, rows in batches for row in rows])
    return {"discovery": discovery, "usage_summary": mock_usage_summary()}, batches

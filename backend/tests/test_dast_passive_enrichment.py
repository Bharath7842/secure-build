from app.dast.passive_enrichment import enrich_passive_rows
from tests.dast_fixtures.gateway import FakeModelGateway


def row():
    return {
        "rule_id": "dast-passive-missing-csp",
        "title": "Missing Content-Security-Policy header: Content-Security-Policy",
        "severity": "MEDIUM",
        "target": "GET http://127.0.0.1:3001",
        "param": "Content-Security-Policy",
        "location": "header",
        "standards": ["OWASP A05:2021", "CWE-693"],
        "evidence": {"test_excerpt": "HTTP 200 /; header absent", "signals": [{"name": "header_absent", "detail": "no header"}]},
    }


def test_model_can_choose_severity_and_write_reproduction_without_changing_evidence():
    gateway = FakeModelGateway()
    gateway.script("rule", {"severity": "LOW", "reproduction": "1. Send GET to the recorded URL.\n2. Confirm the response omits the header."})

    result = enrich_passive_rows([row()], gateway)[0]

    assert result["severity"] == "LOW"
    assert result["evidence"]["reproduction"].startswith("1. Send GET")
    assert result["evidence"]["severity_source"] == "LLM review"
    assert result["evidence"]["signals"][0]["name"] == "header_absent"
    assert gateway.calls[0].task == "rule"


def test_invalid_model_output_preserves_catalog_severity_and_has_reproduction_fallback():
    gateway = FakeModelGateway()
    gateway.script("rule", {"severity": "not-a-severity", "reproduction": "too short"})

    result = enrich_passive_rows([row()], gateway)[0]

    assert result["severity"] == "MEDIUM"
    assert "header_absent" in result["evidence"]["reproduction"]
    assert result["evidence"]["severity_source"] == "catalog fallback"

"""Standard-based severity (`app/services/severity.py`): a CVSS v3.1 score from
the CWE baseline or a rule's refinement, adjusted only by evidence."""

import json
import re
from pathlib import Path

import pytest

from app.defaults.cwe_cvss import CWE_BASELINES, SCHEME
from app.models import Finding
from app.services import cvss
from app.services.finding_rows import build_finding_row
from app.services.severity import apply_severity, rule_vectors, score_finding, severity_basis_text

RULES_DIR = Path(__file__).resolve().parents[1] / "sast_engine" / "rules"


def _finding(**kw):
    base = {"kind": "regex", "rule_id": "some-rule", "cwe": "CWE-89", "severity": "LOW",
            "issue_class": "security", "verdict": "true_positive"}
    return {**base, **kw}


def test_the_cwe_baseline_replaces_the_rule_severity_and_keeps_it_as_the_original():
    scored = score_finding(_finding(severity="LOW"))
    assert (scored["severity"], scored["cvss"]) == ("CRITICAL", 9.8)
    assert scored["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    basis = scored["severity_basis"]
    assert basis["source"] == "cwe" and basis["cwe"] == "CWE-89" and basis["scheme"] == SCHEME
    assert basis["original_severity"] == "LOW"


@pytest.mark.parametrize("spelling", ["CWE-89", "cwe 089", "89", "CWE-89: SQL Injection"])
def test_every_spelling_of_a_cwe_finds_its_baseline(spelling):
    assert score_finding(_finding(cwe=spelling))["cvss"] == 9.8


def test_a_rule_vector_refines_its_cwe():
    rule_id = "spring-h2-console-enabled"
    assert rule_id in rule_vectors()
    scored = score_finding(_finding(rule_id=rule_id, cwe="CWE-489", severity="MEDIUM"))
    assert scored["severity_basis"]["source"] == "rule"
    assert scored["cvss_vector"] == rule_vectors()[rule_id]
    assert (scored["severity"], scored["cvss"]) == ("HIGH", 8.1)


def test_without_a_baseline_the_original_severity_is_kept():
    scored = score_finding(_finding(cwe="CWE-99999", severity="high"))
    assert (scored["severity"], scored["cvss"], scored["cvss_vector"]) == ("HIGH", None, None)
    assert scored["severity_basis"]["source"] == "original"
    no_cwe = score_finding(_finding(cwe=None, severity="LOW"))
    assert no_cwe["severity"] == "LOW" and "no CWE" in no_cwe["severity_basis"]["note"]


def test_a_quality_issue_is_low_without_a_score():
    scored = score_finding(_finding(issue_class="quality", cwe="CWE-209", severity="MEDIUM"))
    assert (scored["severity"], scored["cvss"]) == ("LOW", None)


def test_inactive_code_keeps_its_score_but_is_capped_at_low():
    scored = score_finding(_finding(issue_class="inactive"))
    assert (scored["severity"], scored["cvss"]) == ("LOW", 9.8)


def test_a_sanitizer_on_the_path_raises_attack_complexity():
    scored = score_finding(_finding(reachability={"status": "sanitized_path"}))
    assert "AC:H" in scored["cvss_vector"] and scored["cvss"] == 8.1
    assert scored["severity_basis"]["adjustments"][0]["metric"] == "AC"


def test_an_authenticated_entry_point_raises_privileges_required():
    scored = score_finding(_finding(reachability={"status": "entry_reachable", "authenticated": True}))
    assert "PR:L" in scored["cvss_vector"] and scored["cvss"] == 8.8


def test_missing_evidence_never_lowers_the_score():
    for reachability in (None, {}, {"status": "path"}, {"status": "entry_reachable", "authenticated": False}):
        assert score_finding(_finding(reachability=reachability))["cvss"] == 9.8


@pytest.mark.parametrize("text", [
    "apiKey: 'AIzaSyCMhXUeRCjDuYAfwcakpPRiFQ-PMli4itE'",
    '_tmp_1.apiKey = "AIzaSyCMhXUeRCjDuYAfwcakpPRiFQ-PMli4itE"',
    "const key = 'pk_live_51HcQbVExampleKey000'",
])
def test_a_publishable_client_key_is_not_scored_as_a_leaked_secret(text):
    scored = score_finding(_finding(cwe="CWE-798", matched_text=text, kind="joern", severity="HIGH"))
    assert (scored["severity"], scored["cvss"]) == ("MEDIUM", 5.3)
    assert "publishable" in scored["severity_basis"]["adjustments"][0]["why"]


def test_a_real_secret_stays_critical():
    scored = score_finding(_finding(cwe="CWE-798", matched_text="password = 'hunter2hunter2'"))
    assert (scored["severity"], scored["cvss"]) == ("CRITICAL", 9.8)


def test_dast_and_sca_findings_are_not_scored():
    assert score_finding(_finding(kind="dast")) is None
    assert score_finding(_finding(kind="sca")) is None


def test_rescoring_is_idempotent_and_starts_from_the_original():
    row = _finding(severity="LOW")
    assert apply_severity(row) is True
    assert row["severity"] == "CRITICAL"
    assert apply_severity(row) is False
    assert row["severity_basis"]["original_severity"] == "LOW"


def test_a_written_sast_row_is_scored_and_a_dast_row_is_not():
    row = build_finding_row("s1", {"kind": "llm", "cwe": "CWE-79", "severity": "HIGH", "title": "XSS"}, "a.ts")
    assert (row.severity, row.cvss) == ("MEDIUM", 6.1)
    assert row.severity_basis["original_severity"] == "HIGH"
    dast = build_finding_row("s1", {"kind": "dast", "target": "http://x/", "cwe": "CWE-79",
                                    "severity": "HIGH", "title": "XSS"}, "label")
    assert (dast.severity, dast.cvss, dast.severity_basis) == ("HIGH", None, None)


def test_the_basis_reads_as_one_line():
    scored = score_finding(_finding(reachability={"status": "entry_reachable", "authenticated": True}))
    text = severity_basis_text(scored["severity_basis"])
    assert text.startswith("CWE-89 baseline: SQL injection")
    assert "PR:L" in text and text.endswith("was LOW")


# --- the tables ----------------------------------------------------------------------

def _catalog_rules():
    for path in sorted(RULES_DIR.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        for rule in data if isinstance(data, list) else data.get("rules", []) if isinstance(data, dict) else []:
            if isinstance(rule, dict) and rule.get("id"):
                yield rule


def test_every_catalog_cwe_has_a_baseline():
    missing = sorted({
        rule["cwe"] for rule in _catalog_rules()
        if rule.get("cwe") and int(re.search(r"\d+", rule["cwe"]).group()) not in CWE_BASELINES
    })
    assert missing == []


def test_every_baseline_and_rule_vector_is_a_valid_cvss_vector():
    for number, (vector, why) in CWE_BASELINES.items():
        cvss.base_score(vector)
        assert why, number
    for rule in _catalog_rules():
        if rule.get("cvss_vector"):
            cvss.base_score(rule["cvss_vector"])


def test_finding_model_has_the_new_columns():
    assert {"cvss_vector", "severity_basis"} <= set(Finding.__table__.columns.keys())


def test_reachability_evidence_written_later_rescores_the_row(tmp_path):
    from app.db import init_db
    from app.models import Project, Scan
    from app.services.scan_runner import _make_findings_writer, _make_reachability_updates_writer

    SessionLocal = init_db(f"sqlite:///{(tmp_path / 'severity.db').as_posix()}")
    with SessionLocal() as db:
        project = Project(name="sev", default_git_url="https://github.com/org/repo.git")
        db.add(project)
        db.commit()
        scan = Scan(project_id=project.id, git_url=project.default_git_url)
        db.add(scan)
        db.commit()
        scan_id = scan.id
    path = "src/main/java/com/x/UserDao.java"
    _make_findings_writer(scan_id)(path, [{
        "severity": "HIGH", "cwe": "CWE-89", "rule_id": "llm-extra", "title": "SQLi", "file_path": path,
        "snippet": "x", "kind": "llm", "verdict": "true_positive", "confidence": 0.6, "line": 8,
    }])
    with SessionLocal() as db:
        row = db.query(Finding).filter(Finding.scan_id == scan_id).one()
        assert (row.severity, row.cvss, row.severity_basis["original_severity"]) == ("CRITICAL", 9.8, "HIGH")

    _make_reachability_updates_writer(scan_id)(path, [{
        "rule_id": "llm-extra", "line": 8, "confidence": 0.9,
        "reachability": {"status": "entry_reachable", "authenticated": True},
    }])
    with SessionLocal() as db:
        row = db.query(Finding).filter(Finding.scan_id == scan_id).one()
        assert (row.severity, row.cvss) == ("HIGH", 8.8)
        assert "PR:L" in row.cvss_vector and row.severity_basis["original_severity"] == "HIGH"

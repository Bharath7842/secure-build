"""DAST-04-010 / -050: entities, the finding <-> row mapping, dedupe keys and the writer."""

from __future__ import annotations

import pytest

from app import db as app_db
from app.dast import api_analysis
from app.dast.domain import dedupe
from app.dast.domain.entities import (
    Confidence, DetectorSignal, Evidence, Finding, FindingVerdict, Location, Severity, Signal, Verdict,
)
from app.dast.domain.mapping import cvss_of, cwe_of, finding_from_row, finding_to_row, owasp_category_of, validated_reason
from app.models import UNVERIFIED_VERDICT, DastEvidence, Finding as FindingRow, Project, Scan
from app.services.dast_findings import DastFindingsWriter

pytestmark = pytest.mark.unit


def make_finding(**kw) -> Finding:
    base = dict(
        check_id="dast-sqli", severity=Severity.HIGH, confidence=Confidence.HIGH, verdict=FindingVerdict.TRUE_POSITIVE,
        target="GET /users/1", param="id", location=Location.QUERY,
        standards=("OWASP A03:2021", "OWASP API8:2023", "WSTG-INPV-05", "CWE-89"), remediation_ref="rem-sqli",
        evidence=Evidence("ok", "ORA-00933", (DetectorSignal("db_error_surfaced", "ORA-00933"),), "7"),
    )
    base.update(kw)
    return Finding(**base)


def test_vocabulary_aliases_and_the_shared_unverified_constant():
    assert Signal is DetectorSignal and Verdict is FindingVerdict
    assert FindingVerdict.UNVERIFIED.value == UNVERIFIED_VERDICT
    assert {v.value for v in FindingVerdict} == {"true_positive", "unverified", "false_positive"}


def test_round_trip_domain_row_domain():
    finding = make_finding(affected_targets=("GET /users/1", "GET /users/2"), roles=("user", "admin"), first_seen_scan_id="s1")
    row = finding_to_row(finding, title="SQL injection", source="db_error_surfaced", sink="http://t/users/1")
    assert row["kind"] == "dast" and row["file_path"] == "GET /users/1" and row["rule_id"] == "dast-sqli"
    assert row["cwe"] == "CWE-89" and row["owasp_category"] == "A03:2021" and row["title"] == "SQL injection"
    assert row["cvss"] == 8.0  # Severity.HIGH's band midpoint
    assert row["owasp_ref"] == "OWASP A03:2021, OWASP API8:2023"
    assert row["verdict"] == "true_positive" and row["confidence_label"] == "HIGH"
    assert finding_from_row(row) == finding


def test_validated_reason_passes_through_when_it_names_the_evidence():
    signals = (DetectorSignal("db_error_surfaced", "ORA-00933"),)
    reason = "the 'id' parameter triggered a db_error_surfaced signal (ORA-00933)"
    assert validated_reason(reason, signals, "id") == reason


def test_validated_reason_is_replaced_when_it_does_not_name_the_evidence():
    signals = (DetectorSignal("db_error_surfaced", "ORA-00933"),)
    replaced = validated_reason("this looks like a problem", signals, "id")
    assert replaced != "this looks like a problem"
    assert "db_error_surfaced" in replaced and "'id'" in replaced and "did not reference the evidence" in replaced


def test_validated_reason_catches_a_wrong_parameter_too():
    signals = (DetectorSignal("db_error_surfaced", "ORA-00933"),)
    reason = "db_error_surfaced fired"  # names the signal but not the actual parameter
    replaced = validated_reason(reason, signals, "username")
    assert "username" in replaced and replaced != reason


def test_validated_reason_passes_through_with_no_signal_or_no_text():
    assert validated_reason("", (), "id") == ""
    assert validated_reason("model judged FAIL", (), "id") == "model judged FAIL"  # nothing structured to check


def test_finding_to_row_validates_the_reason_end_to_end():
    finding = make_finding()  # evidence signal is db_error_surfaced, param is "id"
    row = finding_to_row(finding, title="t", verdict_reason="looks exploitable")
    assert "db_error_surfaced" in row["verdict_reason"] and row["verdict_reason"] != "looks exploitable"
    honest = finding_to_row(finding, title="t", verdict_reason="db_error_surfaced fired on 'id'")
    assert honest["verdict_reason"] == "db_error_surfaced fired on 'id'"


def test_unverified_finding_maps_without_a_signal():
    finding = make_finding(verdict=FindingVerdict.UNVERIFIED, evidence=Evidence("a", "a", (), ""))
    assert finding_from_row(finding_to_row(finding, title="t")).verdict is FindingVerdict.UNVERIFIED


@pytest.mark.parametrize(
    "mutation",
    [{"severity": "SEVERE"}, {"location": "cookie-jar"}, {"confidence_label": "CERTAIN"}, {"verdict": "maybe"}],
)
def test_invalid_enum_values_are_rejected(mutation):
    row = finding_to_row(make_finding(), title="t")
    row.update(mutation)
    with pytest.raises(ValueError):
        finding_from_row(row)


def test_true_positive_without_a_signal_is_allowed_unless_required():
    row = finding_to_row(make_finding(evidence=Evidence("", "", (), "")), title="t")
    assert finding_from_row(row).verdict is FindingVerdict.TRUE_POSITIVE
    with pytest.raises(ValueError, match="no detector signal"):
        finding_from_row(row, require_signal=True)


def test_legacy_api_analysis_output_still_maps():
    result = {
        "label": "POST /api/login", "url": "http://t/api/login",
        "checks": [
            {"check_id": "dast-sqli", "check": "SQL Injection", "cwe": "CWE-89", "owasp_category": "A03:2021-Injection",
             "target": "username", "location": "body", "payload": "p", "severity": "HIGH", "verdict": "FAIL",
             "confidence": "HIGH", "finding": "reflected", "evidence": "e", "response": {"status_code": 500}},
            {"check_id": "dast-xss", "check": "XSS", "cwe": "CWE-79", "owasp_category": "A03:2021-Injection",
             "target": "q", "location": "query", "payload": "p", "severity": "MEDIUM", "verdict": "INCONCLUSIVE",
             "confidence": "LOW", "finding": "?", "evidence": "", "response": {"status_code": 200}},
        ],
    }
    rows = api_analysis.finding_rows_from_analysis(result)
    assert len(rows) == 1
    domain = finding_from_row(rows[0], require_signal=False)
    assert domain.target == "POST /api/login"
    assert finding_from_row(rows[0]).verdict is FindingVerdict.TRUE_POSITIVE


def test_standards_helpers():
    assert cwe_of(["OWASP A03:2021", "cwe-79"]) == "CWE-79" and cwe_of([]) is None
    assert owasp_category_of(["OWASP API1:2023", "OWASP A01:2021"]) == "A01:2021"
    assert owasp_category_of(["OWASP API1:2023"]) == "API1:2023" and owasp_category_of(["WSTG-X"]) is None


def test_cvss_of_uses_the_cvss_v31_severity_band_midpoint():
    assert cvss_of(Severity.CRITICAL) == 9.5
    assert cvss_of(Severity.HIGH) == 8.0
    assert cvss_of(Severity.MEDIUM) == 5.5
    assert cvss_of(Severity.LOW) == 2.0
    assert cvss_of(Severity.INFO) == 0.0


@pytest.mark.parametrize(
    "path, expected",
    [
        ("/users/1", "/users/{id}"), ("/users/2?x=1", "/users/{id}"), ("/a/b", "/a/b"), ("/", "/"), ("", "/"),
        ("/o/550e8400-e29b-41d4-a716-446655440000/items", "/o/{uuid}/items"),
        ("/f/507f1f77bcf86cd799439011", "/f/{hex}"), ("/p/order-2024-0042", "/p/{slug}"),
        ("/v1/users/{id}", "/v1/users/{id}"), ("http://t.test/x/42/", "/x/{id}"),
    ],
)
def test_path_template(path, expected):
    assert dedupe.path_template(path) == expected


def test_dedupe_key_groups_ids_and_separates_parameters():
    a, b = make_finding(target="GET /users/1"), make_finding(target="GET /users/2")
    assert dedupe.dedupe_key(a) == dedupe.dedupe_key(b) == ("dast-sqli", "GET /users/{id}", "id")
    assert dedupe.dedupe_key(make_finding(param="name")) != dedupe.dedupe_key(a)
    assert dedupe.dedupe_key(make_finding(param=None))[2] == ""
    assert dedupe.merge_locations(["a"], "a") == ["a"] and dedupe.merge_locations(["a"], "b") == ["a", "b"]


# ---- writer (integration) ---------------------------------------------------------------------


@pytest.fixture()
def scan_id(tmp_path):
    app_db.init_db(f"sqlite:///{(tmp_path / 'w.db').as_posix()}")
    with app_db.SessionLocal() as db:
        project = Project(name="w", default_git_url="")
        db.add(project)
        db.commit()
        scan = Scan(project_id=project.id, git_url="http://t", scan_type="dast")
        db.add(scan)
        db.commit()
        return scan.id


def row_for(target, *, param="id", verdict="true_positive", **kw):
    f = make_finding(target=target, param=param, verdict=FindingVerdict(verdict))
    if verdict == "unverified":
        f = make_finding(target=target, param=param, verdict=FindingVerdict.UNVERIFIED, evidence=Evidence("a", "a", (), "3"))
    row = finding_to_row(f, title="SQL injection")
    row.update(kw)
    return row


def stored(scan_id):
    with app_db.SessionLocal() as db:
        return db.query(FindingRow).filter(FindingRow.scan_id == scan_id).order_by(FindingRow.id).all()


@pytest.mark.integration
def test_same_issue_on_two_endpoints_is_one_finding_with_two_locations(scan_id):
    writer = DastFindingsWriter(scan_id)
    writer.write("GET /users/1", [row_for("GET /users/1")])
    counts = writer.write("GET /users/2", [row_for("GET /users/2")])
    assert counts == {"created": 0, "merged": 1, "duplicate": 0}
    (finding,) = stored(scan_id)
    assert finding.affected_files == ["GET /users/1", "GET /users/2"]
    assert finding.kind == "dast" and finding.first_seen_scan_id == scan_id


@pytest.mark.integration
def test_different_parameter_or_check_stays_separate(scan_id):
    writer = DastFindingsWriter(scan_id)
    writer.write("x", [row_for("GET /users/1"), row_for("GET /users/1", param="name"), row_for("GET /users/1", rule_id="dast-xss")])
    assert len(stored(scan_id)) == 3


@pytest.mark.integration
def test_retry_is_idempotent_even_through_a_fresh_writer(scan_id):
    rows = [row_for("GET /users/1")]
    DastFindingsWriter(scan_id).write("a", rows)
    again = DastFindingsWriter(scan_id).write("a", rows)  # a retried stage builds a new writer
    assert again == {"created": 0, "merged": 0, "duplicate": 1}
    assert len(stored(scan_id)) == 1
    with app_db.SessionLocal() as db:
        assert db.query(DastEvidence).count() == 1


@pytest.mark.integration
def test_evidence_is_stored_and_capped(scan_id):
    row = row_for("GET /users/1")
    row["evidence"]["test_excerpt"] = "z" * 5000
    DastFindingsWriter(scan_id).write("a", [row])
    with app_db.SessionLocal() as db:
        ev = db.query(DastEvidence).one()
        assert [s["name"] for s in ev.signals] == ["db_error_surfaced"] and ev.audit_ref == "7"
        assert len(ev.test_excerpt) <= 2000 and ev.test_excerpt.endswith("[truncated]")


@pytest.mark.integration
def test_unverified_is_stored_like_a_confirmed_one_and_can_be_upgraded(scan_id):
    writer = DastFindingsWriter(scan_id)
    writer.write("a", [row_for("GET /users/1", verdict="unverified")])
    (finding,) = stored(scan_id)
    assert finding.verdict == "unverified"
    with app_db.SessionLocal() as db:
        assert db.query(DastEvidence).one().signals == []
    writer.write("b", [row_for("GET /users/2", verdict="true_positive")])
    (finding,) = stored(scan_id)
    assert finding.verdict == "true_positive" and finding.affected_files == ["GET /users/1", "GET /users/2"]
    with app_db.SessionLocal() as db:
        (ev,) = db.query(DastEvidence).all()
        assert [s["name"] for s in ev.signals] == ["db_error_surfaced"]
    # a weaker later result never downgrades a confirmed one
    writer.write("c", [row_for("GET /users/3", verdict="unverified")])
    assert stored(scan_id)[0].verdict == "true_positive"


@pytest.mark.integration
def test_browser_execution_attaches_to_an_existing_reflected_finding(scan_id):
    writer = DastFindingsWriter(scan_id)
    writer.write("a", [row_for("GET http://target.test/search", param="q", rule_id="dast-xss")])
    confirmed = row_for("GET http://target.test/search", param="q", rule_id="dast-xss")
    confirmed["evidence"] = {**confirmed["evidence"], "signals": [{"name": "marker_executed_in_browser", "detail": "marker ran"}]}
    assert writer.write("b", [confirmed])["merged"] == 1
    with app_db.SessionLocal() as db:
        signals = db.query(DastEvidence).one().signals
    assert any(s["name"] == "marker_executed_in_browser" for s in signals)
    assert writer.write("c", [confirmed])["duplicate"] == 1

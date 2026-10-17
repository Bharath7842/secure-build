"""DAST-04-060: `GET /scans/{id}/findings` for DAST scans (filters, grouping, evidence, remediation)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import db as app_db
from app.config import settings
from app.dast.domain.entities import Confidence, DetectorSignal, Evidence, Finding, FindingVerdict, Location, Severity
from app.dast.domain.mapping import finding_to_row
from app.main import app
from app.models import DastRequestAudit
from app.services.dast_findings import DastFindingsWriter

pytestmark = pytest.mark.integration

from tests.auth_helpers import ADMIN_HEADERS  # noqa: E402

HDR = ADMIN_HEADERS


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("USE_MOCK_ENGINE", "true")
    settings.use_mock_engine = True
    settings.scan_logs_dir = str(tmp_path / "scan_logs")
    app_db.init_db(f"sqlite:///{(tmp_path / 'f.db').as_posix()}")
    return TestClient(app)


def new_scan(client, name="f", scan_type="dast"):
    project = client.post("/projects", json={"name": name, "default_git_url": "https://github.com/o/r.git"}, headers=HDR).json()
    body = {"project_id": project["id"], "scan_type": scan_type}
    if scan_type == "dast":
        body["dast"] = {"target_url": "http://localhost:3000", "authorized": True}
    return client.post("/scans", json=body, headers=HDR).json()["scan_id"]


def row(check_id, target, *, param="id", verdict="true_positive", severity=Severity.HIGH, roles=(), remediation="rem-sqli", standards=("OWASP A03:2021", "CWE-89")):
    signals = (DetectorSignal("db_error_surfaced", "ORA-00933"),) if verdict == "true_positive" else ()
    finding = Finding(
        check_id=check_id, severity=severity, confidence=Confidence.HIGH if signals else Confidence.LOW,
        verdict=FindingVerdict(verdict), target=target, param=param, location=Location.QUERY, standards=standards,
        remediation_ref=remediation, evidence=Evidence("base", "test", signals, "4"), roles=tuple(roles),
    )
    return finding_to_row(finding, title=f"{check_id} on {target}")


@pytest.fixture()
def seeded(client):
    scan_id = new_scan(client)
    # The mock scan already wrote findings; replace them with a controlled set.
    with app_db.SessionLocal() as db:
        from app.models import DastEvidence, Finding as F

        db.query(DastEvidence).delete()
        db.query(F).filter(F.scan_id == scan_id).delete()
        db.commit()
    writer = DastFindingsWriter(scan_id)
    writer.write("a", [
        row("dast-sqli", "GET /users/1"),
        row("dast-sqli", "GET /users/2"),  # same issue, second location
        row("dast-sqli", "GET /users/1", param="name"),
        row("dast-xss", "GET /search", param="q", verdict="unverified", severity=Severity.MEDIUM, remediation="rem-xss", standards=("OWASP A03:2021", "CWE-79")),
        row("dast-bfla", "GET /api/admin/users", param=None, severity=Severity.CRITICAL, roles=("admin", "user"), remediation="rem-bfla", standards=("OWASP API5:2023", "CWE-285")),
        row("dast-bola", "GET /api/orders/7", param="id", severity=Severity.HIGH, roles=("user", "anonymous"), remediation="rem-bola", standards=("CWE-639",)),
    ])
    return scan_id


def get(client, scan_id, **params):
    r = client.get(f"/scans/{scan_id}/findings", params=params, headers=HDR)
    assert r.status_code == 200, r.text
    return r.json()


def test_findings_are_grouped_with_every_location(client, seeded):
    body = get(client, seeded)
    sqli_id = [f for f in body["findings"] if f["rule_id"] == "dast-sqli" and f["param"] == "id"]
    assert len(sqli_id) == 1 and sqli_id[0]["affected_files"] == ["GET /users/1", "GET /users/2"]
    assert len(body["findings"]) == 5  # sqli id, sqli name, xss, bfla, bola
    assert body["total_count"] == 5 and body["tp_count"] == 4 and body["unverified_count"] == 1


def test_finding_carries_triage_fields_evidence_and_remediation_text(client, seeded):
    body = get(client, seeded)
    sqli = next(f for f in body["findings"] if f["rule_id"] == "dast-sqli" and f["param"] == "id")
    assert sqli["target"] == "GET /users/1" and sqli["location"] == "query" and sqli["confidence_label"] == "HIGH"
    assert sqli["standards"] == ["OWASP A03:2021", "CWE-89"] and sqli["remediation_ref"] == "rem-sqli"
    assert "parameterized queries" in sqli["remediation"]
    assert sqli["evidence"]["signals"] == [{"name": "db_error_surfaced", "detail": "ORA-00933"}]
    assert sqli["evidence"]["baseline_excerpt"] == "base" and sqli["evidence"]["audit_ref"] == "4"
    assert sqli["evidence"]["request"]["method"] == "GET" and "/users/1" in sqli["evidence"]["request"]["url"]
    assert sqli["evidence"]["request"]["parameter"] == "id"


def test_finding_request_uses_the_audit_log_when_the_seq_is_known(client, seeded):
    with app_db.SessionLocal() as db:
        db.query(DastRequestAudit).filter(DastRequestAudit.scan_id == seeded).delete()
        db.add(
            DastRequestAudit(
                scan_id=seeded, seq=4, method="GET", url="http://localhost:3000/users/1?id=1%27",
                allowed=True, response_status=500, identity_label="demo",
                request_headers={"accept": "application/json"},
                response_headers={"content-type": "application/json"},
            )
        )
        db.commit()
    sqli = next(f for f in get(client, seeded)["findings"] if f["rule_id"] == "dast-sqli" and f["param"] == "id")
    req = sqli["evidence"]["request"]
    assert req["url"] == "http://localhost:3000/users/1?id=1%27" and req["response_status"] == 500
    assert req["identity_label"] == "demo" and req["headers"]["accept"] == "application/json"


def test_unverified_is_present_by_default_and_only_removed_by_asking(client, seeded):
    assert any(f["verdict"] == "unverified" for f in get(client, seeded)["findings"])
    confirmed = get(client, seeded, verdict="true_positive")
    assert all(f["verdict"] == "true_positive" for f in confirmed["findings"])
    assert confirmed["unverified_count"] == 1  # the summary still says what is hidden
    assert [f["rule_id"] for f in get(client, seeded, verdict="unverified")["findings"]] == ["dast-xss"]


def test_each_filter_alone(client, seeded):
    ids = lambda **p: sorted({f["rule_id"] for f in get(client, seeded, **p)["findings"]})  # noqa: E731
    assert ids(severity="CRITICAL") == ["dast-bfla"]
    assert ids(severity="critical,medium") == ["dast-bfla", "dast-xss"]
    assert ids(check="dast-xss") == ["dast-xss"]
    assert ids(check="dast-authz") == ["dast-bola"]  # an alias resolves
    assert ids(role="admin") == ["dast-bfla"]
    assert ids(role="user") == ["dast-bfla", "dast-bola"]
    assert ids(role="user:anonymous") == ["dast-bola"]
    assert ids(role="viewer") == []


def test_filters_combine(client, seeded):
    assert [f["rule_id"] for f in get(client, seeded, severity="high", check="dast-sqli,dast-bola", role="user")["findings"]] == ["dast-bola"]
    assert get(client, seeded, severity="low")["findings"] == []
    assert get(client, seeded, severity="low")["total_count"] == 5


def test_findings_are_ordered_by_severity(client, seeded):
    sev = [f["severity"] for f in get(client, seeded)["findings"]]
    assert sev == sorted(sev, key=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index)


def test_a_scan_with_no_findings_returns_an_empty_list(client):
    scan_id = new_scan(client, "empty")
    with app_db.SessionLocal() as db:
        from app.models import DastEvidence, Finding as F

        db.query(DastEvidence).delete()
        db.query(F).delete()
        db.commit()
    body = get(client, scan_id)
    assert body["findings"] == [] and body["total_count"] == 0


def test_sast_responses_are_unchanged(client):
    scan_id = new_scan(client, "sast", scan_type="sast")
    body = get(client, scan_id)
    assert set(body) == {
        "scan_id", "tp_count", "fp_count", "unverified_count", "files_scanned", "severity_group_counts", "findings",
    }
    for finding in body["findings"]:
        assert "evidence" not in finding and "remediation" not in finding

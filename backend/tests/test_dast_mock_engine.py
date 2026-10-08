"""Mock DAST engine contract (DAST-00-050): full result shape, deterministic, fully offline."""

import contextlib
import io
import json
import socket

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.dast import contract, mock_engine
from app.db import init_db
from app.main import app
from app.models import DastEvidence, Finding, Scan

pytestmark = pytest.mark.integration

HDR = {"Authorization": f"Bearer {settings.sast_api_token}"}
TARGET = {"target_url": "http://localhost:3000", "authorized": True}


def _run(dast_input=None):
    """Run the mock engine, returning (serialized result, serialized finding batches, log text)."""
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        result, batches = mock_engine.run_mock_dast(dast_input or TARGET)
    return (
        json.dumps(result, sort_keys=True),
        json.dumps(batches, sort_keys=True),
        buffer.getvalue(),
    )


def _all_rows(dast_input=None):
    with contextlib.redirect_stdout(io.StringIO()):
        _, batches = mock_engine.run_mock_dast(dast_input or TARGET)
    return [row for _, rows in batches for row in rows]


def test_identical_input_yields_byte_identical_output():
    first = _run()
    second = _run()
    assert first[0].encode() == second[0].encode()
    assert first[1].encode() == second[1].encode()
    assert first[2] == second[2]


def test_different_targets_change_the_output():
    other = _run({"target_url": "http://localhost:3001", "authorized": True})
    assert other[0] != _run()[0]


def test_every_result_kind_is_present():
    result_json, _, _ = _run()
    result = json.loads(result_json)
    discovery = result["discovery"]

    assert discovery["pages"] and discovery["api_calls"]
    assert discovery["analysis_summary"]["apis_tested"] == len(discovery["api_analysis"])
    assert discovery["passive_analysis"]["findings"] == 2
    assert result["usage_summary"]["total_tokens"] == (
        result["usage_summary"]["input_tokens"] + result["usage_summary"]["output_tokens"]
    ) > 0

    rows = _all_rows()
    by_rule = {row["rule_id"]: row for row in rows}
    # passive, active (legacy ids preserved), authorization
    assert {"dast-passive-missing-csp", "dast-sqli", "dast-bfla"} <= set(by_rule)
    # active findings carry evidence with a detector signal when confirmed
    sqli = by_rule["dast-sqli"]
    assert sqli["verdict"] == "true_positive"
    assert sqli["evidence"]["test_excerpt"] and sqli["evidence"]["signals"]
    assert sqli["target"] == "POST http://localhost:3000/api/login" and sqli["param"] == "username" and sqli["location"] == "body"
    assert "dast-xss" not in by_rule
    assert not [row for row in rows if row["verdict"] == "unverified"]


def test_two_role_authorization_result():
    authorization = json.loads(_run()[0])["discovery"]["authorization"]
    assert [i["role"] for i in authorization["identities"]] == ["admin", "user"]
    assert authorization["baseline_identity"] == "anonymous"
    cells = {(c["owner"], c["actor"]): c for c in authorization["matrix"]}
    assert cells[("admin", "user")]["result"] == "FAIL" and cells[("admin", "user")]["failures"] == 1
    assert cells[("admin", "anonymous")]["result"] == "OK"
    assert cells[("user", "admin")]["result"] == "untested" and cells[("user", "admin")]["reason"]
    # the failing cell points at a finding the engine actually emitted
    emitted = {f"{row['rule_id']}|{row['target']}" for row in _all_rows()}
    assert set(cells[("admin", "user")]["finding_keys"]) <= emitted


def test_output_validates_against_the_domain_entities():
    discovery = json.loads(_run()[0])["discovery"]
    rows = _all_rows()
    contract.validate_result(discovery, rows)  # raises on any drift

    domain_findings = [contract.finding_from_row(row) for row in rows]
    assert len(domain_findings) == len(rows)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda row: row.update(severity="SEVERE"),
        lambda row: row.update(location="cookie-jar"),
        lambda row: row.update(confidence_label="CERTAIN"),
    ],
)
def test_domain_validation_rejects_drifted_rows(mutate):
    discovery = json.loads(_run()[0])["discovery"]
    rows = _all_rows()
    target = next(row for row in rows if row["rule_id"] == "dast-sqli")
    mutate(target)
    with pytest.raises((ValueError, KeyError)):
        contract.validate_result(discovery, rows)


def test_domain_validation_rejects_a_bad_matrix_cell():
    discovery = json.loads(_run()[0])["discovery"]
    discovery["authorization"]["matrix"][0]["failures"] = 0  # FAIL with zero failures
    with pytest.raises(ValueError):
        contract.validate_result(discovery, [])


def test_mock_run_needs_no_network_or_browser(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("the mock engine must not open sockets")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    _run()  # would raise if it tried


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("USE_MOCK_ENGINE", "true")
    settings.use_mock_engine = True
    settings.scan_logs_dir = str(tmp_path / "scan_logs")
    SessionLocal = init_db(f"sqlite:///{(tmp_path / 'mock.db').as_posix()}")
    test_client = TestClient(app)
    test_client.session_factory = SessionLocal
    return test_client


def _scan_via_api(client, name):
    project = client.post(
        "/projects", json={"name": name, "default_git_url": "https://example.test/r.git"}, headers=HDR
    ).json()
    resp = client.post(
        "/scans", headers=HDR, json={"project_id": project["id"], "scan_type": "dast", "dast": TARGET}
    )
    assert resp.status_code == 202, resp.text
    return resp.json()["scan_id"]


def test_scan_stores_findings_and_evidence_via_the_api_path(client):
    scan_id = _scan_via_api(client, "mock-contract")

    with client.session_factory() as db:
        findings = db.query(Finding).filter_by(scan_id=scan_id).all()
        by_rule = {f.rule_id: f for f in findings}
        assert "dast-xss" not in by_rule
        assert by_rule["dast-sqli"].verdict == "true_positive"

        sqli = by_rule["dast-sqli"]
        assert (sqli.target, sqli.param, sqli.location, sqli.confidence_label) == (
            "POST http://localhost:3000/api/login", "username", "body", "HIGH",
        )
        assert sqli.first_seen_scan_id == sqli.last_seen_scan_id == scan_id
        assert "CWE-89" in sqli.standards

        evidence = db.query(DastEvidence).filter_by(finding_id=sqli.id).one()
        assert [s["name"] for s in evidence.signals] == ["sql_error_text", "status_changed"]
        assert evidence.audit_ref == "5"
        assert db.query(DastEvidence).count() == len(findings)

        metadata = db.get(Scan, scan_id).metadata_json
        assert metadata["usage_summary"]["total_tokens"] > 0
        assert metadata["discovery"]["authorization"]["matrix"]


def test_two_scans_of_the_same_target_store_identical_discovery(client):
    first = _scan_via_api(client, "determinism-a")
    second = _scan_via_api(client, "determinism-b")
    with client.session_factory() as db:
        a = db.get(Scan, first).metadata_json
        b = db.get(Scan, second).metadata_json
    assert json.dumps(a["discovery"], sort_keys=True) == json.dumps(b["discovery"], sort_keys=True)
    assert a["usage_summary"] == b["usage_summary"]


def test_every_mock_rule_id_is_a_catalog_check_with_resolvable_remediation():
    """The mock engine speaks the catalog's vocabulary, so API and UI work built against it
    sees the same ids, standards and remediation text a real scan produces."""
    from app.services.dast_catalog import default_catalog, remediation_text

    catalog = default_catalog()
    for row in _all_rows():
        check = catalog.get(row["rule_id"])
        assert check is not None, row["rule_id"]
        assert row["remediation_ref"] == check.remediation_ref, row["rule_id"]
        assert remediation_text(row["remediation_ref"]), row["rule_id"]

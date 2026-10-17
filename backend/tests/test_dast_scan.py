import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.db import init_db
from app.main import app

from tests.auth_helpers import ADMIN_HEADERS  # noqa: E402

HDR = ADMIN_HEADERS
PASSWORD = "s3cr3t-pw-value"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("USE_MOCK_ENGINE", "true")
    settings.use_mock_engine = True
    settings.scan_logs_dir = str(tmp_path / "scan_logs")
    init_db(f"sqlite:///{(tmp_path / 'test.db').as_posix()}")
    return TestClient(app)


@pytest.fixture()
def project_id(client):
    resp = client.post("/projects", json={"name": "dast-target", "default_git_url": "https://github.com/org/repo.git"}, headers=HDR)
    assert resp.status_code == 201
    return resp.json()["id"]


def _payload(project_id, **dast_overrides):
    dast = {
        "target_url": "http://localhost:3000",
        "login_url": "http://localhost:3000/login",
        "username": "admin",
        "password": PASSWORD,
        "authorized": True,
    }
    dast.update(dast_overrides)
    return {"project_id": project_id, "scan_type": "dast", "dast": dast}


def test_dast_scan_runs_with_mock_engine(client, project_id):
    resp = client.post("/scans", headers=HDR, json=_payload(project_id))
    assert resp.status_code == 202
    scan_id = resp.json()["scan_id"]

    status = client.get(f"/scans/{scan_id}/status", headers=HDR).json()
    assert status["scan_type"] == "dast"
    assert status["status"] == "success"
    assert status["progress"] == 100

    results = client.get(f"/scans/{scan_id}/results", headers=HDR).json()
    discovery = results["discovery"]
    assert discovery["target_url"] == "http://localhost:3000"
    assert discovery["login_success"] is True
    assert len(discovery["pages"]) == 3
    assert len(discovery["api_calls"]) == 3

    listed = client.get("/scans", headers=HDR, params={"scan_type": "dast"}).json()
    assert [s["id"] for s in listed] == [scan_id]


def test_dast_password_never_leaks(client, project_id):
    resp = client.post("/scans", headers=HDR, json=_payload(project_id))
    scan_id = resp.json()["scan_id"]
    for path in ("status", "results", "logs"):
        assert PASSWORD not in client.get(f"/scans/{scan_id}/{path}", headers=HDR).text
    assert PASSWORD not in client.get("/scans", headers=HDR).text


def test_dast_requires_authorization_ack(client, project_id):
    resp = client.post("/scans", headers=HDR, json=_payload(project_id, authorized=False))
    assert resp.status_code == 400


def test_dast_requires_target_url(client, project_id):
    resp = client.post(
        "/scans", headers=HDR, json={"project_id": project_id, "scan_type": "dast"}
    )
    assert resp.status_code == 400


def test_dast_rejects_non_http_target(client, project_id):
    resp = client.post(
        "/scans", headers=HDR, json=_payload(project_id, target_url="file:///etc/passwd")
    )
    assert resp.status_code == 422


def test_dast_login_url_needs_credentials(client, project_id):
    resp = client.post(
        "/scans", headers=HDR, json=_payload(project_id, username="", password=None)
    )
    assert resp.status_code == 400


def test_dast_scans_are_never_reused(client, project_id):
    a = client.post("/scans", headers=HDR, json=_payload(project_id)).json()
    b = client.post("/scans", headers=HDR, json=_payload(project_id)).json()
    assert a["scan_id"] != b["scan_id"]
    assert b["reused"] is False


def test_dast_scan_produces_api_analysis_and_findings(client, project_id):
    """The analysis stage must surface a per-API drill-down tree in discovery
    and persist FAIL checks as findings (PASS checks stay in the tree only)."""
    scan_id = client.post("/scans", headers=HDR, json=_payload(project_id)).json()["scan_id"]

    discovery = client.get(f"/scans/{scan_id}/results", headers=HDR).json()["discovery"]
    analysis = discovery["api_analysis"]
    assert len(analysis) == 2
    login_api = next(a for a in analysis if a["label"] == "POST http://localhost:3000/api/login")
    assert login_api["overall_verdict"] == "FAIL"
    # Every check carries the full drill-down payload the UI renders.
    sqli = next(c for c in login_api["checks"] if c["check_id"] == "dast-sqli")
    for key in ("check", "target", "payload", "response", "finding", "severity", "verdict", "confidence"):
        assert key in sqli
    assert sqli["verdict"] == "FAIL"

    summary = discovery["analysis_summary"]
    assert summary["apis_tested"] == 2
    assert summary["fail"] == 1
    assert summary["pass"] == 2
    assert summary["inconclusive"] == 0

    findings = client.get(f"/scans/{scan_id}/findings", headers=HDR).json()
    # Active: FAIL -> true_positive, PASS -> not written.
    # The mock also emits passive and authorization findings (see app/dast/mock_engine.py).
    kinds = {f["kind"] for f in findings["findings"]}
    assert kinds == {"dast"}
    by_rule = {f["rule_id"]: f for f in findings["findings"]}
    assert "dast-sqli" in by_rule
    assert "dast-xss" not in by_rule
    assert "dast-misconfig" not in by_rule  # the PASS check
    assert by_rule["dast-sqli"]["verdict"] == "true_positive"
    assert findings["unverified_count"] == 0
    assert findings["tp_count"] == len(findings["findings"])

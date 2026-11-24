"""Short issue ids (`SB-7F3A9C21`), the project issue endpoints and the `secure-fix` skill download."""

import pytest
from fastapi.testclient import TestClient

from app import db as db_module
from app.config import settings
from app.db import init_db
from app.main import app
from app.models import Finding, Scan
from app.routers import projects as projects_router
from app.services import scan_runner
from app.services.occurrence import group_short_id, normalize_short_id, short_id

from tests.auth_helpers import ADMIN_HEADERS, CI_HEADERS

HDR = ADMIN_HEADERS
ID_SQLI = "7f3a9c21" + "0" * 56
ID_XSS = "1b2c3d4e" + "0" * 56
ID_LOW_A = "aaaaaaaa" + "1" * 56
ID_LOW_B = "aaaaaaaa" + "2" * 56  # same first 8 hex as ID_LOW_A: a short-id collision
ID_UNVERIFIED = "99999999" + "0" * 56


def test_short_id_is_the_first_eight_hex_characters_upper_cased():
    assert short_id(ID_SQLI) == "SB-7F3A9C21"
    assert short_id(None) is None
    assert short_id("") is None


def test_a_group_is_named_by_its_lowest_member_so_the_representative_does_not_matter():
    assert group_short_id(ID_XSS, [ID_SQLI, ID_XSS]) == "SB-1B2C3D4E"
    assert group_short_id(ID_SQLI, [ID_XSS, ID_SQLI]) == "SB-1B2C3D4E"
    assert group_short_id(ID_SQLI, None) == "SB-7F3A9C21"


@pytest.mark.parametrize("text", ["SB-7F3A9C21", "sb-7f3a9c21", "SB7F3A9C21", " 7f3a9c21 ", "sb_7F3A9C21"])
def test_normalize_accepts_the_ways_a_person_types_an_id(text):
    assert normalize_short_id(text) == "SB-7F3A9C21"


@pytest.mark.parametrize("text", ["", None, "SB-", "SB-7F3A9C2", "SB-7F3A9C211", "SB-ZZZZZZZZ", "issue-1"])
def test_normalize_rejects_anything_else(text):
    assert normalize_short_id(text) is None


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("USE_MOCK_ENGINE", "true")
    settings.use_mock_engine = True
    settings.scan_logs_dir = str(tmp_path / "scan_logs")
    init_db(f"sqlite:///{(tmp_path / 'issues.db').as_posix()}")
    monkeypatch.setattr(projects_router, "_ngrok_backend_url", lambda port: None)
    monkeypatch.setattr(scan_runner, "execute_scan", lambda scan_id: None)
    return TestClient(app)


def _project(client, name="issues-demo") -> str:
    resp = client.post(
        "/projects",
        headers=HDR,
        json={"name": name, "default_git_url": "https://github.com/org/repo.git"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def _finished_scan(client, project_id: str, commit: str, findings: list[dict]) -> str:
    scan_id = client.post("/scans", headers=HDR, json={"project_id": project_id, "commit_sha": commit}).json()["scan_id"]
    with db_module.SessionLocal() as db:
        db.get(Scan, scan_id).status = "success"
        db.add_all([Finding(scan_id=scan_id, kind="llm", identity_quality="exact", **f) for f in findings])
        db.commit()
    return scan_id


SQLI = dict(severity="CRITICAL", cvss=9.8, title="SQL injection", cwe="CWE-89", rule_id="sqli",
            file_path="src/Dao.java", line=10, verdict="true_positive", occurrence_id=ID_SQLI,
            snippet='query("select " + id)', ai_fix="Use a prepared statement.")
XSS = dict(severity="HIGH", cvss=7.5, title="Reflected XSS", cwe="CWE-79", rule_id="xss",
           file_path="src/Page.java", line=5, verdict="true_positive", occurrence_id=ID_XSS)
UNVERIFIED = dict(severity="MEDIUM", cvss=5.0, title="Maybe weak hash", cwe="CWE-327", rule_id="hash",
                  file_path="src/Hash.java", line=3, verdict="unverified", unresolved_reason="not_reviewed_regex",
                  occurrence_id=ID_UNVERIFIED)


def test_the_findings_api_carries_a_short_id(client):
    pid = _project(client)
    scan_id = _finished_scan(client, pid, "c1", [SQLI])
    body = client.get(f"/scans/{scan_id}/findings", headers=HDR).json()
    assert body["findings"][0]["short_id"] == "SB-7F3A9C21"


def test_list_returns_confirmed_issues_most_severe_first(client):
    pid = _project(client)
    _finished_scan(client, pid, "c1", [XSS, UNVERIFIED, SQLI])
    body = client.get(f"/projects/{pid}/issues", headers=HDR).json()
    assert body["project_id"] == pid
    assert body["scan"]["commit_sha"] == "c1"
    assert body["total"] == 2
    assert [i["short_id"] for i in body["issues"]] == ["SB-7F3A9C21", "SB-1B2C3D4E"]
    assert body["issues"][0]["file_path"] == "src/Dao.java"
    assert body["issues"][0]["occurrence_count"] == 1


def test_list_limit_and_verdict_filters(client):
    pid = _project(client)
    _finished_scan(client, pid, "c1", [XSS, UNVERIFIED, SQLI])
    top1 = client.get(f"/projects/{pid}/issues?limit=1", headers=HDR).json()
    assert top1["total"] == 2 and len(top1["issues"]) == 1
    everything = client.get(f"/projects/{pid}/issues?verdict=all", headers=HDR).json()
    assert everything["total"] == 3
    unverified = client.get(f"/projects/{pid}/issues?verdict=unverified", headers=HDR).json()
    assert [i["short_id"] for i in unverified["issues"]] == ["SB-99999999"]
    assert client.get(f"/projects/{pid}/issues?verdict=bogus", headers=HDR).status_code == 422


def test_detail_has_everything_needed_to_fix_the_issue(client):
    pid = _project(client)
    scan_id = _finished_scan(client, pid, "c1", [SQLI])
    body = client.get(f"/projects/{pid}/issues/SB-7F3A9C21", headers=HDR).json()
    assert body["scan"]["id"] == scan_id
    issue = body["issue"]
    assert issue["short_id"] == "SB-7F3A9C21"
    assert issue["file_path"] == "src/Dao.java" and issue["line"] == 10
    assert issue["snippet"] == 'query("select " + id)'
    assert issue["ai_fix"] == "Use a prepared statement."
    assert issue["verdict"] == "true_positive"


def test_detail_accepts_a_typed_id_in_any_case(client):
    pid = _project(client)
    _finished_scan(client, pid, "c1", [SQLI])
    assert client.get(f"/projects/{pid}/issues/sb-7f3a9c21", headers=HDR).status_code == 200


def test_detail_unknown_and_malformed_ids(client):
    pid = _project(client)
    _finished_scan(client, pid, "c1", [SQLI])
    assert client.get(f"/projects/{pid}/issues/SB-00000000", headers=HDR).status_code == 404
    assert client.get(f"/projects/{pid}/issues/not-an-id", headers=HDR).status_code == 422


def test_any_member_id_of_a_group_names_the_group(client):
    pid = _project(client)
    members = [
        dict(SQLI, file_path="src/A.java", occurrence_id=ID_SQLI, group_by_rule=True),
        dict(SQLI, file_path="src/B.java", occurrence_id=ID_XSS, group_by_rule=True),
    ]
    _finished_scan(client, pid, "c1", members)
    listed = client.get(f"/projects/{pid}/issues", headers=HDR).json()
    assert listed["total"] == 1
    assert listed["issues"][0]["occurrence_count"] == 2
    assert listed["issues"][0]["short_id"] == "SB-1B2C3D4E"  # the lowest member id
    for typed in ("SB-1B2C3D4E", "SB-7F3A9C21"):
        issue = client.get(f"/projects/{pid}/issues/{typed}", headers=HDR).json()["issue"]
        assert issue["occurrence_count"] == 2
        assert sorted(f["file_path"] for f in issue["affected_lines"]) == ["src/A.java", "src/B.java"]


def test_two_different_issues_sharing_an_id_prefix_are_a_conflict_not_a_guess(client):
    pid = _project(client)
    one = dict(SQLI, title="First", occurrence_id=ID_LOW_A, file_path="src/One.java")
    two = dict(XSS, title="Second", occurrence_id=ID_LOW_B, file_path="src/Two.java")
    _finished_scan(client, pid, "c1", [one, two])
    resp = client.get(f"/projects/{pid}/issues/SB-AAAAAAAA", headers=HDR)
    assert resp.status_code == 409
    assert "First" in resp.json()["detail"] and "Second" in resp.json()["detail"]


def test_the_same_issue_keeps_its_id_after_a_rescan_and_the_latest_scan_is_used(client):
    pid = _project(client)
    first = _finished_scan(client, pid, "c1", [SQLI])
    moved = dict(SQLI, line=40)  # a rescan after lines shifted: same occurrence id, new line
    second = _finished_scan(client, pid, "c2", [moved])
    body = client.get(f"/projects/{pid}/issues/SB-7F3A9C21", headers=HDR).json()
    assert body["scan"]["id"] == second and body["issue"]["line"] == 40
    pinned = client.get(f"/projects/{pid}/issues/SB-7F3A9C21?scan_id={first}", headers=HDR).json()
    assert pinned["scan"]["id"] == first and pinned["issue"]["line"] == 10


def test_an_issue_that_is_gone_after_a_fix_is_a_404(client):
    pid = _project(client)
    _finished_scan(client, pid, "c1", [SQLI, XSS])
    _finished_scan(client, pid, "c2", [XSS])  # the SQL injection was fixed
    assert client.get(f"/projects/{pid}/issues/SB-7F3A9C21", headers=HDR).status_code == 404
    assert client.get(f"/projects/{pid}/issues/SB-1B2C3D4E", headers=HDR).status_code == 200


def test_a_project_without_a_finished_scan_says_so(client):
    pid = _project(client)
    resp = client.get(f"/projects/{pid}/issues", headers=HDR)
    assert resp.status_code == 404 and "no finished SAST scan" in resp.json()["detail"]


def test_a_scan_that_is_still_running_is_not_read(client):
    pid = _project(client)
    scan_id = client.post("/scans", headers=HDR, json={"project_id": pid, "commit_sha": "c1"}).json()["scan_id"]
    assert client.get(f"/projects/{pid}/issues?scan_id={scan_id}", headers=HDR).status_code == 409


def test_a_scan_of_another_project_is_not_found(client):
    pid, other = _project(client, "one"), _project(client, "two")
    scan_id = _finished_scan(client, other, "c1", [SQLI])
    assert client.get(f"/projects/{pid}/issues?scan_id={scan_id}", headers=HDR).status_code == 404


def test_the_ci_token_and_nothing_else_unauthenticated(client):
    pid = _project(client)
    _finished_scan(client, pid, "c1", [SQLI])
    assert client.get(f"/projects/{pid}/issues", headers=CI_HEADERS).status_code == 200
    assert client.get(f"/projects/{pid}/issues/SB-7F3A9C21", headers=CI_HEADERS).status_code == 200
    assert client.get(f"/projects/{pid}/issues").status_code == 401
    assert client.get(f"/projects/{pid}/claude-skill").status_code == 401


def test_skill_download_names_the_project_and_never_holds_the_token(client, monkeypatch):
    monkeypatch.setattr(settings, "public_api_url", "https://sb-api.example.com/")
    pid = _project(client, 'My "Payments" API')
    resp = client.get(f"/projects/{pid}/claude-skill", headers=HDR)
    assert resp.status_code == 200
    assert resp.headers["content-disposition"] == 'attachment; filename="SKILL.md"'
    text = resp.text
    assert text.startswith("---\nname: secure-fix\n")
    assert pid in text
    assert "https://sb-api.example.com" in text and "https://sb-api.example.com/" not in text
    assert "My 'Payments' API" in text  # a quote cannot break the YAML description
    assert "{{" not in text  # every placeholder was filled
    assert settings.sast_api_token not in text
    assert "SAST_API_TOKEN" in text
    # The developer chooses how much Claude does.
    assert "plan" in text and "agent" in text


def test_skill_falls_back_to_localhost_without_a_public_url(client, monkeypatch):
    monkeypatch.setattr(settings, "public_api_url", None)
    pid = _project(client)
    text = client.get(f"/projects/{pid}/claude-skill", headers=HDR).text
    assert "${SAST_API_URL:-http://localhost:8000}" in text


def test_skill_for_an_unknown_project_is_a_404(client):
    assert client.get("/projects/nope/claude-skill", headers=HDR).status_code == 404


def test_the_vulnerability_dashboard_shows_the_same_id_the_issue_api_resolves(client):
    pid = _project(client)
    _finished_scan(client, pid, "c1", [SQLI, XSS])
    report = client.get(f"/projects/{pid}/vulnerability-report", headers=HDR).json()
    items = {v["title"]: v for v in report["vulnerabilities"]}
    assert items["SQL injection"]["short_id"] == "SB-7F3A9C21"
    assert items["Reflected XSS"]["short_id"] == "SB-1B2C3D4E"
    # Whatever the dashboard shows, typing it finds the issue.
    typed = items["SQL injection"]["short_id"]
    assert client.get(f"/projects/{pid}/issues/{typed}", headers=HDR).status_code == 200

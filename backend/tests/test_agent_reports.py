import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.db import init_db
from app.main import app
from tests.auth_helpers import ADMIN_HEADERS, CI_HEADERS, make_user

HDR = ADMIN_HEADERS

PAYLOAD = {
    "source": "claude",
    "summary": "Fix the SQL injection in Dao first, then the overdue XSS.",
    "context": "Dao is on the login path.",
    "items": [
        {"short_id": "SB-AAAAAAAA", "title": "SQL injection", "severity": "HIGH", "reason": "Confirmed"},
        {"short_id": "SB-BBBBBBBB", "title": "Reflected XSS", "severity": "MEDIUM", "reason": "Overdue"},
    ],
}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("USE_MOCK_ENGINE", "true")
    settings.use_mock_engine = True
    settings.scan_logs_dir = str(tmp_path / "scan_logs")
    settings.workspaces_dir = str(tmp_path / "workspaces")
    init_db(f"sqlite:///{(tmp_path / 'test.db').as_posix()}")
    return TestClient(app)


def _project(client, headers=HDR):
    return client.post(
        "/projects",
        json={"name": "p", "default_git_url": "https://github.com/o/r.git"},
        headers=headers,
    ).json()["id"]


def test_ci_pushes_a_priority_list_not_a_full_report(client):
    pid = _project(client)
    resp = client.post("/agent-reports", headers=CI_HEADERS, json={**PAYLOAD, "project_id": pid})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["source"] == "claude"
    assert body["summary"].startswith("Fix the SQL")
    assert body["context"] == "Dao is on the login path."
    assert [i["title"] for i in body["items"]] == ["SQL injection", "Reflected XSS"]
    assert body["items"][0]["rank"] == 1
    assert "vulnerabilities" not in body
    listed = client.get("/agent-reports", headers=CI_HEADERS).json()
    assert listed[0]["id"] == body["id"]
    assert listed[0]["item_count"] == 2
    got = client.get(f"/agent-reports/{body['id']}", headers=CI_HEADERS).json()
    assert got["items"][1]["short_id"] == "SB-BBBBBBBB"


def test_posted_order_is_kept_even_when_titles_sort_the_other_way(client):
    resp = client.post(
        "/agent-reports",
        headers=CI_HEADERS,
        json={
            "summary": "XSS first, then SQL.",
            "items": [
                {"short_id": "SB-XSS", "title": "Reflected XSS", "severity": "MEDIUM"},
                {"short_id": "SB-SQL", "title": "SQL injection", "severity": "HIGH"},
            ],
        },
    )
    assert resp.status_code == 201, resp.text
    titles = [i["title"] for i in resp.json()["items"]]
    assert titles == ["Reflected XSS", "SQL injection"]
    assert [i["rank"] for i in resp.json()["items"]] == [1, 2]


def test_codex_source_is_accepted(client):
    resp = client.post("/agent-reports", headers=CI_HEADERS, json={**PAYLOAD, "source": "codex"})
    assert resp.status_code == 201
    assert resp.json()["source"] == "codex"


def test_unknown_project_is_404(client):
    resp = client.post(
        "/agent-reports",
        headers=CI_HEADERS,
        json={**PAYLOAD, "project_id": "00000000-0000-4000-8000-000000000099"},
    )
    assert resp.status_code == 404


def test_empty_items_rejected(client):
    resp = client.post("/agent-reports", headers=CI_HEADERS, json={"summary": "x", "items": []})
    assert resp.status_code == 422


def test_user_does_not_see_another_users_list(client):
    _, user_h = make_user("writer@test.local")
    _, other_h = make_user("reader@test.local")
    pid = _project(client, user_h)
    created = client.post("/agent-reports", headers=user_h, json={**PAYLOAD, "project_id": pid}).json()
    assert client.get(f"/agent-reports/{created['id']}", headers=user_h).status_code == 200
    assert client.get(f"/agent-reports/{created['id']}", headers=other_h).status_code == 404
    assert client.get("/agent-reports", headers=other_h).json() == []


def test_skill_tells_claude_to_post_a_summary(client):
    pid = _project(client)
    resp = client.get(f"/agent-reports/skill?project_id={pid}", headers=HDR)
    assert resp.status_code == 200
    text = resp.text
    assert "POST" in text and "/agent-reports" in text
    assert pid in text
    assert "full vulnerability report" in text.lower() or "Do **not** upload" in text
    assert "/issues?limit=10" in text

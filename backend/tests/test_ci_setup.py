"""GET /projects/{id}/ci-setup: the values the GitLab CI guide shows."""

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.db import init_db
from app.main import app
from app.routers import projects as projects_router
from tests.auth_helpers import ADMIN_HEADERS, make_user


@pytest.fixture()
def client(tmp_path, monkeypatch):
    init_db(f"sqlite:///{(tmp_path / 'test.db').as_posix()}")
    # Never reach a real ngrok agent from the suite.
    monkeypatch.setattr(projects_router, "_ngrok_backend_url", lambda port: None)
    return TestClient(app)


def _project(client) -> str:
    resp = client.post(
        "/projects",
        json={"name": "ci-demo", "default_git_url": "https://gitlab.com/org/repo.git", "owasp_mode": "top10", "enable_sca": True},
        headers=ADMIN_HEADERS,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def test_admin_gets_token_and_configured_api_url(client, monkeypatch):
    monkeypatch.setattr(settings, "public_api_url", "https://sb-api.example.com/")
    pid = _project(client)
    body = client.get(f"/projects/{pid}/ci-setup", headers=ADMIN_HEADERS).json()
    assert body["project_id"] == pid
    assert body["api_url"] == "https://sb-api.example.com"
    assert body["api_url_source"] == "setting"
    assert body["token_visible"] is True
    assert body["token"] == settings.sast_api_token
    assert "sast" in body["scan_types"] and "sca" in body["scan_types"]


def test_non_admin_never_gets_token(client, monkeypatch):
    monkeypatch.setattr(settings, "public_api_url", None)
    _, headers = make_user("member@test.local")
    resp = client.post(
        "/projects",
        json={"name": "own", "default_git_url": "https://gitlab.com/org/own.git", "owasp_mode": "top10"},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    body = client.get(f"/projects/{resp.json()['id']}/ci-setup", headers=headers).json()
    assert body["token"] is None and body["token_visible"] is False
    assert body["api_url"] is None and body["api_url_source"] is None
    assert "sast" in body["scan_types"]


def test_ngrok_tunnel_is_used_when_no_setting(client, monkeypatch):
    monkeypatch.setattr(settings, "public_api_url", None)
    monkeypatch.setattr(projects_router, "_ngrok_backend_url", lambda port: "https://abc.ngrok-free.app")
    pid = _project(client)
    body = client.get(f"/projects/{pid}/ci-setup", headers=ADMIN_HEADERS).json()
    assert body["api_url"] == "https://abc.ngrok-free.app"
    assert body["api_url_source"] == "ngrok"


def test_anonymous_is_rejected(client):
    pid = _project(client)
    assert client.get(f"/projects/{pid}/ci-setup").status_code == 401

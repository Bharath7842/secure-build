"""`GET /git-auth/{provider}/repo` finds one repository by its pasted Git URL."""

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.db import init_db
from app.main import app
from app.routers import git_auth
from app.routers.git_auth import repo_path_from_url

from tests.auth_helpers import ADMIN_HEADERS, make_user  # noqa: E402

HDR = ADMIN_HEADERS


@pytest.fixture()
def client(tmp_path):
    init_db(f"sqlite:///{(tmp_path / 'test.db').as_posix()}")
    git_auth._pending_connections.clear()
    client = TestClient(app)
    client.conn = git_auth._store_pending_connection("gitlab", {"access_token": "tok-123"})  # type: ignore[attr-defined]
    return client


class _Resp:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            import httpx
            raise httpx.HTTPStatusError("boom", request=None, response=self)  # type: ignore[arg-type]


@pytest.mark.parametrize("url,expected", [
    ("https://gitlab.com/group/repo.git", "group/repo"),
    ("https://gitlab.com/group/sub/deep/repo", "group/sub/deep/repo"),
    ("  https://gitlab.com/group/repo/  ", "group/repo"),
    ("https://gitlab.com/group/repo/-/tree/main/src", "group/repo"),
    ("git@gitlab.com:group/sub/repo.git", "group/sub/repo"),
    ("ssh://git@gitlab.com/group/repo.git", "group/repo"),
    ("https://user:pw@gitlab.com/group/repo.git", "group/repo"),
])
def test_gitlab_url_forms(url, expected):
    assert repo_path_from_url("gitlab", url) == expected


@pytest.mark.parametrize("provider,url", [
    ("gitlab", ""),
    ("gitlab", "not a url"),
    ("gitlab", "https://gitlab.com/onlyone"),
    ("gitlab", "https://gitlab.com/group/../etc"),
    ("gitlab", "https://evil.example/group/repo.git"),
    ("gitlab", "https://gitlab.com.evil.example/group/repo.git"),
    ("gitlab", "ftp://gitlab.com/group/repo.git"),
    ("gitlab", "https://github.com/org/repo"),
])
def test_rejects_bad_or_foreign_urls(provider, url):
    with pytest.raises(ValueError):
        repo_path_from_url(provider, url)


def test_gitlab_lookup_uses_encoded_path_and_token(client, monkeypatch):
    seen = {}

    def fake_get(url, **kwargs):
        seen["url"], seen["headers"] = url, kwargs["headers"]
        return _Resp(200, {
            "name": "repo", "path_with_namespace": "group/sub/repo",
            "http_url_to_repo": "https://gitlab.com/group/sub/repo.git",
            "default_branch": "develop", "visibility": "private",
        })

    monkeypatch.setattr(git_auth.httpx, "get", fake_get)
    r = client.get("/git-auth/gitlab/repo", headers=HDR, params={
        "url": "https://gitlab.com/group/sub/repo.git", "connection_id": client.conn})
    assert r.status_code == 200
    assert r.json() == {
        "name": "repo", "full_name": "group/sub/repo",
        "clone_url": "https://gitlab.com/group/sub/repo.git",
        "default_branch": "develop", "private": True,
    }
    assert seen["url"] == "https://gitlab.com/api/v4/projects/group%2Fsub%2Frepo"
    assert seen["headers"]["Authorization"] == "Bearer tok-123"


def test_github_provider_is_unsupported(client):
    r = client.get("/git-auth/github/authorize", headers=HDR)
    assert r.status_code == 400


def test_not_found_is_404_and_does_not_distinguish_private(client, monkeypatch):
    monkeypatch.setattr(git_auth.httpx, "get", lambda *a, **k: _Resp(404))
    r = client.get("/git-auth/gitlab/repo", headers=HDR, params={
        "url": "https://gitlab.com/group/secret.git", "connection_id": client.conn})
    assert r.status_code == 404
    assert "visible to your gitlab account" in r.json()["detail"]


def test_foreign_host_is_rejected_before_any_request(client, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("must not call the provider for a foreign host")

    monkeypatch.setattr(git_auth.httpx, "get", boom)
    r = client.get("/git-auth/gitlab/repo", headers=HDR, params={
        "url": "https://evil.example/group/repo.git", "connection_id": client.conn})
    assert r.status_code == 400


def test_requires_auth_and_a_connection(client):
    assert client.get("/git-auth/gitlab/repo", params={"url": "https://gitlab.com/a/b"}).status_code in {401, 403}
    r = client.get("/git-auth/gitlab/repo", headers=HDR, params={
        "url": "https://gitlab.com/a/b", "connection_id": "missing"})
    assert r.status_code == 404


REPO = {
    "name": "repo", "path_with_namespace": "group/repo",
    "http_url_to_repo": "https://gitlab.com/group/repo.git",
    "default_branch": "main", "visibility": "private",
}


def test_token_check_keeps_the_token_as_a_pending_connection_for_a_new_project(client, monkeypatch):
    monkeypatch.setattr(git_auth.httpx, "get", lambda url, **kw: _Resp(200, REPO))
    r = client.post("/git-auth/gitlab/token", headers=HDR, json={
        "url": "https://gitlab.com/group/repo.git", "access_token": "pat-1",
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["full_name"] == "group/repo" and body["clone_url"] == "https://gitlab.com/group/repo.git"
    assert body["connection_id"]
    assert "pat-1" not in r.text  # the token itself never comes back
    assert git_auth.consume_pending_connection(body["connection_id"])["access_token"] == "pat-1"


def test_token_check_saves_the_token_on_an_existing_project(client, monkeypatch):
    from app.db import SessionLocal
    from app.models import Project

    monkeypatch.setattr(git_auth.httpx, "get", lambda url, **kw: _Resp(200, REPO))
    project = client.post("/projects", headers=HDR, json={"name": "tokproj", "default_git_url": ""}).json()
    r = client.post("/git-auth/gitlab/token", headers=HDR, json={
        "url": "https://gitlab.com/group/repo.git", "access_token": "pat-2", "project_id": project["id"],
    })
    assert r.status_code == 200, r.text
    assert r.json()["connection_id"] is None
    with SessionLocal() as db:
        row = db.get(Project, project["id"])
        assert row.git_provider == "gitlab" and row.git_access_token == "pat-2"
        assert row.git_refresh_token is None and row.git_token_expires_at is None
    assert client.get(f"/projects/{project['id']}", headers=HDR).json()["git_connected"] is True


def test_token_check_refuses_a_repo_the_token_cannot_see(client, monkeypatch):
    monkeypatch.setattr(git_auth.httpx, "get", lambda url, **kw: _Resp(404))
    r = client.post("/git-auth/gitlab/token", headers=HDR, json={
        "url": "https://gitlab.com/group/repo.git", "access_token": "bad",
    })
    assert r.status_code == 404
    assert all(v["access_token"] != "bad" for v in git_auth._pending_connections.values())


def test_token_check_rejects_a_foreign_url_before_calling_the_provider(client, monkeypatch):
    def boom(url, **kw):
        raise AssertionError("must not call the provider for a foreign host")

    monkeypatch.setattr(git_auth.httpx, "get", boom)
    r = client.post("/git-auth/gitlab/token", headers=HDR, json={
        "url": "https://evil.example/group/repo.git", "access_token": "pat",
    })
    assert r.status_code == 400


def test_token_check_cannot_attach_a_token_to_someone_elses_project(client, monkeypatch):
    monkeypatch.setattr(git_auth.httpx, "get", lambda url, **kw: _Resp(200, REPO))
    project = client.post("/projects", headers=HDR, json={"name": "not-yours", "default_git_url": ""}).json()
    _, bob = make_user("bob@test.local")
    r = client.post("/git-auth/gitlab/token", headers=bob, json={
        "url": "https://gitlab.com/group/repo.git", "access_token": "pat-x", "project_id": project["id"],
    })
    assert r.status_code == 404

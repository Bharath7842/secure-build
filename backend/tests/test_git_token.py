"""git_token.fresh_access_token — refreshing an expired GitLab OAuth token.

GitLab tokens last ~2h; scans started after that used to fail at `git fetch`
with "HTTP Basic: Access denied". The token endpoint is faked (no network).
"""

import threading
from datetime import timedelta

import httpx
import pytest

from app import db as db_module
from app.config import settings
from app.db import init_db
from app.models import Project, utcnow
from app.services import git_token


@pytest.fixture()
def session(tmp_path):
    init_db(f"sqlite:///{(tmp_path / 'test.db').as_posix()}")
    db = db_module.SessionLocal()
    yield db
    db.close()


def _project(db, **overrides) -> Project:
    fields = dict(
        name="p",
        default_git_url="https://gitlab.com/org/repo.git",
        git_provider="gitlab",
        git_access_token="old-access",
        git_refresh_token="old-refresh",
        git_token_expires_at=utcnow() - timedelta(hours=1),
    )
    fields.update(overrides)
    project = Project(**fields)
    db.add(project)
    db.commit()
    return project


class _Resp:
    def __init__(self, payload, status=200):
        self._payload, self.status_code = payload, status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                f"{self.status_code}", request=httpx.Request("POST", "http://x"), response=httpx.Response(self.status_code)
            )

    def json(self):
        return self._payload


@pytest.fixture()
def token_endpoint(monkeypatch):
    """Records every POST; `.respond` is what the next call returns."""
    class Calls(list):
        state: dict

    calls = Calls()
    state = {"respond": _Resp({"access_token": "new-access", "refresh_token": "new-refresh", "expires_in": 7200})}

    def post(url, data=None, timeout=None):
        calls.append((url, dict(data)))
        return state["respond"]

    monkeypatch.setattr(httpx, "post", post)
    monkeypatch.setattr(settings, "gitlab_base_url", "https://gitlab.example")
    calls.state = state
    return calls


def test_expired_token_is_refreshed_and_persisted(session, token_endpoint):
    project = _project(session)
    assert git_token.fresh_access_token(project) == "new-access"

    url, data = token_endpoint[0]
    assert url == "https://gitlab.example/oauth/token"
    assert data["grant_type"] == "refresh_token" and data["refresh_token"] == "old-refresh"

    session.expire_all()  # read back from the DB, not the identity map
    stored = session.get(Project, project.id)
    # GitLab rotates the refresh token: the new one must replace the old.
    assert (stored.git_access_token, stored.git_refresh_token) == ("new-access", "new-refresh")
    assert git_token._as_utc(stored.git_token_expires_at) > utcnow() + timedelta(hours=1)


def test_valid_token_is_left_alone(session, token_endpoint):
    project = _project(session, git_token_expires_at=utcnow() + timedelta(hours=1))
    assert git_token.fresh_access_token(project) == "old-access"
    assert token_endpoint == []


def test_token_inside_the_skew_window_is_refreshed(session, token_endpoint):
    project = _project(session, git_token_expires_at=utcnow() + timedelta(minutes=2))
    assert git_token.fresh_access_token(project) == "new-access"


def test_naive_expiry_from_sqlite_is_treated_as_utc(session, token_endpoint):
    project = _project(session)
    session.expire_all()
    reloaded = session.get(Project, project.id)
    assert reloaded.git_token_expires_at.tzinfo is None  # what SQLite returns
    assert git_token.fresh_access_token(reloaded) == "new-access"


@pytest.mark.parametrize("overrides", [
    {"git_provider": "github"},           # GitHub tokens don't expire
    {"git_token_expires_at": None},       # no expiry recorded
    {"git_access_token": None},           # not connected
])
def test_projects_that_never_need_a_refresh_skip_the_endpoint(session, token_endpoint, overrides):
    project = _project(session, **overrides)
    assert git_token.fresh_access_token(project) == overrides.get("git_access_token", "old-access")
    assert token_endpoint == []


def test_failed_refresh_returns_the_stale_token_and_keeps_the_stored_state(session, token_endpoint):
    token_endpoint.state["respond"] = _Resp({"error": "invalid_grant"}, status=400)
    project = _project(session)
    assert git_token.fresh_access_token(project) == "old-access"  # git then fails as before; no new error path

    session.expire_all()
    stored = session.get(Project, project.id)
    assert (stored.git_access_token, stored.git_refresh_token) == ("old-access", "old-refresh")


def test_error_body_with_200_status_is_a_failure(session, token_endpoint):
    token_endpoint.state["respond"] = _Resp({"error": "invalid_grant", "error_description": "revoked"})
    assert git_token.fresh_access_token(_project(session)) == "old-access"


def test_missing_refresh_token_returns_the_stale_token(session, token_endpoint):
    project = _project(session, git_refresh_token=None)
    assert git_token.fresh_access_token(project) == "old-access"
    assert token_endpoint == []


def test_concurrent_scans_refresh_once(tmp_path, token_endpoint):
    # Two scans of one project, each on its own session. The refresh token
    # rotates on use, so a second refresh with the old one would disconnect
    # the project; the loser must pick up the winner's stored result.
    init_db(f"sqlite:///{(tmp_path / 'race.db').as_posix()}")
    setup = db_module.SessionLocal()
    project_id = _project(setup).id
    setup.close()

    results, barrier = [], threading.Barrier(2)

    def scan():
        db = db_module.SessionLocal()
        try:
            project = db.get(Project, project_id)
            barrier.wait()
            results.append(git_token.fresh_access_token(project))
        finally:
            db.close()

    threads = [threading.Thread(target=scan) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results == ["new-access", "new-access"]
    assert len(token_endpoint) == 1

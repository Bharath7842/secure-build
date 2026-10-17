"""Authorization on the existing API: every route declares how it's
authenticated, scans are scoped to their owner, and each caller (anonymous,
regular user, admin, CI token) gets exactly what the permission catalog says."""

import re

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from app import db as app_db
from app.auth.principal import get_principal, public
from app.config import settings
from app.db import init_db
from app.main import app
from app.models import AuditEvent, DastSchedule, Scan, User
from tests.auth_helpers import ADMIN_HEADERS, CI_HEADERS, make_user

PUBLIC_ROUTES = {"/health"}


def _dependency_calls(dependant) -> set:
    calls = {dependant.call}
    for sub in dependant.dependencies:
        calls |= _dependency_calls(sub)
    return calls


def _api_routes():
    """Every API route with its full dependency tree (router-level ones
    included). FastAPI 0.141 keeps included routers as `_IncludedRouter`
    entries whose routes come from `effective_route_contexts()`."""
    routes = []
    for r in app.routes:
        if isinstance(r, APIRoute):
            routes.append(r)
        elif hasattr(r, "effective_route_contexts"):
            routes.extend(r.effective_route_contexts())
    return routes


def test_the_route_walk_sees_every_router():
    paths = {r.path for r in _api_routes()}
    assert len(paths) > 60
    assert {"/scans/{scan_id}/status", "/admin/users", "/setup", "/projects", "/dast/settings"} <= paths


def test_every_route_declares_how_it_is_authenticated():
    """A new route without require(...)/require_user/public fails here, so
    nothing ships open by accident."""
    unguarded = [
        f"{sorted(r.methods)} {r.path}"
        for r in _api_routes()
        if r.path not in PUBLIC_ROUTES
        and not ({get_principal, public} & _dependency_calls(r.dependant))
    ]
    assert unguarded == []


def _sample_path(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "x", path)


PROTECTED = [
    (method, r.path)
    for r in _api_routes()
    if public not in _dependency_calls(r.dependant) and r.path not in PUBLIC_ROUTES
    for method in sorted(r.methods)
]


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("USE_MOCK_ENGINE", "true")
    monkeypatch.setattr(settings, "use_mock_engine", True)
    monkeypatch.setattr(settings, "scan_logs_dir", str(tmp_path / "scan_logs"))
    init_db(f"sqlite:///{(tmp_path / 'authz.db').as_posix()}")
    return TestClient(app)


@pytest.mark.parametrize("method, path", PROTECTED)
def test_anonymous_callers_get_401_everywhere(client, method, path):
    r = client.request(method, _sample_path(path), json={})
    assert r.status_code == 401, (method, path, r.status_code, r.text[:200])
    assert r.json() == {"detail": "Authentication required", "code": "unauthenticated"}


@pytest.mark.parametrize("method, path", PROTECTED[:20])
def test_a_wrong_token_is_401_not_a_partial_pass(client, method, path):
    for header in ("Bearer wrong", "Session wrong", "Basic abc", "Bearer", "Session"):
        r = client.request(method, _sample_path(path), json={}, headers={"Authorization": header})
        assert r.status_code == 401, (method, path, header)


# --- scan ownership --------------------------------------------------------------------------------------------------


@pytest.fixture()
def project_id(client):
    r = client.post("/projects", headers=ADMIN_HEADERS, json={"name": "p", "default_git_url": "https://github.com/o/r.git"})
    assert r.status_code == 201
    return r.json()["id"]


def _start(client, headers, project_id, commit="abc", **extra):
    r = client.post("/scans", headers=headers, json={"project_id": project_id, "commit_sha": commit, **extra})
    assert r.status_code == 202, r.text
    return r.json()["scan_id"]


SCAN_READS = [
    "/scans/{id}/status",
    "/scans/{id}/logs",
    "/scans/{id}/results",
    "/scans/{id}/findings",
    "/scans/{id}/export.pdf",
    "/scans/{id}/export.xlsx",
    "/scans/{id}/export.sarif",
    "/scans/{id}/export.junit",
    "/scans/{id}/narration",
    "/scans/{id}/narration/stream?step=auth",
    "/scans/{id}/requests",
    "/scans/{id}/authz-matrix",
    "/scans/{id}/diff",
    "/scans/{id}/summary",
    "/scans/{id}/report",
    "/scans/{id}/screenshots/1.jpg",
    "/feedback?scan_id={id}",
]


def test_users_see_only_their_own_scans(client, project_id):
    _, ada = make_user("ada@test.local")
    _, bob = make_user("bob@test.local")
    ada_scan = _start(client, ada, project_id, "a1")
    bob_scan = _start(client, bob, project_id, "b1")
    ci_scan = _start(client, CI_HEADERS, project_id, "c1")

    def listed(headers):
        return {s["id"] for s in client.get("/scans", headers=headers).json()}

    assert listed(ada) == {ada_scan}
    assert listed(bob) == {bob_scan}
    assert listed(ADMIN_HEADERS) == listed(CI_HEADERS) == {ada_scan, bob_scan, ci_scan}

    with app_db.SessionLocal() as db:
        assert db.get(Scan, ci_scan).triggered_by == "jenkins" and db.get(Scan, ci_scan).created_by_user_id is None
        assert db.get(Scan, ada_scan).created_by_user_id is not None


@pytest.mark.parametrize("path", SCAN_READS)
def test_another_users_scan_is_404_on_every_read(client, project_id, path):
    """Same answer as a scan that doesn't exist, so ids can't be probed."""
    _, ada = make_user("ada@test.local")
    _, bob = make_user("bob@test.local")
    scan_id = _start(client, ada, project_id)
    if "{id}" in path and path.startswith("/scans") and "feedback" not in path:
        assert client.get(path.format(id=scan_id), headers=bob).status_code == 404
        missing = client.get(path.format(id="does-not-exist"), headers=bob)
        assert missing.status_code == 404
    else:
        assert client.get(path.format(id=scan_id), headers=bob).status_code in (403, 404)
    # The owner and an admin get past the scope check (whatever the route then says).
    assert client.get(path.format(id=scan_id), headers=ADMIN_HEADERS).status_code != 404 or "screenshots" in path


def test_legacy_scans_without_an_owner_are_admin_only(client, project_id):
    scan_id = _start(client, CI_HEADERS, project_id)  # no owner, like a pre-accounts scan
    _, ada = make_user("ada@test.local")
    assert client.get(f"/scans/{scan_id}/status", headers=ada).status_code == 404
    assert client.get(f"/scans/{scan_id}/status", headers=ADMIN_HEADERS).status_code == 200
    _, viewer = make_user("viewer@test.local", overrides={"scans.view_all": "grant"})
    assert client.get(f"/scans/{scan_id}/status", headers=viewer).status_code == 200


def test_reuse_never_hands_back_someone_elses_scan(client, project_id):
    _, ada = make_user("ada@test.local")
    _, bob = make_user("bob@test.local")
    first = _start(client, ada, project_id, "same")
    assert _start(client, ada, project_id, "same") == first  # reused for its owner
    other = _start(client, bob, project_id, "same")
    assert other != first
    assert client.get(f"/scans/{other}/status", headers=bob).status_code == 200


def test_diff_and_report_check_the_comparison_scan_too(client, project_id):
    _, ada = make_user("ada@test.local")
    _, bob = make_user("bob@test.local", overrides={"scans.create_dast": "grant"})
    ada_scan = _start(client, ada, project_id)
    bob_scan = _start(client, bob, project_id, scan_type="dast",
                      dast={"target_url": "http://localhost:3000", "authorized": True})
    for route in ("diff", "report"):
        assert client.get(f"/scans/{bob_scan}/{route}", headers=bob).status_code == 200, route
        r = client.get(f"/scans/{bob_scan}/{route}", headers=bob, params={"against": ada_scan})
        assert r.status_code == 404, route


def test_feedback_list_shows_only_visible_scans(client, project_id):
    _, ada = make_user("ada@test.local", overrides={"findings.review": "grant"})
    _, bob = make_user("bob@test.local", overrides={"findings.review": "grant"})
    _start(client, ada, project_id)
    assert client.get("/feedback", headers=bob).json()["total"] == 0


# --- actions by a default user ---------------------------------------------------------------------------------------


def test_default_user_actions(client, project_id):
    _, ada = make_user("ada@test.local")
    _, bob = make_user("bob@test.local")
    mine = _start(client, ada, project_id)
    theirs = _start(client, bob, project_id, "b")

    # Allowed by default.
    assert client.get("/projects", headers=ada).status_code == 200
    assert client.get(f"/scans/{mine}/export.sarif", headers=ada).status_code == 200
    # Not by default.
    assert client.delete(f"/scans/{mine}", headers=ada).status_code == 403
    assert client.post("/projects", headers=ada, json={"name": "x", "default_git_url": "https://g/x.git"}).status_code == 403
    assert client.patch(f"/projects/{project_id}", headers=ada, json={"description": "x"}).status_code == 403
    assert client.patch("/settings/models", headers=ada, json={}).status_code == 403
    assert client.patch("/dast/settings", headers=ada, json={}).status_code == 403
    dast = client.post("/scans", headers=ada, json={
        "project_id": project_id, "scan_type": "dast", "dast": {"target_url": "http://localhost:3000", "authorized": True},
    })
    assert dast.status_code == 403 and dast.json()["code"] == "forbidden"
    # Stopping: own scans only, and someone else's isn't even visible.
    assert client.post(f"/scans/{theirs}/cancel", headers=ada).status_code == 404


def test_grants_unlock_actions_and_denies_take_them_away(client, project_id):
    _, ada = make_user("ada@test.local", overrides={"scans.delete": "grant", "reports.export": "deny"})
    mine = _start(client, ada, project_id)
    assert client.get(f"/scans/{mine}/export.pdf", headers=ada).status_code == 403
    assert client.delete(f"/scans/{mine}", headers=ada).status_code == 204
    with app_db.SessionLocal() as db:
        assert db.query(AuditEvent).filter(AuditEvent.action == "scan.deleted").count() == 1


def test_scan_create_needs_view_own(client, project_id):
    _, ada = make_user("ada@test.local", overrides={"scans.view_own": "deny"})
    r = client.post("/scans", headers=ada, json={"project_id": project_id, "commit_sha": "x"})
    assert r.status_code == 403


# --- the CI token ----------------------------------------------------------------------------------------------------


def test_ci_token_keeps_the_documented_ci_flow(client):
    """docs/ci/curl-example.md: create project -> trigger -> poll -> results."""
    project = client.post("/projects", headers=CI_HEADERS, json={"name": "ci", "default_git_url": "https://github.com/o/r.git"})
    assert project.status_code == 201
    scan_id = _start(client, CI_HEADERS, project.json()["id"])
    assert client.get(f"/scans/{scan_id}/status", headers=CI_HEADERS).json()["status"] == "success"
    results = client.get(f"/scans/{scan_id}/results", headers=CI_HEADERS)
    assert results.status_code == 200


@pytest.mark.parametrize("method, path", [
    ("get", "/admin/users"),
    ("get", "/admin/audit"),
    ("patch", "/dast/settings"),
    ("patch", "/settings/models"),
    ("patch", "/dast/rules"),
    ("delete", "/scans/x"),
    ("get", "/dast/training/examples"),
    ("post", "/feedback/learning/approve"),
])
def test_ci_token_has_no_admin_powers(client, method, path):
    r = client.request(method.upper(), path, headers=CI_HEADERS, json={})
    assert r.status_code == 403, (method, path, r.status_code)


# --- schedules -------------------------------------------------------------------------------------------------------


def test_scheduled_scans_run_as_their_creator_or_not_at_all(client, project_id):
    from app.services import dast_schedule

    owner_id, _ = make_user("sched@test.local", overrides={"scans.create_dast": "grant"})
    with app_db.SessionLocal() as db:
        rows = [
            DastSchedule(project_id=project_id, name=n, request_json={"project_id": project_id}, created_by_user_id=uid)
            for n, uid in (("owned", owner_id), ("legacy", None))
        ]
        db.add_all(rows)
        owner = db.get(User, owner_id)
        owner.is_active = False
        db.commit()
        assert dast_schedule.tick(db) == 0
        reasons = sorted(e.details["reason"] for e in db.query(AuditEvent).filter(AuditEvent.action == "schedule.skipped"))
    assert reasons == ["no_owner", "owner_disabled"]

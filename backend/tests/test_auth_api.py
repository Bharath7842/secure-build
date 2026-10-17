"""HTTP tests for first-admin setup, sign-in, sessions, invite/reset links
and admin user management."""

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app import db as app_db
from app.auth import passwords, ratelimit
from app.config import settings
from app.db import init_db
from app.main import app
from app.models import AuditEvent, User

SETUP_TOKEN = "s" * 40
PW = "correct horse battery"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    init_db(f"sqlite:///{(tmp_path / 'auth.db').as_posix()}")
    monkeypatch.setattr(settings, "setup_token", SecretStr(SETUP_TOKEN))
    ratelimit.reset_all()
    yield TestClient(app)
    ratelimit.reset_all()


def _db():
    return app_db.SessionLocal()


def _bearer(token: str) -> dict:
    return {"Authorization": f"Session {token}"}


def _setup_admin(client, email="root@example.com") -> dict:
    r = client.post("/setup", json={"setup_token": SETUP_TOKEN, "email": email, "display_name": "Root", "password": PW})
    assert r.status_code == 201, r.text
    return _bearer(r.json()["token"])


def _invite_and_accept(client, admin: dict, email="ada@example.com", role="user", overrides=None) -> tuple[str, dict]:
    r = client.post("/admin/users", headers=admin, json={"email": email, "role": role, "overrides": overrides or {}})
    assert r.status_code == 201, r.text
    body = r.json()
    token = body["invite_url"].split("#t=", 1)[1]
    assert client.post("/auth/setup", json={"token": token, "password": PW}).status_code == 200
    login = client.post("/auth/login", json={"email": email, "password": PW})
    assert login.status_code == 200, login.text
    return body["user"]["id"], _bearer(login.json()["token"])


def _audit_actions() -> list[str]:
    with _db() as db:
        return [e.action for e in db.query(AuditEvent).order_by(AuditEvent.at).all()]


# --- first-admin setup ---


def test_setup_creates_the_first_admin_once(client):
    assert client.get("/setup/status").json() == {"open": True, "configured": True, "has_users": False}
    admin = _setup_admin(client)
    me = client.get("/auth/me", headers=admin).json()
    assert me["user"]["role"] == "admin"
    assert "users.manage" in me["permissions"] and "page.admin_users" in me["pages"]

    assert client.get("/setup/status").json()["open"] is False
    again = client.post("/setup", json={"setup_token": SETUP_TOKEN, "email": "x@example.com", "password": PW})
    assert again.status_code == 404
    assert "admin.bootstrap" in _audit_actions()


def test_setup_refuses_a_wrong_token(client):
    r = client.post("/setup", json={"setup_token": "w" * 40, "email": "root@example.com", "password": PW})
    assert r.status_code == 403
    assert r.json()["code"] == "invalid_setup_token"
    with _db() as db:
        assert db.query(User).count() == 0


@pytest.mark.parametrize("token", [None, "too-short"])
def test_setup_is_closed_without_a_usable_token(client, monkeypatch, token):
    monkeypatch.setattr(settings, "setup_token", SecretStr(token) if token else None)
    assert client.get("/setup/status").json()["open"] is False
    r = client.post("/setup", json={"setup_token": token or "", "email": "root@example.com", "password": PW})
    assert r.status_code == 503
    assert r.json()["code"] == "setup_not_configured"


def test_setup_applies_the_password_policy(client):
    r = client.post("/setup", json={"setup_token": SETUP_TOKEN, "email": "root@example.com", "password": "short"})
    assert r.status_code == 400
    assert r.json()["code"] == "weak_password"
    assert client.get("/setup/status").json()["open"] is True


# --- sign-in ---


def test_unknown_email_and_wrong_password_look_identical(client):
    _setup_admin(client)
    unknown = client.post("/auth/login", json={"email": "nobody@example.com", "password": PW})
    wrong = client.post("/auth/login", json={"email": "root@example.com", "password": "wrong password!"})
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json() == wrong.json() == {"detail": "Invalid email or password", "code": "invalid_credentials"}


def test_login_is_case_insensitive_and_returns_landing(client):
    _setup_admin(client)
    r = client.post("/auth/login", json={"email": "  ROOT@Example.com ", "password": PW, "remember": True})
    assert r.status_code == 200
    body = r.json()
    assert body["remember"] is True and body["landing"] == "/projects"
    assert "password_hash" not in body["user"]


def test_repeated_failures_pause_the_account(client):
    _setup_admin(client)
    for _ in range(5):
        assert client.post("/auth/login", json={"email": "root@example.com", "password": "nope nope nope"}).status_code == 401
    blocked = client.post("/auth/login", json={"email": "root@example.com", "password": PW})
    assert blocked.status_code == 429
    assert blocked.json()["code"] == "too_many_attempts"
    assert int(blocked.headers["Retry-After"]) > 0


def test_one_address_is_limited_across_accounts(client):
    for i in range(30):
        client.post("/auth/login", json={"email": f"u{i}@example.com", "password": PW})
    assert client.post("/auth/login", json={"email": "other@example.com", "password": PW}).status_code == 429


def test_forwarded_client_ip_needs_the_frontend_key(client, monkeypatch):
    monkeypatch.setattr(settings, "frontend_proxy_secret", SecretStr("k" * 32))
    # A spoofed X-Client-IP without the key still counts against the real address.
    for i in range(30):
        client.post("/auth/login", json={"email": f"u{i}@example.com", "password": PW}, headers={"X-Client-IP": f"10.0.0.{i}"})
    assert client.post("/auth/login", json={"email": "z@example.com", "password": PW}).status_code == 429
    # With the key, the forwarded address is what's counted.
    ok = client.post(
        "/auth/login",
        json={"email": "z@example.com", "password": PW},
        headers={"X-Client-IP": "10.9.9.9", "X-Frontend-Key": "k" * 32},
    )
    assert ok.status_code == 401


def test_logout_revokes_the_session(client):
    admin = _setup_admin(client)
    assert client.post("/auth/logout", headers=admin).status_code == 204
    r = client.get("/auth/me", headers=admin)
    assert r.status_code == 401
    assert r.json() == {"detail": "Authentication required", "code": "unauthenticated"}


def test_me_needs_a_user_session(client):
    assert client.get("/auth/me").status_code == 401
    assert client.get("/auth/me", headers={"Authorization": "Session made-up"}).status_code == 401
    ci = client.get("/auth/me", headers={"Authorization": f"Bearer {settings.sast_api_token}"})
    assert ci.status_code == 403


# --- invites, resets, password changes ---


def test_invited_user_cannot_sign_in_until_accepting(client):
    admin = _setup_admin(client)
    r = client.post("/admin/users", headers=admin, json={"email": "ada@example.com"})
    assert r.status_code == 201
    body = r.json()
    assert body["user"]["status"] == "invited"
    assert body["invite_url"].startswith(f"{settings.public_app_url}/account/setup#t=")
    assert client.post("/auth/login", json={"email": "ada@example.com", "password": PW}).status_code == 401

    token = body["invite_url"].split("#t=", 1)[1]
    weak = client.post("/auth/setup", json={"token": token, "password": "short"})
    assert weak.status_code == 400  # link still usable after a rejected password
    assert client.post("/auth/setup", json={"token": token, "password": PW}).status_code == 200
    assert client.post("/auth/setup", json={"token": token, "password": PW}).json()["code"] == "invalid_or_expired_token"
    assert client.post("/auth/login", json={"email": "ada@example.com", "password": PW}).status_code == 200


def test_link_preview_names_the_account_without_using_the_link_up(client):
    admin = _setup_admin(client)
    r = client.post("/admin/users", headers=admin, json={"email": "ada@example.com", "role": "user", "overrides": {}})
    token = r.json()["invite_url"].split("#t=", 1)[1]
    for _ in range(2):  # previewing twice proves nothing was consumed
        p = client.post("/auth/setup/preview", json={"token": token})
        assert p.status_code == 200 and p.json() == {"email": "ada@example.com", "purpose": "invite"}
    assert client.post("/auth/setup", json={"token": token, "password": PW}).status_code == 200
    # Used up: the preview now refuses it, like any bad token.
    used = client.post("/auth/setup/preview", json={"token": token})
    assert used.status_code == 400 and used.json()["code"] == "invalid_or_expired_token"
    assert client.post("/auth/setup/preview", json={"token": "nope"}).status_code == 400


def test_reset_link_signs_the_user_out_everywhere(client):
    admin = _setup_admin(client)
    user_id, ada = _invite_and_accept(client, admin)
    link = client.post(f"/admin/users/{user_id}/reset-link", headers=admin).json()["url"]
    assert client.get("/auth/me", headers=ada).status_code == 200  # issuing alone changes nothing
    new_pw = "a different long phrase"
    assert client.post("/auth/setup", json={"token": link.split("#t=")[1], "password": new_pw}).status_code == 200
    assert client.get("/auth/me", headers=ada).status_code == 401
    assert client.post("/auth/login", json={"email": "ada@example.com", "password": new_pw}).status_code == 200


def test_change_password_keeps_this_session_only(client):
    admin = _setup_admin(client)
    _, ada = _invite_and_accept(client, admin)
    other = _bearer(client.post("/auth/login", json={"email": "ada@example.com", "password": PW}).json()["token"])

    wrong = client.post("/auth/password", headers=ada, json={"current_password": "nope", "new_password": "another long phrase"})
    assert wrong.json()["code"] == "wrong_current_password"

    r = client.post("/auth/password", headers=ada, json={"current_password": PW, "new_password": "another long phrase"})
    assert r.status_code == 200
    rotated = _bearer(r.json()["token"])
    assert client.get("/auth/me", headers=rotated).status_code == 200
    assert client.get("/auth/me", headers=ada).status_code == 401  # old token of this session
    assert client.get("/auth/me", headers=other).status_code == 401


def test_sessions_list_and_revoke_others(client):
    admin = _setup_admin(client)
    second = _bearer(client.post("/auth/login", json={"email": "root@example.com", "password": PW}).json()["token"])
    listed = client.get("/auth/sessions", headers=admin).json()
    assert len(listed) == 2 and sum(s["current"] for s in listed) == 1
    assert client.post("/auth/sessions/revoke-others", headers=admin).json() == {"revoked": 1}
    assert client.get("/auth/me", headers=second).status_code == 401


# --- admin user management ---


def test_regular_users_cannot_reach_admin_routes(client):
    admin = _setup_admin(client)
    user_id, ada = _invite_and_accept(client, admin)
    for method, path in [
        ("get", "/admin/users"),
        ("post", "/admin/users"),
        ("get", f"/admin/users/{user_id}"),
        ("patch", f"/admin/users/{user_id}"),
        ("put", f"/admin/users/{user_id}/permissions"),
        ("get", "/admin/audit"),
        ("get", "/admin/permissions/catalog"),
    ]:
        r = getattr(client, method)(path, headers=ada, **({"json": {}} if method in ("post", "patch", "put") else {}))
        assert r.status_code == 403, (method, path)
        assert r.json()["code"] == "forbidden"
    ci = {"Authorization": f"Bearer {settings.sast_api_token}"}
    assert client.get("/admin/users", headers=ci).status_code == 403


def test_duplicate_email_is_refused(client):
    admin = _setup_admin(client)
    assert client.post("/admin/users", headers=admin, json={"email": "Root@Example.com"}).json()["code"] == "email_taken"


def test_list_users_filters(client):
    admin = _setup_admin(client)
    _invite_and_accept(client, admin, "ada@example.com")
    client.post("/admin/users", headers=admin, json={"email": "bob@example.com", "display_name": "Bob"})
    statuses = {u["email"]: u["status"] for u in client.get("/admin/users", headers=admin).json()["items"]}
    assert statuses == {"root@example.com": "active", "ada@example.com": "active", "bob@example.com": "invited"}
    assert [u["email"] for u in client.get("/admin/users?status=invited", headers=admin).json()["items"]] == ["bob@example.com"]
    assert [u["email"] for u in client.get("/admin/users?q=bob", headers=admin).json()["items"]] == ["bob@example.com"]
    assert [u["email"] for u in client.get("/admin/users?role=admin", headers=admin).json()["items"]] == ["root@example.com"]


def test_permission_changes_apply_on_the_next_request(client):
    admin = _setup_admin(client)
    user_id, ada = _invite_and_accept(client, admin)
    assert "page.feedback" not in client.get("/auth/me", headers=ada).json()["pages"]

    r = client.put(f"/admin/users/{user_id}/permissions", headers=admin,
                   json={"overrides": {"page.feedback": "grant", "reports.export": "deny"}})
    assert r.status_code == 200, r.text
    assert r.json()["added_dependencies"] == ["findings.review"]
    me = client.get("/auth/me", headers=ada).json()
    assert "page.feedback" in me["pages"] and "findings.review" in me["permissions"]
    assert "reports.export" not in me["permissions"]

    bad = client.put(f"/admin/users/{user_id}/permissions", headers=admin, json={"overrides": {"users.manage": "grant"}})
    assert bad.status_code == 400 and bad.json()["code"] == "invalid_permissions"
    assert "user.permissions.changed" in _audit_actions()


def test_disabling_signs_the_user_out_and_blocks_login(client):
    admin = _setup_admin(client)
    user_id, ada = _invite_and_accept(client, admin)
    assert client.patch(f"/admin/users/{user_id}", headers=admin, json={"is_active": False}).json()["user"]["status"] == "disabled"
    assert client.get("/auth/me", headers=ada).status_code == 401
    login = client.post("/auth/login", json={"email": "ada@example.com", "password": PW})
    assert login.status_code == 401 and login.json()["code"] == "invalid_credentials"
    client.patch(f"/admin/users/{user_id}", headers=admin, json={"is_active": True})
    assert client.post("/auth/login", json={"email": "ada@example.com", "password": PW}).status_code == 200


def test_admin_deletes_only_disabled_users_and_keeps_their_scans(client):
    from app.models import Project, Scan, UserSession

    admin = _setup_admin(client)
    me_id = client.get("/auth/me", headers=admin).json()["user"]["id"]
    user_id, ada = _invite_and_accept(client, admin)
    with _db() as db:
        project = Project(name="p", default_git_url="https://example.com/r.git")
        db.add(project)
        db.flush()
        scan = Scan(project_id=project.id, git_url=project.default_git_url, created_by_user_id=user_id)
        db.add(scan)
        db.commit()
        scan_id = scan.id

    assert client.delete(f"/admin/users/{user_id}", headers=admin).json()["code"] == "not_disabled"
    assert client.delete(f"/admin/users/{me_id}", headers=admin).json()["code"] == "cannot_delete_self"
    assert client.delete("/admin/users/nope", headers=admin).status_code == 404

    client.patch(f"/admin/users/{user_id}", headers=admin, json={"is_active": False})
    assert client.delete(f"/admin/users/{user_id}", headers=admin).status_code == 204
    assert client.get(f"/admin/users/{user_id}", headers=admin).status_code == 404
    assert client.post("/auth/login", json={"email": "ada@example.com", "password": PW}).status_code == 401
    with _db() as db:
        kept = db.get(Scan, scan_id)
        assert kept.created_by_user_id is None and kept.deleted_creator_email == "ada@example.com"
        assert db.query(UserSession).filter(UserSession.user_id == user_id).count() == 0
    listed = next(x for x in client.get("/scans", headers=admin).json() if x["id"] == scan_id)
    assert listed["created_by_deleted"] is True and listed["created_by_email"] == "ada@example.com"
    events = client.get("/admin/audit", headers=admin).json()
    assert "user.deleted" in {e["action"] for e in events["items"]}

    # A regular user can't delete anyone.
    other_id, other = _invite_and_accept(client, admin, "other@example.com")
    assert client.delete(f"/admin/users/{other_id}", headers=other).status_code == 403


def test_last_admin_cannot_be_demoted_or_disabled(client):
    admin = _setup_admin(client)
    me_id = client.get("/auth/me", headers=admin).json()["user"]["id"]
    assert client.patch(f"/admin/users/{me_id}", headers=admin, json={"is_active": False}).json()["code"] == "cannot_disable_self"
    assert client.patch(f"/admin/users/{me_id}", headers=admin, json={"role": "user"}).json()["code"] == "cannot_change_own_role"

    second_id, second = _invite_and_accept(client, admin, "second@example.com", role="admin")
    # With two admins, either may demote the other ...
    assert client.patch(f"/admin/users/{second_id}", headers=admin, json={"role": "user"}).status_code == 200
    assert client.get("/auth/me", headers=second).status_code == 401  # demotion signs them out
    # ... but not the last one left.
    client.patch(f"/admin/users/{second_id}", headers=admin, json={"role": "admin"})
    second = _bearer(client.post("/auth/login", json={"email": "second@example.com", "password": PW}).json()["token"])
    client.patch(f"/admin/users/{me_id}", headers=second, json={"is_active": False})
    r = client.patch(f"/admin/users/{second_id}", headers=second, json={"role": "user"})
    assert r.json()["code"] == "cannot_change_own_role"
    with _db() as db:
        assert db.query(User).filter(User.role == "admin", User.is_active.is_(True)).count() == 1


def test_admins_demoting_each_other_at_once_leave_one_admin(client):
    """The second of two crossing demotions runs with a principal resolved
    before the first one landed; it must be refused, not obeyed."""
    from starlette.requests import Request

    from app.auth.principal import Principal
    from app.auth.schemas import UserUpdateIn
    from app.authz.catalog import ALL_KEYS
    from app.routers import admin_users

    admin = _setup_admin(client)
    root_id = client.get("/auth/me", headers=admin).json()["user"]["id"]
    second_id, _ = _invite_and_accept(client, admin, "second@example.com", role="admin")
    stale_second = Principal(kind="user", permissions=ALL_KEYS, user_id=second_id, email="second@example.com", role="admin")

    request = Request({"type": "http", "method": "PATCH", "headers": [], "client": ("127.0.0.1", 1)})
    with _db() as db, pytest.raises(admin_users.ApiError) as exc:
        # Second's own row was loaded into this session while they were still admin
        # (as authentication does; keep a reference so it stays in the identity map) ...
        cached = db.get(User, second_id)
        assert cached.role == "admin"
        # ... then root's demotion of them lands ...
        assert client.patch(f"/admin/users/{second_id}", headers=admin, json={"role": "user"}).status_code == 200
        # ... and their in-flight demotion of root must see that.
        admin_users.update_user(root_id, UserUpdateIn(role="user"), request, stale_second, db)
    assert exc.value.status_code == 403
    with _db() as db:
        assert db.get(User, root_id).role == "admin"


def test_permissions_for_admins_are_refused(client):
    admin = _setup_admin(client)
    me_id = client.get("/auth/me", headers=admin).json()["user"]["id"]
    r = client.put(f"/admin/users/{me_id}/permissions", headers=admin, json={"overrides": {}})
    assert r.json()["code"] == "admin_has_full_access"


def test_invite_and_reset_links_follow_status(client):
    admin = _setup_admin(client)
    invited_id = client.post("/admin/users", headers=admin, json={"email": "bob@example.com"}).json()["user"]["id"]
    active_id, _ = _invite_and_accept(client, admin)
    assert client.post(f"/admin/users/{invited_id}/invite-link", headers=admin).status_code == 200
    assert client.post(f"/admin/users/{invited_id}/reset-link", headers=admin).json()["code"] == "not_active"
    assert client.post(f"/admin/users/{active_id}/invite-link", headers=admin).json()["code"] == "not_invited"
    assert client.post(f"/admin/users/{active_id}/reset-link", headers=admin).status_code == 200


def test_user_detail_shows_access_and_activity(client):
    admin = _setup_admin(client)
    user_id, _ = _invite_and_accept(client, admin, overrides={"scans.view_own": "deny"})
    detail = client.get(f"/admin/users/{user_id}", headers=admin).json()
    assert detail["overrides"] == {"scans.view_own": "deny"}
    assert "scans.create" not in detail["effective"]
    assert {"key": "scans.create", "missing": ["scans.view_own"]} in detail["inactive"]
    assert {"user.created", "user.invite.accepted", "auth.login.succeeded"} <= {e["action"] for e in detail["recent_activity"]}


def test_audit_log_filters_and_never_holds_secrets(client):
    admin = _setup_admin(client)
    _invite_and_accept(client, admin)
    client.post("/auth/login", json={"email": "ada@example.com", "password": "wrong wrong wrong"})

    failed = client.get("/admin/audit?action=auth.login.failed", headers=admin).json()["items"]
    assert len(failed) == 1 and failed[0]["details"] == {"reason": "wrong_password"}
    logins = client.get("/admin/audit?action=auth.", headers=admin).json()["items"]
    assert {e["action"] for e in logins} == {"auth.login.succeeded", "auth.login.failed"}
    assert client.get("/admin/audit?actor=ada@&limit=1", headers=admin).json()["next_cursor"] == 1

    with _db() as db:
        dumped = repr([(e.details, e.actor_label) for e in db.query(AuditEvent).all()])
    assert PW not in dumped and "#t=" not in dumped and SETUP_TOKEN not in dumped


def test_link_expiry_is_sent_as_utc(client):
    """A naive timestamp would be read as local time by the browser and show
    the wrong expiry (e.g. 66 instead of 72 hours at UTC+5:30)."""
    admin = _setup_admin(client)
    created = client.post("/admin/users", headers=admin, json={"email": "tz@example.com"}).json()
    assert created["invite_expires_at"].endswith(("Z", "+00:00"))
    link = client.post(f"/admin/users/{created['user']['id']}/invite-link", headers=admin).json()
    assert link["expires_at"].endswith(("Z", "+00:00"))


def test_users_see_and_change_only_the_projects_they_created(client):
    admin = _setup_admin(client)
    _, ada = _invite_and_accept(client, admin, "ada@example.com")
    _, bob = _invite_and_accept(client, admin, "bob@example.com")
    body = {"name": "ada-proj", "default_git_url": "https://github.com/o/a.git"}
    ada_proj = client.post("/projects", headers=ada, json=body)
    assert ada_proj.status_code == 201, ada_proj.text
    pid = ada_proj.json()["id"]
    client.post("/projects", headers=admin, json={"name": "admin-proj", "default_git_url": "https://github.com/o/b.git"})

    names = lambda h: sorted(p["name"] for p in client.get("/projects", headers=h).json())
    assert names(ada) == ["ada-proj"]
    assert names(bob) == []
    assert names(admin) == ["ada-proj", "admin-proj"]

    # Bob can't open, edit or scan Ada's project; the answer is the same as for a missing one.
    assert client.get(f"/projects/{pid}", headers=bob).status_code == 404
    assert client.patch(f"/projects/{pid}", headers=bob, json={"name": "hijack"}).status_code == 404
    assert client.get(f"/projects/{pid}", headers=ada).status_code == 200
    assert client.get(f"/projects/{pid}", headers=admin).status_code == 200

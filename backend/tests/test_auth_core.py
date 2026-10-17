"""Accounts core: password policy and hashing, sessions, account tokens, the
permission catalog and audit scrubbing. No HTTP here (see the auth API tests)."""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError

from app.auth import passwords, sessions
from app.authz import catalog
from app.config import settings
from app.db import init_db
from app.models import AuditEvent, User, UserPermissionOverride
from app.services import audit

T0 = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)


@pytest.fixture()
def db(tmp_path):
    SessionLocal = init_db(f"sqlite:///{(tmp_path / 'auth.db').as_posix()}")
    with SessionLocal() as session:
        yield session


def _user(db, email="Ada@Example.com", role="user", password="correct horse battery") -> User:
    user = User(
        email=email,
        email_normalized=passwords.normalize_email(email),
        role=role,
        password_hash=passwords.hash_password(password) if password else None,
    )
    db.add(user)
    db.commit()
    return user


# --- passwords ---


def test_normalize_email_folds_case_width_and_whitespace():
    assert passwords.normalize_email("  Ada@Example.COM ") == "ada@example.com"
    assert passwords.normalize_email("ａｄａ@example.com") == "ada@example.com"  # full-width


@pytest.mark.parametrize(
    "password, problem",
    [
        ("short", "at least"),
        ("x" * 129, "at most"),
        ("Password1234", "too common"),
        ("aaaaaaaaaaaaaaaa", "too common"),
        ("ada@example.com", "email"),
        ("a perfectly fine phrase", None),
    ],
)
def test_password_policy(password, problem):
    result = passwords.password_problem(password, email="Ada@Example.com")
    if problem is None:
        assert result is None
    else:
        assert problem in result


def test_hash_and_verify():
    hashed = passwords.hash_password("correct horse battery")
    assert hashed.startswith("$argon2id$")
    assert passwords.verify_password("correct horse battery", hashed)[0] is True
    assert passwords.verify_password("wrong horse battery", hashed)[0] is False
    assert passwords.verify_password("anything", None) == (False, None)


def test_email_normalized_is_unique(db):
    _user(db, "ada@example.com")
    with pytest.raises(IntegrityError):
        _user(db, "ADA@example.com")


def test_role_is_constrained(db):
    with pytest.raises(IntegrityError):
        _user(db, role="superuser")


def test_user_status(db):
    assert _user(db, "a@x.io").status == "active"
    invited = _user(db, "b@x.io", password=None)
    assert invited.status == "invited"
    invited.is_active = False
    assert invited.status == "disabled"


# --- sessions ---


def test_session_round_trip_stores_only_a_hash(db):
    user = _user(db)
    token, row = sessions.create_session(db, user, now=T0)
    assert row.token_hash == sessions.hash_token(token) != token
    assert sessions.resolve_session(db, token, now=T0 + timedelta(minutes=1)).id == row.id
    assert sessions.resolve_session(db, "not-a-token", now=T0) is None
    assert sessions.resolve_session(db, None) is None


def test_session_idle_timeout_slides_with_use(db, monkeypatch):
    monkeypatch.setattr(settings, "session_idle_minutes", 30)  # well inside the absolute limit
    user = _user(db)
    token, _ = sessions.create_session(db, user, now=T0)
    idle = timedelta(minutes=settings.session_idle_minutes)
    # Used just before the idle limit: the window moves forward.
    t1 = T0 + idle - timedelta(minutes=1)
    assert sessions.resolve_session(db, token, now=t1) is not None
    assert sessions.resolve_session(db, token, now=t1 + idle - timedelta(minutes=1)) is not None
    # Then left alone past the idle limit.
    assert sessions.resolve_session(db, token, now=t1 + idle * 3) is None


def test_session_absolute_limit_wins_over_activity(db):
    user = _user(db)
    token, _ = sessions.create_session(db, user, now=T0)
    t = T0
    end = T0 + timedelta(hours=settings.session_absolute_hours)
    while t + timedelta(minutes=30) < end:
        t += timedelta(minutes=30)
        assert sessions.resolve_session(db, token, now=t) is not None
    assert sessions.resolve_session(db, token, now=end) is None


def test_remember_me_session_has_no_idle_timeout(db):
    user = _user(db)
    token, row = sessions.create_session(db, user, remember=True, now=T0)
    assert row.idle_expires_at is None
    assert sessions.resolve_session(db, token, now=T0 + timedelta(days=3)) is not None
    assert sessions.resolve_session(db, token, now=T0 + timedelta(days=settings.session_remember_days)) is None


def test_revoked_and_disabled_sessions_stop_working(db):
    user = _user(db)
    token_a, row_a = sessions.create_session(db, user, now=T0)
    token_b, row_b = sessions.create_session(db, user, now=T0)
    token_c, _ = sessions.create_session(db, user, now=T0)

    sessions.revoke_session(db, row_a, "logout", now=T0)
    assert sessions.resolve_session(db, token_a, now=T0) is None

    assert sessions.revoke_user_sessions(db, user.id, "password_changed", except_session_id=row_b.id, now=T0) == 1
    assert sessions.resolve_session(db, token_b, now=T0) is not None
    assert sessions.resolve_session(db, token_c, now=T0) is None

    user.is_active = False
    db.commit()
    assert sessions.resolve_session(db, token_b, now=T0) is None


def test_rotate_session_retires_the_old_token(db):
    user = _user(db)
    old, row = sessions.create_session(db, user, now=T0)
    new = sessions.rotate_session(db, row)
    assert sessions.resolve_session(db, old, now=T0) is None
    assert sessions.resolve_session(db, new, now=T0).id == row.id


def test_purge_expired_sessions(db):
    user = _user(db)
    sessions.create_session(db, user, now=T0)
    live, _ = sessions.create_session(db, user, now=T0 + timedelta(days=2))
    assert sessions.purge_expired_sessions(db, now=T0 + timedelta(days=2)) == 1
    assert sessions.resolve_session(db, live, now=T0 + timedelta(days=2)) is not None


# --- invite / reset tokens ---


def test_user_token_is_single_use_and_expires(db):
    user = _user(db, password=None)
    token, _ = sessions.issue_user_token(db, user, "invite", now=T0)
    assert sessions.consume_user_token(db, token, now=T0 + timedelta(hours=1)) is not None
    db.commit()
    assert sessions.consume_user_token(db, token, now=T0 + timedelta(hours=1)) is None

    late, _ = sessions.issue_user_token(db, user, "reset", now=T0)
    assert sessions.consume_user_token(db, late, now=T0 + timedelta(hours=settings.reset_ttl_hours)) is None


def test_new_token_retires_the_previous_one(db):
    user = _user(db, password=None)
    first, _ = sessions.issue_user_token(db, user, "invite", now=T0)
    second, _ = sessions.issue_user_token(db, user, "invite", now=T0)
    assert sessions.consume_user_token(db, first, now=T0) is None
    assert sessions.consume_user_token(db, second, now=T0) is not None


def test_unknown_token_purpose_is_rejected(db):
    with pytest.raises(ValueError):
        sessions.issue_user_token(db, _user(db), "login")


# --- permission catalog ---


def test_catalog_entries_are_well_formed():
    keys = [p.key for p in catalog.PERMISSIONS]
    assert len(keys) == len(set(keys))
    for p in catalog.PERMISSIONS:
        assert p.kind in ("page", "action")
        assert p.label and p.description
        assert p.key.startswith("page.") == (p.kind == "page")
        assert set(p.requires) <= catalog.ALL_KEYS, p.key
        # A key a user holds by default can't depend on something they can't have.
        if p.user_default:
            assert p.grantable_to_user
            assert all(catalog.BY_KEY[r].grantable_to_user for r in p.requires), p.key


def test_admin_only_keys_cannot_reach_a_user():
    admin_only = {"users.manage", "audit.view", "settings.manage", "dast.training", "page.settings"}
    assert admin_only <= {p.key for p in catalog.PERMISSIONS if not p.grantable_to_user}
    grants = {k: "grant" for k in admin_only}
    assert not admin_only & catalog.effective_permissions("user", grants)
    with pytest.raises(ValueError, match="admin-only"):
        catalog.validate_overrides({"users.manage": "grant"})


def test_admin_holds_everything_regardless_of_overrides():
    assert catalog.effective_permissions("admin", {"scans.view_all": "deny"}) == catalog.ALL_KEYS


def test_unknown_role_holds_nothing():
    assert catalog.effective_permissions("superuser") == frozenset()


def test_user_defaults():
    held = catalog.effective_permissions("user")
    assert {"projects.view", "projects.manage", "scans.view_own", "scans.create", "reports.export", "page.history"} <= held
    assert not {"scans.view_all", "projects.view_all", "scans.delete", "scans.create_dast", "page.dast"} & held


def test_grant_adds_and_deny_wins():
    held = catalog.effective_permissions("user", {"scans.view_all": "grant", "reports.export": "deny"})
    assert "scans.view_all" in held
    assert "reports.export" not in held


def test_unmet_requirements_drop_dependents():
    # Denying view_own takes away everything that needs it.
    held = catalog.effective_permissions("user", {"scans.view_own": "deny"})
    assert not {"scans.create", "page.history", "page.scan_sast", "reports.export"} & held
    assert "projects.view" in held
    inactive = catalog.inactive_permissions("user", {"scans.view_own": "deny"})
    assert inactive["scans.create"] == ["scans.view_own"]
    assert inactive["page.scan_sast"] == ["scans.create"]


def test_with_requirements_adds_missing_grants():
    overrides, added = catalog.with_requirements({"page.feedback": "grant"})
    assert overrides == {"page.feedback": "grant", "findings.review": "grant"}
    assert added == ["findings.review"]
    assert "page.feedback" in catalog.effective_permissions("user", overrides)


def test_with_requirements_respects_an_explicit_deny():
    overrides, added = catalog.with_requirements({"page.feedback": "grant", "findings.review": "deny"})
    assert added == []
    assert "page.feedback" not in catalog.effective_permissions("user", overrides)


def test_validate_overrides_rejects_unknown_keys_and_effects():
    with pytest.raises(ValueError, match="Unknown permission"):
        catalog.validate_overrides({"scans.fly": "grant"})
    with pytest.raises(ValueError, match="grant' or 'deny"):
        catalog.validate_overrides({"scans.view_all": "allow"})
    catalog.validate_overrides({"scans.view_all": "grant", "reports.export": "deny"})


def test_ci_service_permissions_are_catalog_keys_without_admin_powers():
    assert catalog.CI_SERVICE_PERMISSIONS <= catalog.ALL_KEYS
    assert not {"users.manage", "audit.view", "settings.manage", "scans.delete"} & catalog.CI_SERVICE_PERMISSIONS


def test_one_override_row_per_user_and_key(db):
    user = _user(db)
    db.add(UserPermissionOverride(user_id=user.id, permission_key="scans.view_all", effect="grant"))
    db.commit()
    db.add(UserPermissionOverride(user_id=user.id, permission_key="scans.view_all", effect="deny"))
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()
    assert user.overrides == {"scans.view_all": "grant"}


# --- audit ---


def test_audit_scrubs_secret_keys_at_any_depth(db):
    event = audit.record(
        db,
        "user.created",
        actor_label="admin@example.com",
        details={
            "role": "user",
            "password": "hunter2hunter2",
            "nested": {"invite_token": "abc", "api_key": "k", "Authorization": "Bearer x", "kept": 1},
            "items": [{"session_id": "s", "email": "e@x.io"}],
        },
    )
    assert event.details == {"role": "user", "nested": {"kept": 1}, "items": [{"email": "e@x.io"}]}


def test_purge_old_audit_events(db):
    old = audit.record(db, "auth.login.succeeded")
    old.at = datetime.now(timezone.utc) - timedelta(days=settings.audit_retention_days + 1)
    db.commit()
    audit.record(db, "auth.login.succeeded")
    assert audit.purge_old_events(db) == 1
    assert db.query(AuditEvent).count() == 1


# --- migrations ---


def test_existing_db_gains_owner_columns(tmp_path):
    import sqlite3

    path = tmp_path / "old.db"
    # Tables as they were before accounts existed (only the columns that matter here).
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE scans (id VARCHAR(36) PRIMARY KEY, project_id VARCHAR(36), created_at DATETIME)")
        conn.execute("CREATE TABLE dast_schedules (id VARCHAR(36) PRIMARY KEY, project_id VARCHAR(36))")

    engine = init_db(f"sqlite:///{path.as_posix()}").kw["bind"]
    insp = inspect(engine)
    assert "created_by_user_id" in {c["name"] for c in insp.get_columns("scans")}
    assert "ix_scans_created_by_user_id" in {i["name"] for i in insp.get_indexes("scans")}
    assert "created_by_user_id" in {c["name"] for c in insp.get_columns("dast_schedules")}
    with engine.connect() as conn:
        assert conn.execute(text("PRAGMA journal_mode")).scalar() == "wal"

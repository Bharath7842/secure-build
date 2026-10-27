"""Schema additions for DAST evidence and audit (DAST-00-040)."""

import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect, text

from app.config import settings
from app.db import init_db
from app.main import app
from app.models import (
    DAST_SETTINGS_SNAPSHOT_KEY,
    DastEvidence,
    DastRequestAudit,
    Finding,
    Project,
    Scan,
)

pytestmark = pytest.mark.integration

LEGACY_SQL = Path(__file__).parent / "fixtures" / "pre_dast_schema.sql"
from tests.auth_helpers import ADMIN_HEADERS  # noqa: E402

HDR = ADMIN_HEADERS

NEW_FINDING_COLUMNS = {
    "target", "param", "location", "confidence_label", "remediation_ref",
    "standards", "first_seen_scan_id", "last_seen_scan_id",
}


def _legacy_db(tmp_path) -> str:
    path = tmp_path / "legacy.db"
    conn = sqlite3.connect(path)
    conn.executescript(LEGACY_SQL.read_text())
    conn.commit()
    conn.close()
    return f"sqlite:///{path.as_posix()}"


def _schema_fingerprint(url: str):
    conn = sqlite3.connect(url.removeprefix("sqlite:///"))
    try:
        objects = conn.execute("SELECT type, name, sql FROM sqlite_master ORDER BY type, name").fetchall()
        columns = {
            table: conn.execute(f"PRAGMA table_info({table})").fetchall()
            for (kind, table, _) in objects
            if kind == "table"
        }
        return objects, columns
    finally:
        conn.close()


def test_fixture_really_is_the_pre_change_schema(tmp_path):
    conn = sqlite3.connect(_legacy_db(tmp_path).removeprefix("sqlite:///"))
    cols = {row[1] for row in conn.execute("PRAGMA table_info(findings)")}
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert not (NEW_FINDING_COLUMNS & cols)
    assert not ({"dast_evidence", "dast_request_audit"} & tables)


def test_migration_upgrades_a_pre_change_database(tmp_path):
    url = _legacy_db(tmp_path)
    SessionLocal = init_db(url)

    from app.db import engine

    inspector = inspect(engine)
    finding_cols = {c["name"] for c in inspector.get_columns("findings")}
    assert NEW_FINDING_COLUMNS <= finding_cols
    assert "confidence" in finding_cols  # float column untouched
    assert {"dast_evidence", "dast_request_audit"} <= set(inspector.get_table_names())

    # Existing SAST rows survive, with every new column empty.
    with SessionLocal() as db:
        legacy = db.get(Finding, "f1")
        assert legacy.title == "Legacy SAST finding"
        assert legacy.verdict == "true_positive"
        assert legacy.confidence == 0.9
        for name in NEW_FINDING_COLUMNS:
            assert getattr(legacy, name) is None, name
        assert db.query(Scan).count() == 1 and db.query(Project).count() == 1


def test_running_the_migration_twice_changes_nothing(tmp_path):
    url = _legacy_db(tmp_path)
    init_db(url)
    first = _schema_fingerprint(url)
    SessionLocal = init_db(url)
    second = _schema_fingerprint(url)

    assert first == second
    with SessionLocal() as db:
        assert db.query(Finding).count() == 1


def test_fresh_database_gets_the_same_schema_as_a_migrated_one(tmp_path):
    migrated = _legacy_db(tmp_path)
    init_db(migrated)
    fresh = f"sqlite:///{(tmp_path / 'fresh.db').as_posix()}"
    init_db(fresh)

    def finding_cols(url):
        conn = sqlite3.connect(url.removeprefix("sqlite:///"))
        return {row[1] for row in conn.execute("PRAGMA table_info(findings)")}

    assert finding_cols(migrated) == finding_cols(fresh)


def test_audit_and_evidence_are_indexed(tmp_path):
    init_db(f"sqlite:///{(tmp_path / 'idx.db').as_posix()}")
    from app.db import engine

    inspector = inspect(engine)
    audit_ix = {tuple(ix["column_names"]): ix for ix in inspector.get_indexes("dast_request_audit")}
    assert ("scan_id", "seq") in audit_ix
    assert audit_ix[("scan_id", "seq")]["unique"]
    assert ("finding_id",) in {tuple(ix["column_names"]) for ix in inspector.get_indexes("dast_evidence")}


def _seed_dast_scan(db) -> tuple[str, str]:
    project = Project(name="dast-schema", default_git_url="https://example.test/r.git")
    db.add(project)
    db.flush()
    scan = Scan(
        project_id=project.id, git_url="http://target.test", branch="main",
        status="success", scan_type="dast", metadata_json={},
    )
    db.add(scan)
    db.flush()
    finding = Finding(
        scan_id=scan.id, severity="HIGH", title="SQL injection in login", rule_id="dast-sqli",
        kind="dast", verdict="true_positive", confidence=0.9,
        target="POST /api/login", param="username", location="body", confidence_label="HIGH",
        remediation_ref="rem-sqli", standards=["OWASP A03:2021", "CWE-89"],
        first_seen_scan_id=scan.id, last_seen_scan_id=scan.id,
    )
    db.add(finding)
    db.flush()
    db.add(
        DastEvidence(
            finding_id=finding.id, baseline_excerpt='{"ok":true}', test_excerpt="SQLSyntaxErrorException",
            signals=[{"name": "sql_error_text", "detail": "near '--'"}], audit_ref="2",
        )
    )
    db.add_all(
        [
            DastRequestAudit(scan_id=scan.id, seq=1, method="POST", url="http://target.test/api/login",
                             identity_label="admin", allowed=True, response_status=200, check_id=None),
            DastRequestAudit(scan_id=scan.id, seq=2, method="POST", url="http://target.test/api/login",
                             identity_label="admin", allowed=True, response_status=500, check_id="dast-sqli"),
            DastRequestAudit(scan_id=scan.id, seq=3, method="GET", url="http://elsewhere.test/",
                             identity_label=None, allowed=False, deny_reason="off-scope"),
        ]
    )
    db.commit()
    return scan.id, finding.id


def test_finding_with_evidence_round_trips(tmp_path):
    SessionLocal = init_db(f"sqlite:///{(tmp_path / 'rt.db').as_posix()}")
    with SessionLocal() as db:
        scan_id, finding_id = _seed_dast_scan(db)
    with SessionLocal() as db:
        finding = db.get(Finding, finding_id)
        assert (finding.target, finding.param, finding.location) == ("POST /api/login", "username", "body")
        assert finding.confidence_label == "HIGH" and finding.confidence == 0.9
        assert finding.standards == ["OWASP A03:2021", "CWE-89"]
        assert finding.first_seen_scan_id == finding.last_seen_scan_id == scan_id

        evidence = db.query(DastEvidence).filter_by(finding_id=finding_id).one()
        assert evidence.signals == [{"name": "sql_error_text", "detail": "near '--'"}]
        assert evidence.audit_ref == "2"

        audit = db.query(DastRequestAudit).filter_by(scan_id=scan_id).order_by(DastRequestAudit.seq).all()
        assert [a.seq for a in audit] == [1, 2, 3]
        assert [a.allowed for a in audit] == [True, True, False]
        assert audit[2].deny_reason == "off-scope" and audit[2].response_status is None
        assert audit[1].check_id == "dast-sqli"


def test_audit_sequence_is_unique_per_scan(tmp_path):
    from sqlalchemy.exc import IntegrityError

    SessionLocal = init_db(f"sqlite:///{(tmp_path / 'uq.db').as_posix()}")
    with SessionLocal() as db:
        scan_id, _ = _seed_dast_scan(db)
        db.add(DastRequestAudit(scan_id=scan_id, seq=1, method="GET", url="http://target.test/", allowed=True))
        with pytest.raises(IntegrityError):
            db.commit()


def test_deleting_a_scan_leaves_no_orphan_evidence_or_audit_rows(tmp_path, monkeypatch):
    monkeypatch.setenv("USE_MOCK_ENGINE", "true")
    settings.use_mock_engine = True
    SessionLocal = init_db(f"sqlite:///{(tmp_path / 'del.db').as_posix()}")
    with SessionLocal() as db:
        scan_id, _ = _seed_dast_scan(db)
        other_scan_id, _ = _seed_dast_scan_second(db)

    resp = TestClient(app).delete(f"/scans/{scan_id}", headers=HDR)
    assert resp.status_code == 204

    with SessionLocal() as db:
        assert db.query(DastEvidence).count() == 1  # the other scan's evidence survives
        assert db.query(DastRequestAudit).filter_by(scan_id=scan_id).count() == 0
        assert db.query(DastRequestAudit).filter_by(scan_id=other_scan_id).count() == 3
        orphans = db.execute(
            text("SELECT COUNT(*) FROM dast_evidence WHERE finding_id NOT IN (SELECT id FROM findings)")
        ).scalar()
        assert orphans == 0


def _seed_dast_scan_second(db):
    project = db.query(Project).one()
    scan = Scan(project_id=project.id, git_url="http://other.test", branch="main",
                status="success", scan_type="dast", metadata_json={})
    db.add(scan)
    db.flush()
    finding = Finding(scan_id=scan.id, severity="LOW", title="other", kind="dast", verdict="unverified")
    db.add(finding)
    db.flush()
    db.add(DastEvidence(finding_id=finding.id, test_excerpt="x"))
    db.add_all([DastRequestAudit(scan_id=scan.id, seq=i, method="GET", url="http://other.test/", allowed=True)
                for i in (1, 2, 3)])
    db.commit()
    return scan.id, finding.id


def test_deleting_a_project_leaves_no_orphan_audit_rows(tmp_path, monkeypatch):
    monkeypatch.setenv("USE_MOCK_ENGINE", "true")
    settings.use_mock_engine = True
    SessionLocal = init_db(f"sqlite:///{(tmp_path / 'delp.db').as_posix()}")
    with SessionLocal() as db:
        _seed_dast_scan(db)
        project_id = db.query(Project).one().id

    resp = TestClient(app).delete(f"/projects/{project_id}", headers=HDR)
    assert resp.status_code == 200, resp.text

    with SessionLocal() as db:
        assert db.query(DastEvidence).count() == 0
        assert db.query(DastRequestAudit).count() == 0


def test_dast_scan_snapshots_effective_settings_in_metadata(tmp_path, monkeypatch):
    monkeypatch.setenv("USE_MOCK_ENGINE", "true")
    settings.use_mock_engine = True
    settings.scan_logs_dir = str(tmp_path / "scan_logs")
    SessionLocal = init_db(f"sqlite:///{(tmp_path / 'snap.db').as_posix()}")
    client = TestClient(app)
    project = client.post(
        "/projects", json={"name": "snap", "default_git_url": "https://example.test/r.git"}, headers=HDR
    ).json()
    resp = client.post(
        "/scans",
        json={"project_id": project["id"], "scan_type": "dast",
              "dast": {"target_url": "http://localhost:3000", "authorized": True}},
        headers=HDR,
    )
    assert resp.status_code in (200, 201, 202), resp.text
    with SessionLocal() as db:
        scan = db.query(Scan).one()
        snapshot = scan.metadata_json[DAST_SETTINGS_SNAPSHOT_KEY]
    assert snapshot["max_pages"] == settings.dast_max_pages
    assert snapshot["rate_limit_per_sec"] == settings.dast_rate_limit_per_sec
    assert set(snapshot["model_routing"]) == {
        "fingerprint", "crawl_plan", "login_selectors", "plan", "construct", "rule", "narrate"
    }
    assert "password" not in str(snapshot).lower()

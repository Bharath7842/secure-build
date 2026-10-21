"""App side of the verdict contract (SAST-00-010): the two new Finding
columns, their migration, how the writers fill them, and the findings API."""

import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect

from app.config import settings
from app.db import init_db
from app.main import app
from app.models import Finding, Project, Scan
from app.services import scan_runner
from app.services.finding_rows import build_finding_row
from app.services.scan_runner import (
    _make_findings_writer,
    _make_verdict_updates_writer,
    unresolved_counts,
)

from tests.auth_helpers import ADMIN_HEADERS

pytestmark = pytest.mark.integration

LEGACY_SQL = Path(__file__).parent / "fixtures" / "pre_dast_schema.sql"
NEW_COLUMNS = {"issue_class", "unresolved_reason"}


def _legacy_db(tmp_path) -> str:
    path = tmp_path / "legacy.db"
    conn = sqlite3.connect(path)
    conn.executescript(LEGACY_SQL.read_text())
    conn.commit()
    conn.close()
    return f"sqlite:///{path.as_posix()}"


def _finding_columns(url: str) -> set[str]:
    conn = sqlite3.connect(url.removeprefix("sqlite:///"))
    try:
        return {row[1] for row in conn.execute("PRAGMA table_info(findings)")}
    finally:
        conn.close()


def _seed_scan(SessionLocal, name="contract-demo") -> str:
    with SessionLocal() as db:
        project = Project(name=name, default_git_url="https://github.com/org/repo.git")
        db.add(project)
        db.commit()
        scan = Scan(project_id=project.id, git_url=project.default_git_url)
        db.add(scan)
        db.commit()
        return scan.id


def _regex_finding(**overrides) -> dict:
    finding = {
        "verdict": "unverified", "unresolved_reason": "not_reviewed_regex",
        "issue_class": "security", "severity": "MEDIUM", "cwe": "CWE-798",
        "rule_id": "secret-password-assign", "title": "hardcoded password",
        "file_path": "app/config.py", "line": 5, "snippet": "password = 'x'",
        "matched_text": "password = 'x'", "kind": "regex", "confidence": None,
    }
    finding.update(overrides)
    return finding


# --- migration --------------------------------------------------------------

def test_legacy_database_lacks_the_columns(tmp_path):
    assert not (NEW_COLUMNS & _finding_columns(_legacy_db(tmp_path)))


def test_migration_adds_both_columns_and_old_rows_stay_null(tmp_path):
    url = _legacy_db(tmp_path)
    SessionLocal = init_db(url)

    from app.db import engine

    assert NEW_COLUMNS <= {c["name"] for c in inspect(engine).get_columns("findings")}
    with SessionLocal() as db:
        legacy = db.get(Finding, "f1")
        assert legacy.issue_class is None
        assert legacy.unresolved_reason is None


def test_running_the_migration_twice_is_a_no_op(tmp_path):
    url = _legacy_db(tmp_path)
    init_db(url)
    first = _finding_columns(url)
    SessionLocal = init_db(url)
    assert _finding_columns(url) == first
    with SessionLocal() as db:
        assert db.query(Finding).count() == 1


# --- row mapping and writers ------------------------------------------------

def test_build_finding_row_keeps_class_and_reason_for_unverified():
    row = build_finding_row("s1", _regex_finding(), "app/config.py")
    assert (row.issue_class, row.unresolved_reason) == ("security", "not_reviewed_regex")


def test_build_finding_row_drops_a_reason_on_a_decided_verdict():
    row = build_finding_row(
        "s1", _regex_finding(verdict="true_positive", unresolved_reason="llm_call_failed"), "x"
    )
    assert row.unresolved_reason is None


def test_an_unverified_finding_without_a_reason_is_stored_as_evidence_missing(caplog):
    finding = _regex_finding()
    del finding["unresolved_reason"]
    with caplog.at_level("WARNING"):
        row = build_finding_row("s1", finding, "app/config.py")
    assert row.unresolved_reason == "evidence_missing"
    assert "without unresolved_reason" in caplog.text


def test_legacy_style_finding_without_a_class_is_stored_null():
    row = build_finding_row("s1", {"verdict": "true_positive", "title": "x"}, "a.py")
    assert row.issue_class is None


def test_findings_writer_persists_class_and_reason(tmp_path):
    SessionLocal = init_db(f"sqlite:///{(tmp_path / 'w.db').as_posix()}")
    scan_id = _seed_scan(SessionLocal)
    _make_findings_writer(scan_id)("app/config.py", [
        _regex_finding(),
        _regex_finding(rule_id="serializable-missing-svuid", issue_class="quality", line=9,
                       matched_text="class A implements Serializable"),
    ])
    with SessionLocal() as db:
        rows = {r.rule_id: r for r in db.query(Finding).filter(Finding.scan_id == scan_id)}
    assert rows["secret-password-assign"].issue_class == "security"
    assert rows["serializable-missing-svuid"].issue_class == "quality"
    assert {r.unresolved_reason for r in rows.values()} == {"not_reviewed_regex"}


def test_verdict_update_clears_the_reason_when_a_verdict_is_decided(tmp_path):
    SessionLocal = init_db(f"sqlite:///{(tmp_path / 'v.db').as_posix()}")
    scan_id = _seed_scan(SessionLocal)
    _make_findings_writer(scan_id)("app/config.py", [_regex_finding()])

    _make_verdict_updates_writer(scan_id)("app/config.py", [{
        "rule_id": "secret-password-assign", "line": 5, "verdict": "true_positive",
        "confidence": 0.9, "verdict_reason": "real", "ai_fix": "use env",
    }])
    with SessionLocal() as db:
        row = db.query(Finding).filter(Finding.scan_id == scan_id).one()
    assert row.verdict == "true_positive"
    assert row.unresolved_reason is None


def test_a_reason_only_update_keeps_the_verdict_and_reasoning(tmp_path):
    SessionLocal = init_db(f"sqlite:///{(tmp_path / 'r.db').as_posix()}")
    scan_id = _seed_scan(SessionLocal)
    _make_findings_writer(scan_id)(
        "app/config.py", [_regex_finding(verdict_reason="regex match, not reviewed")]
    )

    _make_verdict_updates_writer(scan_id)("app/config.py", [{
        "rule_id": "secret-password-assign", "line": 5, "unresolved_reason": "llm_call_failed",
    }])
    with SessionLocal() as db:
        row = db.query(Finding).filter(Finding.scan_id == scan_id).one()
    assert row.verdict == "unverified"
    assert row.unresolved_reason == "llm_call_failed"
    assert row.verdict_reason == "regex match, not reviewed"


def test_unresolved_counts_group_by_reason(tmp_path):
    SessionLocal = init_db(f"sqlite:///{(tmp_path / 'c.db').as_posix()}")
    scan_id = _seed_scan(SessionLocal)
    _make_findings_writer(scan_id)("a.py", [
        _regex_finding(line=1),
        _regex_finding(line=2, unresolved_reason="llm_budget_exhausted"),
        _regex_finding(line=3, unresolved_reason="llm_budget_exhausted"),
        _regex_finding(line=4, verdict="true_positive"),
    ])
    with SessionLocal() as db:
        assert unresolved_counts(db, scan_id) == {
            "not_reviewed_regex": 1, "llm_budget_exhausted": 2,
        }


def test_the_unresolved_summary_is_logged_once_per_scan(tmp_path, monkeypatch):
    SessionLocal = init_db(f"sqlite:///{(tmp_path / 'l.db').as_posix()}")
    scan_id = _seed_scan(SessionLocal)
    _make_findings_writer(scan_id)("a.py", [_regex_finding()])
    lines: list[str] = []
    monkeypatch.setattr(scan_runner.scan_log, "log", lambda _id, line: lines.append(line))

    scan_runner._log_unresolved_summary(scan_id)

    assert lines == ["Unresolved findings by reason: not_reviewed_regex=1."]


# --- API --------------------------------------------------------------------

@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("USE_MOCK_ENGINE", "true")
    settings.use_mock_engine = True
    settings.scan_logs_dir = str(tmp_path / "scan_logs")
    init_db(f"sqlite:///{(tmp_path / 'api.db').as_posix()}")
    return TestClient(app)


def test_findings_api_returns_both_keys_and_null_for_legacy_rows(client, monkeypatch):
    from app.db import SessionLocal

    monkeypatch.setattr(scan_runner, "execute_scan", lambda scan_id: None)
    project_id = client.post(
        "/projects",
        json={"name": "api-contract", "default_git_url": "https://github.com/org/repo.git"},
        headers=ADMIN_HEADERS,
    ).json()["id"]
    scan_id = client.post(
        "/scans", headers=ADMIN_HEADERS, json={"project_id": project_id, "commit_sha": "c1"}
    ).json()["scan_id"]
    with SessionLocal() as db:
        db.add_all([
            Finding(scan_id=scan_id, severity="LOW", title="new style", rule_id="svuid",
                    file_path="A.java", line=1, verdict="unverified", kind="regex",
                    issue_class="quality", unresolved_reason="not_reviewed_regex"),
            Finding(scan_id=scan_id, severity="LOW", title="legacy row", rule_id="old",
                    file_path="B.java", line=2, verdict="true_positive", kind="llm"),
        ])
        db.commit()

    body = client.get(f"/scans/{scan_id}/findings", headers=ADMIN_HEADERS).json()
    by_title = {f["title"]: f for f in body["findings"]}
    assert by_title["new style"]["issue_class"] == "quality"
    assert by_title["new style"]["unresolved_reason"] == "not_reviewed_regex"
    assert by_title["legacy row"]["issue_class"] is None
    assert by_title["legacy row"]["unresolved_reason"] is None

"""Tests for scan_runner._make_verdict_updates_writer — updates existing
Finding rows in place after grouped confirmation of unverified findings
(never a fresh insert, unlike _make_findings_writer)."""

from app.db import init_db
from app.models import Finding, Project, Scan
from app.services.scan_runner import _make_findings_writer, _make_verdict_updates_writer


def _seed_scan(SessionLocal, project_name: str) -> str:
    with SessionLocal() as db:
        project = Project(name=project_name, default_git_url="https://github.com/org/repo.git")
        db.add(project)
        db.commit()
        scan = Scan(project_id=project.id, git_url=project.default_git_url)
        db.add(scan)
        db.commit()
        return scan.id


def _seed_unverified_finding(SessionLocal, scan_id: str, **overrides) -> None:
    findings_writer = _make_findings_writer(scan_id)
    finding = {
        "verdict": "unverified", "severity": "MEDIUM", "cwe": "CWE-798",
        "owasp_category": "A07:2021-Identification-and-Authentication-Failures",
        "rule_id": "secret-password-assign", "title": "hardcoded password",
        "file_path": "app/config.py", "line": 5, "snippet": "password = 'x'",
        "matched_text": "password = 'x'",
        "verdict_reason": "Regex pattern match, not reviewed by an LLM — confirm before acting on it.",
        "kind": "regex", "confidence": None,
    }
    finding.update(overrides)
    findings_writer(finding["file_path"], [finding])


def test_verdict_updates_writer_updates_matching_row_in_place(tmp_path):
    url = f"sqlite:///{(tmp_path / 'verdict-updates.db').as_posix()}"
    SessionLocal = init_db(url)
    scan_id = _seed_scan(SessionLocal, "demo-verdict-updates-1")
    _seed_unverified_finding(SessionLocal, scan_id)

    writer = _make_verdict_updates_writer(scan_id)
    writer("app/config.py", [{
        "rule_id": "secret-password-assign", "line": 5,
        "verdict": "true_positive", "confidence": 0.9,
        "verdict_reason": "confirmed via grouped review of 1 occurrence(s) of this pattern",
        "ai_fix": "load from env",
    }])

    with SessionLocal() as db:
        rows = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        assert len(rows) == 1  # updated in place, not a second row
        row = rows[0]
        assert row.verdict == "true_positive"
        assert row.confidence == 0.9
        assert row.ai_fix == "load from env"
        assert "grouped review" in row.verdict_reason
        # untouched fields survive the update
        assert row.severity == "MEDIUM"
        assert row.matched_text == "password = 'x'"


def test_verdict_updates_writer_only_touches_the_matching_rule_and_line(tmp_path):
    url = f"sqlite:///{(tmp_path / 'verdict-updates2.db').as_posix()}"
    SessionLocal = init_db(url)
    scan_id = _seed_scan(SessionLocal, "demo-verdict-updates-2")
    _seed_unverified_finding(SessionLocal, scan_id, line=5, rule_id="secret-password-assign")
    _seed_unverified_finding(SessionLocal, scan_id, line=9, rule_id="secret-password-assign")

    writer = _make_verdict_updates_writer(scan_id)
    writer("app/config.py", [{
        "rule_id": "secret-password-assign", "line": 5,
        "verdict": "false_positive", "confidence": 0.3,
        "verdict_reason": "test fixture", "ai_fix": None,
    }])

    with SessionLocal() as db:
        rows = {r.line: r for r in db.query(Finding).filter(Finding.scan_id == scan_id).all()}
        assert rows[5].verdict == "false_positive"
        assert rows[9].verdict == "unverified"  # different line, left untouched


def test_verdict_updates_writer_noop_on_empty_updates(tmp_path):
    url = f"sqlite:///{(tmp_path / 'verdict-updates3.db').as_posix()}"
    SessionLocal = init_db(url)
    scan_id = _seed_scan(SessionLocal, "demo-verdict-updates-3")
    _seed_unverified_finding(SessionLocal, scan_id)

    writer = _make_verdict_updates_writer(scan_id)
    writer("app/config.py", [])  # must not raise

    with SessionLocal() as db:
        row = db.query(Finding).filter(Finding.scan_id == scan_id).one()
        assert row.verdict == "unverified"

"""Tests for scan_runner._make_findings_writer — one short DB session per
CRITICAL file, writing true- and false-positive findings together."""

from app.db import init_db
from app.models import Finding, Project, Scan
from app.services.scan_runner import _make_findings_writer


def _seed_scan(SessionLocal, project_name: str) -> str:
    with SessionLocal() as db:
        project = Project(name=project_name, default_git_url="https://github.com/org/repo.git")
        db.add(project)
        db.commit()
        scan = Scan(project_id=project.id, git_url=project.default_git_url)
        db.add(scan)
        db.commit()
        return scan.id


def test_findings_writer_persists_tp_and_fp_in_one_call(tmp_path):
    url = f"sqlite:///{(tmp_path / 'findings.db').as_posix()}"
    SessionLocal = init_db(url)
    scan_id = _seed_scan(SessionLocal, "demo-writer-1")

    writer = _make_findings_writer(scan_id)
    writer("app/auth.py", [
        {
            "verdict": "true_positive", "severity": "HIGH", "cwe": "CWE-798",
            "owasp_category": "A07:2021-Identification-and-Authentication-Failures",
            "rule_id": "secret-password-assign", "title": "hardcoded password",
            "file_path": "app/auth.py", "line": 12, "snippet": "password = 'x'",
            "verdict_reason": "real secret", "ai_fix": "load from env",
        },
        {
            "verdict": "false_positive", "severity": "LOW", "cwe": None,
            "owasp_category": "A04:2021-Insecure-Design",
            "rule_id": "llm-extra", "title": "not an issue",
            "file_path": "app/auth.py", "line": 30, "snippet": "x = 1",
            "verdict_reason": "not security relevant", "ai_fix": None,
        },
    ])

    with SessionLocal() as db:
        rows = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        assert len(rows) == 2
        assert {r.verdict for r in rows} == {"true_positive", "false_positive"}
        assert all(r.kind == "llm" for r in rows)
        tp = next(r for r in rows if r.verdict == "true_positive")
        assert tp.owasp_category == "A07:2021-Identification-and-Authentication-Failures"
        assert tp.ai_fix == "load from env"
        fp = next(r for r in rows if r.verdict == "false_positive")
        assert fp.verdict_reason == "not security relevant"


def test_findings_writer_uses_kind_from_finding(tmp_path):
    url = f"sqlite:///{(tmp_path / 'findings-kind.db').as_posix()}"
    SessionLocal = init_db(url)
    scan_id = _seed_scan(SessionLocal, "demo-writer-kind")

    writer = _make_findings_writer(scan_id)
    writer("tests/test_app.py", [
        {
            "verdict": "false_positive", "severity": "LOW", "cwe": "CWE-798",
            "owasp_category": "A07:2021-Identification-and-Authentication-Failures",
            "rule_id": "secret-password-assign", "title": "hardcoded password",
            "file_path": "tests/test_app.py", "line": 1, "snippet": "password = 'x'",
            "verdict_reason": "test fixture", "kind": "regex",
        },
    ])

    with SessionLocal() as db:
        row = db.query(Finding).filter(Finding.scan_id == scan_id).one()
        assert row.kind == "regex"


def test_findings_writer_logs_when_no_findings(tmp_path):
    url = f"sqlite:///{(tmp_path / 'findings2.db').as_posix()}"
    SessionLocal = init_db(url)
    scan_id = _seed_scan(SessionLocal, "demo-writer-2")

    writer = _make_findings_writer(scan_id)
    writer("app/clean.py", [])

    with SessionLocal() as db:
        rows = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        assert rows == []


def test_findings_writer_owasp_category_holds_full_label(tmp_path):
    """Regression: owasp_category was widened from VARCHAR(10) to VARCHAR(64)
    to hold full "A0x:2021-Some-Category" labels instead of just the short code."""
    url = f"sqlite:///{(tmp_path / 'findings3.db').as_posix()}"
    SessionLocal = init_db(url)
    scan_id = _seed_scan(SessionLocal, "demo-writer-3")

    long_label = "A07:2021-Identification-and-Authentication-Failures"
    assert len(long_label) > 10

    writer = _make_findings_writer(scan_id)
    writer("app/auth.py", [{
        "verdict": "true_positive", "severity": "HIGH", "cwe": "CWE-798",
        "owasp_category": long_label, "rule_id": "secret-password-assign",
        "title": "hardcoded password", "file_path": "app/auth.py", "line": 1,
        "snippet": "password = 'x'", "verdict_reason": "real secret", "ai_fix": None,
    }])

    with SessionLocal() as db:
        row = db.query(Finding).filter(Finding.scan_id == scan_id).one()
        assert row.owasp_category == long_label


def test_findings_writer_persists_flow_path_and_affected_files(tmp_path):
    url = f"sqlite:///{(tmp_path / 'findings-flow.db').as_posix()}"
    SessionLocal = init_db(url)
    scan_id = _seed_scan(SessionLocal, "demo-writer-flow")

    hops = [
        {"step": 1, "file": "FooController.java", "method": "FooController.create",
         "line": 12, "role": "source", "label": "id", "snippet": "create() { svc.find(id); }"},
        {"step": 2, "file": "FooDao.java", "method": "FooDao.query",
         "line": 20, "role": "sink", "label": "executeQuery", "snippet": "stmt.executeQuery()"},
    ]
    writer = _make_findings_writer(scan_id)
    writer("FooDao.java", [{
        "verdict": "true_positive", "severity": "HIGH", "cwe": "CWE-89",
        "owasp_category": "A03:2021-Injection", "rule_id": "llm-extra",
        "title": "SQL injection", "file_path": "FooDao.java", "line": 20,
        "snippet": hops[1]["snippet"], "verdict_reason": "concat SQL",
        "kind": "flow", "flow_path": hops,
        "affected_files": ["FooController.java", "FooDao.java"],
        "source": "id", "sink": "executeQuery", "data_flow": "id -> executeQuery",
    }])

    with SessionLocal() as db:
        row = db.query(Finding).filter(Finding.scan_id == scan_id).one()
        assert row.kind == "flow"
        assert row.flow_path == hops
        assert row.affected_files == ["FooController.java", "FooDao.java"]

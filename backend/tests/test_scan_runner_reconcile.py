"""Tests for scan_runner.reconcile_unverified_findings — the auto-confirm
sweep that re-runs LLM confirmation for any Finding rows still stuck at
verdict='unverified' once a scan reaches a terminal state (success/failed/
cancelled). Covers every guard condition plus the happy path and the
failure-isolation path, all against a real (tmp sqlite) DB session so the
`_make_verdict_updates_writer` update path is exercised for real.
"""

import pytest

from app import db as db_module
from app.config import settings
from app.db import init_db
from app.models import Finding, Project, Scan
from app.services import agent_bridge, engine_adapter, git_workspace, scan_runner


@pytest.fixture()
def SessionLocal(tmp_path, monkeypatch):
    monkeypatch.setenv("USE_MOCK_ENGINE", "true")
    settings.use_mock_engine = True
    settings.scan_logs_dir = str(tmp_path / "scan_logs")
    url = f"sqlite:///{(tmp_path / 'test.db').as_posix()}"
    init_db(url)
    return db_module.SessionLocal


def _seed_scan(SessionLocal, *, use_llm=True, attempted=False, project_id="p1", scan_id="s1"):
    db = SessionLocal()
    try:
        project = Project(
            id=project_id,
            name=f"proj-{project_id}",
            default_git_url="https://example.com/repo.git",
            default_branch="main",
        )
        db.add(project)
        metadata = {"use_llm": use_llm}
        if attempted:
            metadata["auto_confirm"] = {"attempted": True}
        scan = Scan(
            id=scan_id,
            project_id=project_id,
            git_url=project.default_git_url,
            branch="main",
            commit_sha="abc123",
            status="running",
            version=1,
            llm_provider="bedrock",
            llm_model="haiku",
            metadata_json=metadata,
        )
        db.add(scan)
        db.commit()
    finally:
        db.close()


def _add_finding(SessionLocal, *, scan_id="s1", verdict="unverified", **overrides):
    db = SessionLocal()
    try:
        defaults = dict(
            scan_id=scan_id,
            severity="MEDIUM",
            title="hardcoded password",
            file_path="src/App.java",
            line=10,
            rule_id="secret-password-assign",
            matched_text="password = 'hunter2'",
            verdict=verdict,
            kind="regex",
            cwe="CWE-798",
            owasp_category="A07:2021-Identification-and-Authentication-Failures",
        )
        defaults.update(overrides)
        db.add(Finding(**defaults))
        db.commit()
    finally:
        db.close()


def _make_fake_agent(*, calls=None, raise_error=False):
    """A stand-in for the dynamically-loaded sast_scan_agent module, exposing
    just enough of its surface (regex_scan, llm_file_scan, init_usage) for
    reconcile_unverified_findings to run without any real LLM/regex work."""

    class _RegexScan:
        @staticmethod
        def load_rules(path):
            return []

    class _LlmFileScan:
        DEFAULT_GROUPS_PER_CALL = 5
        TRIAGE_CONFIRM_GROUP_CAP = 50

        @staticmethod
        def group_confirm_unverified_findings(
            *, file_results, repo_root, rules, stack_context, usage,
            llm_provider, llm_model, group_cap, groups_per_call, verdict_updates_writer,
        ):
            if calls is not None:
                calls.append({"group_cap": group_cap, "groups_per_call": groups_per_call})
            if raise_error:
                raise RuntimeError("llm provider unavailable")
            confirmed = 0
            for fr in file_results:
                updates = [
                    {
                        "rule_id": f.get("rule_id"),
                        "line": f.get("line"),
                        "verdict": "true_positive",
                        "confidence": 0.9,
                        "verdict_reason": "confirmed in test",
                        "ai_fix": None,
                    }
                    for f in fr["findings"]
                ]
                confirmed += len(updates)
                if verdict_updates_writer is not None:
                    verdict_updates_writer(fr["file_path"], updates)
            return {
                "candidate_count": confirmed,
                "group_count": 1,
                "confirm_group_count": 1,
                "skipped_group_count": 0,
                "tp_group_count": 1,
                "fp_group_count": 0,
                "error_group_count": 0,
                "confirmed_finding_count": confirmed,
            }

    class _Agent:
        regex_scan = _RegexScan
        llm_file_scan = _LlmFileScan

        @staticmethod
        def init_usage(provider, model, fallback_provider=None, fallback_model=None, **_options):
            return {}

    return _Agent()


def _disable_mock_engine(monkeypatch):
    monkeypatch.setattr(engine_adapter, "mock_engine_enabled", lambda: False)


def test_noop_when_mock_engine_enabled(SessionLocal):
    _seed_scan(SessionLocal)
    _add_finding(SessionLocal)

    scan_runner.reconcile_unverified_findings("s1")

    db = SessionLocal()
    try:
        finding = db.query(Finding).filter(Finding.scan_id == "s1").one()
        assert finding.verdict == "unverified"
        scan = db.get(Scan, "s1")
        assert "auto_confirm" not in (scan.metadata_json or {})
    finally:
        db.close()


def test_noop_when_scan_missing(SessionLocal, monkeypatch):
    _disable_mock_engine(monkeypatch)
    scan_runner.reconcile_unverified_findings("does-not-exist")  # must not raise


def test_noop_when_use_llm_false(SessionLocal, monkeypatch):
    _disable_mock_engine(monkeypatch)
    _seed_scan(SessionLocal, use_llm=False)
    _add_finding(SessionLocal)

    scan_runner.reconcile_unverified_findings("s1")

    db = SessionLocal()
    try:
        finding = db.query(Finding).filter(Finding.scan_id == "s1").one()
        assert finding.verdict == "unverified"
        scan = db.get(Scan, "s1")
        assert "auto_confirm" not in (scan.metadata_json or {})
    finally:
        db.close()


def test_noop_when_already_attempted(SessionLocal, monkeypatch):
    _disable_mock_engine(monkeypatch)
    _seed_scan(SessionLocal, attempted=True)
    _add_finding(SessionLocal)

    scan_runner.reconcile_unverified_findings("s1")

    db = SessionLocal()
    try:
        finding = db.query(Finding).filter(Finding.scan_id == "s1").one()
        assert finding.verdict == "unverified"
    finally:
        db.close()


def test_noop_when_no_unverified_findings(SessionLocal, monkeypatch):
    _disable_mock_engine(monkeypatch)
    _seed_scan(SessionLocal)
    _add_finding(SessionLocal, verdict="true_positive")

    scan_runner.reconcile_unverified_findings("s1")

    db = SessionLocal()
    try:
        scan = db.get(Scan, "s1")
        assert "auto_confirm" not in (scan.metadata_json or {})
    finally:
        db.close()


def test_happy_path_confirms_findings_and_marks_attempted(SessionLocal, monkeypatch, tmp_path):
    _disable_mock_engine(monkeypatch)
    _seed_scan(SessionLocal)
    _add_finding(SessionLocal)

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setattr(git_workspace, "ensure_workspace", lambda *a, **k: workspace)

    calls = []
    fake_agent = _make_fake_agent(calls=calls)
    monkeypatch.setattr(agent_bridge, "_load_agent_module", lambda: fake_agent)

    scan_runner.reconcile_unverified_findings("s1")

    assert calls == [{"group_cap": None, "groups_per_call": 5}]

    db = SessionLocal()
    try:
        finding = db.query(Finding).filter(Finding.scan_id == "s1").one()
        assert finding.verdict == "true_positive"
        assert finding.verdict_reason == "confirmed in test"

        scan = db.get(Scan, "s1")
        auto_confirm = (scan.metadata_json or {}).get("auto_confirm")
        assert auto_confirm is not None
        assert auto_confirm["attempted"] is True
        assert "error" not in auto_confirm
        assert auto_confirm["result"]["tp_group_count"] == 1
    finally:
        db.close()


def test_legacy_hunt_findings_are_not_reconfirmed(SessionLocal, monkeypatch, tmp_path):
    """Old scans can hold kind=hunt rows from the removed agentic hunt; their
    unverified verdict is an evidence cap, so a re-run leaves them alone."""
    _disable_mock_engine(monkeypatch)
    _seed_scan(SessionLocal)
    _add_finding(SessionLocal)
    _add_finding(SessionLocal, kind="hunt", rule_id="hunt-cwe-89", line=20)

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setattr(git_workspace, "ensure_workspace", lambda *a, **k: workspace)
    monkeypatch.setattr(agent_bridge, "_load_agent_module", lambda: _make_fake_agent())

    scan_runner.reconcile_unverified_findings("s1")

    db = SessionLocal()
    try:
        verdicts = {f.kind: f.verdict for f in db.query(Finding).filter(Finding.scan_id == "s1")}
        assert verdicts == {"regex": "true_positive", "hunt": "unverified"}
    finally:
        db.close()


def test_capped_true_passes_triage_confirm_group_cap(SessionLocal, monkeypatch, tmp_path):
    _disable_mock_engine(monkeypatch)
    _seed_scan(SessionLocal)
    _add_finding(SessionLocal)

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setattr(git_workspace, "ensure_workspace", lambda *a, **k: workspace)

    calls = []
    fake_agent = _make_fake_agent(calls=calls)
    monkeypatch.setattr(agent_bridge, "_load_agent_module", lambda: fake_agent)

    scan_runner.reconcile_unverified_findings("s1", capped=True)

    assert calls == [{"group_cap": 50, "groups_per_call": 5}]


def test_marks_attempted_with_error_on_failure_without_raising(SessionLocal, monkeypatch, tmp_path):
    _disable_mock_engine(monkeypatch)
    _seed_scan(SessionLocal)
    _add_finding(SessionLocal)

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setattr(git_workspace, "ensure_workspace", lambda *a, **k: workspace)

    fake_agent = _make_fake_agent(raise_error=True)
    monkeypatch.setattr(agent_bridge, "_load_agent_module", lambda: fake_agent)

    scan_runner.reconcile_unverified_findings("s1")  # must not raise

    db = SessionLocal()
    try:
        finding = db.query(Finding).filter(Finding.scan_id == "s1").one()
        assert finding.verdict == "unverified"  # left untouched

        scan = db.get(Scan, "s1")
        auto_confirm = (scan.metadata_json or {}).get("auto_confirm")
        assert auto_confirm["attempted"] is True
        assert "llm provider unavailable" in auto_confirm["error"]
    finally:
        db.close()


def test_second_call_is_noop_after_attempted(SessionLocal, monkeypatch, tmp_path):
    """Retry-once semantics: a second sweep must not re-invoke the LLM even
    though the first sweep's error left findings unverified."""
    _disable_mock_engine(monkeypatch)
    _seed_scan(SessionLocal)
    _add_finding(SessionLocal)

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setattr(git_workspace, "ensure_workspace", lambda *a, **k: workspace)

    calls = []
    fake_agent = _make_fake_agent(calls=calls, raise_error=True)
    monkeypatch.setattr(agent_bridge, "_load_agent_module", lambda: fake_agent)

    scan_runner.reconcile_unverified_findings("s1")
    scan_runner.reconcile_unverified_findings("s1")

    assert len(calls) == 1

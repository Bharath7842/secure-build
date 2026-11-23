"""A cancelled SAST scan stops making LLM calls.

Before this, cancel only flipped the scan row: the engine never saw it and kept
calling the provider until every stage had finished.
"""

import sys
from pathlib import Path

import pytest

from app.db import init_db
from app.models import Project, Scan

SAST_ENGINE_DIR = Path(__file__).resolve().parents[1] / "sast_engine"


@pytest.fixture()
def llm(monkeypatch):
    pytest.importorskip("boto3", reason="llm_client requires boto3")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    if str(SAST_ENGINE_DIR) not in sys.path:
        sys.path.insert(0, str(SAST_ENGINE_DIR))
    import llm_client as module

    monkeypatch.setattr(module.time, "sleep", lambda _s: None)
    return module


def _ollama_usage(llm, cancel_check):
    usage = llm.init_usage("ollama", "test-model")
    usage[llm.CANCEL_CHECK_USAGE_KEY] = cancel_check
    return usage


def test_cancelled_scan_sends_nothing(llm, monkeypatch):
    posts = []
    monkeypatch.setattr(llm.requests, "post", lambda *a, **k: posts.append(1))
    usage = _ollama_usage(llm, lambda: True)

    with pytest.raises(llm.LlmScanCancelled):
        llm.call_llm("sys", "user", usage=usage, step="scan_deep_files")

    assert posts == []
    assert usage["cancelled"] is True


def test_cancel_is_a_budget_stop_for_existing_handlers(llm):
    # Stages already stop their LLM work on LlmBudgetExhausted; cancel reuses that path.
    assert issubclass(llm.LlmScanCancelled, llm.LlmBudgetExhausted)


def test_cancel_during_retry_stops_the_retry(llm, monkeypatch):
    cancelled = {"v": False}
    posts = []

    def failing_post(*_a, **_k):
        posts.append(1)
        cancelled["v"] = True  # the user cancels while this request is failing
        raise llm.requests.ConnectionError("boom")

    monkeypatch.setattr(llm.requests, "post", failing_post)
    usage = _ollama_usage(llm, lambda: cancelled["v"])

    with pytest.raises(llm.LlmScanCancelled):
        llm.call_llm("sys", "user", usage=usage, step="scan_deep_files", retries=3)

    assert len(posts) == 1


def test_unreadable_cancel_flag_does_not_stop_the_scan(llm, monkeypatch):
    class _Resp:
        status_code = 200
        is_redirect = False
        headers: dict = {}

        def raise_for_status(self):
            return None

        def json(self):
            return {"message": {"content": "ok"}, "prompt_eval_count": 1, "eval_count": 1}

    monkeypatch.setattr(llm.requests, "post", lambda *a, **k: _Resp())

    def broken():
        raise RuntimeError("flag store down")

    usage = _ollama_usage(llm, broken)
    assert llm.call_llm("sys", "user", usage=usage, step="scan_deep_files") == "ok"


def test_engine_adapter_forwards_should_abort(monkeypatch, tmp_path):
    from app.services import agent_bridge, engine_adapter

    seen = {}
    monkeypatch.setattr(engine_adapter, "mock_engine_enabled", lambda: False)
    monkeypatch.setattr(engine_adapter, "run_live_sast_enabled", lambda: True)
    monkeypatch.setattr(agent_bridge, "run_real_scan", lambda **kw: seen.update(kw) or {})

    def abort():
        return True

    engine_adapter.run_scan(
        project=object(), git_url="u", branch="main", commit_sha="c",
        workspace=tmp_path, should_abort=abort,
    )
    assert seen["should_abort"] is abort


def test_engine_stopped_by_cancel_is_cancelled_not_failed(tmp_path, monkeypatch):
    from app.config import settings
    from app.services import scan_runner

    monkeypatch.setattr(settings, "workspaces_dir", str(tmp_path / "workspaces"))
    monkeypatch.setenv("USE_MOCK_ENGINE", "true")
    SessionLocal = init_db(f"sqlite:///{(tmp_path / 'cancel.db').as_posix()}")

    with SessionLocal() as db:
        project = Project(name="cancel-demo", default_git_url="https://github.com/org/repo.git")
        db.add(project)
        db.commit()
        scan = Scan(project_id=project.id, git_url=project.default_git_url, branch="main", commit_sha="c1")
        db.add(scan)
        db.commit()
        scan_id = scan.id

    seen = {}

    def engine(**kwargs):
        seen["before"] = kwargs["should_abort"]()
        scan_runner.request_cancel(scan_id)  # the user clicks Stop mid-scan
        seen["after"] = kwargs["should_abort"]()
        raise RuntimeError("scan was cancelled")  # what an escaping LlmScanCancelled looks like here

    monkeypatch.setattr(scan_runner.engine_adapter, "run_scan", engine)
    scan_runner.execute_scan(scan_id)

    assert seen == {"before": False, "after": True}
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        assert scan.status == "cancelled"
        assert scan.message == "Cancelled by user"
    assert not scan_runner.is_cancel_requested(scan_id)

"""A deep-scan chunk whose LLM call fails must not read as a clean file."""

from pathlib import Path

import pytest

pytest.importorskip("langgraph")

from app.config import settings  # noqa: E402
from app.services.agent_bridge import _load_agent_module  # noqa: E402

_ENGINE_DIR = Path(__file__).resolve().parents[1] / "sast_engine"


@pytest.fixture()
def modules(monkeypatch):
    import sys

    monkeypatch.setattr(settings, "sast_framework_path", str(_ENGINE_DIR))
    sys.modules.pop("sast_scan_agent", None)
    _load_agent_module()
    return sys.modules["pipeline.llm_file_scan"], sys.modules["pipeline.regex_scan"]


def _failing_llm(system, user, **kwargs):
    raise RuntimeError("500 Server Error: Internal Server Error for url: http://localhost:11434/api/chat")


def test_failed_llm_call_is_recorded_not_reported_clean(tmp_path, modules):
    llm_file_scan, regex_scan = modules
    rules = regex_scan.load_rules(_ENGINE_DIR / "rules")
    (tmp_path / "run.py").write_text("import os\nos.system(cmd)\nexec(code)\n", encoding="utf-8")

    result = llm_file_scan.scan_file(
        repo_root=tmp_path, rel_path="run.py", rules=rules,
        active_frameworks=set(), stack_context="", call_llm_fn=_failing_llm,
    )

    assert result["failed_chunks"] == 1
    assert len(result["chunk_errors"]) == 1
    unresolved = [f for f in result["findings"] if f["verdict"] == llm_file_scan.VERDICT_UNVERIFIED]
    assert unresolved, "the catalog's hits in the failed chunk must be kept as undecided work"
    assert {f["unresolved_reason"] for f in unresolved} == {"llm_call_failed"}
    assert all(f["verdict_reason"] == llm_file_scan.LLM_CALL_FAILED_REASON for f in unresolved)


def test_successful_call_reports_no_failed_chunks(tmp_path, modules):
    llm_file_scan, regex_scan = modules
    rules = regex_scan.load_rules(_ENGINE_DIR / "rules")
    (tmp_path / "ok.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

    result = llm_file_scan.scan_file(
        repo_root=tmp_path, rel_path="ok.py", rules=rules, active_frameworks=set(),
        stack_context="", call_llm_fn=lambda system, user, **kw: '{"findings": []}',
    )

    assert result["failed_chunks"] == 0
    assert result["chunk_errors"] == []

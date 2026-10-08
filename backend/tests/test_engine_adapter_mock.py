"""Engine adapter tests.

CI stays green with the mock engine only — no AWS credentials, Bedrock
model access, langgraph, or tree-sitter installs required. The real path is
covered only up to its clearly-documented failure/guard branches (missing
workspace, RUN_LIVE_SAST not set, agent import failure) so we never
actually invoke Bedrock or clone a real repo from a test.
"""

import pytest

from app.config import settings
from app.models import Project
from app.services import engine_adapter


@pytest.fixture(autouse=True)
def _reset_engine_flags(monkeypatch):
    monkeypatch.setenv("USE_MOCK_ENGINE", "true")
    monkeypatch.delenv("RUN_LIVE_SAST", raising=False)
    settings.use_mock_engine = True
    settings.run_live_sast = False
    yield
    settings.use_mock_engine = False
    settings.run_live_sast = False


def _project(**overrides) -> Project:
    defaults = dict(name="engine-adapter-test", default_git_url="https://example.com/repo.git")
    defaults.update(overrides)
    return Project(**defaults)


def test_mock_engine_enabled_reads_env_flag(monkeypatch):
    monkeypatch.setenv("USE_MOCK_ENGINE", "true")
    assert engine_adapter.mock_engine_enabled() is True

    monkeypatch.setenv("USE_MOCK_ENGINE", "false")
    settings.use_mock_engine = False
    assert engine_adapter.mock_engine_enabled() is False


def test_run_scan_mock_path_returns_deterministic_discovery():
    result = engine_adapter.run_scan(
        project=_project(),
        git_url="https://example.com/repo.git",
        branch="main",
        commit_sha="c1",
    )
    discovery = result["discovery"]
    assert discovery["llm_analysis"]["tech_stack"]
    assert discovery["scan_summary"]["total_files"] > 0
    module_plan = discovery["module_plan"]
    assert module_plan["risk_counts"]["CRITICAL"] >= 1
    assert {f["risk_level"] for f in module_plan["files"]} <= {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def test_run_scan_real_path_requires_run_live_sast_opt_in(monkeypatch):
    monkeypatch.setenv("USE_MOCK_ENGINE", "false")
    monkeypatch.delenv("RUN_LIVE_SAST", raising=False)
    settings.use_mock_engine = False
    settings.run_live_sast = False

    with pytest.raises(RuntimeError, match="live SAST is disabled"):
        engine_adapter.run_scan(
            project=_project(),
            git_url="https://example.com/repo.git",
            branch="main",
            commit_sha=None,
        )


def test_run_scan_real_path_requires_workspace(monkeypatch):
    monkeypatch.setenv("USE_MOCK_ENGINE", "false")
    monkeypatch.setenv("RUN_LIVE_SAST", "1")
    settings.use_mock_engine = False
    settings.run_live_sast = True

    with pytest.raises(RuntimeError, match="workspace"):
        engine_adapter.run_scan(
            project=_project(),
            git_url="https://example.com/repo.git",
            branch="main",
            commit_sha=None,
            workspace=None,
        )


def test_run_real_scan_missing_agent_module_raises_install_hint(tmp_path, monkeypatch):
    import sys

    monkeypatch.setattr(settings, "sast_framework_path", str(tmp_path / "does-not-exist"))
    sys.modules.pop("sast_scan_agent", None)

    from app.services.agent_bridge import run_real_scan

    with pytest.raises(RuntimeError, match="pip install"):
        run_real_scan(project=_project(), workspace=tmp_path, changed_paths=None)


def test_load_agent_module_imports_sast_scan_agent(monkeypatch):
    """Regression: sast_scan_agent must import cleanly (TypedDict, langgraph, pipeline)."""
    import sys
    from pathlib import Path

    pytest.importorskip("langgraph")
    engine_dir = Path(__file__).resolve().parents[1] / "sast_engine"
    monkeypatch.setattr(settings, "sast_framework_path", str(engine_dir))
    sys.modules.pop("sast_scan_agent", None)

    from app.services.agent_bridge import _load_agent_module

    module = _load_agent_module()
    assert hasattr(module, "build_graph")
    assert hasattr(module, "SastState")

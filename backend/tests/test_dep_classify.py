"""Coverage for the additive LLM pass that labels unrecognized dependencies
(backend/sast_engine/pipeline/dep_classify.py) and its wiring into
node_analyze_tech_stack. LLM calls are faked; nothing touches the network."""

import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("langgraph")

from app.config import settings  # noqa: E402
from app.services.agent_bridge import _load_agent_module  # noqa: E402


@pytest.fixture()
def agent(monkeypatch):
    engine_dir = Path(__file__).resolve().parents[1] / "sast_engine"
    monkeypatch.setattr(settings, "sast_framework_path", str(engine_dir))
    sys.modules.pop("sast_scan_agent", None)
    return _load_agent_module()


@pytest.fixture()
def dep_classify(agent):
    return sys.modules["pipeline.dep_classify"]


def _deps():
    return [
        {"ecosystem": "npm", "name": "@nestjs/common", "version": "10.0.0"},
        {"ecosystem": "npm", "name": "left-pad", "version": "1.3.0"},
    ]


def _fake(payload, calls=None):
    def fake(system, user, **kwargs):
        if calls is not None:
            calls.append((system, user, kwargs))
        return payload if isinstance(payload, str) else json.dumps(payload)
    return fake


def test_labels_a_known_framework_package(dep_classify):
    got = dep_classify.classify_unrecognized(
        _deps(), call_llm_fn=_fake({"decisions": [{"dependency": "npm:@nestjs/common", "label": "NestJS"}]}),
    )
    assert [e["label"] for e in got] == ["NestJS"]
    assert got[0]["source"] == "llm"
    assert got[0]["matched_dependencies"] == [{"name": "@nestjs/common", "version": "10.0.0"}]


def test_drops_unknown_label_unsent_dependency_and_wrong_ecosystem(dep_classify):
    payload = {"decisions": [
        {"dependency": "npm:left-pad", "label": "Totally Made Up"},
        {"dependency": "npm:never-sent", "label": "NestJS"},
        {"dependency": "npm:left-pad", "label": "Spring Framework"},  # a Maven-only label
    ]}
    assert dep_classify.classify_unrecognized(_deps(), call_llm_fn=_fake(payload)) == []


def test_no_dependencies_makes_no_call(dep_classify):
    calls = []
    assert dep_classify.classify_unrecognized([], call_llm_fn=_fake({"decisions": []}, calls)) == []
    assert calls == []


def test_prompt_is_byte_stable_for_the_result_cache(dep_classify):
    calls = []
    fake = _fake({"decisions": []}, calls)
    dep_classify.classify_unrecognized(_deps(), call_llm_fn=fake)
    dep_classify.classify_unrecognized(_deps(), call_llm_fn=fake)
    assert calls[0][1] == calls[1][1]


def test_unparseable_answer_retries_once_then_returns_nothing(dep_classify):
    calls = []
    assert dep_classify.classify_unrecognized(_deps(), call_llm_fn=_fake("not json at all", calls)) == []
    assert len(calls) == 2


def test_provider_failure_and_budget_exhaustion_return_nothing(dep_classify):
    def boom(*_a, **_k):
        raise RuntimeError("provider down")
    assert dep_classify.classify_unrecognized(_deps(), call_llm_fn=boom) == []

    llm_client = sys.modules["llm_client"]

    def over(*_a, **_k):
        raise llm_client.LlmBudgetExhausted("cutoff")
    assert dep_classify.classify_unrecognized(_deps(), call_llm_fn=over) == []


def test_active_framework_labels_unions_llm_labels(dep_classify):
    summary = {"frameworks": [{"label": "Angular"}], "llm_labels": [{"label": "NestJS"}]}
    assert dep_classify.active_framework_labels(summary) == {"Angular", "NestJS"}
    assert dep_classify.active_framework_labels(None) == set()


def _node_state(agent, root, **overrides):
    state = {
        "local_path": str(root), "scope": None, "context_note": "", "verbose": False,
        "verbose_files": False, "use_llm": True, "persist_to_disk": False,
        "_tracer": agent.AgentTrace(verbose=False),
    }
    state.update(overrides)
    state.update(agent.node_scan_directory(state))
    return state


def _node_repo(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"@angular/core": "17.0.0", "@nestjs/common": "10.0.0"}}),
        encoding="utf-8",
    )
    return tmp_path


def test_node_adds_llm_labels_without_moving_the_stack_verdict(agent, tmp_path, monkeypatch):
    root = _node_repo(tmp_path)
    baseline = agent.node_analyze_tech_stack(_node_state(agent, root, use_llm=False))["llm_analysis"]
    assert baseline["dependency_summary"]["unrecognized_dependencies"][0]["name"] == "@nestjs/common"
    assert "llm_labels" not in baseline["dependency_summary"]

    monkeypatch.setattr(
        sys.modules["pipeline.dep_classify"], "call_llm",
        _fake({"decisions": [{"dependency": "npm:@nestjs/common", "label": "NestJS"}]}),
    )
    got = agent.node_analyze_tech_stack(_node_state(agent, root))["llm_analysis"]
    assert [e["label"] for e in got["dependency_summary"]["llm_labels"]] == ["NestJS"]
    # additive: nothing the prompts and cache keys are built from has moved
    assert [f["label"] for f in got["dependency_summary"]["frameworks"]] == ["Angular"]
    for key in ("tech_stack", "project_type", "confidence", "risk_areas"):
        assert got[key] == baseline[key]


def test_node_makes_no_call_when_disabled(agent, tmp_path, monkeypatch):
    root = _node_repo(tmp_path)
    calls = []
    monkeypatch.setattr(sys.modules["pipeline.dep_classify"], "call_llm", _fake({"decisions": []}, calls))
    agent.node_analyze_tech_stack(_node_state(agent, root, classify_unrecognized_deps=False))
    agent.node_analyze_tech_stack(_node_state(agent, root, use_llm=False))
    assert calls == []

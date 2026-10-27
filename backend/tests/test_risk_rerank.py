"""Coverage for the additive LLM pass that promotes catch-all source files to
HIGH (backend/sast_engine/pipeline/risk_rerank.py) and its wiring into
node_map_modules_and_risk. LLM calls are faked; nothing touches the network."""

import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("langgraph")

from app.config import settings  # noqa: E402
from app.services.agent_bridge import _load_agent_module  # noqa: E402

BASE = "src/main/java/com/acme/"
HANDLER = BASE + "config/GlobalHandler.java"
PLAIN = BASE + "misc/Dto.java"
SERVICE = BASE + "service/OrderService.java"
TEST_FILE = "src/test/java/com/acme/FooTest.java"


@pytest.fixture()
def agent(monkeypatch):
    engine_dir = Path(__file__).resolve().parents[1] / "sast_engine"
    monkeypatch.setattr(settings, "sast_framework_path", str(engine_dir))
    sys.modules.pop("sast_scan_agent", None)
    return _load_agent_module()


@pytest.fixture()
def risk_rerank(agent):
    return sys.modules["pipeline.risk_rerank"]


def _repo(tmp_path):
    (tmp_path / "pom.xml").write_text("<project/>", encoding="utf-8")
    files = {
        HANDLER: "class GlobalHandler { String h(Exception e) { return e.getMessage(); } }\n",
        PLAIN: "class Dto { int id; }\n",
        SERVICE: "class OrderService {}\n",
        TEST_FILE: "class FooTest {}\n",
    }
    for rel, body in files.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
    return tmp_path


def _answer(by_path):
    def fake(system, user, **kwargs):
        sent = [line[len("### FILE "):] for line in user.splitlines() if line.startswith("### FILE ")]
        fake.sent.extend(sent)
        return json.dumps({"decisions": [{"path": p, "handles": by_path.get(p, ["none"])} for p in sent]})
    fake.sent = []
    return fake


def _plan(agent, root, **overrides):
    state = {
        "local_path": str(root), "scope": None, "context_note": "", "verbose": False,
        "verbose_files": False, "use_llm": True, "persist_to_disk": False,
        "_tracer": agent.AgentTrace(verbose=False),
    }
    state.update(overrides)
    state.update(agent.node_scan_directory(state))
    state.update(agent.node_analyze_tech_stack(state))
    state.update(agent.node_categorize_files(state))
    return agent.node_map_modules_and_risk(state)["module_plan"]


def _risk(plan):
    return {f["path"]: f["risk_level"] for f in plan["files"]}


def test_without_the_pass_the_handler_is_a_medium_leftover(agent, tmp_path):
    plan = _plan(agent, _repo(tmp_path), use_llm=False)
    assert _risk(plan)[HANDLER] == "MEDIUM"
    assert plan["llm_promoted"] == 0


def test_promotes_only_what_the_model_names_and_keeps_counts_consistent(agent, tmp_path, monkeypatch):
    root = _repo(tmp_path)
    before = _plan(agent, root, use_llm=False)
    fake = _answer({HANDLER: ["errors"]})
    monkeypatch.setattr(sys.modules["pipeline.risk_rerank"], "call_llm", fake)
    plan = _plan(agent, root)

    risk = _risk(plan)
    assert risk[HANDLER] == "HIGH"
    assert risk[PLAIN] == "MEDIUM"
    assert plan["llm_promoted"] == 1
    assert plan["risk_counts"]["HIGH"] == before["risk_counts"]["HIGH"] + 1
    assert plan["risk_counts"]["MEDIUM"] == before["risk_counts"]["MEDIUM"] - 1
    assert sum(plan["risk_counts"].values()) == sum(before["risk_counts"].values())
    assert HANDLER in [e["path"] for e in plan["scan_priority"]]
    assert HANDLER in plan["deep_scan_paths"]
    reason = next(f["reason"] for f in plan["files"] if f["path"] == HANDLER)
    assert reason.startswith("LLM-promoted: handles errors")


def test_only_catch_all_files_are_sent(agent, tmp_path, monkeypatch):
    fake = _answer({})
    monkeypatch.setattr(sys.modules["pipeline.risk_rerank"], "call_llm", fake)
    _plan(agent, _repo(tmp_path))
    # service/ is a specific HIGH rule, the test file is test code, pom.xml is a manifest
    assert sorted(fake.sent) == sorted([HANDLER, PLAIN])


def test_model_cannot_demote_or_promote_beyond_high(agent, tmp_path, monkeypatch):
    fake = _answer({SERVICE: ["auth"], TEST_FILE: ["auth"], "pom.xml": ["config"]})
    monkeypatch.setattr(sys.modules["pipeline.risk_rerank"], "call_llm", fake)
    root = _repo(tmp_path)
    before = _risk(_plan(agent, root, use_llm=False))
    after = _risk(_plan(agent, root))
    assert after == before


def test_failure_leaves_every_risk_unchanged(agent, tmp_path, monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("provider down")
    root = _repo(tmp_path)
    before = _plan(agent, root, use_llm=False)
    monkeypatch.setattr(sys.modules["pipeline.risk_rerank"], "call_llm", boom)
    after = _plan(agent, root)
    assert _risk(after) == _risk(before)
    assert after["risk_counts"] == before["risk_counts"]
    assert after["llm_promoted"] == 0


def test_budget_exhaustion_leaves_risk_unchanged(agent, tmp_path, monkeypatch):
    llm_client = sys.modules["llm_client"]

    def over(*_a, **_k):
        raise llm_client.LlmBudgetExhausted("cutoff")
    root = _repo(tmp_path)
    monkeypatch.setattr(sys.modules["pipeline.risk_rerank"], "call_llm", over)
    assert _risk(_plan(agent, root))[HANDLER] == "MEDIUM"


def test_no_calls_when_llm_off_or_flag_off(agent, tmp_path, monkeypatch):
    fake = _answer({HANDLER: ["errors"]})
    monkeypatch.setattr(sys.modules["pipeline.risk_rerank"], "call_llm", fake)
    root = _repo(tmp_path)
    _plan(agent, root, use_llm=False)
    _plan(agent, root, rerank_leftover_files=False)
    assert fake.sent == []


def test_generated_and_vendored_leftovers_are_not_sent(agent, risk_rerank, tmp_path):
    (tmp_path / "Gen.java").write_text("// DO NOT EDIT\nclass Gen {}\n", encoding="utf-8")
    (tmp_path / "Ok.java").write_text("class Ok {}\n", encoding="utf-8")
    (tmp_path / "app.min.js").write_text("var a=1;", encoding="utf-8")
    sent = [c["path"] for c in risk_rerank.select_candidates(tmp_path, ["Gen.java", "Ok.java", "app.min.js", "Missing.java"])]
    assert sent == ["Ok.java"]


def test_candidates_are_capped(risk_rerank, tmp_path):
    for i in range(5):
        (tmp_path / f"F{i}.java").write_text("class F {}\n", encoding="utf-8")
    got = risk_rerank.select_candidates(tmp_path, [f"F{i}.java" for i in range(5)], limit=3)
    assert [c["path"] for c in got] == ["F0.java", "F1.java", "F2.java"]


def test_batches_split_and_unknown_paths_are_ignored(risk_rerank, tmp_path):
    paths = []
    for i in range(10):
        (tmp_path / f"F{i}.java").write_text("class F {}\n", encoding="utf-8")
        paths.append(f"F{i}.java")
    calls = []

    def fake(system, user, **kwargs):
        calls.append(user)
        return json.dumps({"decisions": [
            {"path": "F0.java", "handles": "auth"},
            {"path": "Elsewhere.java", "handles": ["auth"]},
        ]})
    got = risk_rerank.rerank_leftover_files(tmp_path, paths, call_llm_fn=fake, workers=1)
    assert len(calls) == 2  # 10 files, 8 per call
    assert got["considered"] == 10
    assert got["promoted"] == {"F0.java": ["auth"]}


def test_promotes_to_critical_when_the_project_deep_scans_critical_only(agent, tmp_path, monkeypatch):
    """With deep-scan-critical-only a HIGH file never reaches the deep scan, so
    promoting to HIGH would change nothing: the target tier follows the setting."""
    root = _repo(tmp_path)
    fake = _answer({HANDLER: ["errors"]})
    monkeypatch.setattr(sys.modules["pipeline.risk_rerank"], "call_llm", fake)
    plan = _plan(agent, root, deep_scan_critical_only=True)
    assert _risk(plan)[HANDLER] == "CRITICAL"
    assert HANDLER in plan["deep_scan_paths"]
    assert plan["risk_counts"]["CRITICAL"] >= 1 and plan["llm_promoted"] == 1

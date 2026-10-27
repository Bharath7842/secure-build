"""openai_cli: one `exec --json` subprocess per call, one thread per scan."""

import json
import re
import subprocess
import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

SAST_ENGINE_DIR = Path(__file__).resolve().parents[1] / "sast_engine"

pytest.importorskip("boto3", reason="llm_client requires boto3")
pytest.importorskip("langgraph", reason="sast_scan_agent requires langgraph")

SESSION = "11111111-2222-3333-4444-555555555555"
THREAD = "01a17b3c-79d0-71c2-a6f0-aa0146ba2fdd"


@pytest.fixture()
def llm(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    if str(SAST_ENGINE_DIR) not in sys.path:
        sys.path.insert(0, str(SAST_ENGINE_DIR))
    import llm_client as module

    monkeypatch.setattr(module.time, "sleep", lambda _s: None)
    monkeypatch.setattr(module, "OPENAI_CLI_PATH", "/usr/bin/agent-cli")
    module._OPENAI_CLI_SESSIONS.clear()
    return module


def _proc(text='{"findings": []}', *, returncode=0, stderr="", events=None, usage=None, thread=THREAD):
    proc = MagicMock()
    proc.returncode = returncode
    proc.stderr = stderr
    if events is None:
        events = [
            {"type": "thread.started", "thread_id": thread},
            {"type": "turn.started"},
            {"type": "item.completed", "item": {"id": "item_0", "type": "agent_message", "text": text}},
            {"type": "turn.completed", "usage": usage if usage is not None else {
                "input_tokens": 130, "cached_input_tokens": 100,
                "cache_write_input_tokens": 0, "output_tokens": 8,
            }},
        ]
    proc.stdout = "\n".join(json.dumps(e) for e in events)
    return proc


def _usage(llm, tmp_path, session_id=SESSION):
    return llm.init_usage(
        "openai_cli", "gpt-5.6-sol",
        provider_options={"openai_cli": {"session_id": session_id, "workdir": str(tmp_path / "wd")}},
    )


def test_is_a_known_uncapped_provider_with_a_default_model(llm):
    assert "openai_cli" in llm.KNOWN_PROVIDERS
    usage = llm.init_usage("openai_cli", None)
    assert usage["model"] == llm.OPENAI_CLI_MODEL == "gpt-5.6-sol"
    assert usage["cost_cutoff_usd"] is None
    assert llm._price_per_mtok("openai_cli", "gpt-5.6-sol") == (
        llm.OPENAI_CLI_INPUT_PRICE_PER_MTOK, llm.OPENAI_CLI_OUTPUT_PRICE_PER_MTOK,
    )


def test_first_call_creates_a_thread_then_resumes_it(llm, monkeypatch, tmp_path):
    run = MagicMock(return_value=_proc())
    monkeypatch.setattr(llm.subprocess, "run", run)
    usage = _usage(llm, tmp_path)

    out = llm.call_llm("SYS", "USER", usage=usage, step="unit", json_mode=True)

    assert out == '{"findings": []}'
    first = run.call_args_list[0].args[0]
    assert first[:2] == ["/usr/bin/agent-cli", "exec"]
    assert "resume" not in first and "--ephemeral" not in first
    assert first[first.index("-m") + 1] == "gpt-5.6-sol"
    assert 'sandbox_mode="read-only"' in first and "--ignore-user-config" in first
    assert first[-1] == "-"
    sent = run.call_args_list[0].kwargs["input"]
    assert "SYS" in sent and "USER" in sent and "JSON object only" in sent
    assert run.call_args_list[0].kwargs["cwd"] == str(tmp_path / "wd")
    assert (tmp_path / "wd").is_dir()

    llm.call_llm("SYS2", "USER2", usage=usage, step="unit", json_mode=True)
    second = run.call_args_list[1].args[0]
    assert second[:4] == ["/usr/bin/agent-cli", "exec", "resume", THREAD]


def test_records_usage_with_cached_tokens(llm, monkeypatch, tmp_path):
    monkeypatch.setattr(llm.subprocess, "run", MagicMock(return_value=_proc()))
    usage = _usage(llm, tmp_path)
    meta = {}

    llm.call_llm("s", "u", usage=usage, step="unit", json_mode=True, meta_out=meta)

    assert usage["input_tokens"] == 130  # already the logical prompt size
    assert usage["output_tokens"] == 8
    assert usage["calls"][-1]["provider"] == "openai_cli"
    assert usage["cost_usd"] > 0
    assert meta["input_tokens"] == 130


def test_failed_first_call_keeps_creating_the_thread(llm, monkeypatch, tmp_path):
    run = MagicMock(side_effect=[
        _proc(returncode=1, stderr="boom", events=[]),
        _proc(),
    ])
    monkeypatch.setattr(llm.subprocess, "run", run)

    llm.call_llm("s", "u", usage=_usage(llm, tmp_path), step="unit", json_mode=True)

    assert "resume" not in run.call_args_list[1].args[0]


def test_turn_failed_is_retried_then_raised(llm, monkeypatch, tmp_path):
    bad = _proc(events=[
        {"type": "thread.started", "thread_id": THREAD},
        {"type": "turn.failed", "error": {"message": "model exploded"}},
    ])
    run = MagicMock(return_value=bad)
    monkeypatch.setattr(llm.subprocess, "run", run)

    with pytest.raises(RuntimeError, match="model exploded"):
        llm.call_llm("s", "u", usage=_usage(llm, tmp_path), step="unit", retries=2)

    assert run.call_count == 2


def test_missing_thread_starts_a_new_one_without_using_a_retry(llm, monkeypatch, tmp_path):
    run = MagicMock(side_effect=[
        _proc(),
        _proc(returncode=1, stderr="thread/resume failed: no rollout found for thread id x", events=[]),
        _proc(thread="new-thread"),
        _proc(),
    ])
    monkeypatch.setattr(llm.subprocess, "run", run)
    usage = _usage(llm, tmp_path)

    llm.call_llm("s", "u", usage=usage, step="unit", retries=1)
    llm.call_llm("s", "u", usage=usage, step="unit", retries=1)  # resume fails, restarts fresh
    llm.call_llm("s", "u", usage=usage, step="unit", retries=1)

    assert "resume" in run.call_args_list[1].args[0]
    assert "resume" not in run.call_args_list[2].args[0]
    assert run.call_args_list[3].args[0][:4][-1] == "new-thread"


def test_rate_limit_backs_off_without_using_a_retry(llm, monkeypatch, tmp_path):
    run = MagicMock(side_effect=[
        _proc(returncode=1, stderr="429 rate limit reached", events=[]),
        _proc(),
    ])
    monkeypatch.setattr(llm.subprocess, "run", run)

    out = llm.call_llm("s", "u", usage=_usage(llm, tmp_path), step="unit", retries=1)

    assert out == '{"findings": []}'
    assert run.call_count == 2


def test_timeout_is_retried(llm, monkeypatch, tmp_path):
    run = MagicMock(side_effect=[subprocess.TimeoutExpired("x", 1), _proc()])
    monkeypatch.setattr(llm.subprocess, "run", run)

    llm.call_llm("s", "u", usage=_usage(llm, tmp_path), step="unit")

    assert run.call_count == 2


def test_missing_binary_is_not_retried(llm, monkeypatch, tmp_path):
    monkeypatch.setattr(llm, "OPENAI_CLI_PATH", "")
    monkeypatch.delenv("CODEX_CLI_PATH", raising=False)
    monkeypatch.setattr(llm.shutil, "which", lambda _n: None)
    run = MagicMock()
    monkeypatch.setattr(llm.subprocess, "run", run)

    with pytest.raises(Exception, match="OpenAI CLI not found"):
        llm.call_llm("s", "u", usage=_usage(llm, tmp_path), step="unit")

    run.assert_not_called()


def test_without_a_session_the_call_is_ephemeral(llm, monkeypatch):
    run = MagicMock(return_value=_proc())
    monkeypatch.setattr(llm.subprocess, "run", run)
    usage = llm.init_usage("openai_cli", "gpt-5.6-sol")

    llm.call_llm("s", "u", usage=usage, step="unit")

    cmd = run.call_args.args[0]
    assert "--ephemeral" in cmd and "resume" not in cmd
    assert run.call_args.kwargs["cwd"] is None


def test_calls_of_one_scan_never_overlap(llm, monkeypatch, tmp_path):
    active = []
    overlap = []

    def fake_run(cmd, **_kw):
        active.append(1)
        if len(active) > 1:
            overlap.append(1)
        time.sleep(0.02)
        active.pop()
        return _proc()

    monkeypatch.setattr(llm.time, "sleep", time.sleep)
    monkeypatch.setattr(llm.subprocess, "run", fake_run)
    usage = _usage(llm, tmp_path)
    threads = [
        threading.Thread(target=llm.call_llm, args=("s", "u"), kwargs={"usage": usage, "step": "unit"})
        for _ in range(4)
    ]
    [t.start() for t in threads]
    [t.join() for t in threads]

    assert overlap == []


def test_no_user_facing_label_names_the_cli():
    from app.defaults.llm_presets import LLM_PRESETS
    from app.services.scan_export import _llm_display
    from app.services.scan_runner import _PROVIDER_LABELS, _friendly_llm_label

    presets = [p for p in LLM_PRESETS if p.provider == "openai_cli"]
    assert {p.model for p in presets} == {"gpt-6-astra", "gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna"}
    shown = [p.label for p in presets] + [_PROVIDER_LABELS["openai_cli"]]
    shown += [_friendly_llm_label("openai_cli", p.model, True) for p in presets]
    scan = MagicMock(llm_provider="openai_cli", llm_model="gpt-5.6-sol")
    shown.append(_llm_display(scan))
    assert shown[-1] == "GPT-5.6 Sol"
    assert not [s for s in shown if re.search("codex", s, re.IGNORECASE)]

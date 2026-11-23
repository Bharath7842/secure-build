"""The live LLM call log (sast_engine/llm_events.py) read by tools/llm_monitor."""

import json
import sys
from pathlib import Path

import pytest

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


class _Resp:
    status_code = 200
    is_redirect = False
    headers: dict = {}

    def raise_for_status(self):
        return None

    def json(self):
        return {"message": {"content": '{"findings": []}'}, "prompt_eval_count": 12, "eval_count": 3, "done_reason": "stop"}


def _events(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def _usage(llm, path, **extra):
    return llm.init_usage("ollama", "test-model", event_context={"file": str(path), "scan_id": "scan-1"}, **extra)


def test_successful_call_logs_queued_started_done(llm, monkeypatch, tmp_path):
    log = tmp_path / "events.jsonl"
    monkeypatch.setattr(llm.requests, "post", lambda *a, **k: _Resp())

    llm.call_llm("system text", "user text", usage=_usage(llm, log), step="scan_deep_files")

    events = _events(log)
    assert [e["event"] for e in events] == ["queued", "started", "done"]
    assert {e["id"] for e in events} == {events[0]["id"]}
    assert all(e["scan_id"] == "scan-1" for e in events)
    queued, done = events[0], events[2]
    assert (queued["step"], queued["provider"], queued["model"]) == ("scan_deep_files", "ollama", "test-model")
    assert queued["user"] == "user text" and queued["user_chars"] == 9
    assert (done["input_tokens"], done["output_tokens"], done["stop_reason"]) == (12, 3, "stop")
    assert done["response"] == '{"findings": []}' and done["duration_ms"] >= 0


def test_full_prompt_and_response_are_saved_beside_the_log(llm, monkeypatch, tmp_path):
    import llm_events

    log = tmp_path / "events.jsonl"
    long_user = "u" * (llm_events.USER_PREVIEW_CHARS + 500)
    long_system = "s" * (llm_events.SYSTEM_PREVIEW_CHARS + 500)
    monkeypatch.setattr(llm.requests, "post", lambda *a, **k: _Resp())
    usage = _usage(llm, log)
    llm.call_llm(long_system, long_user, usage=usage, step="scan_deep_files")
    llm.call_llm(long_system, "second", usage=usage, step="scan_deep_files")

    queued = [e for e in _events(log) if e["event"] == "queued"]
    assert queued[0]["user"].endswith("[+500 chars]")  # the JSONL keeps previews
    bodies = tmp_path / "events_bodies"
    assert (bodies / f"{queued[0]['id']}.user.txt").read_text() == long_user
    assert (bodies / f"{queued[0]['id']}.response.txt").read_text() == '{"findings": []}'
    assert queued[0]["system_sha"] == queued[1]["system_sha"]
    assert (bodies / f"system-{queued[0]['system_sha']}.txt").read_text() == long_system
    assert len(list(bodies.glob("system-*.txt"))) == 1  # one copy per distinct system prompt


def test_gpt_oss_gets_a_thinking_budget_and_its_reasoning_is_saved(llm, monkeypatch, tmp_path):
    log = tmp_path / "events.jsonl"
    sent = {}

    class _Thinking(_Resp):
        def json(self):
            return {"message": {"content": '{"findings": []}', "thinking": "let me check"},
                    "prompt_eval_count": 5, "eval_count": 40, "done_reason": "stop"}

    def post(_url, json=None, **_k):
        sent.update(json)
        return _Thinking()

    monkeypatch.setattr(llm.requests, "post", post)
    usage = llm.init_usage("ollama", "gpt-oss:20b", event_context={"file": str(log), "scan_id": "s"})
    llm.call_llm("s", "u", usage=usage, step="scan_deep_files", max_tokens=512)

    assert sent["think"] == llm.OLLAMA_THINK_LEVEL
    assert sent["options"]["num_predict"] == 512 + llm.OLLAMA_THINKING_TOKENS
    call_id = _events(log)[0]["id"]
    assert (tmp_path / "events_bodies" / f"{call_id}.thinking.txt").read_text() == "let me check"


class _Stream(_Resp):
    def __init__(self, chunks):
        self._chunks = chunks
        self.closed = False

    def iter_lines(self):
        for chunk in self._chunks:
            yield json.dumps(chunk).encode()

    def close(self):
        self.closed = True


def test_reasoning_streams_into_the_scan_log_as_thinking_lines(llm, monkeypatch, tmp_path):
    sent, logged = {}, []
    stream = _Stream([
        {"message": {"thinking": "Look at the query.\nThe id is "}, "done": False},
        {"message": {"thinking": "concatenated."}, "done": False},
        {"message": {"content": '{"findings": '}, "done": False},
        {"message": {"content": "[]}"}, "done": False},
        {"message": {}, "done": True, "done_reason": "stop", "prompt_eval_count": 7, "eval_count": 30},
    ])

    def post(_url, json=None, stream=False, **_k):
        sent.update(json, stream_kw=stream)
        return stream_resp

    stream_resp = stream
    monkeypatch.setattr(llm.requests, "post", post)
    usage = llm.init_usage("ollama", "gpt-oss:20b", log_sink=lambda line, stage=None: logged.append((line, stage)))
    llm.reserve_stage_budgets(usage)  # a parallel scan: the deep stage is running

    text = llm.call_llm("s", "u", usage=usage, step="scan_deep_files")

    assert text == '{"findings": []}'
    assert sent["stream"] is True and sent["stream_kw"] is True and stream.closed
    assert logged == [
        ("[thinking] Look at the query.", "deep"),
        ("[thinking] The id is concatenated.", "deep"),
    ]
    assert usage["input_tokens"] == 7 and usage["output_tokens"] == 30


def test_reasoning_lines_are_capped_per_call_and_untagged_after_the_stage_ends(llm, monkeypatch):
    logged = []
    monkeypatch.setattr(llm, "THINKING_LOG_MAX_LINES", 2)
    chunks = [{"message": {"thinking": f"line {i}\n"}, "done": False} for i in range(5)]
    chunks.append({"message": {"content": "{}"}, "done": True, "done_reason": "stop"})
    monkeypatch.setattr(llm.requests, "post", lambda *a, **k: _Stream(chunks))
    usage = llm.init_usage("ollama", "gpt-oss:20b", log_sink=lambda line, stage=None: logged.append((line, stage)))
    llm.reserve_stage_budgets(usage)
    llm.finish_stage(usage, "triage")  # group confirmation runs after the join

    llm.call_llm("s", "u", usage=usage, step="group_confirm_triage_findings")

    assert [line for line, _ in logged[:2]] == ["[thinking] line 0", "[thinking] line 1"]
    assert "more chars of reasoning" in logged[2][0]
    assert len(logged) == 3 and {stage for _, stage in logged} == {None}


def test_reasoning_text_never_moves_scan_progress():
    from app.services.scan_progress import ProgressTracker

    tracker = ProgressTracker()
    assert tracker.feed("[[stage:deep]] [thinking] Stage finished: deep") == tracker.feed("[thinking] Repository ready")
    assert tracker.feed("Repository ready") > 0


def test_logs_read_from_disk_once_memory_dropped_older_lines(monkeypatch, tmp_path):
    from app.services import scan_log

    monkeypatch.setattr(scan_log, "_logs_dir", lambda: tmp_path)
    monkeypatch.setattr(scan_log, "_MAX_LINES_PER_SCAN", 3)
    scan_log.reset("scan-x")
    for i in range(5):
        scan_log.log("scan-x", f"line {i}")
    assert [row["line"] for row in scan_log.get_logs("scan-x", after=0)[0]] == [f"line {i}" for i in range(5)]
    assert [row["line"] for row in scan_log.get_logs("scan-x", after=3)[0]] == ["line 3", "line 4"]
    scan_log.log("scan-x", "staged", stage="deep")
    assert scan_log.get_logs("scan-x", after=5)[0][0]["line"] == "[[stage:deep]] staged"


def test_rotation_prunes_bodies_of_the_discarded_log(monkeypatch, tmp_path):
    import os

    if str(SAST_ENGINE_DIR) not in sys.path:
        sys.path.insert(0, str(SAST_ENGINE_DIR))
    import llm_events

    log = tmp_path / "events.jsonl"
    usage = {llm_events.USAGE_KEY: {"file": str(log)}}
    old, new = tmp_path / "events.jsonl.1", tmp_path / "events_bodies"
    old.write_text("old")
    llm_events.store_body(usage, "gone.user.txt", "a")
    llm_events.store_body(usage, "kept.user.txt", "b")
    os.utime(new / "gone.user.txt", (1000, 1000))
    os.utime(old, (2000, 2000))
    log.write_text("x" * 50)
    monkeypatch.setattr(llm_events, "MAX_BYTES", 10)
    llm_events.emit(usage, "queued", "id1")
    assert sorted(p.name for p in new.iterdir()) == ["kept.user.txt"]


def test_retry_then_failure_is_logged_with_reasons(llm, monkeypatch, tmp_path):
    log = tmp_path / "events.jsonl"

    def refuse(*_a, **_k):
        raise llm.requests.ConnectionError("refused")

    monkeypatch.setattr(llm.requests, "post", refuse)
    with pytest.raises(llm.requests.ConnectionError):
        llm.call_llm("s", "u", usage=_usage(llm, log), step="scan_deep_files", retries=3)

    kinds = [e["event"] for e in _events(log)]
    assert kinds == ["queued", "started", "retry", "retry", "retry", "failed"]
    assert "ConnectionError" in _events(log)[2]["reason"]


def test_cancelled_call_is_logged_as_cancelled(llm, monkeypatch, tmp_path):
    log = tmp_path / "events.jsonl"
    flag = {"cancelled": False}
    monkeypatch.setattr(llm.requests, "post", lambda *a, **k: _Resp())
    usage = _usage(llm, log)
    usage[llm.CANCEL_CHECK_USAGE_KEY] = lambda: flag["cancelled"]
    original_slot = llm.llm_gate.GATE.slot

    def slot_then_cancel(*args, **kwargs):
        flag["cancelled"] = True  # cancelled while the call waited for its slot
        return original_slot(*args, **kwargs)

    # Ollama calls wait in llm_gate's ordered gate, not the adaptive limiter.
    monkeypatch.setattr(llm.llm_gate.GATE, "slot", slot_then_cancel)
    with pytest.raises(llm.LlmScanCancelled):
        llm.call_llm("s", "u", usage=usage, step="scan_deep_files")
    assert [e["event"] for e in _events(log)] == ["queued", "cancelled"]


def test_no_event_context_writes_nothing(llm, monkeypatch, tmp_path):
    monkeypatch.setattr(llm.requests, "post", lambda *a, **k: _Resp())
    llm.call_llm("s", "u", usage=llm.init_usage("ollama", "test-model"), step="scan_deep_files")
    assert list(tmp_path.iterdir()) == []


def test_unwritable_log_never_fails_the_call(llm, monkeypatch, tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    monkeypatch.setattr(llm.requests, "post", lambda *a, **k: _Resp())
    usage = _usage(llm, blocker / "events.jsonl")  # parent is a file: every write fails
    assert llm.call_llm("s", "u", usage=usage, step="scan_deep_files") == '{"findings": []}'


def test_log_rotates_past_its_size_limit(llm, monkeypatch, tmp_path):
    import llm_events

    log = tmp_path / "events.jsonl"
    log.write_text("x" * 50)
    monkeypatch.setattr(llm_events, "MAX_BYTES", 10)
    llm_events.emit({llm_events.USAGE_KEY: {"file": str(log)}}, "queued", "id1")
    assert (tmp_path / "events.jsonl.1").read_text() == "x" * 50
    assert _events(log)[0]["id"] == "id1"


def test_scan_options_carry_the_event_context_only_when_configured(monkeypatch):
    from types import SimpleNamespace

    from app.config import settings
    from app.services import agent_bridge

    monkeypatch.setattr(agent_bridge.llm_policy, "load_policy", lambda: {})
    monkeypatch.setattr(agent_bridge.llm_policy, "engine_policy", lambda _policy: {})
    project = SimpleNamespace(llm_base_url=None, llm_api_key=None, limitations_config={}, llm_provider=None)
    scan = SimpleNamespace(id="scan-9", llm_base_url=None, llm_provider=None, llm_model=None)
    assert agent_bridge.llm_usage_options(project, scan)["event_context"] is None
    monkeypatch.setattr(settings, "llm_events_file", "/tmp/x.jsonl")
    assert agent_bridge.llm_usage_options(project, scan)["event_context"] == {"file": "/tmp/x.jsonl", "scan_id": "scan-9"}

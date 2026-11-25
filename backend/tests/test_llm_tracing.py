"""Optional Langfuse tracing of SAST LLM calls (sast_engine/llm_tracing.py)."""

import json
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

SAST_ENGINE_DIR = Path(__file__).resolve().parents[1] / "sast_engine"
CTX = {
    "host": "http://localhost:3200", "public_key": "pk-lf-test", "secret_key": "sk-lf-test",
    "scan_id": "scan-1", "project": "demo", "policy": {"allowed_hosts": [], "allow_loopback": True},
}


class _Resp:
    status_code = 200
    is_redirect = False
    headers: dict = {}

    def raise_for_status(self):
        return None

    def json(self):
        return {"message": {"content": '{"findings": []}'}, "prompt_eval_count": 12, "eval_count": 3, "done_reason": "stop"}


@pytest.fixture()
def llm(monkeypatch):
    pytest.importorskip("boto3", reason="llm_client requires boto3")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    if str(SAST_ENGINE_DIR) not in sys.path:
        sys.path.insert(0, str(SAST_ENGINE_DIR))
    import llm_client as module

    monkeypatch.setattr(module.time, "sleep", lambda _s: None)
    monkeypatch.setattr(module.llm_tracing, "_paused_until", 0.0)
    return module


class _Langfuse:
    """Stands in for `requests.post`: model calls answer, Langfuse calls are kept."""

    def __init__(self, status=200, error=None, model_error=None):
        self.sent, self.status, self.error, self.model_error = [], status, error, model_error
        self.arrived = threading.Event()

    def __call__(self, url, **kwargs):
        if "/api/public/otel" not in url:
            if self.model_error:
                raise self.model_error
            return _Resp()
        self.sent.append((url, kwargs))
        self.arrived.set()
        if self.error:
            raise self.error
        return SimpleNamespace(status_code=self.status)

    def spans(self):
        return [
            s for _url, kw in self.sent
            for s in json.loads(kw["data"])["resourceSpans"][0]["scopeSpans"][0]["spans"]
        ]


def _wait(llm):
    # `time.sleep` is patched away, so join on the queue rather than poll it.
    llm.llm_tracing._QUEUE.join()


def _attrs(span):
    return {a["key"]: a["value"].get("stringValue") for a in span["attributes"]}


def _call(llm, monkeypatch, langfuse, *, ctx=CTX, system="system text", user="user text", usage=None, **kw):
    monkeypatch.setattr(llm.requests, "post", langfuse)
    usage = usage or llm.init_usage("ollama", "test-model", tracing=ctx, mask_secrets=False)
    try:
        return llm.call_llm(system, user, usage=usage, step="scan_deep_files", **kw)
    finally:
        _wait(llm)


def test_a_finished_call_becomes_one_generation(llm, monkeypatch):
    langfuse = _Langfuse()
    assert _call(llm, monkeypatch, langfuse) == '{"findings": []}'

    (url, kwargs), = langfuse.sent
    assert url == "http://localhost:3200/api/public/otel/v1/traces"
    assert kwargs["auth"] == ("pk-lf-test", "sk-lf-test")
    assert kwargs["allow_redirects"] is False
    span, = langfuse.spans()
    attrs = _attrs(span)
    assert span["traceId"] == llm.llm_tracing.trace_id("scan-1") and len(span["traceId"]) == 32
    assert attrs["langfuse.observation.type"] == "generation"
    assert attrs["langfuse.observation.model.name"] == "test-model"
    assert attrs["langfuse.session.id"] == "scan-1"
    assert json.loads(attrs["langfuse.observation.usage_details"]) == {"input": 12, "output": 3, "total": 15}
    assert [m["content"] for m in json.loads(attrs["langfuse.observation.input"])] == ["system text", "user text"]
    assert attrs["langfuse.observation.output"] == '{"findings": []}'
    assert int(span["endTimeUnixNano"]) >= int(span["startTimeUnixNano"])


def test_without_tracing_nothing_is_sent(llm, monkeypatch):
    langfuse = _Langfuse()
    assert _call(llm, monkeypatch, langfuse, ctx=None) == '{"findings": []}'
    assert langfuse.sent == []


@pytest.mark.parametrize("langfuse", [_Langfuse(status=500), _Langfuse(status=302), _Langfuse(error=ConnectionError("down"))])
def test_langfuse_failing_pauses_tracing_and_never_fails_the_call(llm, monkeypatch, capsys, langfuse):
    assert _call(llm, monkeypatch, langfuse) == '{"findings": []}'
    assert _call(llm, monkeypatch, langfuse) == '{"findings": []}'
    assert len(langfuse.sent) == 1  # paused: the second call is not sent
    out = capsys.readouterr().out
    assert "tracing paused" in out and "sk-lf" not in out


def test_a_full_queue_drops_instead_of_blocking(llm, monkeypatch):
    class _Full:
        def put_nowait(self, _item):
            raise llm.llm_tracing.queue.Full

    before = llm.llm_tracing.dropped
    with monkeypatch.context() as m:
        m.setattr(llm.llm_tracing, "_QUEUE", _Full())
        m.setattr(llm.requests, "post", _Langfuse())
        usage = llm.init_usage("ollama", "test-model", tracing=CTX)
        assert llm.call_llm("s", "u", usage=usage, step="scan_deep_files") == '{"findings": []}'
    assert llm.llm_tracing.dropped == before + 1


def test_secrets_are_masked_even_when_scan_masking_is_off(llm, monkeypatch):
    langfuse = _Langfuse()
    _call(llm, monkeypatch, langfuse, user='String password = "hunter2-very-secret";')
    body = langfuse.sent[0][1]["data"].decode()
    assert "hunter2-very-secret" not in body and "REDACTED" in body
    assert "sk-lf-test" not in body


def test_a_failed_call_is_an_error_observation_and_still_raises(llm, monkeypatch):
    langfuse = _Langfuse(model_error=ValueError("model broke"))
    with pytest.raises(Exception):
        _call(llm, monkeypatch, langfuse, retries=1)
    span, = langfuse.spans()
    assert _attrs(span)["langfuse.observation.level"] == "ERROR"
    assert span["status"] == {"code": 2}


def test_a_cached_answer_is_not_counted_as_a_generation(llm, monkeypatch):
    class _Cache:
        def get(self, _key):
            return {"text": '{"findings": []}', "input_tokens": 5, "output_tokens": 2}

    langfuse = _Langfuse()
    usage = llm.init_usage("ollama", "test-model", tracing=CTX)
    usage[llm.RESULT_CACHE_USAGE_KEY] = _Cache()
    _call(llm, monkeypatch, langfuse, usage=usage, json_mode=True)
    attrs = _attrs(langfuse.spans()[0])
    assert attrs["langfuse.observation.type"] == "span"
    assert "langfuse.observation.usage_details" not in attrs


def test_a_host_the_policy_refuses_at_send_time_gets_nothing(llm, monkeypatch):
    langfuse = _Langfuse()
    _call(llm, monkeypatch, langfuse, ctx={**CTX, "host": "http://169.254.169.254"})
    assert langfuse.sent == []


# --- configuration -----------------------------------------------------------


def _context(monkeypatch, host, *, allowed=(), loopback=True, secret="sk-lf-x"):
    from pydantic import SecretStr

    from app.config import settings
    from app.services import llm_policy

    monkeypatch.setattr(settings, "langfuse_host", host)
    monkeypatch.setattr(settings, "langfuse_public_key", "pk-lf-x")
    monkeypatch.setattr(settings, "langfuse_secret_key", SecretStr(secret) if secret else None)
    return llm_policy.langfuse_context(
        SimpleNamespace(name="demo"), SimpleNamespace(id="scan-9"),
        {"allowed_hosts": list(allowed), "allow_loopback": loopback},
    )


def test_local_langfuse_is_allowed(monkeypatch):
    ctx = _context(monkeypatch, "http://localhost:3200/")
    assert (ctx["host"], ctx["scan_id"], ctx["project"]) == ("http://localhost:3200", "scan-9", "demo")


@pytest.mark.parametrize("kwargs", [
    {"host": ""},
    {"host": "http://localhost:3200", "secret": ""},
    {"host": "http://localhost:3200", "loopback": False},
    {"host": "https://8.8.8.8"},  # public https: fine for an LLM endpoint, not for traces
    {"host": "http://10.0.0.5:3000"},
    {"host": "http://169.254.169.254", "allowed": ["169.254.169.254"]},
    {"host": "file:///etc/passwd"},
])
def test_tracing_stays_off(monkeypatch, kwargs):
    assert _context(monkeypatch, **kwargs) is None


def test_an_approved_host_is_allowed(monkeypatch):
    assert _context(monkeypatch, "https://8.8.8.8", allowed=["8.8.8.8"])["host"] == "https://8.8.8.8"
    assert _context(monkeypatch, "http://10.0.0.5:3000", allowed=["10.0.0.5:3000"])["host"] == "http://10.0.0.5:3000"


def test_scan_options_have_no_tracing_by_default(monkeypatch):
    from app.services import agent_bridge

    monkeypatch.setattr(agent_bridge.llm_policy, "load_policy", lambda: {})
    monkeypatch.setattr(agent_bridge.llm_policy, "engine_policy", lambda _policy: {})
    project = SimpleNamespace(llm_base_url=None, llm_api_key=None, limitations_config={}, llm_provider=None)
    scan = SimpleNamespace(id="scan-9", llm_base_url=None, llm_provider=None, llm_model=None)
    assert agent_bridge.llm_usage_options(project, scan)["tracing"] is None

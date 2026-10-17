"""Regression tests for the pluggable LLM backend in llm_client.py."""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

SAST_ENGINE_DIR = Path(__file__).resolve().parents[1] / "sast_engine"

pytest.importorskip("boto3", reason="llm_client requires boto3")
pytest.importorskip("langgraph", reason="sast_scan_agent requires langgraph")


@pytest.fixture()
def llm(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    if str(SAST_ENGINE_DIR) not in sys.path:
        sys.path.insert(0, str(SAST_ENGINE_DIR))
    import llm_client as module

    return module


def test_init_usage_defaults_to_bedrock_haiku(llm):
    usage = llm.init_usage()
    assert usage["provider"] == "bedrock"
    assert usage["model"] == llm.BEDROCK_MODEL_ID
    assert usage["cost_cutoff_usd"] == pytest.approx(llm.LLM_COST_CUTOFF_USD)
    # No Ollama dependency: past the cutoff, LLM work stops unless a
    # fallback provider is configured explicitly.
    assert usage["fallback_provider"] == "none"


def test_init_usage_honors_ollama_provider_and_model(llm):
    usage = llm.init_usage("ollama", "granite-code:3b")
    assert usage["provider"] == "ollama"
    assert usage["model"] == "granite-code:3b"
    assert usage["cost_cutoff_usd"] is None


def test_init_usage_ollama_without_model_falls_back_to_default(llm):
    usage = llm.init_usage("ollama", None)
    assert usage["model"] == llm.OLLAMA_MODEL


def test_call_llm_routes_to_bedrock_by_default(llm, monkeypatch):
    called = {}

    def fake_bedrock(*_a, **kwargs):
        called["model_id"] = _a[2] if len(_a) > 2 else kwargs.get("model_id")
        # signature: system, user, model_id, ...
        called["model_id"] = _a[2]
        return "bedrock response"

    monkeypatch.setattr(llm, "_call_bedrock", fake_bedrock)
    result = llm.call_llm("sys", "usr", step="test")
    assert result == "bedrock response"
    assert called["model_id"] == llm.BEDROCK_MODEL_ID


def test_call_llm_routes_to_ollama_when_provider_is_ollama(llm, monkeypatch):
    called = {}

    def fake_ollama(*_a, **kwargs):
        called["model"] = _a[2]
        called["json_mode"] = kwargs.get("json_mode", False)
        return "ollama response"

    monkeypatch.setattr(llm, "_call_ollama", fake_ollama)
    result = llm.call_llm(
        "sys", "usr", provider="ollama", model="granite-code:3b", step="test", json_mode=True,
    )
    assert result == "ollama response"
    assert called["model"] == "granite-code:3b"
    assert called["json_mode"] is True


def test_call_llm_ollama_without_explicit_model_uses_default(llm, monkeypatch):
    called = {}

    def fake_ollama(*_a, **kwargs):
        called["model"] = _a[2]
        return "ok"

    monkeypatch.setattr(llm, "_call_ollama", fake_ollama)
    llm.call_llm("sys", "usr", provider="ollama", step="test")
    assert called["model"] == llm.OLLAMA_MODEL


def test_call_llm_stays_on_bedrock_under_cutoff(llm, monkeypatch):
    routes = []

    def fake_bedrock(*_a, **kwargs):
        routes.append("bedrock")
        usage = kwargs.get("usage")
        if usage is not None:
            # Simulate cheap call so cost stays under cutoff
            llm.record_llm_usage(usage, "test", 1_000, 1_000, provider="bedrock")
        return "ok"

    def fake_ollama(*_a, **kwargs):
        routes.append("ollama")
        return "ok"

    monkeypatch.setattr(llm, "_call_bedrock", fake_bedrock)
    monkeypatch.setattr(llm, "_call_ollama", fake_ollama)
    usage = llm.init_usage(
        "bedrock",
        llm.BEDROCK_MODEL_ID,
        fallback_provider="ollama",
        fallback_model="granite-code:3b",
        cost_cutoff_usd=2.0,
    )
    # Manually set cost just under cutoff without going through record twice
    usage["cost_usd"] = 1.99
    llm.call_llm("sys", "usr", provider="bedrock", usage=usage, step="batch_1")
    assert routes == ["bedrock"]
    assert usage["fallback_switched"] is False


def test_call_llm_switches_to_ollama_at_cutoff(llm, monkeypatch):
    routes = []

    def fake_bedrock(*_a, **kwargs):
        routes.append("bedrock")
        return "bedrock"

    def fake_ollama(*_a, **kwargs):
        routes.append("ollama")
        usage = kwargs.get("usage")
        if usage is not None:
            llm.record_llm_usage(usage, "test", 100, 50, provider="ollama")
        return "ollama"

    monkeypatch.setattr(llm, "_call_bedrock", fake_bedrock)
    monkeypatch.setattr(llm, "_call_ollama", fake_ollama)
    usage = llm.init_usage(
        "bedrock",
        llm.BEDROCK_MODEL_ID,
        fallback_provider="ollama",
        fallback_model="granite-code:8b",
        cost_cutoff_usd=2.0,
    )
    usage["cost_usd"] = 2.0
    text = llm.call_llm("sys", "usr", provider="bedrock", usage=usage, step="batch_2")
    assert text == "ollama"
    assert routes == ["ollama"]
    assert usage["fallback_switched"] is True
    assert usage["active_provider"] == "ollama"
    assert usage["active_model"] == "granite-code:8b"


def test_call_llm_ollama_primary_never_switches(llm, monkeypatch):
    routes = []

    def fake_bedrock(*_a, **kwargs):
        routes.append("bedrock")
        return "bedrock"

    def fake_ollama(*_a, **kwargs):
        routes.append("ollama")
        return "ollama"

    monkeypatch.setattr(llm, "_call_bedrock", fake_bedrock)
    monkeypatch.setattr(llm, "_call_ollama", fake_ollama)
    usage = llm.init_usage("ollama", "granite-code:3b")
    usage["cost_usd"] = 999.0  # would trip any cutoff if enabled
    llm.call_llm("sys", "usr", provider="ollama", usage=usage, step="batch")
    assert routes == ["ollama"]
    assert usage["cost_cutoff_usd"] is None
    assert usage["fallback_switched"] is False


def test_mixed_provider_cost_accumulates_per_call(llm):
    usage = llm.init_usage(
        "bedrock",
        llm.BEDROCK_MODEL_ID,
        fallback_provider="ollama",
        fallback_model="granite-code:3b",
        cost_cutoff_usd=2.0,
    )
    # 1M in + 1M out on Bedrock ≈ input+output prices
    llm.record_llm_usage(usage, "b1", 1_000_000, 1_000_000, provider="bedrock")
    bedrock_cost = usage["cost_usd"]
    assert bedrock_cost == pytest.approx(
        llm.BEDROCK_INPUT_PRICE_PER_MTOK + llm.BEDROCK_OUTPUT_PRICE_PER_MTOK
    )
    # Ollama call should add ~0
    llm.record_llm_usage(usage, "o1", 1_000_000, 1_000_000, provider="ollama")
    assert usage["cost_usd"] == pytest.approx(bedrock_cost)
    summary = llm.usage_cost_summary(usage)
    assert summary["cost_usd"] == pytest.approx(bedrock_cost)
    assert summary["call_count"] == 2
    assert usage["calls"][0]["provider"] == "bedrock"
    assert usage["calls"][1]["provider"] == "ollama"

def test_call_ollama_posts_chat_request_and_records_usage(llm, monkeypatch):
    fake_response = MagicMock()
    fake_response.raise_for_status = MagicMock()
    fake_response.json.return_value = {
        "message": {"role": "assistant", "content": "hello from ollama"},
        "prompt_eval_count": 12,
        "eval_count": 4,
    }
    post = MagicMock(return_value=fake_response)
    monkeypatch.setattr(llm.requests, "post", post)

    usage = llm.init_usage("ollama", "granite-code:3b")
    text = llm.call_llm(
        "system prompt", "user prompt", provider="ollama", model="granite-code:3b",
        usage=usage, step="unit_test", json_mode=True,
    )
    assert text == "hello from ollama"
    assert usage["input_tokens"] == 12
    assert usage["output_tokens"] == 4
    assert usage["estimated_tokens"] is False
    body = post.call_args.kwargs["json"]
    assert body["format"] == "json"
    assert body["options"]["num_ctx"] == llm.OLLAMA_NUM_CTX
    assert body["options"]["temperature"] == 0.0


def test_salvage_json_objects_keeps_complete_objects_from_truncated(llm):
    raw = (
        '[{"cwe": "CWE-89", "matcher": "(?i)executeQuery"}, '
        '{"cwe": "CWE-798", "matcher": "password\\s*=\\s*\\"...'  # unterminated
    )
    objs = llm.salvage_json_objects(raw)
    assert len(objs) == 1
    assert objs[0]["cwe"] == "CWE-89"


def test_parse_llm_json_array_salvages_malformed_array_commas(llm):
    raw = (
        '[{"title": "A", "file": "a.py", "verdict": "TRUE_POSITIVE"}, '
        '{"title": "B", "file": "b.py", "verdict": "NEEDS_REVIEW"}'  # missing closing ]
    )
    items, err = llm.parse_llm_json_array(raw)
    assert err is None
    assert len(items) == 2


def test_parse_llm_json_array_salvages_truncated_response(llm):
    raw = (
        '[{"cwe": "CWE-89", "matcher": "a+b"}, '
        '{"cwe": "CWE-79", "matcher": "innerHTML\\s*='  # cut mid-string
    )
    items, err = llm.parse_llm_json_array(raw)
    assert err is None
    assert len(items) == 1
    assert items[0]["cwe"] == "CWE-89"


def test_parse_llm_json_dict_ignores_trailing_extra_text(llm):
    raw = (
        '{"verdict": "TRUE_POSITIVE", "reasoning": "SQL concat", "severity": "HIGH"}\n'
        "Note: this flow is dangerous."
    )
    data, err = llm.parse_llm_json_dict(raw)
    assert err is None
    assert data["verdict"] == "TRUE_POSITIVE"


def test_usage_cost_summary_is_zero_cost_for_ollama_by_default(llm):
    usage = llm.init_usage("ollama", "granite-code:3b")
    llm.record_llm_usage(usage, "step", 1000, 500)
    summary = llm.usage_cost_summary(usage)
    assert summary["provider"] == "ollama"
    assert summary["cost_usd"] == 0.0


def test_usage_cost_summary_computes_bedrock_cost(llm):
    usage = llm.init_usage("bedrock")
    llm.record_llm_usage(usage, "step", 1_000_000, 1_000_000)
    summary = llm.usage_cost_summary(usage)
    assert summary["provider"] == "bedrock"
    expected = llm.BEDROCK_INPUT_PRICE_PER_MTOK + llm.BEDROCK_OUTPUT_PRICE_PER_MTOK
    assert summary["cost_usd"] == pytest.approx(expected)



def _openai_response(status=200, payload=None, text=""):
    resp = MagicMock()
    resp.status_code = status
    resp.text = text
    resp.json.return_value = payload or {}
    if status >= 400:
        resp.raise_for_status.side_effect = llm_http_error(status)
    else:
        resp.raise_for_status = MagicMock()
    return resp


def llm_http_error(status):
    import requests

    return requests.HTTPError(f"HTTP {status}")


@pytest.fixture()
def openai_llm(llm, monkeypatch):
    monkeypatch.setattr(llm, "_RESPONSE_FORMAT_UNSUPPORTED", set())
    monkeypatch.setattr(llm.time, "sleep", lambda _s: None)
    return llm


def test_call_openai_compat_posts_chat_completion_and_records_usage(openai_llm, monkeypatch):
    llm = openai_llm
    post = MagicMock(return_value=_openai_response(payload={
        "choices": [{
            "message": {"role": "assistant", "content": '<think>hmm</think>{"findings": []}'},
            "finish_reason": "stop",
        }],
        "usage": {
            "prompt_tokens": 120, "completion_tokens": 8,
            "prompt_tokens_details": {"cached_tokens": 100},
        },
    }))
    monkeypatch.setattr(llm.requests, "post", post)
    usage = llm.init_usage(
        "openai_compat", "qwen2.5-coder-32b",
        provider_options={"openai_compat": {"base_url": "http://10.0.0.5:8000/v1/", "api_key": "sk-test"}},
    )
    text = llm.call_llm("system", "user", usage=usage, step="unit", json_mode=True)

    # A local reasoning model's <think> preamble is stripped in JSON mode.
    assert text == '{"findings": []}'
    assert post.call_args.args[0] == "http://10.0.0.5:8000/v1/chat/completions"
    assert post.call_args.kwargs["headers"]["Authorization"] == "Bearer sk-test"
    body = post.call_args.kwargs["json"]
    assert body["model"] == "qwen2.5-coder-32b"
    assert body["response_format"] == {"type": "json_object"}
    assert [m["role"] for m in body["messages"]] == ["system", "user"]
    assert usage["input_tokens"] == 120
    assert usage["output_tokens"] == 8
    assert usage["cache_read_input_tokens"] == 100
    assert usage["calls"][0]["provider"] == "openai_compat"
    # Local endpoints are free by default.
    assert usage["cost_usd"] == 0.0


def test_call_openai_compat_retries_without_rejected_response_format(openai_llm, monkeypatch):
    llm = openai_llm
    ok = _openai_response(payload={
        "choices": [{"message": {"content": '{"rules": []}'}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 5, "completion_tokens": 2},
    })
    rejected = _openai_response(status=400, text='{"error": "response_format is not supported"}')
    post = MagicMock(side_effect=[rejected, ok, ok])
    monkeypatch.setattr(llm.requests, "post", post)
    usage = llm.init_usage("openai_compat", "local-model")

    assert llm.call_llm("s", "u", usage=usage, step="unit", json_mode=True) == '{"rules": []}'
    assert "response_format" in post.call_args_list[0].kwargs["json"]
    assert "response_format" not in post.call_args_list[1].kwargs["json"]
    # Remembered per endpoint: the next call skips the doomed attempt.
    llm.call_llm("s", "u2", usage=usage, step="unit", json_mode=True)
    assert post.call_count == 3
    assert "response_format" not in post.call_args_list[2].kwargs["json"]


def test_call_openai_compat_does_not_retry_auth_errors(openai_llm, monkeypatch):
    llm = openai_llm
    post = MagicMock(return_value=_openai_response(status=401, text="invalid api key"))
    monkeypatch.setattr(llm.requests, "post", post)
    usage = llm.init_usage("openai_compat", "m")
    with pytest.raises(RuntimeError, match="HTTP 401"):
        llm.call_llm("s", "u", usage=usage, step="unit")
    assert post.call_count == 1


def test_call_openai_compat_retries_server_errors(openai_llm, monkeypatch):
    llm = openai_llm
    ok = _openai_response(payload={"choices": [{"message": {"content": "hi"}}]})
    post = MagicMock(side_effect=[_openai_response(status=503), ok])
    monkeypatch.setattr(llm.requests, "post", post)
    usage = llm.init_usage("openai_compat", "m")
    assert llm.call_llm("s", "u", usage=usage, step="unit") == "hi"
    assert post.call_count == 2
    # No usage block in the response: tokens are estimated, not dropped.
    assert usage["estimated_tokens"] is True


def test_openai_compat_price_is_configurable(openai_llm, monkeypatch):
    llm = openai_llm
    monkeypatch.setattr(llm, "OPENAI_COMPAT_INPUT_PRICE_PER_MTOK", 2.0)
    monkeypatch.setattr(llm, "OPENAI_COMPAT_OUTPUT_PRICE_PER_MTOK", 8.0)
    usage = llm.init_usage("openai_compat", "gpt-hosted")
    llm.record_llm_usage(usage, "step", 1_000_000, 1_000_000)
    assert usage["cost_usd"] == pytest.approx(10.0)


def test_call_llm_rejects_unknown_provider(llm, monkeypatch):
    called = []
    monkeypatch.setattr(llm, "_call_bedrock", lambda *a, **k: called.append(1) or "x")
    with pytest.raises(ValueError, match="unknown LLM provider"):
        llm.call_llm("s", "u", provider="openai", model="gpt", step="unit")
    # Never silently routed to Bedrock.
    assert called == []


def test_call_llm_without_fallback_stops_at_cutoff(llm, monkeypatch):
    called = []
    monkeypatch.setattr(llm, "_call_bedrock", lambda *a, **k: called.append(1) or "x")
    usage = llm.init_usage("bedrock", llm.BEDROCK_MODEL_ID, cost_cutoff_usd=2.0)
    usage["cost_usd"] = 2.0
    with pytest.raises(llm.LlmBudgetExhausted):
        llm.call_llm("s", "u", usage=usage, step="unit")
    assert called == []
    assert usage["budget_exhausted"] is True
    assert llm.usage_cost_summary(usage)["budget_exhausted"] is True



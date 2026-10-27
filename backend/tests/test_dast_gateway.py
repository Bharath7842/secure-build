"""DAST-02-010 / -030 / -040 / -050 / -060: gateway core, adapters, accounting and prompts."""

from __future__ import annotations

import json
import subprocess
import sys
from types import SimpleNamespace

import pytest

from app.dast.domain import schema as S
from app.dast.domain import usage as U
from app.dast.domain.interfaces import AdapterResponse
from app.dast.domain.model_errors import (
    ModelAuthError, ModelConfigurationError, ModelError, ModelTimeout, ModelUnavailable, UnknownTaskError,
)
from app.dast.domain.redaction import redact_text
from app.services.model_gateway import PromptError, PromptLibrary, adapter_for, build_gateway, default_library
from app.services.model_gateway.adapters import OLLAMA_REASONING_HEADROOM, AnthropicAdapter, BedrockAdapter, ClaudeCliAdapter, OllamaAdapter, OpenAIAdapter
from app.services.model_gateway.gateway import ModelGatewayImpl

pytestmark = pytest.mark.unit

ROUTING = {t: ("ollama", "gpt-oss:20b") for t in ("fingerprint", "crawl_plan", "login_selectors", "plan", "construct", "rule", "narrate")}
SCHEMA = {"type": "object", "required": ["verdict"], "properties": {"verdict": {"type": "string", "enum": ["PASS", "FAIL", "INCONCLUSIVE"]}}}


class ScriptedAdapter:
    provider = "ollama"
    supports_tool_choice = False

    def __init__(self, *replies):
        self.replies, self.calls = list(replies), []

    def call(self, system, prompt, schema, max_tokens, temperature, thinking=False):
        self.calls.append(SimpleNamespace(system=system, prompt=prompt, schema=schema, max_tokens=max_tokens, temperature=temperature, thinking=thinking))
        item = self.replies.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item if isinstance(item, AdapterResponse) else AdapterResponse(text=item, input_tokens=10, output_tokens=5)


def make(adapter, routing=None, **kw):
    logs: list[str] = []
    gateway = ModelGatewayImpl(routing or ROUTING, lambda provider, model: adapter, log=logs.append, **kw)
    return gateway, logs


def ask(gateway, task="rule", **kw):
    return gateway.complete(task, "sys", "prompt", SCHEMA, **kw)


# ---- core -------------------------------------------------------------------------------------


def test_valid_reply_passes_through_validated():
    adapter = ScriptedAdapter('{"verdict": "FAIL"}')
    gateway, logs = make(adapter)
    reply = ask(gateway, max_tokens=300, temperature=0.0)
    assert reply.data == {"verdict": "FAIL"} and not reply.fallback_used and not reply.repaired and logs == []
    assert reply.provider == "ollama" and reply.model == "gpt-oss:20b" and reply.input_tokens == 10
    assert adapter.calls[0].max_tokens == 300 and adapter.calls[0].temperature == 0.0 and adapter.calls[0].schema == SCHEMA


def test_fenced_and_chatty_replies_are_accepted():
    for text in ('```json\n{"verdict": "PASS"}\n```', 'Here you go: {"verdict": "PASS"} hope that helps'):
        assert ask(make(ScriptedAdapter(text))[0]).data == {"verdict": "PASS"}


def test_routing_uses_the_task_provider_and_model():
    seen = []
    routing = {**ROUTING, "rule": ("anthropic", "claude-x"), "narrate": ("bedrock", "b-model")}

    def factory(provider, model):
        seen.append((provider, model))
        return ScriptedAdapter('{"verdict": "PASS"}')

    gateway = ModelGatewayImpl(routing, factory, log=lambda _: None)
    gateway.complete("rule", "", "p", SCHEMA)
    gateway.complete("narrate", "", "p", SCHEMA)
    gateway.complete("rule", "", "p", SCHEMA)  # the adapter is reused
    assert seen == [("anthropic", "claude-x"), ("bedrock", "b-model")]


def test_unknown_task_raises_a_clear_error():
    gateway, _ = make(ScriptedAdapter())
    with pytest.raises(UnknownTaskError, match=r"unknown model task 'nope'; known tasks: .*rule"):
        ask(gateway, "nope")
    with pytest.raises(UnknownTaskError):
        gateway.register_fallback("nope", {})


def test_invalid_reply_gets_one_repair_then_succeeds():
    adapter = ScriptedAdapter("this is not json", '{"verdict": "FAIL"}')
    gateway, _ = make(adapter)
    reply = ask(gateway)
    assert reply.data == {"verdict": "FAIL"} and reply.repaired and not reply.fallback_used
    assert len(adapter.calls) == 2 and "could not be used" in adapter.calls[1].prompt and "prompt" in adapter.calls[1].prompt
    assert reply.input_tokens == 20 and reply.output_tokens == 10  # both attempts are counted


def test_schema_violation_is_repaired_too():
    adapter = ScriptedAdapter('{"verdict": "MAYBE"}', '{"verdict": "PASS"}')
    reply = ask(make(adapter)[0])
    assert reply.data == {"verdict": "PASS"} and "MAYBE" in adapter.calls[1].prompt


def test_still_invalid_after_repair_returns_the_fallback_flagged():
    adapter = ScriptedAdapter("garbage", "still garbage")
    gateway, logs = make(adapter)
    gateway.register_fallback("rule", {"verdict": "INCONCLUSIVE"})
    reply = ask(gateway)
    assert reply.data == {"verdict": "INCONCLUSIVE"} and reply.fallback_used and "no valid JSON" in reply.reason
    assert len(adapter.calls) == 2  # exactly one repair, never more
    assert any("fallback" in line for line in logs)


@pytest.mark.parametrize("error", [ModelTimeout("slow"), ModelUnavailable("down"), ModelAuthError("denied"), ModelConfigurationError("no key", "k"), RuntimeError("boom")])
def test_provider_errors_return_the_fallback_and_do_not_raise(error):
    gateway, logs = make(ScriptedAdapter(error))
    gateway.register_fallback("rule", lambda: {"verdict": "PASS"})
    reply = ask(gateway)
    assert reply.fallback_used and reply.data == {"verdict": "PASS"} and type(error).__name__ in reply.reason
    assert logs and "fallback" in logs[0]


def test_no_registered_fallback_means_an_empty_result():
    reply = ask(make(ScriptedAdapter(ModelTimeout("x")))[0])
    assert reply.fallback_used and reply.data == {}


def test_fallback_data_is_copied_so_callers_cannot_poison_it():
    gateway, _ = make(ScriptedAdapter(ModelTimeout("a"), ModelTimeout("b")))
    gateway.register_fallback("rule", {"list": [1]})
    ask(gateway).data["list"].append(2)  # type: ignore[union-attr]
    assert ask(gateway).data == {"list": [1]}


def test_errors_and_logs_never_contain_the_api_key():
    secret = "sk-supersecretvalue123"
    gateway = ModelGatewayImpl(
        ROUTING, lambda p, m: ScriptedAdapter(RuntimeError(f"Incorrect API key provided: {secret}")),
        secrets=lambda: [secret], log=(logs := []).append,
    )
    reply = ask(gateway)
    assert secret not in reply.reason and all(secret not in line for line in logs) and "[REDACTED]" in reply.reason


def test_configuration_check_names_the_problem():
    cfg = SimpleNamespace(
        anthropic_api_key=None, openai_api_key=None, aws_region="us-east-1", bedrock_model_id="b", dast_ollama_url="http://x",
        dast_ollama_model="m", dast_ollama_num_ctx=4096, dast_ollama_no_think_prefixes=['gemma'], dast_model_timeout_s=5, dast_model_max_tokens=100, dast_model_prices={}, dast_fewshot_max_examples=1,
        dast_model_routing={**ROUTING, "rule": ("anthropic", "claude-x")},
    )
    problems = build_gateway(cfg=cfg).check_configuration()
    assert len(problems) == 1 and "rule (anthropic)" in problems[0] and "anthropic_api_key" in problems[0]


# ---- streaming ----------------------------------------------------------------------------------


def test_stream_uses_the_adapter_when_it_can_and_degrades_when_it_cannot():
    class Streaming(ScriptedAdapter):
        def stream(self, system, prompt, max_tokens=None, temperature=None):
            yield "thinking", "hmm", None
            yield "response", '{"a":', None
            yield "response", "1}", None

    gateway, _ = make(Streaming())
    assert list(gateway.stream("narrate", "", "p")) == [("thinking", "hmm"), ("response", '{"a":'), ("response", "1}"), ("done", "")]
    plain, _ = make(ScriptedAdapter('{"a": 1}'))
    assert list(plain.stream("narrate", "", "p")) == [("response", '{"a": 1}'), ("done", "")]
    failing, _ = make(ScriptedAdapter(ModelUnavailable("down")))
    assert list(failing.stream("narrate", "", "p"))[0][0] == "error"


# ---- accounting (DAST-02-050) -----------------------------------------------------------------


def test_usage_totals_equal_the_sum_of_calls_and_count_fallbacks():
    adapter = ScriptedAdapter('{"verdict": "PASS"}', "junk", "junk", ModelTimeout("x"))
    gateway, _ = make(adapter, routing={**ROUTING, "narrate": ("openai", "gpt-x")})
    gateway.complete("rule", "", "p", SCHEMA)
    gateway.complete("rule", "", "p", SCHEMA)  # repaired attempts fail -> fallback
    gateway.complete("narrate", "", "p", SCHEMA)  # timeout -> fallback
    s = gateway.usage.summary()
    assert s["call_count"] == 3 and s["fallback_count"] == 2
    assert s["by_step"]["rule"]["calls"] == 2 and s["by_step"]["narrate"]["calls"] == 1
    assert s["input_tokens"] == sum(v["input_tokens"] for v in s["by_step"].values()) == sum(v["input_tokens"] for v in s["by_provider"].values())
    assert s["total_tokens"] == s["input_tokens"] + s["output_tokens"] and set(s["by_provider"]) == {"ollama", "openai"}
    assert s["cost_usd"] == 0.0 and "openai/gpt-x" in s["unpriced_models"]


def test_local_calls_are_free_and_hosted_calls_use_the_price_table_with_overrides():
    records = [U.UsageRecord("rule", "ollama", "m", 1_000_000, 1_000_000), U.UsageRecord("rule", "bedrock", "b", 1_000_000, 2_000_000)]
    assert U.summarize(records)["cost_usd"] == 11.0  # 0 + (1 * $1) + (2 * $5)
    custom = U.summarize(records, {"bedrock/b": (2.0, 4.0)})
    assert custom["cost_usd"] == 10.0 and custom["by_provider"]["bedrock"]["cost_usd"] == 10.0
    assert U.summarize(records, {"ollama": (1.0, 1.0)})["by_provider"]["ollama"]["cost_usd"] == 2.0
    assert U.summarize([])["call_count"] == 0 and U.summarize([])["provider"] == ""


def test_reply_cost_uses_defaults_and_overrides():
    adapter = ScriptedAdapter(AdapterResponse(text='{"verdict":"PASS"}', input_tokens=1_000_000, output_tokens=0))
    gateway = ModelGatewayImpl({**ROUTING, "rule": ("bedrock", "b")}, lambda p, m: adapter, log=lambda _: None)
    assert gateway.complete("rule", "", "p", SCHEMA).cost_usd == 1.0


def test_missing_token_counts_are_estimated_and_flagged():
    gateway, _ = make(ScriptedAdapter(AdapterResponse(text='{"verdict": "PASS"}')))
    reply = ask(gateway)
    assert (reply.input_tokens > 0 or reply.output_tokens > 0) and gateway.usage.summary()["estimated"] is True


# ---- adapters ---------------------------------------------------------------------------------


class FakeChat:
    """Stands in for a LangChain chat model."""

    instances: list = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        FakeChat.instances.append(self)

    def invoke(self, messages):
        self.messages = messages
        return SimpleNamespace(content='{"verdict": "PASS"}', usage_metadata={"input_tokens": 7, "output_tokens": 3})

    def stream(self, messages):
        yield SimpleNamespace(content="", additional_kwargs={"reasoning_content": "thinking..."})
        yield SimpleNamespace(content='{"verdict":', additional_kwargs={})
        yield SimpleNamespace(content=' "PASS"}', additional_kwargs={}, usage_metadata={"input_tokens": 4, "output_tokens": 2})


@pytest.mark.parametrize("cls, setting, env", [(AnthropicAdapter, "anthropic_api_key", "ANTHROPIC_API_KEY"), (OpenAIAdapter, "openai_api_key", "OPENAI_API_KEY")])
def test_hosted_adapters_map_the_request_and_return_validated_json(cls, setting, env):
    FakeChat.instances.clear()
    adapter = cls(SimpleNamespace(get_secret_value=lambda: "key-123456789"), "model-x", client_factory=FakeChat)
    response = adapter.call("SYS", "USER", SCHEMA, 321, 0.4)
    kw = FakeChat.instances[0].kwargs
    assert kw["model"] == "model-x" and kw["max_tokens"] == 321 and kw["temperature"] == 0.4 and kw["api_key"] == "key-123456789"
    assert [m.content for m in FakeChat.instances[0].messages] == ["SYS", "USER"]
    assert (response.input_tokens, response.output_tokens, response.estimated) == (7, 3, False)
    gateway = ModelGatewayImpl({**ROUTING, "rule": (adapter.provider, "model-x")}, lambda p, m: adapter, log=lambda _: None)
    assert gateway.complete("rule", "", "p", SCHEMA).data == {"verdict": "PASS"}


@pytest.mark.parametrize("cls, setting, env", [(AnthropicAdapter, "anthropic_api_key", "ANTHROPIC_API_KEY"), (OpenAIAdapter, "openai_api_key", "OPENAI_API_KEY")])
def test_missing_key_is_a_clear_configuration_error_naming_the_setting(cls, setting, env):
    adapter = cls(None, "m", client_factory=FakeChat)
    with pytest.raises(ModelConfigurationError) as err:
        adapter.call("s", "p", None, None, None)
    assert setting in str(err.value) and env in str(err.value) and err.value.setting == setting
    with pytest.raises(ModelConfigurationError):
        adapter.check_configuration()


def test_hosted_sdks_are_not_imported_until_the_first_call():
    for name in ("langchain_anthropic", "langchain_openai", "boto3"):
        sys.modules.pop(name, None)
    AnthropicAdapter(SimpleNamespace(get_secret_value=lambda: "k"), "m")
    OpenAIAdapter(SimpleNamespace(get_secret_value=lambda: "k"), "m")
    BedrockAdapter("m", "us-east-1")
    OllamaAdapter("http://x", "m")
    adapter_for("anthropic", "m")
    assert not {"langchain_anthropic", "langchain_openai", "boto3", "langchain_ollama"} & set(sys.modules)


def test_a_missing_sdk_is_a_configuration_error_not_a_crash(monkeypatch):
    monkeypatch.setitem(sys.modules, "langchain_anthropic", None)  # makes the import raise ImportError
    adapter = AnthropicAdapter(SimpleNamespace(get_secret_value=lambda: "key-123456789"), "m")
    with pytest.raises(ModelConfigurationError, match="not installed"):
        adapter.call("s", "p", None, None, None)


def test_provider_error_text_is_scrubbed_of_the_key():
    class Boom(FakeChat):
        def invoke(self, messages):
            raise RuntimeError("401 Incorrect API key provided: key-123456789")

    adapter = OpenAIAdapter(SimpleNamespace(get_secret_value=lambda: "key-123456789"), "m", client_factory=Boom)
    with pytest.raises(ModelAuthError) as err:
        adapter.call("s", "p", None, None, None)
    assert "key-123456789" not in str(err.value)


class FakeBedrock:
    def __init__(self, response=None, error=None):
        self.response, self.error, self.requests = response, error, []

    def converse(self, **request):
        self.requests.append(request)
        if self.error:
            raise self.error
        return self.response


def test_bedrock_uses_converse_with_system_messages_and_inference_config():
    client = FakeBedrock({"output": {"message": {"content": [{"text": '{"verdict": "PASS"}'}]}}, "usage": {"inputTokens": 11, "outputTokens": 6}})
    adapter = BedrockAdapter("us.anthropic.claude-haiku-4-5-20251001-v1:0", "us-east-1", client=client)
    response = adapter.call("SYS", "USER", SCHEMA, 200, 0.3)
    request = client.requests[0]
    assert request["modelId"].startswith("us.anthropic") and request["system"] == [{"text": "SYS"}]
    assert request["messages"] == [{"role": "user", "content": [{"text": "USER"}]}]
    assert request["inferenceConfig"] == {"maxTokens": 200, "temperature": 0.3}
    assert (response.text, response.input_tokens, response.output_tokens) == ('{"verdict": "PASS"}', 11, 6)


def test_bedrock_default_model_is_the_repos_setting():
    from app.config import settings

    assert adapter_for("bedrock", "").model == settings.bedrock_model_id


def test_bedrock_throttling_falls_back_and_credentials_errors_are_clear():
    class ThrottlingException(Exception):
        response = {"Error": {"Code": "ThrottlingException"}}

    gateway = ModelGatewayImpl({**ROUTING, "rule": ("bedrock", "b")}, lambda p, m: BedrockAdapter(m, "us-east-1", client=FakeBedrock(error=ThrottlingException())), log=lambda _: None)
    gateway.register_fallback("rule", {"verdict": "INCONCLUSIVE"})
    reply = gateway.complete("rule", "", "p", SCHEMA)
    assert reply.fallback_used and "ModelUnavailable" in reply.reason

    class NoCredentialsError(Exception):
        pass

    with pytest.raises(ModelConfigurationError, match="no AWS credentials"):
        BedrockAdapter("m", "us-east-1", client=FakeBedrock(error=NoCredentialsError())).call("s", "p", None, None, None)
    with pytest.raises(ModelConfigurationError, match="aws_region"):
        BedrockAdapter("m", "").call("s", "p", None, None, None)


def test_bedrock_thinking_requests_extended_thinking_and_emits_it_separately():
    client = FakeBedrock({
        "output": {"message": {"content": [
            {"reasoningContent": {"reasoningText": {"text": "First I check the status code."}}},
            {"text": "I confirmed the target is reachable."},
        ]}},
        "usage": {"inputTokens": 11, "outputTokens": 6},
    })
    emitted: list[str] = []
    adapter = BedrockAdapter("us.anthropic.claude-haiku-4-5-20251001-v1:0", "us-east-1", client=client, emit=emitted.append)
    response = adapter.call("SYS", "USER", SCHEMA, 200, 0.3, thinking=True)

    request = client.requests[0]
    assert request["additionalModelRequestFields"] == {"thinking": {"type": "enabled", "budget_tokens": 2000}}
    assert request["inferenceConfig"]["temperature"] == 1.0  # overridden, not the caller's 0.3
    assert request["inferenceConfig"]["maxTokens"] == 200 + 2000

    assert response.text == "I confirmed the target is reachable."  # reasoning never joins the answer text
    assert emitted == ["    [thinking] First I check the status code.\n"]


def test_bedrock_without_thinking_sends_no_extra_fields_and_keeps_the_callers_temperature():
    client = FakeBedrock({"output": {"message": {"content": [{"text": "ok"}]}}, "usage": {}})
    adapter = BedrockAdapter("m", "us-east-1", client=client)
    adapter.call("s", "p", None, 200, 0.3, thinking=False)
    request = client.requests[0]
    assert "additionalModelRequestFields" not in request
    assert request["inferenceConfig"] == {"maxTokens": 200, "temperature": 0.3}


def test_bedrock_degrades_gracefully_when_a_model_rejects_thinking():
    class ValidationException(Exception):
        response = {"Error": {"Code": "ValidationException"}}

        def __str__(self):
            return "the model us.x does not support additionalModelRequestFields.thinking"

    # First call (thinking requested) raises; the adapter retries once without thinking and succeeds.
    client = FakeBedrock(response={"output": {"message": {"content": [{"text": "ok"}]}}, "usage": {}})
    real_converse = client.converse
    calls: list[dict] = []

    def converse(**request):
        calls.append(request)
        if len(calls) == 1:
            raise ValidationException()
        return real_converse(**request)

    client.converse = converse
    emitted: list[str] = []
    adapter = BedrockAdapter("m", "us-east-1", client=client, emit=emitted.append)

    response = adapter.call("s", "p", None, 200, 0.3, thinking=True)
    assert response.text == "ok"
    assert "additionalModelRequestFields" in calls[0]
    assert "additionalModelRequestFields" not in calls[1]
    assert any("does not support extended thinking" in m for m in emitted)
    assert adapter._thinking_unsupported is True

    # A later call on the same (cached) instance skips straight to the no-thinking request.
    response2 = adapter.call("s", "p", None, 200, 0.3, thinking=True)
    assert response2.text == "ok" and len(calls) == 3  # no extra failed attempt this time
    assert "additionalModelRequestFields" not in calls[2]


def test_ollama_adapter_streams_reasoning_to_the_console_and_returns_text():
    FakeChat.instances.clear()
    out: list[str] = []
    adapter = OllamaAdapter("http://ollama:11434", "gpt-oss:20b", chat_factory=FakeChat, emit=out.append)
    response = adapter.call("SYS", "USER", None, 100, None)
    assert response.text == '{"verdict": "PASS"}' and (response.input_tokens, response.output_tokens) == (4, 2)
    assert "".join(out) == "    [thinking] thinking...\n"
    kw = FakeChat.instances[0].kwargs
    assert kw["base_url"] == "http://ollama:11434" and kw["model"] == "gpt-oss:20b" and kw["reasoning"] is True and kw["num_predict"] == 100 + OLLAMA_REASONING_HEADROOM


def test_ollama_connection_errors_become_unavailable():
    class Down(FakeChat):
        def stream(self, messages):
            raise ConnectionError("connection refused")
            yield

    with pytest.raises(ModelUnavailable):
        OllamaAdapter("http://x", "m", chat_factory=Down, emit=lambda _: None).call("s", "p", None, None, None)


def test_ollama_availability_probe_reports_a_down_server(monkeypatch):
    def down(*args, **kwargs):
        raise ConnectionRefusedError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", down)
    with pytest.raises(ModelUnavailable, match="connection refused"):
        OllamaAdapter("http://127.0.0.1:11434", "gpt-oss:20b").check_availability()


def test_default_ollama_model_is_gpt_oss():
    assert adapter_for("ollama", "").model == "gpt-oss:20b"


# ---- schema + redaction helpers ---------------------------------------------------------------


def test_schema_validator_covers_the_subset():
    schema = {"type": "object", "required": ["a"], "additionalProperties": False, "properties": {
        "a": {"type": ["string", "null"], "maxLength": 3}, "n": {"type": "integer", "minimum": 1, "maximum": 5},
        "l": {"type": "array", "minItems": 1, "maxItems": 2, "items": {"type": "string"}}}}
    assert S.validate_reply({"a": None, "n": 3, "l": ["x"]}, schema) == []
    problems = S.validate_reply({"a": "toolong", "n": 9, "l": [], "z": 1}, schema)
    assert len(problems) == 4 and S.validate_reply([1], {"type": "object"})
    assert S.validate_reply({"n": True}, {"properties": {"n": {"type": "integer"}}})  # a bool is not an integer
    assert S.validate_reply("anything", None) == [] and S.validate_reply(5, {"type": "weird"}) == []


def test_redact_text_covers_values_and_key_shapes():
    out = redact_text("fail sk-ant-abcdef12345678 AKIAABCDEFGHIJKLMNOP Bearer abcdefghijklmnopqrst hunter2", ["hunter2"])
    assert "hunter2" not in out and "sk-ant" not in out and "AKIA" not in out and "abcdefghijkl" not in out


# ---- prompts (DAST-02-060) --------------------------------------------------------------------

TASKS = ("fingerprint", "crawl_plan", "login_selectors", "plan", "construct", "rule", "narrate")


def test_every_task_loads_and_carries_the_shared_preamble():
    library = default_library()
    for task in TASKS:
        system = library.compose(task)
        assert system.startswith(library.preamble) and library.tasks[task] in system
    assert "ethical hacker" in library.preamble and "authorized" in library.preamble


def test_construct_prompt_states_non_destructive_and_the_reply_shape():
    text = default_library().tasks["construct"]
    assert "Non-destructive requirement" in text and '"tests"' in text and "check_id" in text and "location" in text


def test_examples_are_capped_ordered_and_deterministic():
    library = PromptLibrary.load(max_examples=2)
    shots = library.examples_for("rule")
    assert len(shots) == 2 and shots == list(library.examples["rule"])[:2]
    assert library.compose("rule") == PromptLibrary.load(max_examples=2).compose("rule")
    assert library.compose("rule").count("\nInput: ") == 2 and library.compose("narrate").count("Input: ") == 0
    assert PromptLibrary.load(max_examples=0).compose("rule").count("Input: ") == 0
    assert len(PromptLibrary.load(max_examples=100).examples_for("rule")) == 14


def test_few_shot_examples_use_the_detector_vocabulary():
    from app.dast.domain.detectors import signal_names

    library = PromptLibrary.load(max_examples=100)
    allowed = signal_names() | {"input_reflected_encoded", "transport_error"}
    for block in library.examples.values():
        for example in block:
            assert set(example["input"].get("signals") or ()) <= allowed, example


def test_extra_system_text_is_appended_last():
    assert default_library().compose("rule", "EXTRA").endswith("EXTRA")


def test_gateway_composes_the_system_prompt_from_the_library():
    adapter = ScriptedAdapter('{"verdict": "PASS"}')
    gateway = ModelGatewayImpl(ROUTING, lambda p, m: adapter, prompts=default_library(), log=lambda _: None)
    gateway.complete("rule", "caller note", "p", SCHEMA)
    assert adapter.calls[0].system.startswith(default_library().preamble) and adapter.calls[0].system.endswith("caller note")


def test_invalid_prompt_files_fail_fast_naming_the_file(tmp_path):
    import shutil
    from app.services.model_gateway.prompts import DATA_DIR

    prompts = tmp_path / "prompts"
    shutil.copytree(DATA_DIR / "prompts", prompts)
    fewshot = tmp_path / "fs.json"
    shutil.copy(DATA_DIR / "dast_fewshot_examples.json", fewshot)
    PromptLibrary.load(prompts, fewshot)  # baseline is valid

    (prompts / "rule.md").write_text("   \n")
    with pytest.raises(PromptError, match=r"^rule\.md: file is empty"):
        PromptLibrary.load(prompts, fewshot)
    (prompts / "rule.md").write_bytes(b"\xff\xfe\x00bad")
    with pytest.raises(PromptError, match=r"rule\.md"):
        PromptLibrary.load(prompts, fewshot)
    (prompts / "rule.md").unlink()
    with pytest.raises(PromptError, match=r"rule\.md: file is missing"):
        PromptLibrary.load(prompts, fewshot)
    shutil.copy(DATA_DIR / "prompts" / "rule.md", prompts / "rule.md")
    (prompts / "_preamble.md").unlink()
    with pytest.raises(PromptError, match=r"_preamble\.md"):
        PromptLibrary.load(prompts, fewshot)
    shutil.copy(DATA_DIR / "prompts" / "_preamble.md", prompts / "_preamble.md")
    fewshot.write_text("{not json")
    with pytest.raises(PromptError, match=r"fs\.json: is not valid JSON"):
        PromptLibrary.load(prompts, fewshot)
    fewshot.write_text(json.dumps({"rule": [{"input": {}}]}))
    with pytest.raises(PromptError, match=r"rule\[0\] needs"):
        PromptLibrary.load(prompts, fewshot)
    fewshot.write_text(json.dumps({"nonsense": []}))
    with pytest.raises(PromptError, match="unknown task"):
        PromptLibrary.load(prompts, fewshot)


def test_reasoning_is_off_only_for_the_configured_models():
    from app.services.model_gateway import ollama_reasoning

    assert ollama_reasoning("gemma4:12b") is False and ollama_reasoning("Gemma3:4b") is False
    assert ollama_reasoning("phi4-mini:3.8b") is False
    assert ollama_reasoning("granite4.2:3b") is False and ollama_reasoning("gemma4:12b") is False
    assert ollama_reasoning("gpt-oss:20b") is True and ollama_reasoning("") is True  # "" = the default model (gpt-oss)
    assert adapter_for("ollama", "gemma4:12b").reasoning is False and adapter_for("ollama", "gpt-oss:20b").reasoning is True
    assert adapter_for("ollama", "phi4-mini:3.8b").reasoning is False


def test_ollama_retries_without_thinking_when_the_model_rejects_it():
    class NoThinkChat(FakeChat):
        def stream(self, messages):
            if self.kwargs.get("reasoning"):
                raise RuntimeError('"phi4-mini:3.8b" does not support thinking (status code: 400)')
            yield SimpleNamespace(
                content='{"verdict": "PASS"}',
                additional_kwargs={},
                usage_metadata={"input_tokens": 2, "output_tokens": 1},
            )

    FakeChat.instances.clear()
    adapter = OllamaAdapter("http://x", "phi4-mini:3.8b", chat_factory=NoThinkChat, emit=lambda _: None)
    response = adapter.call("s", "p", None, 50, None)
    assert response.text == '{"verdict": "PASS"}'
    assert adapter.reasoning is False
    assert FakeChat.instances[0].kwargs["reasoning"] is True
    assert FakeChat.instances[1].kwargs["reasoning"] is False


def test_ollama_adapter_passes_the_reasoning_flag_to_the_client():
    FakeChat.instances.clear()
    OllamaAdapter("http://x", "gemma4:12b", chat_factory=FakeChat, emit=lambda _: None, reasoning=False).call("s", "p", None, 50, None)
    assert FakeChat.instances[0].kwargs["reasoning"] is False


# ---- claude CLI provider --------------------------------------------------------------------


def _cli_proc(payload=None, *, returncode=0, stderr=""):
    return SimpleNamespace(returncode=returncode, stdout=json.dumps(payload) if payload is not None else "", stderr=stderr)


class FakeRunner:
    def __init__(self, proc=None, error=None):
        self.proc, self.error, self.calls = proc, error, []

    def __call__(self, cmd, **kwargs):
        self.calls.append((cmd, kwargs))
        if self.error:
            raise self.error
        return self.proc


def test_claude_cli_sends_an_ephemeral_toolless_call_and_reads_usage(tmp_path):
    runner = FakeRunner(_cli_proc({"result": '{"verdict": "PASS"}', "usage": {"input_tokens": 10, "cache_read_input_tokens": 5, "cache_creation_input_tokens": 2, "output_tokens": 7}}))
    adapter = ClaudeCliAdapter("/bin/claude", "sonnet", workdir=str(tmp_path / "dast"), runner=runner)
    response = adapter.call("SYS", "PROMPT", SCHEMA, 100, 0.5)
    cmd, kwargs = runner.calls[0]
    assert cmd[0] == "/bin/claude" and cmd[cmd.index("--model") + 1] == "claude-sonnet-5-5"  # alias pinned
    assert "--no-session-persistence" in cmd and "--resume" not in cmd and "--session-id" not in cmd
    assert cmd[cmd.index("--tools") + 1] == "" and "--strict-mcp-config" in cmd
    assert "<instructions>\nSYS\n</instructions>" in kwargs["input"] and "PROMPT" in kwargs["input"] and "single JSON" in kwargs["input"]
    assert kwargs["cwd"] == str(tmp_path / "dast") and (tmp_path / "dast").is_dir()
    assert (response.text, response.input_tokens, response.output_tokens, response.estimated) == ('{"verdict": "PASS"}', 17, 7, False)


def test_claude_cli_without_a_schema_does_not_ask_for_json():
    runner = FakeRunner(_cli_proc({"result": "plain narration"}))
    response = ClaudeCliAdapter("/bin/claude", "claude-haiku-5-5", runner=runner).call("", "P", None, None, None)
    assert "single JSON" not in runner.calls[0][1]["input"] and response.estimated and response.text == "plain narration"


@pytest.mark.parametrize(
    "proc, error, expected",
    [
        (_cli_proc({"is_error": True, "result": "Not logged in · Please run /login"}, returncode=1), None, ModelAuthError),
        (_cli_proc({"is_error": True, "result": "usage limit reached"}, returncode=1), None, ModelUnavailable),
        (_cli_proc(None, returncode=2, stderr="boom"), None, ModelError),
        (_cli_proc({"result": ""}), None, ModelUnavailable),
        (None, subprocess.TimeoutExpired("claude", 5), ModelTimeout),
        (None, FileNotFoundError(2, "no such file", "/bin/claude"), ModelConfigurationError),
    ],
)
def test_claude_cli_failures_map_onto_gateway_errors(proc, error, expected):
    adapter = ClaudeCliAdapter("/bin/claude", "claude-sonnet-5-5", runner=FakeRunner(proc, error))
    with pytest.raises(expected):
        adapter.call("s", "p", SCHEMA, None, None)


def test_claude_cli_missing_binary_is_a_configuration_error(monkeypatch):
    monkeypatch.setattr("app.services.model_gateway.adapters.shutil.which", lambda name: None)
    adapter = ClaudeCliAdapter("", "claude-sonnet-5-5", runner=FakeRunner(_cli_proc({"result": "x"})))
    with pytest.raises(ModelConfigurationError, match="CLAUDE_CLI_PATH"):
        adapter.check_configuration()


def test_claude_cli_is_routable_through_the_gateway_and_priced_notionally():
    adapter = ClaudeCliAdapter("/bin/claude", "claude-sonnet-5-5", runner=FakeRunner(_cli_proc({"result": '{"verdict": "FAIL"}', "usage": {"input_tokens": 1_000_000, "output_tokens": 1_000_000}})))
    gateway = ModelGatewayImpl({**ROUTING, "rule": ("claude_cli", "claude-sonnet-5-5")}, lambda p, m: adapter, log=lambda _: None)
    reply = gateway.complete("rule", "s", "p", SCHEMA)
    assert reply.data == {"verdict": "FAIL"} and not reply.fallback_used and reply.cost_usd == pytest.approx(18.0)


def test_adapter_for_claude_cli_uses_settings_and_defaults_the_model():
    from app.config import settings

    adapter = adapter_for("claude_cli", "")
    assert isinstance(adapter, ClaudeCliAdapter) and adapter.model == settings.dast_claude_cli_model
    assert adapter.workdir.endswith("dast")

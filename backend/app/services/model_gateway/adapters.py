"""Provider adapters behind the model gateway (DAST-02-020, -030, -040).

Every adapter implements `ModelAdapter` (`app.dast.domain.interfaces`): `call(system, prompt,
schema, max_tokens, temperature) -> AdapterResponse`, and raises the `model_errors` hierarchy.
Provider SDKs are imported lazily inside the method that needs them, so importing this module,
building an adapter, and the whole mock suite never require a provider package; a test asserts
that. This module (and `model_gateway/`) is the only place in the DAST code allowed to import a
model SDK, which `tests/test_dast_layering.py` enforces.

Secrets: keys are held as `SecretStr` values from settings, read only at call time, never put in
a log line, and stripped from any provider error text by `redact_text` before it leaves here.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Iterator, Mapping

from app.dast.domain.interfaces import AdapterResponse
from app.dast.domain.model_errors import (
    ModelAuthError,
    ModelConfigurationError,
    ModelError,
    ModelTimeout,
    ModelUnavailable,
)
from app.dast.domain.redaction import redact_text
from app.dast.domain.usage import estimate_tokens

logger = logging.getLogger(__name__)

DEFAULT_TEMPERATURE = 0.1
# A reasoning model (gpt-oss) spends tokens thinking before it writes the answer, and Ollama's
# `num_predict` counts both. A cap sized for the answer alone yields an empty reply, so the local
# adapter adds this much room on top of whatever the caller asks for.
OLLAMA_REASONING_HEADROOM = 6000
# Anthropic's extended-thinking minimum is 1024 tokens; this leaves comfortable headroom for a
# few sentences of reasoning. Added on top of the caller's max_tokens (same headroom idea as
# OLLAMA_REASONING_HEADROOM above) so the thinking budget doesn't crowd out the answer itself.
_BEDROCK_THINKING_BUDGET_TOKENS = 2000


def _secret(value: Any) -> str:
    if value is None:
        return ""
    getter = getattr(value, "get_secret_value", None)
    return (getter() if getter else str(value)).strip()


def _classify(exc: BaseException, secrets: tuple[str, ...]) -> ModelError:
    """Map whatever an SDK raised onto the gateway's error types without importing the SDK."""
    name = type(exc).__name__.lower()
    message = redact_text(str(exc), secrets) or type(exc).__name__
    text = f"{name} {message}".lower()
    if isinstance(exc, ModelError):
        return exc
    if isinstance(exc, TimeoutError) or "timeout" in text or "timed out" in text:
        return ModelTimeout(message)
    if "auth" in text and ("error" in text or "denied" in text) or "401" in text or "403" in text or "invalid api key" in text or "incorrect api key" in text:
        return ModelAuthError(message)
    if any(k in text for k in ("connect", "refused", "unreachable", "unavailable", "throttl", "rate limit", "429", "503", "overloaded")):
        return ModelUnavailable(message)
    return ModelError(message)


def _usage(message: Any, prompt_text: str, output_text: str) -> tuple[int, int, bool]:
    """Token counts from a LangChain message's usage metadata, else an estimate."""
    meta = getattr(message, "usage_metadata", None) or {}
    try:
        input_tokens, output_tokens = int(meta.get("input_tokens") or 0), int(meta.get("output_tokens") or 0)
    except (TypeError, ValueError):
        input_tokens = output_tokens = 0
    if input_tokens or output_tokens:
        return input_tokens, output_tokens, False
    return estimate_tokens(prompt_text), estimate_tokens(output_text), True


# ---- Ollama (local, default) -----------------------------------------------------------------


class OllamaAdapter:
    """The local model. Streams the model's reasoning tokens to the engine log as `[thinking]`
    lines (the narration layer reads them) without any provider detail leaking to callers."""

    provider = "ollama"
    supports_tool_choice = False

    def __init__(
        self,
        base_url: str,
        model: str,
        *,
        timeout_s: float = 120.0,
        chat_factory: Callable[..., Any] | None = None,
        emit: Callable[[str], None] | None = None,
        num_ctx: int | None = None,
        reasoning: bool = True,
    ) -> None:
        self.base_url, self.model, self.timeout_s, self.num_ctx = base_url, model, timeout_s, num_ctx
        self.reasoning = reasoning
        self._chat_factory = chat_factory
        self._emit = emit if emit is not None else lambda text: print(text, end="", flush=True)

    def _chat(self, temperature: float | None, max_tokens: int | None):
        factory = self._chat_factory
        if factory is None:
            from langchain_ollama import ChatOllama  # lazy: only when this provider is used

            factory = ChatOllama
        kwargs: dict[str, Any] = {
            "model": self.model,
            "base_url": self.base_url,
            "temperature": DEFAULT_TEMPERATURE if temperature is None else temperature,
            "reasoning": self.reasoning,
            "client_kwargs": {"timeout": self.timeout_s},
        }
        if self.num_ctx:
            kwargs["num_ctx"] = self.num_ctx
        if self.num_ctx:
            kwargs["num_ctx"] = self.num_ctx
        if max_tokens:
            kwargs["num_predict"] = max_tokens + OLLAMA_REASONING_HEADROOM
        return factory(**kwargs)

    def stream(
        self, system: str, prompt: str, max_tokens: int | None = None, temperature: float | None = None
    ) -> Iterator[tuple[str, str, Any]]:
        """Yield `("thinking"|"response", text, chunk)` as tokens arrive."""
        from langchain_core.messages import HumanMessage, SystemMessage  # core ships with langgraph

        try:
            chat = self._chat(temperature, max_tokens)
            for chunk in chat.stream([SystemMessage(content=system), HumanMessage(content=prompt)]):
                reasoning = (getattr(chunk, "additional_kwargs", None) or {}).get("reasoning_content")
                if reasoning:
                    yield "thinking", reasoning, chunk
                if getattr(chunk, "content", None):
                    yield "response", chunk.content, chunk
        except ModelError:
            raise
        except Exception as exc:  # noqa: BLE001 - classified below
            # phi4-mini and similar reject `reasoning=true` with HTTP 400; retry once without it.
            if self.reasoning and "does not support thinking" in str(exc).lower():
                self.reasoning = False
                yield from self.stream(system, prompt, max_tokens, temperature)
                return
            raise _classify(exc, ()) from exc

    def call(
        self,
        system: str,
        prompt: str,
        schema: Mapping[str, Any] | None,
        max_tokens: int | None,
        temperature: float | None,
        thinking: bool = False,  # ignored: this adapter already streams its own reasoning unconditionally
    ) -> AdapterResponse:
        parts: list[str] = []
        in_thinking = False
        last: Any = None
        for kind, text, chunk in self.stream(system, prompt, max_tokens, temperature):
            last = chunk
            if kind == "thinking":
                if not in_thinking:
                    self._emit("    [thinking] ")
                    in_thinking = True
                self._emit(text)
            else:
                if in_thinking:
                    self._emit("\n")
                    in_thinking = False
                parts.append(text)
        if in_thinking:
            self._emit("\n")
        text = "".join(parts).strip()
        if not text:
            raise ModelUnavailable("the model returned an empty reply")
        input_tokens, output_tokens, estimated = _usage(last, system + prompt, text)
        return AdapterResponse(text=text, input_tokens=input_tokens, output_tokens=output_tokens, estimated=estimated)


# ---- hosted providers via LangChain ----------------------------------------------------------


class _LangChainAdapter:
    provider = ""
    supports_tool_choice = True
    setting_name = ""
    env_name = ""

    def __init__(self, api_key: Any, model: str, *, timeout_s: float = 120.0, client_factory: Callable[..., Any] | None = None):
        self._api_key, self.model, self.timeout_s = api_key, model, timeout_s
        self._client_factory = client_factory

    def _key(self) -> str:
        key = _secret(self._api_key)
        if not key:
            raise ModelConfigurationError(
                f"{self.provider} is configured for a model task but no API key is set; set "
                f"{self.setting_name} (environment variable {self.env_name})",
                setting=self.setting_name,
            )
        return key

    def _make_client(self, key: str, max_tokens: int | None, temperature: float | None):
        raise NotImplementedError

    def check_configuration(self) -> None:
        self._key()

    def call(
        self,
        system: str,
        prompt: str,
        schema: Mapping[str, Any] | None,
        max_tokens: int | None,
        temperature: float | None,
        thinking: bool = False,  # ignored: no extended-thinking support wired up for this provider
    ) -> AdapterResponse:
        key = self._key()  # before any import, so a missing key never needs the SDK installed
        secrets = (key,)
        try:
            from langchain_core.messages import HumanMessage, SystemMessage

            client = self._make_client(key, max_tokens, temperature)
            message = client.invoke([SystemMessage(content=system), HumanMessage(content=prompt)])
        except ModelError:
            raise
        except ImportError as exc:
            raise ModelConfigurationError(
                f"the {self.provider} provider package is not installed ({exc.name or 'import failed'})",
                setting=f"{self.provider} provider package",
            ) from exc
        except Exception as exc:  # noqa: BLE001
            raise _classify(exc, secrets) from exc
        content = getattr(message, "content", "")
        text = content if isinstance(content, str) else "".join(
            part.get("text", "") if isinstance(part, dict) else str(part) for part in content
        )
        input_tokens, output_tokens, estimated = _usage(message, system + prompt, text)
        return AdapterResponse(text=text.strip(), input_tokens=input_tokens, output_tokens=output_tokens, estimated=estimated)


class AnthropicAdapter(_LangChainAdapter):
    provider = "anthropic"
    setting_name = "anthropic_api_key"
    env_name = "ANTHROPIC_API_KEY"

    def _make_client(self, key, max_tokens, temperature):
        factory = self._client_factory
        if factory is None:
            from langchain_anthropic import ChatAnthropic  # lazy

            factory = ChatAnthropic
        return factory(
            model=self.model,
            api_key=key,
            max_tokens=max_tokens or 1500,
            temperature=DEFAULT_TEMPERATURE if temperature is None else temperature,
            timeout=self.timeout_s,
            max_retries=0,
        )


class OpenAIAdapter(_LangChainAdapter):
    provider = "openai"
    setting_name = "openai_api_key"
    env_name = "OPENAI_API_KEY"

    def _make_client(self, key, max_tokens, temperature):
        factory = self._client_factory
        if factory is None:
            from langchain_openai import ChatOpenAI  # lazy

            factory = ChatOpenAI
        return factory(
            model=self.model,
            api_key=key,
            max_tokens=max_tokens or 1500,
            temperature=DEFAULT_TEMPERATURE if temperature is None else temperature,
            timeout=self.timeout_s,
            max_retries=0,
        )


# ---- AWS Bedrock (Converse API through boto3) ------------------------------------------------


class BedrockAdapter:
    """Calls Bedrock's Converse API directly through boto3, not through the Anthropic client.
    Region and credentials follow the standard AWS resolution (environment, profile, role).

    Mirrors `OllamaAdapter`'s `[thinking]` log convention: when `call(..., thinking=True)` is
    asked for extended thinking and the model returns a `reasoningContent` block, the whole
    block is emitted as one `    [thinking] ...` log line (not token-by-token — Bedrock's
    Converse API has no streaming path here, only the blocking `converse()` call) rather than
    folded into the returned answer text."""

    provider = "bedrock"
    supports_tool_choice = False

    def __init__(self, model_id: str, region: str, *, timeout_s: float = 120.0, client: Any = None, emit: Callable[[str], None] | None = None):
        self.model, self.region, self.timeout_s = model_id, (region or "").strip(), timeout_s
        self._client = client
        self._emit = emit if emit is not None else lambda text: print(text, end="", flush=True)
        # Set once a model/profile rejects the `thinking` request field, so the rest of the
        # scan (this instance is cached per (provider, model) by the gateway) stops asking.
        self._thinking_unsupported = False

    def check_configuration(self) -> None:
        if self._client is None and not self.region:
            raise ModelConfigurationError(
                "Bedrock needs an AWS region; set aws_region (environment variable AWS_REGION)", setting="aws_region"
            )

    def _get_client(self):
        if self._client is not None:
            return self._client
        if not self.region:
            raise ModelConfigurationError(
                "Bedrock needs an AWS region; set aws_region (environment variable AWS_REGION)", setting="aws_region"
            )
        try:
            import boto3  # lazy
            from botocore.config import Config
        except ImportError as exc:
            raise ModelConfigurationError("boto3 is not installed; it is required for the bedrock provider", setting="boto3") from exc
        self._client = boto3.client(
            "bedrock-runtime",
            region_name=self.region,
            config=Config(read_timeout=self.timeout_s, connect_timeout=10, retries={"max_attempts": 1}),
        )
        return self._client

    def call(
        self,
        system: str,
        prompt: str,
        schema: Mapping[str, Any] | None,
        max_tokens: int | None,
        temperature: float | None,
        thinking: bool = False,
    ) -> AdapterResponse:
        client = self._get_client()
        want_thinking = thinking and not self._thinking_unsupported
        base_max_tokens = max_tokens or 1500
        request: dict[str, Any] = {
            "modelId": self.model,
            "messages": [{"role": "user", "content": [{"text": prompt}]}],
            "inferenceConfig": {
                "maxTokens": base_max_tokens + (_BEDROCK_THINKING_BUDGET_TOKENS if want_thinking else 0),
                # Anthropic's API requires temperature == 1 while extended thinking is on;
                # the caller's configured temperature is overridden rather than rejected.
                "temperature": (1.0 if want_thinking else (DEFAULT_TEMPERATURE if temperature is None else temperature)),
            },
        }
        if system:
            request["system"] = [{"text": system}]
        if want_thinking:
            request["additionalModelRequestFields"] = {
                "thinking": {"type": "enabled", "budget_tokens": _BEDROCK_THINKING_BUDGET_TOKENS}
            }
        try:
            response = client.converse(**request)
        except Exception as exc:  # noqa: BLE001 - botocore errors are classified by name, not import
            if want_thinking and self._is_thinking_unsupported(exc):
                self._thinking_unsupported = True
                self._emit("    (this Bedrock model does not support extended thinking; continuing without it)\n")
                return self.call(system, prompt, schema, max_tokens, temperature, thinking=False)
            raise self._translate(exc) from exc
        blocks = ((response.get("output") or {}).get("message") or {}).get("content") or []
        text_parts: list[str] = []
        thinking_parts: list[str] = []
        for b in blocks:
            if not isinstance(b, dict):
                continue
            if "text" in b:
                text_parts.append(b.get("text", ""))
                continue
            reasoning = b.get("reasoningContent")
            if isinstance(reasoning, dict):
                reasoning_text = (reasoning.get("reasoningText") or {}).get("text") or ""
                if reasoning_text:
                    thinking_parts.append(reasoning_text)
        text = "".join(text_parts).strip()
        if thinking_parts:
            self._emit("    [thinking] " + "\n".join(thinking_parts).strip() + "\n")
        usage = response.get("usage") or {}
        return AdapterResponse(
            text=text,
            input_tokens=int(usage.get("inputTokens") or 0),
            output_tokens=int(usage.get("outputTokens") or 0),
        )

    @staticmethod
    def _is_thinking_unsupported(exc: BaseException) -> bool:
        """True if Bedrock rejected the request specifically because this model/profile
        doesn't support the `thinking` field — never for an unrelated validation error."""
        response = getattr(exc, "response", None)
        code = str((response.get("Error") or {}).get("Code") or "") if isinstance(response, dict) else ""
        if code != "ValidationException":
            return False
        message = str(exc).lower()
        return "thinking" in message or "additionalmodelrequestfields" in message

    @staticmethod
    def _translate(exc: BaseException) -> ModelError:
        name = type(exc).__name__
        if name in ("NoCredentialsError", "PartialCredentialsError", "CredentialRetrievalError"):
            return ModelConfigurationError(
                "no AWS credentials were found for Bedrock; configure them the standard AWS way "
                "(environment variables, a profile, or an instance role)",
                setting="AWS credentials",
            )
        if name in ("NoRegionError",):
            return ModelConfigurationError("Bedrock needs an AWS region; set aws_region", setting="aws_region")
        code = ""
        response = getattr(exc, "response", None)
        if isinstance(response, dict):
            code = str((response.get("Error") or {}).get("Code") or "")
        if code in ("ThrottlingException", "TooManyRequestsException", "ServiceUnavailableException", "ModelNotReadyException"):
            return ModelUnavailable(f"Bedrock is throttling or unavailable ({code})")
        if code in ("AccessDeniedException", "UnrecognizedClientException", "ExpiredTokenException"):
            return ModelAuthError(f"Bedrock refused the credentials or model access ({code})")
        if code == "ModelTimeoutException" or "timeout" in name.lower():
            return ModelTimeout("the Bedrock call timed out")
        return _classify(exc, ())

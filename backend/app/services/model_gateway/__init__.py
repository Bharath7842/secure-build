"""The DAST model gateway package: the only place model SDKs are imported.

    from app.services.model_gateway import build_gateway
    gateway = build_gateway(routing=scan_settings["model_routing"])   # implements domain ModelGateway
"""

from __future__ import annotations

from typing import Any, Callable, Mapping

from app.config import settings as app_settings
from app.dast.domain.interfaces import ModelAdapter
from app.dast.domain.model_errors import ModelConfigurationError
from app.dast.domain.usage import UsageRecorder

from .adapters import AnthropicAdapter, BedrockAdapter, OllamaAdapter, OpenAIAdapter
from .gateway import ModelGatewayImpl
from .prompts import PromptError, PromptLibrary, default_library

__all__ = [
    "ModelGatewayImpl",
    "PromptError",
    "PromptLibrary",
    "adapter_for",
    "build_gateway",
    "build_local_gateway",
    "default_library",
    "configured_secrets",
]


def configured_secrets(cfg: Any = None) -> list[str]:
    """Every credential value the gateway could hold, for redaction of error text."""
    cfg = cfg or app_settings
    out = []
    for key in (cfg.anthropic_api_key, cfg.openai_api_key):
        if key is not None and key.get_secret_value():
            out.append(key.get_secret_value())
    return out


def ollama_reasoning(model: str, cfg: Any = None) -> bool:
    """Whether to ask Ollama for reasoning with `model` (False for the configured no-think prefixes)."""
    cfg = cfg or app_settings
    return not any((model or cfg.dast_ollama_model).lower().startswith(p.lower()) for p in cfg.dast_ollama_no_think_prefixes)


def adapter_for(provider: str, model: str, cfg: Any = None) -> ModelAdapter:
    """Build the adapter for a provider/model pair from settings. No SDK is imported here."""
    cfg = cfg or app_settings
    timeout = cfg.dast_model_timeout_s
    if provider == "ollama":
        return OllamaAdapter(cfg.dast_ollama_url, model or cfg.dast_ollama_model, timeout_s=timeout, num_ctx=cfg.dast_ollama_num_ctx, reasoning=ollama_reasoning(model, cfg))
    if provider == "anthropic":
        return AnthropicAdapter(cfg.anthropic_api_key, model, timeout_s=timeout)
    if provider == "openai":
        return OpenAIAdapter(cfg.openai_api_key, model, timeout_s=timeout)
    if provider == "bedrock":
        return BedrockAdapter(model or cfg.bedrock_model_id, cfg.aws_region, timeout_s=timeout)
    raise ModelConfigurationError(f"unknown model provider {provider!r}", setting="dast_model_<task>_provider")


def build_gateway(
    routing: Mapping[str, tuple[str, str]] | None = None,
    *,
    cfg: Any = None,
    usage: UsageRecorder | None = None,
    prompts: PromptLibrary | None = None,
    log: Callable[[str], None] | None = None,
    adapter_factory: Callable[[str, str], ModelAdapter] | None = None,
) -> ModelGatewayImpl:
    """A gateway for one scan. `routing` is the scan's snapshotted per-task routing; without it
    the current settings are used."""
    cfg = cfg or app_settings
    routing = routing or cfg.dast_model_routing
    recorder = usage or UsageRecorder(prices={k: tuple(v) for k, v in cfg.dast_model_prices.items()})
    return ModelGatewayImpl(
        routing,
        adapter_factory or (lambda provider, model: adapter_for(provider, model, cfg)),
        prompts=prompts if prompts is not None else default_library(),
        usage=recorder,
        secrets=lambda: configured_secrets(cfg),
        log=log,
        default_max_tokens=cfg.dast_model_max_tokens,
    )


def build_local_gateway(
    model: str | None = None,
    base_url: str | None = None,
    *,
    cfg: Any = None,
    log: Callable[[str], None] | None = None,
) -> ModelGatewayImpl:
    """A gateway that sends every task to one local Ollama model. Used by the standalone CLI and
    Flask entry points, which take `--ollama-model` / `--ollama-base-url` and have no scan snapshot."""
    cfg = cfg or app_settings
    chosen = model or cfg.dast_ollama_model
    url = base_url or cfg.dast_ollama_url
    return build_gateway(
        {task: ("ollama", chosen) for task in cfg.dast_model_routing},
        cfg=cfg,
        log=log,
        adapter_factory=lambda provider, name: OllamaAdapter(url, name, timeout_s=cfg.dast_model_timeout_s, num_ctx=cfg.dast_ollama_num_ctx, reasoning=ollama_reasoning(name, cfg)),
    )

"""Known LLM presets — shared catalog for API, agent bridge, and validation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

LlmProvider = Literal["bedrock", "openai_compat", "ollama", "claude_cli", "openai_cli"]
OllamaSizeClass = Literal["small", "large"]


@dataclass(frozen=True)
class LlmPreset:
    id: str
    label: str
    provider: LlmProvider
    model: str
    ollama_size: OllamaSizeClass | None = None  # only for provider=ollama


LLM_PRESETS: tuple[LlmPreset, ...] = (
    LlmPreset(
        id="bedrock-haiku",
        label="AWS Bedrock — Claude Haiku 4.5",
        provider="bedrock",
        model="us.anthropic.claude-haiku-4-5-20251001-v1:0",
    ),
    LlmPreset(
        id="bedrock-sonnet",
        label="AWS Bedrock — Claude Sonnet 4.5",
        provider="bedrock",
        model="us.anthropic.claude-sonnet-4-5-20250929-v1:0",
    ),
    # The local `claude` CLI (one Claude session per scan), using whatever
    # login Claude Code has on this machine. `model` is a CLI alias or id.
    LlmPreset(
        id="claude-cli-sonnet",
        label="Claude Sonnet 5.5",
        provider="claude_cli",
        model="claude-sonnet-5-5",
    ),
    LlmPreset(
        id="claude-cli-haiku",
        label="Claude Haiku 5.5",
        provider="claude_cli",
        model="claude-haiku-5-5",
    ),
    # A local OpenAI-model CLI (one thread per scan), using whatever login it has
    # on this machine. Labels name the model only; the CLI is just how it is reached.
    LlmPreset(
        id="openai-cli-sol",
        label="GPT-5.6 Sol",
        provider="openai_cli",
        model="gpt-5.6-sol",
    ),
    LlmPreset(
        id="openai-cli-astra",
        label="GPT-6 Astra",
        provider="openai_cli",
        model="gpt-6-astra",
    ),
    LlmPreset(
        id="openai-cli-terra",
        label="GPT-5.6 Terra",
        provider="openai_cli",
        model="gpt-5.6-terra",
    ),
    LlmPreset(
        id="openai-cli-luna",
        label="GPT-5.6 Luna",
        provider="openai_cli",
        model="gpt-5.6-luna",
    ),
    # Any OpenAI-compatible /chat/completions server (vLLM, LM Studio,
    # llama.cpp server, SGLang, a hosted gateway, ...). The model id is
    # whatever that server serves; the project's llm_base_url picks the server.
    LlmPreset(
        id="openai-compat-qwen-coder-32b",
        label="OpenAI-compatible — Qwen2.5-Coder-32B-Instruct (vLLM / LM Studio)",
        provider="openai_compat",
        model="Qwen/Qwen2.5-Coder-32B-Instruct",
    ),
    LlmPreset(
        id="ollama-granite-3b",
        label="Ollama — granite-code:3b (local)",
        provider="ollama",
        model="granite-code:3b",
        ollama_size="small",
    ),
    LlmPreset(
        id="ollama-granite4-2-3b",
        label="Ollama — granite4.2:3b (local)",
        provider="ollama",
        model="granite4.2:3b",
        ollama_size="small",
    ),
    LlmPreset(
        id="ollama-granite-3b-instruct",
        label="Ollama — granite-code:3b-instruct (local)",
        provider="ollama",
        model="granite-code:3b-instruct",
        ollama_size="small",
    ),
    LlmPreset(
        id="ollama-granite-8b",
        label="Ollama — granite-code:8b (local)",
        provider="ollama",
        model="granite-code:8b",
        ollama_size="small",
    ),
    LlmPreset(
        id="ollama-gpt-oss",
        label="Ollama — gpt-oss:latest (local)",
        provider="ollama",
        model="gpt-oss:latest",
        ollama_size="large",
    ),
    LlmPreset(
        id="ollama-gpt-oss-20b",
        label="Ollama — gpt-oss:20b (local)",
        provider="ollama",
        model="gpt-oss:20b",
        ollama_size="large",
    ),
    LlmPreset(
        id="ollama-gpt-oss-safeguard",
        label="Ollama — gpt-oss-safeguard:latest (local)",
        provider="ollama",
        model="gpt-oss-safeguard:latest",
        ollama_size="large",
    ),
    LlmPreset(
        id="ollama-starcoder2-3b",
        label="Ollama — starcoder2:3b (local)",
        provider="ollama",
        model="starcoder2:3b",
        ollama_size="small",
    ),
    LlmPreset(
        id="ollama-qwen2-72b",
        label="Ollama — Qwen2 72B Instruct (local)",
        provider="ollama",
        model="hf.co/bartowski/Qwen2-72B-Instruct-GGUF:Q4_K_M",
        ollama_size="large",
    ),
    LlmPreset(
        id="ollama-codegemma",
        label="Ollama — CodeGemma:latest (local)",
        provider="ollama",
        model="codegemma:latest",
        ollama_size="small",
    ),
)

_PRESET_BY_MODEL: dict[tuple[str, str], LlmPreset] = {
    (p.provider, p.model): p for p in LLM_PRESETS
}

_OLLAMA_BY_MODEL: dict[str, LlmPreset] = {
    p.model: p for p in LLM_PRESETS if p.provider == "ollama"
}


@dataclass(frozen=True)
class OllamaRunTuning:
    tag_batch_size: int
    flow_budget: int
    deep_review_max_files: int


def preset_for_model(provider: str, model: str | None) -> LlmPreset | None:
    if not model:
        return None
    return _PRESET_BY_MODEL.get((provider.strip().lower(), model.strip()))


def ollama_size_class(model: str | None) -> OllamaSizeClass:
    """Classify Ollama model for batch/budget tuning (unknown → small)."""
    if not model:
        return "small"
    preset = _OLLAMA_BY_MODEL.get(model.strip())
    if preset and preset.ollama_size:
        return preset.ollama_size
    lowered = model.lower()
    if "72b" in lowered or "70b" in lowered or "gpt-oss" in lowered:
        return "large"
    return "small"


def ollama_run_tuning(model: str | None, *, env: dict[str, str] | None = None) -> OllamaRunTuning:
    """Per-model Ollama stage budgets; env vars override defaults."""
    import os

    env = env if env is not None else os.environ
    size = ollama_size_class(model)
    if size == "large":
        return OllamaRunTuning(
            tag_batch_size=int(env.get("OLLAMA_TAG_BATCH_SIZE_LARGE", env.get("OLLAMA_TAG_BATCH_SIZE", "3"))),
            flow_budget=int(env.get("OLLAMA_FLOW_BUDGET_LARGE", env.get("OLLAMA_FLOW_BUDGET", "8"))),
            deep_review_max_files=int(
                env.get("OLLAMA_DEEP_REVIEW_MAX_FILES_LARGE", env.get("OLLAMA_DEEP_REVIEW_MAX_FILES", "1"))
            ),
        )
    return OllamaRunTuning(
        tag_batch_size=int(env.get("OLLAMA_TAG_BATCH_SIZE", "5")),
        flow_budget=int(env.get("OLLAMA_FLOW_BUDGET", "15")),
        deep_review_max_files=int(env.get("OLLAMA_DEEP_REVIEW_MAX_FILES", "2")),
    )


def presets_as_dicts() -> list[dict[str, str | None]]:
    return [
        {
            "id": p.id,
            "label": p.label,
            "provider": p.provider,
            "model": p.model,
            "ollama_size": p.ollama_size,
        }
        for p in LLM_PRESETS
    ]

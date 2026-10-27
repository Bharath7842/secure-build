"""Known DAST models per provider — the options offered in the DAST model pickers."""

from __future__ import annotations

from app.defaults.llm_presets import LLM_PRESETS

_BEDROCK_HAIKU = next(p.model for p in LLM_PRESETS if p.id == "bedrock-haiku")

# provider -> [(model id, label)]
DAST_MODEL_OPTIONS: dict[str, tuple[tuple[str, str], ...]] = {
    "bedrock": (
        (_BEDROCK_HAIKU, "Claude Haiku 4.5"),
        ("us.anthropic.claude-sonnet-5", "Claude Sonnet 5"),
    ),
    "ollama": (
        ("gpt-oss:20b", "gpt-oss:20b"),
        ("gpt-oss:latest", "gpt-oss:latest"),
        ("granite-code:3b-instruct", "granite-code:3b-instruct"),
        ("granite-code:3b", "granite-code:3b"),
        ("granite-code:8b", "granite-code:8b"),
        ("granite4.2:3b", "granite4.2:3b"),
        ("gemma4:12b", "gemma4:12b"),
        ("phi4-mini:3.8b", "phi4-mini:3.8b"),
    ),
    # The local `claude` CLI; the same two models SAST offers for it.
    "claude_cli": tuple((p.model, p.label) for p in LLM_PRESETS if p.provider == "claude_cli"),
    "openai": (("gpt-4o-mini", "gpt-4o-mini"),),
    "anthropic": (("claude-haiku-4-5", "Claude Haiku 4.5"),),
}

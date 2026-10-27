from app.services.scan_runner import (
    _friendly_llm_label,
    _friendly_model_label,
    _friendly_scope_label,
)


def test_friendly_llm_label_bedrock_prettifies_model_id():
    label = _friendly_llm_label("bedrock", "us.anthropic.claude-haiku-4-5-20251001-v1:0", True)
    assert label == "Bedrock (Claude Haiku 4.5)"


def test_friendly_llm_label_ollama_keeps_raw_tag():
    label = _friendly_llm_label("ollama", "granite-code:3b", True)
    assert label == "Ollama (granite-code:3b)"


def test_friendly_llm_label_claude_cli_keeps_alias():
    assert _friendly_llm_label("claude_cli", "claude-sonnet-5-5", True) == "Claude Sonnet 5.5"
    assert _friendly_llm_label("claude_cli", "claude-haiku-5-5", True) == "Claude Haiku 5.5"


def test_friendly_llm_label_openai_cli_shows_the_model_only():
    assert _friendly_llm_label("openai_cli", "gpt-5.6-sol", True) == "GPT-5.6 Sol"
    assert _friendly_llm_label("openai_cli", "gpt-6-astra", True) == "GPT-6 Astra"


def test_friendly_llm_label_no_llm():
    assert _friendly_llm_label(None, None, False) == "heuristics only (no LLM)"


def test_friendly_model_label_bedrock_without_date_suffix():
    assert _friendly_model_label("bedrock", "anthropic.claude-3-opus") == "Claude 3 Opus"


def test_friendly_model_label_none_model():
    assert _friendly_model_label("bedrock", None) is None


def test_friendly_scope_label_full_vs_subdirectory():
    assert _friendly_scope_label(None) == "the full repository"
    assert _friendly_scope_label("apps/api") == "subdirectory 'apps/api'"

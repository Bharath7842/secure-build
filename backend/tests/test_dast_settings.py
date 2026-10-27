"""DAST settings surface (DAST-00-030): defaults, env overrides, validation, routing."""

import pytest
from pydantic import ValidationError

from app.config import DAST_MODEL_TASKS, Settings

# Env vars that would leak the developer's own .env/shell into default assertions.
_DAST_ENV = [
    "DAST_MAX_RUNTIME_MINUTES", "DAST_MAX_DEPTH", "DAST_MAX_PAGES", "DAST_MAX_PER_PATTERN",
    "DAST_SAME_DOMAIN_MODE", "DAST_SAFE_MODE_DEFAULT", "DAST_RATE_LIMIT_PER_SEC",
    "DAST_AGENT_MODE_DEFAULT", "DAST_MAX_AGENT_TURNS", "DAST_MAX_TURNS_PER_HYPOTHESIS",
    "DAST_MAX_TARGETS", "DAST_MAX_TESTS_PER_TARGET", "DAST_OAST_CALLBACK_URL",
    "DAST_BROWSER_PROBE_ENABLED", "DAST_BROWSER_MARKER_POSTS", "DAST_BROWSER_PROBE_MAX_INPUTS",
    "DAST_OLLAMA_BASE_URL", "DAST_OLLAMA_MODEL", "OLLAMA_BASE_URL", "BEDROCK_MODEL_ID",
] + [f"DAST_MODEL_{t.upper()}_{kind}" for t in DAST_MODEL_TASKS for kind in ("PROVIDER", "MODEL")]


@pytest.fixture()
def clean_env(monkeypatch):
    for name in _DAST_ENV:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def make_settings() -> Settings:
    # Ignore backend/.env so the assertions describe code defaults, not one machine's file.
    return Settings(_env_file=None)


pytestmark = pytest.mark.unit


def test_defaults_match_the_tech_stack_document(clean_env):
    s = make_settings()
    assert s.dast_max_runtime_minutes == 10
    assert s.dast_max_depth == 3
    assert s.dast_max_pages == 100
    assert s.dast_max_per_pattern == 3
    assert s.dast_same_domain_mode == "exact"
    assert s.dast_safe_mode_default is True
    assert s.dast_agent_mode_default is False
    assert s.dast_max_agent_turns == 60 and s.dast_max_turns_per_hypothesis == 4
    assert s.dast_browser_probe_enabled is True
    assert s.dast_browser_marker_posts is False
    assert s.dast_browser_probe_max_inputs == 4
    assert s.dast_rate_limit_per_sec == 5
    assert s.dast_max_targets == 15
    assert s.dast_max_tests_per_target == 12
    assert s.dast_oast_callback_url is None


@pytest.mark.parametrize(
    "env, attr, expected",
    [
        ("DAST_MAX_RUNTIME_MINUTES", "dast_max_runtime_minutes", 2.5),
        ("DAST_MAX_DEPTH", "dast_max_depth", 5),
        ("DAST_MAX_PAGES", "dast_max_pages", 7),
        ("DAST_MAX_PER_PATTERN", "dast_max_per_pattern", 9),
        ("DAST_SAME_DOMAIN_MODE", "dast_same_domain_mode", "root-domain"),
        ("DAST_SAFE_MODE_DEFAULT", "dast_safe_mode_default", False),
        ("DAST_RATE_LIMIT_PER_SEC", "dast_rate_limit_per_sec", 1.5),
        ("DAST_MAX_TARGETS", "dast_max_targets", 4),
        ("DAST_MAX_TESTS_PER_TARGET", "dast_max_tests_per_target", 6),
        ("DAST_OAST_CALLBACK_URL", "dast_oast_callback_url", "https://oast.example.test"),
        ("DAST_OLLAMA_BASE_URL", "dast_ollama_base_url", "http://ollama.internal:11434"),
    ],
)
def test_each_value_is_overridable_by_environment(clean_env, env, attr, expected):
    clean_env.setenv(env, str(expected))
    assert getattr(make_settings(), attr) == expected


def test_invalid_same_domain_mode_is_rejected(clean_env):
    clean_env.setenv("DAST_SAME_DOMAIN_MODE", "subdomains")
    with pytest.raises(ValidationError):
        make_settings()


@pytest.mark.parametrize(
    "env, value",
    [
        ("DAST_MAX_DEPTH", "0"),
        ("DAST_MAX_PAGES", "-1"),
        ("DAST_RATE_LIMIT_PER_SEC", "0"),
        ("DAST_MAX_RUNTIME_MINUTES", "0"),
        ("DAST_MODEL_RULE_PROVIDER", "carrier-pigeon"),
    ],
)
def test_nonsensical_values_are_rejected(clean_env, env, value):
    clean_env.setenv(env, value)
    with pytest.raises(ValidationError):
        make_settings()


def test_blank_oast_url_counts_as_unset(clean_env):
    clean_env.setenv("DAST_OAST_CALLBACK_URL", "")
    assert make_settings().dast_oast_callback_url is None


def test_ollama_url_falls_back_to_the_shared_setting(clean_env):
    s = make_settings()
    assert s.dast_ollama_url == s.ollama_base_url == "http://localhost:11434"

    clean_env.setenv("OLLAMA_BASE_URL", "http://shared:11434")
    assert make_settings().dast_ollama_url == "http://shared:11434"

    clean_env.setenv("DAST_OLLAMA_BASE_URL", "http://dast-only:11434")
    s = make_settings()
    assert s.dast_ollama_url == "http://dast-only:11434"
    assert s.ollama_base_url == "http://shared:11434"  # SAST/other callers untouched


def test_existing_dast_and_bedrock_settings_keep_working(clean_env):
    s = make_settings()
    assert s.dast_ollama_model == "gpt-oss:20b"
    assert s.run_dast is True
    assert s.bedrock_model_id.startswith("us.anthropic.claude-haiku")

    clean_env.setenv("DAST_OLLAMA_MODEL", "llama3.1:8b")
    clean_env.setenv("BEDROCK_MODEL_ID", "my-bedrock-model")
    s = make_settings()
    assert s.dast_ollama_model == "llama3.1:8b"
    assert s.bedrock_model_id == "my-bedrock-model"


def test_routing_covers_all_seven_tasks(clean_env):
    routing = make_settings().dast_model_routing
    assert set(routing) == set(DAST_MODEL_TASKS) == {
        "fingerprint", "crawl_plan", "login_selectors", "normalize_endpoints", "plan", "construct", "rule", "narrate",
    }
    # Plain structure EPIC-15 can persist: task -> (provider, model).
    assert all(provider == "ollama" and model == "gpt-oss:20b" for provider, model in routing.values())


def test_routing_is_overridable_per_task_and_resolves_provider_defaults(clean_env):
    clean_env.setenv("DAST_MODEL_RULE_PROVIDER", "anthropic")
    clean_env.setenv("DAST_MODEL_RULE_MODEL", "claude-sonnet-5-5")
    clean_env.setenv("DAST_MODEL_NARRATE_PROVIDER", "bedrock")  # model left empty
    clean_env.setenv("DAST_OLLAMA_MODEL", "custom:7b")
    routing = make_settings().dast_model_routing

    assert routing["rule"] == ("anthropic", "claude-sonnet-5-5")
    assert routing["narrate"] == ("bedrock", make_settings().bedrock_model_id)
    assert routing["construct"] == ("ollama", "custom:7b")

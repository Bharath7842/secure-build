"""LLM preset catalog and Ollama tuning tests."""

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.db import init_db
from app.defaults.llm_presets import (
    LLM_PRESETS,
    ollama_run_tuning,
    ollama_size_class,
    preset_for_model,
    presets_as_dicts,
)
from app.main import app

HDR = {"Authorization": f"Bearer {settings.sast_api_token}"}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("USE_MOCK_ENGINE", "true")
    settings.use_mock_engine = True
    settings.scan_logs_dir = str(tmp_path / "scan_logs")
    url = f"sqlite:///{(tmp_path / 'test.db').as_posix()}"
    init_db(url)
    return TestClient(app)


def test_presets_include_local_ollama_models():
    models = {p.model for p in LLM_PRESETS if p.provider == "ollama"}
    assert "starcoder2:3b" in models
    assert "gpt-oss:latest" in models
    assert "hf.co/bartowski/Qwen2-72B-Instruct-GGUF:Q4_K_M" in models


def test_presets_include_openai_compatible_provider():
    assert any(p.provider == "openai_compat" for p in LLM_PRESETS)


def test_presets_include_claude_cli_provider():
    models = {p.model for p in LLM_PRESETS if p.provider == "claude_cli"}
    assert models == {"claude-sonnet-5-5", "claude-haiku-5-5"}


def test_presets_include_openai_cli_provider():
    models = {p.model for p in LLM_PRESETS if p.provider == "openai_cli"}
    assert models == {"gpt-6-astra", "gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna"}


def test_preset_for_model_lookup():
    p = preset_for_model("ollama", "starcoder2:3b")
    assert p is not None
    assert p.id == "ollama-starcoder2-3b"


def test_ollama_size_class_large_for_qwen_and_gpt_oss():
    assert ollama_size_class("hf.co/bartowski/Qwen2-72B-Instruct-GGUF:Q4_K_M") == "large"
    assert ollama_size_class("gpt-oss:latest") == "large"
    assert ollama_size_class("starcoder2:3b") == "small"


def test_ollama_run_tuning_smaller_batches_for_large_models():
    small = ollama_run_tuning("granite-code:3b", env={})
    large = ollama_run_tuning("gpt-oss:latest", env={})
    assert large.tag_batch_size <= small.tag_batch_size
    assert large.flow_budget <= small.flow_budget


def test_presets_as_dicts_for_api():
    rows = presets_as_dicts()
    assert len(rows) == len(LLM_PRESETS)
    assert rows[0]["id"] and rows[0]["model"]


def test_list_llm_presets_api(client):
    resp = client.get("/llm-presets", headers=HDR)
    assert resp.status_code == 200
    rows = resp.json()
    assert len(rows) == len(LLM_PRESETS)
    models = {r["model"] for r in rows if r["provider"] == "ollama"}
    assert "gpt-oss:latest" in models
    assert "starcoder2:3b" in models

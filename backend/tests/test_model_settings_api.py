"""Model visibility settings: which models the model selects offer."""

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.db import init_db
from app.defaults.dast_models import DAST_MODEL_OPTIONS
from app.defaults.llm_presets import LLM_PRESETS
from app.main import app

HDR = {"Authorization": f"Bearer {settings.sast_api_token}"}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("USE_MOCK_ENGINE", "true")
    settings.use_mock_engine = True
    settings.scan_logs_dir = str(tmp_path / "scan_logs")
    init_db(f"sqlite:///{(tmp_path / 'test.db').as_posix()}")
    return TestClient(app)


def test_everything_visible_by_default(client):
    body = client.get("/settings/models", headers=HDR).json()
    assert body["hidden"] == []
    assert len(body["sast"]) == len(LLM_PRESETS)
    assert all(m["visible"] for m in body["sast"])
    assert set(body["dast"]) == set(DAST_MODEL_OPTIONS)
    assert all(m["visible"] for models in body["dast"].values() for m in models)


def test_hide_persists_and_is_reflected(client):
    keys = ["sast:ollama-codegemma", "dast:ollama:gemma4:12b"]
    resp = client.patch("/settings/models", json={"hidden": keys}, headers=HDR)
    assert resp.status_code == 200
    body = client.get("/settings/models", headers=HDR).json()
    assert body["hidden"] == sorted(keys)
    sast = {m["id"]: m["visible"] for m in body["sast"]}
    assert sast["ollama-codegemma"] is False
    assert sast["bedrock-haiku"] is True
    dast = {m["id"]: m["visible"] for m in body["dast"]["ollama"]}
    assert dast["gemma4:12b"] is False


def test_patch_replaces_hidden_list(client):
    client.patch("/settings/models", json={"hidden": ["sast:ollama-codegemma"]}, headers=HDR)
    client.patch("/settings/models", json={"hidden": []}, headers=HDR)
    assert client.get("/settings/models", headers=HDR).json()["hidden"] == []


def test_unknown_key_is_422(client):
    resp = client.patch("/settings/models", json={"hidden": ["sast:nope"]}, headers=HDR)
    assert resp.status_code == 422
    assert resp.json()["detail"]["errors"][0]["field"] == "hidden"


def test_pinned_local_granite_cannot_be_hidden(client):
    for key in ("sast:ollama-granite-3b-instruct", "dast:ollama:granite-code:3b-instruct"):
        resp = client.patch("/settings/models", json={"hidden": [key]}, headers=HDR)
        assert resp.status_code == 422
    body = client.get("/settings/models", headers=HDR).json()
    assert body["hidden"] == []
    assert [m["key"] for m in body["sast"] if m["pinned"]] == ["sast:ollama-granite-3b-instruct"]
    assert [m["id"] for m in body["dast"]["ollama"] if m["pinned"]] == ["granite-code:3b-instruct"]


def test_everything_else_can_be_hidden_including_whole_providers(client):
    body = client.get("/settings/models", headers=HDR).json()
    keys = [m["key"] for m in body["sast"] if not m["pinned"]]
    for models in body["dast"].values():
        keys += [m["key"] for m in models if not m["pinned"]]
    resp = client.patch("/settings/models", json={"hidden": keys}, headers=HDR)
    assert resp.status_code == 200
    after = resp.json()
    assert [m["id"] for m in after["sast"] if m["visible"]] == ["ollama-granite-3b-instruct"]
    assert not any(m["visible"] for m in after["dast"]["openai"])
    assert not any(m["visible"] for m in after["dast"]["anthropic"])


def test_requires_bearer_token(client):
    assert client.get("/settings/models").status_code in (401, 403)
    assert client.patch("/settings/models", json={"hidden": []}).status_code in (401, 403)


def test_llm_presets_endpoint_unaffected_by_hiding(client):
    client.patch("/settings/models", json={"hidden": ["sast:ollama-codegemma"]}, headers=HDR)
    rows = client.get("/llm-presets", headers=HDR).json()
    assert len(rows) == len(LLM_PRESETS)

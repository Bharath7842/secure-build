import io
import json


from app.services import ollama_check


def _tags(monkeypatch, names):
    body = json.dumps({"models": [{"name": n, "model": n} for n in names]}).encode()
    monkeypatch.setattr(ollama_check.urllib.request, "urlopen", lambda *a, **k: io.BytesIO(body))


def test_model_present(monkeypatch):
    _tags(monkeypatch, ["granite-code:3b-instruct", "phi4-mini:3.8b"])
    assert ollama_check.ollama_model_error("http://x", "granite-code:3b-instruct") is None


def test_model_missing_names_pull_command(monkeypatch):
    _tags(monkeypatch, ["granite-code:3b-instruct"])
    err = ollama_check.ollama_model_error("http://x", "granite-code:3b")
    assert "ollama pull granite-code:3b" in err


def test_untagged_name_means_latest(monkeypatch):
    _tags(monkeypatch, ["nomic-embed-text:latest"])
    assert ollama_check.ollama_model_error("http://x", "nomic-embed-text") is None


def test_unreachable_server(monkeypatch):
    def boom(*a, **k):
        raise OSError("refused")

    monkeypatch.setattr(ollama_check.urllib.request, "urlopen", boom)
    assert "not reachable" in ollama_check.ollama_model_error("http://x", "m:1")

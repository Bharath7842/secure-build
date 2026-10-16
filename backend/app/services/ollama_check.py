"""Pre-flight check that an Ollama model is pulled, so a scan fails at trigger
time instead of switching to a missing fallback model mid-run."""

import json
import urllib.error
import urllib.request

DEFAULT_FALLBACK_OLLAMA_MODEL = "granite-code:3b-instruct"


def _normalize(name: str) -> str:
    name = name.strip()
    return name if ":" in name else f"{name}:latest"


def ollama_model_error(base_url: str, model: str, *, timeout: float = 3.0) -> str | None:
    """Why `model` can't be used on the Ollama server at `base_url`, or None if it is pulled."""
    try:
        with urllib.request.urlopen(f"{base_url.rstrip('/')}/api/tags", timeout=timeout) as resp:
            tags = json.load(resp)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return f"Ollama is not reachable at {base_url} ({exc}); it is needed for the fallback model {model!r}"
    available = {
        _normalize(str(m.get(key)))
        for m in tags.get("models", [])
        for key in ("name", "model")
        if m.get(key)
    }
    if _normalize(model) not in available:
        return f"Ollama model {model!r} is not available at {base_url}; run `ollama pull {model}`"
    return None

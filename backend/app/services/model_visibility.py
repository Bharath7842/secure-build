"""Which models the model selects offer (SAST project/scan forms and the DAST pickers).

The catalogs live in `app.defaults.llm_presets` (SAST) and `app.defaults.dast_models` (DAST). Each
model has a stable key, `sast:<preset id>` or `dast:<provider>:<model>`, and the settings store the
*hidden* keys, so a model added to a catalog later is visible by default. Hiding only affects what
the forms offer: scans and projects that already use a hidden model keep working.

The local Ollama `granite-code:3b-instruct` is pinned: it can't be hidden, so every select always has
at least one option that needs no external provider. Every other model, including a whole provider,
can be hidden.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.defaults.dast_models import DAST_MODEL_OPTIONS
from app.defaults.llm_presets import LLM_PRESETS
from app.models import AppSetting

KEY = "hidden_models"
PINNED_OLLAMA_MODEL = "granite-code:3b-instruct"


class ModelSettingsError(ValueError):
    """The submitted hidden list is invalid. `errors` lists `{field, message}` for each problem."""

    def __init__(self, errors: list[dict[str, str]]):
        self.errors = errors
        super().__init__("; ".join(f"{e['field']}: {e['message']}" for e in errors))


def sast_key(preset_id: str) -> str:
    return f"sast:{preset_id}"


def dast_key(provider: str, model: str) -> str:
    return f"dast:{provider}:{model}"


def pinned_keys() -> set[str]:
    """Keys that can never be hidden: the local granite-code instruct model, in SAST and DAST."""
    return {
        sast_key(p.id) for p in LLM_PRESETS if p.provider == "ollama" and p.model == PINNED_OLLAMA_MODEL
    } | {dast_key("ollama", PINNED_OLLAMA_MODEL)}


def _all_keys() -> set[str]:
    keys = {sast_key(p.id) for p in LLM_PRESETS}
    for provider, options in DAST_MODEL_OPTIONS.items():
        keys |= {dast_key(provider, model) for model, _ in options}
    return keys


def load_hidden(db: Session) -> set[str]:
    row = db.get(AppSetting, KEY)
    keys = (row.value or {}).get("keys", []) if row else []
    return set(keys)


def save_hidden(db: Session, keys: list[str]) -> None:
    requested = set(keys)
    errors = [
        {"field": "hidden", "message": f"unknown model key: {k}"} for k in sorted(requested - _all_keys())
    ]
    errors += [
        {"field": "hidden", "message": f"{k} is the always-available local model and can't be hidden"}
        for k in sorted(requested & pinned_keys())
    ]
    if errors:
        raise ModelSettingsError(errors)
    value = {"keys": sorted(requested)}
    row = db.get(AppSetting, KEY)
    if row is None:
        db.add(AppSetting(key=KEY, value=value))
    else:
        row.value = value
    db.commit()


def build_catalog(db: Session) -> dict[str, Any]:
    hidden = load_hidden(db)
    pinned = pinned_keys()
    return {
        "sast": [
            {
                "key": sast_key(p.id),
                "id": p.id,
                "label": p.label,
                "provider": p.provider,
                "model": p.model,
                "visible": sast_key(p.id) not in hidden,
                "pinned": sast_key(p.id) in pinned,
            }
            for p in LLM_PRESETS
        ],
        "dast": {
            provider: [
                {
                    "key": dast_key(provider, model),
                    "id": model,
                    "label": label,
                    "provider": provider,
                    "model": model,
                    "visible": dast_key(provider, model) not in hidden,
                    "pinned": dast_key(provider, model) in pinned,
                }
                for model, label in options
            ]
            for provider, options in DAST_MODEL_OPTIONS.items()
        },
        "hidden": sorted(hidden),
    }

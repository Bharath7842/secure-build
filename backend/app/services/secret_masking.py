"""Secret masking for what the app stores and logs (LLM02).

The detector itself is the engine's `sast_engine/secret_mask.py` (stdlib-only,
shared with the prompt boundary in `llm_client.call_llm`), loaded by path through
`engine_files`.
"""

from __future__ import annotations

from typing import Any

from app.services import engine_files

SECRET_MASKING_LIMITATION = "secret-masking"


def mask_text(text: str) -> str:
    return engine_files.load("secret_mask").mask(text)


def mask_value(value: Any) -> Any:
    """Every string inside a dict/list/str with secret values replaced (a copy)."""
    return engine_files.load("secret_mask").mask_value(value)


def mask_enabled(project: Any) -> bool:
    """The project's `secret-masking` limitation (on unless it was switched off)."""
    from app.defaults.scan_limitations import limitation_defaults

    config = getattr(project, "limitations_config", None) or {}
    return bool(config.get(SECRET_MASKING_LIMITATION, limitation_defaults()[SECRET_MASKING_LIMITATION]))

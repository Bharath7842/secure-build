"""Editable global DAST settings and model routing (DAST-15-010, -050).

**Persistence decision (DAST-15-050):** edits are stored in the database, in `dast_global_config`
under the key `settings`, as *overrides* on top of the environment configuration (`DAST_*`
variables), which stays the baseline and the fallback. Removing an override restores the
environment value. Edits apply to scans created afterwards only: a scan snapshots its effective
settings and model routing when it is created (`dast_effective`, `dast_settings`), so running and
past scans never change.

**Secrets (DAST-15-020 decision):** provider API keys stay in the environment (`ANTHROPIC_API_KEY`,
`OPENAI_API_KEY`, AWS credentials). The platform has no secret store and this module does not invent
one: the settings page shows read-only "set" / "not set" status (`provider_status`) and never a
value. The OAST callback address is stored here but is write-only through the API: it is a URL a
target could be made to call, so it is reported only as configured or not.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from sqlalchemy.orm import Session

from app import db as app_db
from app.config import DAST_MODEL_TASKS, Settings
from app.config import settings as env_settings
from app.models import DastGlobalConfig

KEY = "settings"
PROVIDERS = ("ollama", "bedrock", "openai", "anthropic", "claude_cli")


@dataclass(frozen=True)
class Field:
    name: str  # the API name
    attr: str  # the Settings attribute it overrides
    kind: type
    low: float | None = None
    high: float | None = None
    label: str = ""


FIELDS: tuple[Field, ...] = (
    Field("max_runtime_minutes", "dast_max_runtime_minutes", float, 0.5, 480, "Maximum crawl runtime (minutes)"),
    Field("max_depth", "dast_max_depth", int, 1, 10, "Maximum crawl depth"),
    Field("max_pages", "dast_max_pages", int, 1, 1000, "Maximum pages crawled"),
    Field("max_per_pattern", "dast_max_per_pattern", int, 1, 50, "Pages crawled per URL pattern"),
    Field("rate_limit_per_sec", "dast_rate_limit_per_sec", float, 0.1, 100, "Request rate limit (per second)"),
    Field("max_targets", "dast_max_targets", int, 1, 500, "Endpoints tested per scan"),
    Field("max_tests_per_target", "dast_max_tests_per_target", int, 1, 100, "Tests per endpoint"),
    Field("max_agent_turns", "dast_max_agent_turns", int, 1, 1000, "Adaptive turns per scan"),
    Field("max_turns_per_hypothesis", "dast_max_turns_per_hypothesis", int, 1, 20, "Adaptive turns per hypothesis"),
    Field("browser_probe_max_inputs", "dast_browser_probe_max_inputs", int, 1, 20, "Inputs probed per page"),
)
_BY_NAME = {f.name: f for f in FIELDS}
SAME_DOMAIN_MODES = ("exact", "root-domain")


class SettingsError(ValueError):
    """The submitted settings are invalid. `errors` lists `{field, message}` for each problem."""

    def __init__(self, errors: list[dict[str, str]]):
        self.errors = errors
        super().__init__("; ".join(f"{e['field']}: {e['message']}" for e in errors))


def _load(db: Session) -> dict[str, Any]:
    row = db.get(DastGlobalConfig, KEY)
    return dict(row.value or {}) if row else {}


def get_overrides(db: Session) -> dict[str, Any]:
    return _load(db)


def _save(db: Session, value: dict[str, Any]) -> None:
    row = db.get(DastGlobalConfig, KEY)
    if row is None:
        db.add(DastGlobalConfig(key=KEY, value=value))
    else:
        row.value = value
    db.commit()


def _validate_value(f: Field, raw: Any) -> int | float:
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        raise ValueError("must be a number")
    value = f.kind(raw)
    if f.kind is int and float(raw) != value:
        raise ValueError("must be a whole number")
    if f.low is not None and value < f.low:
        raise ValueError(f"must be at least {f.low:g}")
    if f.high is not None and value > f.high:
        raise ValueError(f"must be at most {f.high:g}")
    return value


def validate_oast_url(value: str) -> str:
    value = (value or "").strip()
    if value and not (value.startswith("http://") or value.startswith("https://")):
        raise ValueError("must start with http:// or https://")
    if len(value) > 500 or any(c in value for c in " \t\r\n"):
        raise ValueError("must be a single URL of at most 500 characters")
    return value.rstrip("/")


def update_settings(db: Session, patch: Mapping[str, Any], *, confirm_unsafe: bool = False) -> None:
    """Merge `patch` into the stored overrides. Raises `SettingsError` naming every invalid field."""
    errors: list[dict[str, str]] = []
    current = _load(db)
    updated = dict(current)
    for name, raw in patch.items():
        if name == "same_domain_mode":
            if raw not in SAME_DOMAIN_MODES:
                errors.append({"field": name, "message": f"must be one of: {', '.join(SAME_DOMAIN_MODES)}"})
            else:
                updated[name] = raw
        elif name == "safe_mode_default":
            if not isinstance(raw, bool):
                errors.append({"field": name, "message": "must be true or false"})
            elif raw is False and not confirm_unsafe:
                errors.append({"field": name, "message": "turning safe mode off by default needs explicit confirmation (confirm_unsafe)"})
            else:
                updated[name] = raw
        elif name in ("browser_probe_enabled", "browser_marker_posts", "agent_mode"):
            if not isinstance(raw, bool):
                errors.append({"field": name, "message": "must be true or false"})
            elif name == "browser_marker_posts" and raw is True and not confirm_unsafe:
                errors.append({"field": name, "message": "allowing marker submits by default needs explicit confirmation (confirm_unsafe)"})
            else:
                updated[name] = raw
        elif name == "oast_callback_url":
            try:
                value = validate_oast_url(str(raw))
            except ValueError as exc:
                errors.append({"field": name, "message": str(exc)})
                continue
            if value:
                updated[name] = value
            else:
                updated.pop(name, None)  # an empty string clears it
        elif name in _BY_NAME:
            try:
                updated[name] = _validate_value(_BY_NAME[name], raw)
            except ValueError as exc:
                errors.append({"field": name, "message": str(exc)})
        elif name == "confirm_unsafe":
            continue
        else:
            errors.append({"field": name, "message": "is not an editable setting"})
    if errors:
        raise SettingsError(errors)
    _save(db, updated)


def update_routing(db: Session, routes: list[Mapping[str, Any]]) -> None:
    errors: list[dict[str, str]] = []
    routing: dict[str, dict[str, str]] = {}
    for index, route in enumerate(routes):
        task, provider, model = str(route.get("task") or ""), str(route.get("provider") or "").lower(), str(route.get("model") or "").strip()
        where = f"routes[{index}]"
        if task not in DAST_MODEL_TASKS:
            errors.append({"field": where + ".task", "message": f"must be one of: {', '.join(DAST_MODEL_TASKS)}"})
            continue
        if provider not in PROVIDERS:
            errors.append({"field": where + ".provider", "message": f"must be one of: {', '.join(PROVIDERS)}"})
            continue
        if provider in ("openai", "anthropic") and not model:
            errors.append({"field": where + ".model", "message": f"{provider} needs an explicit model name"})
            continue
        if len(model) > 200 or any(c in model for c in "\r\n\t"):
            errors.append({"field": where + ".model", "message": "is not a valid model name"})
            continue
        routing[task] = {"provider": provider, "model": model}
    if errors:
        raise SettingsError(errors)
    current = _load(db)
    current["model_routing"] = {**(current.get("model_routing") or {}), **routing}
    _save(db, current)


def effective_settings(db: Session, base: Settings | None = None) -> Settings:
    """The environment settings with the stored overrides applied: what a scan created now would use."""
    base = base or env_settings
    stored = _load(db)
    update: dict[str, Any] = {}
    for name, f in _BY_NAME.items():
        if name in stored:
            update[f.attr] = stored[name]
    if "same_domain_mode" in stored:
        update["dast_same_domain_mode"] = stored["same_domain_mode"]
    if "safe_mode_default" in stored:
        update["dast_safe_mode_default"] = bool(stored["safe_mode_default"])
    if "agent_mode" in stored:
        update["dast_agent_mode_default"] = bool(stored["agent_mode"])
    if "browser_probe_enabled" in stored:
        update["dast_browser_probe_enabled"] = bool(stored["browser_probe_enabled"])
    if "browser_marker_posts" in stored:
        update["dast_browser_marker_posts"] = bool(stored["browser_marker_posts"])
    if stored.get("oast_callback_url"):
        update["dast_oast_callback_url"] = stored["oast_callback_url"]
    for task, route in (stored.get("model_routing") or {}).items():
        if task in DAST_MODEL_TASKS:
            update[f"dast_model_{task}_provider"] = route["provider"]
            update[f"dast_model_{task}_model"] = route["model"]
    return base.model_copy(update=update) if update else base


def current_oast_url() -> str | None:
    """The OAST callback address a scan started now would use (override, else the environment)."""
    with app_db.SessionLocal() as db:
        return effective_settings(db).dast_oast_callback_url


def settings_view(db: Session) -> dict[str, Any]:
    cfg = effective_settings(db)
    stored = _load(db)
    routing = cfg.dast_model_routing
    overridden = sorted(k for k in stored if k != "model_routing") + (["model_routing"] if stored.get("model_routing") else [])
    return {
        "max_runtime_minutes": cfg.dast_max_runtime_minutes,
        "max_depth": cfg.dast_max_depth,
        "max_pages": cfg.dast_max_pages,
        "max_per_pattern": cfg.dast_max_per_pattern,
        "same_domain_mode": cfg.dast_same_domain_mode,
        "safe_mode_default": cfg.dast_safe_mode_default,
        "agent_mode": cfg.dast_agent_mode_default,
        "max_agent_turns": cfg.dast_max_agent_turns,
        "max_turns_per_hypothesis": cfg.dast_max_turns_per_hypothesis,
        "browser_probe_enabled": cfg.dast_browser_probe_enabled,
        "browser_marker_posts": cfg.dast_browser_marker_posts,
        "browser_probe_max_inputs": cfg.dast_browser_probe_max_inputs,
        "rate_limit_per_sec": cfg.dast_rate_limit_per_sec,
        "max_targets": cfg.dast_max_targets,
        "max_tests_per_target": cfg.dast_max_tests_per_target,
        "oast_configured": cfg.dast_oast_callback_url is not None,
        "model_routing": [{"task": t, "provider": routing[t][0], "model": routing[t][1]} for t in DAST_MODEL_TASKS],
        "overridden": overridden,
        "limits": {f.name: {"min": f.low, "max": f.high, "label": f.label} for f in FIELDS},
        # What each intensity preset means in numbers, so a form can describe them without hard-coding any.
        "presets": {name: dict(values) for name, values in cfg.dast_presets.items()},
        "applies_to": "new scans only",
    }


def routing_view(db: Session) -> list[dict[str, Any]]:
    routing = effective_settings(db).dast_model_routing
    stored = _load(db).get("model_routing") or {}
    return [{"task": t, "provider": routing[t][0], "model": routing[t][1], "overridden": t in stored} for t in DAST_MODEL_TASKS]


def _aws_credentials_present() -> bool:
    """Whether the standard AWS chain is likely to resolve, without importing boto3 or reading a key."""
    import os
    from pathlib import Path

    if os.environ.get("AWS_ACCESS_KEY_ID") or os.environ.get("AWS_PROFILE") or os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE") or os.environ.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"):
        return True
    return (Path.home() / ".aws" / "credentials").is_file()


def _claude_cli_present(cfg: Settings) -> bool:
    """Whether the `claude` binary can be found. It does not check the sign-in: Test does."""
    import shutil

    return bool((cfg.claude_cli_path or "").strip() or shutil.which("claude"))


def provider_status(cfg: Settings | None = None) -> list[dict[str, Any]]:
    """Read-only "set / not set" per provider, from the environment. Never a value."""
    cfg = cfg or env_settings

    def set_(secret: Any) -> bool:
        return bool(secret and secret.get_secret_value().strip()) if hasattr(secret, "get_secret_value") else bool(secret)

    return [
        {"provider": "ollama", "configured": True, "source": "local", "detail": "no key needed; talks to the configured Ollama server"},
        {"provider": "bedrock", "configured": _aws_credentials_present(), "source": "environment", "detail": "AWS credentials (environment, profile or role)"},
        {"provider": "openai", "configured": set_(cfg.openai_api_key), "source": "environment", "detail": "OPENAI_API_KEY"},
        {"provider": "anthropic", "configured": set_(cfg.anthropic_api_key), "source": "environment", "detail": "ANTHROPIC_API_KEY"},
        {"provider": "claude_cli", "configured": _claude_cli_present(cfg), "source": "local", "detail": "the `claude` CLI on this machine, signed in (CLAUDE_CLI_PATH or PATH)"},
    ]


def default_models(cfg: Settings | None = None) -> dict[str, str]:
    """The model a UI should fill in when the operator picks a provider. Bedrock is Haiku."""
    cfg = cfg or env_settings
    return {
        "ollama": cfg.dast_ollama_model,
        "bedrock": cfg.bedrock_model_id,
        "openai": "",
        "anthropic": "",
        "claude_cli": cfg.dast_claude_cli_model,
    }


def test_route(db: Session, route: Mapping[str, Any], *, gateway_factory: Callable[..., Any] | None = None) -> dict[str, Any]:
    """One harmless call through the gateway for one task's provider and model. Reports success or
    the failure reason with any credential masked; never raises."""
    import time

    from app.dast.domain.redaction import redact_text
    from app.services.model_gateway import build_gateway

    task, provider, model = str(route.get("task") or ""), str(route.get("provider") or "").lower(), str(route.get("model") or "").strip()
    result = {"ok": False, "task": task, "latency_ms": None, "error": None}
    if task not in DAST_MODEL_TASKS or provider not in PROVIDERS:
        result["error"] = "choose a known task and provider"
        return result
    cfg = effective_settings(db)
    if not model:
        model = {"ollama": cfg.dast_ollama_model, "bedrock": cfg.bedrock_model_id, "claude_cli": cfg.dast_claude_cli_model}.get(provider, "")
    if not model:
        result["error"] = f"{provider} needs an explicit model name"
        return result
    try:
        gateway = (gateway_factory or build_gateway)({task: (provider, model)}, cfg=cfg)
        problems = gateway.check_configuration() if hasattr(gateway, "check_configuration") else []
        if problems:
            result["error"] = redact_text("; ".join(problems))[:300]
            return result
        started = time.perf_counter()
        reply = gateway.complete(task, "", 'Reply with exactly this JSON and nothing else: {"ok": true}', {"type": "object"}, max_tokens=20, temperature=0)
        result["latency_ms"] = round((time.perf_counter() - started) * 1000, 1)
        if getattr(reply, "fallback_used", False):
            result["error"] = redact_text(getattr(reply, "reason", "") or "the model did not answer with a usable reply")[:300]
        else:
            result["ok"] = True
    except Exception as exc:  # noqa: BLE001 - the whole point is to report what went wrong
        result["error"] = redact_text(f"{type(exc).__name__}: {exc}")[:300]
    return result

"""SAST LLM provider names, and which endpoints and models scans may use (LLM03).

The constants mirror `sast_engine/llm_client.py`, which the app can't import
directly (it is loaded by path and needs boto3 — see agent_bridge).

An LLM endpoint receives repository code, so where it points is checked, not
trusted: `check_config` runs when a project or scan is configured and again when a
scan starts (`agent_bridge.llm_usage_options`), and the engine re-checks the
resolved address before every request. The rules live in the engine's
`endpoint_policy.py` (shared, stdlib-only); this module adds what is the app's:
the hosts and models an administrator approved.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from app.config import settings
from app.models import AppSetting
from app.services import engine_files

SAST_LLM_PROVIDERS = ("bedrock", "openai_compat", "ollama", "claude_cli", "openai_cli")
# "none": stop LLM work at the cost cutoff instead of switching providers.
SAST_FALLBACK_PROVIDERS = ("none", *SAST_LLM_PROVIDERS)

logger = logging.getLogger(__name__)

POLICY_KEY = "llm_policy"
_HOST_ENTRY = re.compile(r"^[A-Za-z0-9._\-]{1,253}(:\d{1,5})?$|^\[[0-9A-Fa-f:.]{2,45}\](:\d{1,5})?$")
_MAX_ENTRIES = 200


class LlmPolicyError(ValueError):
    """The LLM configuration is not allowed. The message is safe to show the user."""


def _split(value: str) -> list[str]:
    return [part.strip().lower() for part in (value or "").split(",") if part.strip()]


def load_policy(db: Session | None = None) -> dict[str, Any]:
    """The effective policy: approved hosts (the server's `LLM_ALLOWED_HOSTS` plus
    what an administrator added), approved models (empty = no restriction) and
    whether loopback endpoints are allowed."""
    if db is None:
        from app import db as db_module

        session = db_module.SessionLocal()
        try:
            return load_policy(session)
        finally:
            session.close()
    row = db.get(AppSetting, POLICY_KEY)
    stored = (row.value or {}) if row else {}
    admin_hosts = [str(h).lower() for h in stored.get("allowed_hosts", [])]
    env_hosts = _split(settings.llm_allowed_hosts)
    return {
        "allowed_hosts": sorted(set(env_hosts) | set(admin_hosts)),
        "admin_hosts": sorted(set(admin_hosts)),
        "env_hosts": sorted(set(env_hosts)),
        "allowed_models": sorted({str(m) for m in stored.get("allowed_models", [])}),
        "allow_loopback": bool(settings.llm_allow_loopback),
    }


def save_policy(db: Session, *, allowed_hosts: list[str], allowed_models: list[str]) -> None:
    hosts = sorted({h.strip().lower() for h in allowed_hosts if h.strip()})
    models = sorted({m.strip() for m in allowed_models if m.strip()})
    errors = [f"{h!r} is not a host name or host:port" for h in hosts if not _HOST_ENTRY.match(h)]
    if len(hosts) > _MAX_ENTRIES or len(models) > _MAX_ENTRIES:
        errors.append(f"at most {_MAX_ENTRIES} hosts and {_MAX_ENTRIES} models")
    if errors:
        raise LlmPolicyError("; ".join(errors))
    value = {"allowed_hosts": hosts, "allowed_models": models}
    row = db.get(AppSetting, POLICY_KEY)
    if row is None:
        db.add(AppSetting(key=POLICY_KEY, value=value))
    else:
        row.value = value
    db.commit()


def engine_policy(policy: dict[str, Any]) -> dict[str, Any]:
    """What the engine's HTTP providers need (`init_usage(endpoint_policy=...)`)."""
    return {"allowed_hosts": policy["allowed_hosts"], "allow_loopback": policy["allow_loopback"]}


def endpoint_for(provider: str | None, base_url: str | None) -> str | None:
    """The URL `provider` will send prompts to, or None for a provider without one."""
    name = (provider or "").strip().lower()
    if name == "openai_compat":
        return (base_url or "").strip() or settings.openai_compat_base_url
    if name == "ollama":
        return settings.ollama_base_url
    return None


def endpoint_error(url: str, policy: dict[str, Any]) -> str | None:
    return engine_files.load("endpoint_policy").check_endpoint(
        url, allowed_hosts=policy["allowed_hosts"], allow_loopback=policy["allow_loopback"],
    )


def host_of(url: str | None) -> str | None:
    try:
        return urlsplit(url or "").hostname
    except ValueError:
        return None


def langfuse_context(project: Any, scan: Any, policy: dict[str, Any]) -> dict[str, Any] | None:
    """What the engine needs to trace a scan's LLM calls to Langfuse
    (`init_usage(tracing=...)`), or None when it is not configured or not allowed.

    Stricter than an LLM endpoint: a public https host is not enough. Traces copy
    prompts (repository code) somewhere nobody chose as this scan's provider, so
    the host must be loopback or on the approved list. Never raises: a scan does
    not depend on its monitoring."""
    host = settings.langfuse_host.strip().rstrip("/")
    secret = settings.langfuse_secret_key.get_secret_value() if settings.langfuse_secret_key else ""
    if not (host and settings.langfuse_public_key and secret):
        return None
    try:
        reason = endpoint_error(host, policy)
        # Asked about plain http, the policy accepts only loopback and approved hosts.
        if not reason and endpoint_error(re.sub(r"^https:", "http:", host, flags=re.IGNORECASE), policy):
            reason = "the host is not approved"
    except Exception as exc:  # noqa: BLE001
        reason = type(exc).__name__
    if reason:
        logger.warning(
            "Langfuse tracing is off: %s must be loopback or an approved host (LLM_ALLOWED_HOSTS): %s",
            host_of(host), reason,
        )
        return None
    return {
        "host": host,
        "public_key": settings.langfuse_public_key,
        "secret_key": secret,
        "scan_id": getattr(scan, "id", None),
        "project": getattr(project, "name", None),
        "policy": engine_policy(policy),
    }


def check_config(
    *,
    provider: str | None,
    model: str | None = None,
    base_url: str | None = None,
    fallback_provider: str | None = None,
    fallback_model: str | None = None,
    policy: dict[str, Any] | None = None,
) -> None:
    """Raise `LlmPolicyError` when the provider's endpoint or a model is not allowed."""
    policy = policy or load_policy()
    for label, prov, mdl in (
        ("LLM", provider, model),
        ("Fallback LLM", fallback_provider, fallback_model),
    ):
        name = (prov or "").strip().lower()
        if not name or name == "none":
            continue
        url = endpoint_for(name, base_url)
        if url:
            reason = endpoint_error(url, policy)
            if reason:
                raise LlmPolicyError(f"{label} endpoint not allowed: {reason}.")
        if mdl and policy["allowed_models"] and mdl not in policy["allowed_models"]:
            raise LlmPolicyError(f"{label} model {mdl!r} is not on the approved model list.")

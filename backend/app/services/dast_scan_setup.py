"""Turns a DAST scan request into everything a scan needs at start (DAST-05-010, -020).

`prepare_dast_scan` validates the request and produces:

* `dast_input`: the non-secret record of the request, stored in `metadata_json["dast_input"]`
  (identity labels, roles and methods plus `has_secret` flags; never a password, token or session);
* `effective`: the frozen effective settings (`metadata_json["dast_effective"]`);
* `rule_set` and `skipped_degraded`: the rule-set snapshot and the checks that cannot run as
  designed (`metadata_json["dast_rule_set"]`, `["dast_skipped_degraded"]`);
* `credentials`: the secrets by identity id, for the caller to hand to the in-memory holder and
  nowhere else.

Every problem is a `DastSetupError` carrying an HTTP status and a message fit for the operator.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from app.config import DAST_MODEL_TASKS, Settings
from app.config import settings as app_settings
from app.dast.domain.identities import (
    AuthMethod,
    IdentityError,
    IdentitySpec,
    build_identities,
    has_second_identity,
)
from app.dast.domain.presets import PresetError, build_effective_settings
from app.dast.domain.ruleset import RuleConfigError, ScanInputs
from app.models import DAST_SETTINGS_SNAPSHOT_KEY, Project
from app.schemas import DastInput
from app.services import dast_rules, dast_settings

# `Scan.metadata_json` keys (documented here once; readers import these).
DAST_INPUT_KEY = "dast_input"
EFFECTIVE_KEY = "dast_effective"
RULE_SET_KEY = dast_rules.RULE_SET_KEY
SKIPPED_DEGRADED_KEY = dast_rules.SKIPPED_DEGRADED_KEY

LEGACY_IDENTITY_LABEL = "default"


class DastSetupError(ValueError):
    def __init__(self, message: str, status_code: int = 400):
        self.status_code = status_code
        super().__init__(message)


@dataclass
class PreparedDastScan:
    identities: list[IdentitySpec]
    dast_input: dict[str, Any]
    effective: dict[str, Any]
    rule_set: dict[str, Any]
    skipped_degraded: list[dict[str, Any]]
    # identity_id -> secret fields. Memory only: hand to the credential holder, never store.
    credentials: dict[str, dict[str, str]] = field(default_factory=dict, repr=False)

    def metadata(self, base_settings: dict[str, Any]) -> dict[str, Any]:
        """Everything this request adds to `Scan.metadata_json`. Contains no secret."""
        return {
            DAST_INPUT_KEY: self.dast_input,
            DAST_SETTINGS_SNAPSHOT_KEY: base_settings,
            EFFECTIVE_KEY: self.effective,
            RULE_SET_KEY: self.rule_set,
            SKIPPED_DEGRADED_KEY: self.skipped_degraded,
        }


def _raw_identities(dast: DastInput) -> list[dict[str, Any]]:
    """The identity list as plain dicts, the legacy single credential included."""
    if dast.identities:
        return [
            {"label": i.label, "role": i.role, "custom_role": i.custom_role, "auth_method": i.auth_method}
            for i in dast.identities
        ]
    if dast.login_url:
        return [{"label": LEGACY_IDENTITY_LABEL, "role": "User", "auth_method": "form"}]
    return []


def _credentials(dast: DastInput, specs: list[IdentitySpec]) -> dict[str, dict[str, str]]:
    by_label = {s.label: s for s in specs}
    out: dict[str, dict[str, str]] = {}
    if dast.identities:
        for item in dast.identities:
            spec = by_label[item.label.strip()]
            if item.auth_method == "form":
                out[spec.identity_id] = {
                    "login_url": item.login_url,
                    "username": item.username,
                    "password": item.password.get_secret_value() if item.password else "",
                }
            elif item.auth_method == "token":
                out[spec.identity_id] = {
                    "token": item.token.get_secret_value().strip() if item.token else "",
                    "header_name": item.header_name,
                    "scheme": item.scheme,
                }
            elif item.auth_method == "preauth":
                out[spec.identity_id] = {"storage_state": item.storage_state.get_secret_value() if item.storage_state else ""}
    elif dast.login_url:
        spec = by_label[LEGACY_IDENTITY_LABEL]
        out[spec.identity_id] = {
            "login_url": dast.login_url,
            "username": dast.username,
            "password": dast.password.get_secret_value() if dast.password else "",
        }
    return out


def _public_input(dast: DastInput, specs: list[IdentitySpec], credentials: dict[str, dict[str, str]], method_policy: str) -> dict[str, Any]:
    """The stored, secret-free copy of the request. Keeps the legacy keys other readers use."""
    legacy_form = not dast.identities and bool(dast.login_url)
    public_identities = []
    detail = {i.label.strip(): i for i in dast.identities}
    for spec in specs:
        entry = spec.to_public()
        entry["has_secret"] = spec.identity_id in credentials
        item = detail.get(spec.label)
        if item is not None and item.auth_method == "form":
            entry.update(login_url=item.login_url, username=item.username)
        elif item is not None and item.auth_method == "token":
            entry.update(header_name=item.header_name, scheme=item.scheme)
        elif legacy_form and spec.label == LEGACY_IDENTITY_LABEL:
            entry.update(login_url=dast.login_url, username=dast.username)
        public_identities.append(entry)
    return {
        "target_url": dast.target_url,
        "login_url": dast.login_url,
        "username": dast.username,
        "max_depth": dast.max_depth,
        "max_pages": dast.max_pages,
        "headless": dast.headless,
        "has_password": dast.password is not None,
        "identities": public_identities,
        "intensity": dast.intensity,
        "method_policy": method_policy,
        "target_disposable": dast.target_disposable,
        "browser_probe_enabled": dast.browser_probe_enabled,
        "browser_marker_posts": dast.browser_marker_posts,
        "rule_packs": dast.rule_packs,
        "schema_url": dast.schema_url,
    }


def _routing(dast: DastInput, cfg: Settings) -> tuple[dict[str, tuple[str, str]], list[str]]:
    """Global routing with this scan's per-task overrides applied. Returns (routing, problems with
    the *overrides* only: a hosted model chosen for this scan must be usable)."""
    routing = dict(cfg.dast_model_routing)
    problems: list[str] = []
    for task, route in (dast.model_routing or {}).items():
        if task not in DAST_MODEL_TASKS:
            raise DastSetupError(f"unknown model task {task!r}; expected one of: {', '.join(DAST_MODEL_TASKS)}", 422)
        model = route.model.strip()
        if not model:
            model = {"ollama": cfg.dast_ollama_model, "bedrock": cfg.bedrock_model_id}.get(route.provider, "")
        if not model:
            raise DastSetupError(f"model task {task!r}: {route.provider} needs an explicit model name", 422)
        routing[task] = (route.provider, model)
    if dast.model_routing:
        from app.services.model_gateway import build_gateway

        gateway = build_gateway({t: routing[t] for t in dast.model_routing}, cfg=cfg)
        problems = gateway.check_configuration()
    return routing, problems


def prepare_dast_scan(db: Session, project: Project, dast: DastInput, cfg: Settings | None = None) -> PreparedDastScan:
    cfg = cfg or dast_settings.effective_settings(db)  # the environment plus the stored overrides: what a scan created now uses
    try:
        specs = build_identities(_raw_identities(dast))
    except IdentityError as exc:
        raise DastSetupError(str(exc), 422) from exc

    # No explicit choice: safe, unless the configured default is "safe mode off" and the target is disposable
    # (state-changing methods are never allowed against a target that is not marked disposable).
    method_policy = dast.method_policy or ("opt_in_mutating" if (not cfg.dast_safe_mode_default and dast.target_disposable) else "safe")
    if method_policy == "opt_in_mutating" and not dast.target_disposable:
        raise DastSetupError(
            "State-changing methods can only be enabled for a target marked as disposable. "
            "Mark the target disposable, or keep the safe method policy.",
            422,
        )
    marker_posts = dast.browser_marker_posts if dast.browser_marker_posts is not None else cfg.dast_browser_marker_posts
    if marker_posts and not dast.target_disposable:
        raise DastSetupError(
            "Stored XSS marker submits can only be enabled for a target marked as disposable.",
            422,
        )

    credentials = _credentials(dast, specs)
    routing, routing_problems = _routing(dast, cfg)
    if routing_problems:
        raise DastSetupError("The model selected for this scan cannot be used: " + "; ".join(routing_problems), 422)

    oast = cfg.dast_oast_callback_url is not None
    selection: dict[str, Any] = {}
    if dast.rule_packs is not None:
        selection["packs"] = list(dast.rule_packs)
    if dast.rule_overrides:
        selection["checks"] = dict(dast.rule_overrides)
    if marker_posts:
        # The stored-XSS check is opt-in and selected only by the thorough pack, so turning marker
        # posts on also turns that pack and that check on for this scan.
        packs = selection.get("packs")
        if packs is None:
            selection["packs"] = {"thorough": True}
        elif isinstance(packs, list) and "thorough" not in packs:
            selection["packs"] = [*packs, "thorough"]
        checks = dict(selection.get("checks") or {})
        checks["dast-xss-stored"] = {**(checks.get("dast-xss-stored") or {}), "enabled": True}
        selection["checks"] = checks
    try:
        resolved = dast_rules.resolve_for_scan(
            db, project, selection or None, ScanInputs(has_second_identity=has_second_identity(specs), oast_configured=oast)
        )
    except RuleConfigError as exc:
        raise DastSetupError(str(exc), 422) from exc

    request = {
        "intensity": dast.intensity,
        "max_depth": dast.max_depth,
        "max_pages": dast.max_pages,
        "max_targets": dast.max_targets,
        "max_tests_per_target": dast.max_tests_per_target,
        "max_runtime_minutes": dast.max_runtime_minutes,
        "model_parallelism": dast.model_parallelism,
        "method_policy": method_policy,
        "target_disposable": dast.target_disposable,
        "rate_limit_per_sec": dast.rate_limit_per_sec,
        "headless": dast.headless,
        "schema_url": dast.schema_url,
        "browser_probe_enabled": dast.browser_probe_enabled,
        "browser_marker_posts": marker_posts,
    }
    try:
        effective = build_effective_settings(
            request=request,
            base=cfg.dast_effective_settings(),
            presets=cfg.dast_presets,
            identities=specs,
            rule_set=resolved.snapshot,
            model_routing=routing,
            oast_configured=oast,
        )
    except PresetError as exc:
        raise DastSetupError(str(exc), 422) from exc

    return PreparedDastScan(
        identities=specs,
        dast_input=_public_input(dast, specs, credentials, method_policy),
        effective=effective,
        rule_set=resolved.snapshot,
        skipped_degraded=resolved.skipped_degraded,
        credentials=credentials,
    )

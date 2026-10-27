"""Intensity presets and the effective-settings builder (DAST-05-020): pure functions.

A preset maps a name (`light|standard|deep`) to concrete budgets. Explicit per-scan values beat
the preset, which beats nothing: there is no hidden third source. The effective settings are
computed once at scan start from (request, global settings, rule set, identities) and stored
unmodified on the scan, so two scans are comparable by reading what each one actually ran with.

The result is flat on purpose: it keeps every key the earlier settings snapshot had
(`rate_limit_per_sec`, `safe_mode`, `max_concurrent_requests`, `same_domain_mode`,
`model_routing`, ...), so the safety guard and the engine read it exactly as they read that
one, and adds what is new (`intensity`, `budget_sources`, the method policy, the rule packs and
the identity list). No secret ever enters it.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from .identities import IdentitySpec, has_second_identity

PRESET_NAMES = ("light", "standard", "deep")
BUDGET_KEYS = ("max_targets", "max_tests_per_target", "max_depth", "max_pages", "max_runtime_minutes", "max_per_pattern")
EFFECTIVE_VERSION = 1

# Built-in values for the two presets that are not "whatever the global settings say".
# `standard` always comes from the global settings (DAST_MAX_* variables); `light` and `deep` are
# these, overridable through DAST_PRESET_LIGHT / DAST_PRESET_DEEP.
DEFAULT_LIGHT = {"max_targets": 5, "max_tests_per_target": 4, "max_depth": 2, "max_pages": 30, "max_runtime_minutes": 5, "max_per_pattern": 2}
DEFAULT_DEEP = {"max_targets": 40, "max_tests_per_target": 20, "max_depth": 5, "max_pages": 250, "max_runtime_minutes": 30, "max_per_pattern": 5}


class PresetError(ValueError):
    pass


def resolve_budgets(
    intensity: str, presets: Mapping[str, Mapping[str, Any]], overrides: Mapping[str, Any]
) -> tuple[dict[str, Any], dict[str, str]]:
    """Budgets and where each came from (`request` or `preset`). `overrides` entries that are
    None mean "not given"."""
    if intensity not in presets:
        raise PresetError(f"unknown intensity {intensity!r}; expected one of: {', '.join(presets)}")
    budgets: dict[str, Any] = {}
    sources: dict[str, str] = {}
    for key in BUDGET_KEYS:
        explicit = overrides.get(key)
        if explicit is not None:
            budgets[key], sources[key] = explicit, "request"
        else:
            budgets[key], sources[key] = presets[intensity][key], "preset"
    return budgets, sources


def build_effective_settings(
    *,
    request: Mapping[str, Any],
    base: Mapping[str, Any],
    presets: Mapping[str, Mapping[str, Any]],
    identities: Sequence[IdentitySpec],
    rule_set: Mapping[str, Any],
    model_routing: Mapping[str, Sequence[str]],
    oast_configured: bool,
    warnings: Sequence[str] = (),
) -> dict[str, Any]:
    """`request` carries only non-secret per-scan inputs: `intensity`, budget overrides,
    `method_policy`, `target_disposable`, `rate_limit_per_sec`, `headless`, `schema_url`."""
    intensity = str(request.get("intensity") or "standard").lower()
    budgets, sources = resolve_budgets(intensity, presets, request)

    disposable = bool(request.get("target_disposable", False))
    wants_mutating = request.get("method_policy", "safe") == "opt_in_mutating"
    allow_state_changing = wants_mutating and disposable
    rate = request.get("rate_limit_per_sec")
    rate_source = "request" if rate is not None else "settings"

    checks = rule_set.get("checks") or []
    effective: dict[str, Any] = {
        **{k: v for k, v in base.items() if k not in BUDGET_KEYS},
        "version": EFFECTIVE_VERSION,
        "intensity": intensity,
        **budgets,
        "budget_sources": sources,
        "safe_mode": not allow_state_changing,
        "method_policy": "opt_in_mutating" if allow_state_changing else "safe",
        "allow_state_changing": allow_state_changing,
        "target_disposable": disposable,
        "rate_limit_per_sec": float(rate if rate is not None else base["rate_limit_per_sec"]),
        "rate_limit_source": rate_source,
        "model_parallelism": max(1, int(request.get("model_parallelism") or base.get("model_parallelism") or 1)),
        "rule_packs": list(rule_set.get("packs") or []),
        "rule_checks_enabled": sum(1 for c in checks if c.get("enabled")),
        "rule_checks_total": len(checks),
        "catalog_version": rule_set.get("catalog_version", ""),
        "model_routing": {task: list(route) for task, route in model_routing.items()},
        "oast_configured": oast_configured,
        "headless": bool(request.get("headless", True)),
        "schema_url": request.get("schema_url") or "",
        "user_endpoints": request.get("user_endpoints") or {},
        "agent_mode": bool(request["agent_mode"]) if request.get("agent_mode") is not None else bool(base.get("agent_mode", False)),
        "max_agent_turns": int(request.get("max_agent_turns") or base.get("max_agent_turns") or 60),
        "max_turns_per_hypothesis": int(request.get("max_turns_per_hypothesis") or base.get("max_turns_per_hypothesis") or 4),
        "browser_probe_enabled": bool(request["browser_probe_enabled"]) if request.get("browser_probe_enabled") is not None else bool(base.get("browser_probe_enabled", True)),
        # A marker POST is a write. It stays off for a target that is not disposable, whatever the request says.
        "browser_marker_posts": bool(request["browser_marker_posts"] if request.get("browser_marker_posts") is not None else base.get("browser_marker_posts", False)) and disposable,
        "browser_probe_max_inputs": int(request.get("browser_probe_max_inputs") or base.get("browser_probe_max_inputs") or 4),
        "identities": [s.to_public() for s in identities],
        "second_identity": has_second_identity(identities),
        "warnings": list(warnings),
    }
    return effective

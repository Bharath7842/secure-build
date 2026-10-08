"""Rule-set resolution (DAST-03-040) and dependency evaluation (DAST-03-060): pure functions.

Three configuration levels combine into one *effective rule set*:

    global defaults  ->  project defaults  ->  per-scan selection        (later wins)

Each level is a `RuleConfig`: which packs are on (`packs`, pack id -> bool) and per-check
overrides (`checks`, check id -> enabled / severity / mode, any subset). Resolution is
field-by-field, so a project can raise one check's severity without touching its mode.

Rules that hold regardless of level:

* a check runs only if some enabled pack selects it;
* a load-generating check (API4) or an opt-in one stays off until a level enables that check
  explicitly; a pack being on is never enough;
* a mode override cannot give a check evidence it cannot produce: asking for `automated`/`opt-in`
  on a check with no resolvable signal clamps to `assist-only` and says so.

The result serializes (`effective_to_dict`) into the scan's snapshot, which embeds the full
definition of every check it contains so a later catalog or custom-rule edit cannot change what a
past scan ran.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

from .catalog import Catalog, check_from_dict, check_to_dict
from .entities import Check, CheckMode, Severity

RULE_SET_VERSION = 1
LEVELS = ("global", "project", "scan")


class RuleConfigError(ValueError):
    """A rule configuration names something that does not exist or has an invalid value."""


@dataclass(frozen=True)
class CheckOverride:
    enabled: bool | None = None
    severity: Severity | None = None
    mode: CheckMode | None = None

    def merged_over(self, base: "CheckOverride") -> "CheckOverride":
        """This override applied on top of `base`: fields set here win, others fall through."""
        return CheckOverride(
            enabled=self.enabled if self.enabled is not None else base.enabled,
            severity=self.severity or base.severity,
            mode=self.mode or base.mode,
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.enabled is not None:
            out["enabled"] = self.enabled
        if self.severity is not None:
            out["severity"] = self.severity.value
        if self.mode is not None:
            out["mode"] = self.mode.value
        return out


@dataclass(frozen=True)
class RuleConfig:
    packs: Mapping[str, bool] = field(default_factory=dict)
    checks: Mapping[str, CheckOverride] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "packs": dict(self.packs),
            "checks": {cid: ov.to_dict() for cid, ov in self.checks.items() if ov.to_dict()},
        }

    def merged_over(self, base: "RuleConfig") -> "RuleConfig":
        """PATCH semantics: keys present here replace the same keys in `base`."""
        checks = dict(base.checks)
        for cid, ov in self.checks.items():
            checks[cid] = ov.merged_over(checks.get(cid, CheckOverride()))
        return RuleConfig(packs={**base.packs, **self.packs}, checks=checks)


EMPTY_CONFIG = RuleConfig()


def parse_rule_config(raw: Any, catalog: Catalog) -> RuleConfig:
    """Validate a raw config mapping against the catalog. Raises `RuleConfigError` naming the
    offending key; unknown pack and check ids are errors (they would silently do nothing)."""
    if raw is None:
        return EMPTY_CONFIG
    if not isinstance(raw, Mapping):
        raise RuleConfigError("rule configuration must be an object with 'packs' and/or 'checks'")
    unknown = set(raw) - {"packs", "checks"}
    if unknown:
        raise RuleConfigError(f"unknown rule configuration key(s): {', '.join(sorted(unknown))}")

    packs: dict[str, bool] = {}
    raw_packs = raw.get("packs") or {}
    if isinstance(raw_packs, (list, tuple)):  # a plain list means "exactly these"
        selected = {str(p) for p in raw_packs}
        for pid in selected:
            if catalog.pack(pid) is None:
                raise RuleConfigError(f"unknown rule pack {pid!r}")
        packs = {p.pack_id: p.pack_id in selected for p in catalog.packs}
    elif isinstance(raw_packs, Mapping):
        for pid, on in raw_packs.items():
            if catalog.pack(str(pid)) is None:
                raise RuleConfigError(f"unknown rule pack {pid!r}")
            if not isinstance(on, bool):
                raise RuleConfigError(f"rule pack {pid!r} must be true or false")
            packs[str(pid)] = on
    else:
        raise RuleConfigError("'packs' must be a list of pack ids or a pack id -> boolean mapping")

    checks: dict[str, CheckOverride] = {}
    raw_checks = raw.get("checks") or {}
    if not isinstance(raw_checks, Mapping):
        raise RuleConfigError("'checks' must be a mapping of check id to override")
    for cid, ov in raw_checks.items():
        canonical = catalog.resolve_id(str(cid))
        if catalog.get(canonical) is None:
            raise RuleConfigError(f"unknown check {cid!r}")
        if not isinstance(ov, Mapping) or set(ov) - {"enabled", "severity", "mode"}:
            raise RuleConfigError(f"override for {cid!r} may only set enabled, severity and mode")
        enabled = ov.get("enabled")
        if enabled is not None and not isinstance(enabled, bool):
            raise RuleConfigError(f"override for {cid!r}: enabled must be true or false")
        try:
            severity = Severity(str(ov["severity"]).upper()) if ov.get("severity") else None
            mode = CheckMode(str(ov["mode"]).lower()) if ov.get("mode") else None
        except ValueError as exc:
            raise RuleConfigError(f"override for {cid!r}: {exc}") from exc
        checks[canonical] = CheckOverride(enabled, severity, mode)
    return RuleConfig(packs, checks)


# ---- resolution -------------------------------------------------------------------------------


@dataclass(frozen=True)
class EffectiveCheck:
    check: Check
    severity: Severity
    mode: CheckMode
    enabled: bool
    packs: tuple[str, ...]  # enabled packs that select this check
    overrides: Mapping[str, Any] = field(default_factory=dict)  # the merged override, as applied
    notes: tuple[str, ...] = ()

    @property
    def check_id(self) -> str:
        return self.check.check_id


@dataclass(frozen=True)
class EffectiveRuleSet:
    pack_ids: tuple[str, ...]  # enabled packs
    checks: tuple[EffectiveCheck, ...]  # every check an enabled pack selects, enabled or not
    levels: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)  # the three configs as given

    def enabled_checks(self) -> list[EffectiveCheck]:
        return [c for c in self.checks if c.enabled]

    def get(self, check_id: str) -> EffectiveCheck | None:
        return next((c for c in self.checks if c.check_id == check_id or check_id in c.check.aliases), None)


def resolve_effective_rule_set(
    catalog: Catalog,
    global_config: RuleConfig | None = None,
    project_config: RuleConfig | None = None,
    scan_config: RuleConfig | None = None,
) -> EffectiveRuleSet:
    levels = [global_config or EMPTY_CONFIG, project_config or EMPTY_CONFIG, scan_config or EMPTY_CONFIG]

    pack_on = {p.pack_id: p.enabled_by_default for p in catalog.packs}
    merged: dict[str, CheckOverride] = {}
    for level in levels:
        pack_on.update({pid: on for pid, on in level.packs.items() if pid in pack_on})
        for cid, ov in level.checks.items():
            merged[cid] = ov.merged_over(merged.get(cid, CheckOverride()))
    enabled_packs = tuple(p.pack_id for p in catalog.packs if pack_on.get(p.pack_id))

    selected_by: dict[str, list[str]] = {}
    for pack_id in enabled_packs:
        for check in catalog.pack_checks(pack_id):
            selected_by.setdefault(check.check_id, []).append(pack_id)

    effective: list[EffectiveCheck] = []
    for check in catalog.checks:  # catalog order keeps the output stable
        if check.check_id not in selected_by:
            continue
        override = merged.get(check.check_id, CheckOverride())
        notes: list[str] = []
        mode = override.mode or check.mode
        if mode is not CheckMode.ASSIST_ONLY and not check.detector_signals:
            if override.mode is not None:
                notes.append(f"mode {override.mode.value} not applied: the check names no detector signal, so it stays assist-only")
            mode = CheckMode.ASSIST_ONLY
        if override.enabled is not None:
            enabled = override.enabled
        else:
            enabled = check.enabled_by_default and mode is not CheckMode.OPT_IN
        effective.append(
            EffectiveCheck(
                check=check,
                severity=override.severity or check.base_severity,
                mode=mode,
                enabled=enabled,
                packs=tuple(selected_by[check.check_id]),
                overrides=override.to_dict(),
                notes=tuple(notes),
            )
        )
    return EffectiveRuleSet(
        pack_ids=enabled_packs,
        checks=tuple(effective),
        levels={name: cfg.to_dict() for name, cfg in zip(LEVELS, levels)},
    )


def effective_to_dict(rule_set: EffectiveRuleSet, catalog_version: str = "") -> dict[str, Any]:
    """The snapshot stored on the scan. Self-contained: each check carries its full definition,
    custom checks included (with their version)."""
    return {
        "version": RULE_SET_VERSION,
        "catalog_version": catalog_version,
        "packs": list(rule_set.pack_ids),
        "levels": {k: dict(v) for k, v in rule_set.levels.items()},
        "checks": [
            {
                "id": ec.check_id,
                "enabled": ec.enabled,
                "severity": ec.severity.value,
                "mode": ec.mode.value,
                "packs": list(ec.packs),
                "overrides": dict(ec.overrides),
                "notes": list(ec.notes),
                "definition": check_to_dict(ec.check),
            }
            for ec in rule_set.checks
        ],
        "custom_rules": [
            {"id": ec.check_id, "version": ec.check.version}
            for ec in rule_set.checks
            if ec.check.source == "custom"
        ],
    }


def effective_from_dict(data: Mapping[str, Any]) -> EffectiveRuleSet:
    checks = tuple(
        EffectiveCheck(
            check=check_from_dict(item["definition"]),
            severity=Severity(item["severity"]),
            mode=CheckMode(item["mode"]),
            enabled=bool(item["enabled"]),
            packs=tuple(item.get("packs") or ()),
            overrides=dict(item.get("overrides") or {}),
            notes=tuple(item.get("notes") or ()),
        )
        for item in data.get("checks") or ()
    )
    return EffectiveRuleSet(
        pack_ids=tuple(data.get("packs") or ()),
        checks=checks,
        levels={k: dict(v) for k, v in (data.get("levels") or {}).items()},
    )


# ---- dependency-aware skip and degrade (DAST-03-060) ------------------------------------------

_DEPENDENCY_REASONS = {
    "second_identity": "no second identity was supplied",
    "oast": "no OAST callback address is configured",
    "schema": "no API schema was found or supplied",
}


@dataclass(frozen=True)
class ScanInputs:
    """What the scan has, for dependency checks. `schema_present=None` means "not known yet"
    (the schema is discovered by the fingerprint stage); that dependency is then not judged."""

    has_second_identity: bool = False
    oast_configured: bool = False
    schema_present: bool | None = None

    def has(self, dependency: str) -> bool | None:
        return {
            "second_identity": self.has_second_identity,
            "oast": self.oast_configured,
            "schema": self.schema_present,
        }[dependency]


def evaluate_dependencies(rule_set: EffectiveRuleSet, inputs: ScanInputs) -> list[dict[str, Any]]:
    """One entry per enabled check that cannot run as designed:

        {"check_id", "title", "status": "skipped"|"degraded", "dependency", "effective_mode", "reason"}

    `degraded` covers both a reduced run ("BOLA ran no-session replay only: no second identity")
    and a downgrade to assist-only (`effective_mode` says which). Nothing is dropped silently;
    the list is stored on the scan and read by the report and the UI."""
    out: list[dict[str, Any]] = []
    for ec in rule_set.enabled_checks():
        if ec.mode is CheckMode.ASSIST_ONLY:
            continue
        for dependency in ec.check.requires:
            present = inputs.has(dependency)
            if present is None or present:
                continue
            action = ec.check.on_missing.get(dependency, "skip")
            why = _DEPENDENCY_REASONS[dependency]
            if action == "skip":
                status, mode, reason = "skipped", ec.mode.value, f"{ec.check.title} was skipped: {why}"
            elif action == "assist-only":
                status, mode = "degraded", CheckMode.ASSIST_ONLY.value
                reason = f"{ec.check.title} is assist-only: {why}"
            else:
                note = ec.check.degraded_note or "with reduced coverage"
                status, mode, reason = "degraded", ec.mode.value, f"{ec.check.title} ran {note}: {why}"
            out.append(
                {
                    "check_id": ec.check_id,
                    "title": ec.check.title,
                    "status": status,
                    "dependency": dependency,
                    "effective_mode": mode,
                    "reason": reason,
                }
            )
            break  # one entry per check: the first unmet dependency decides
    return out


def merge_dependency_results(previous: Sequence[Mapping[str, Any]], current: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Combine an earlier evaluation with a later one (schema learned after fingerprinting):
    entries are keyed by check id and the later evaluation wins, so nothing duplicates."""
    merged = {e["check_id"]: dict(e) for e in previous}
    for entry in current:
        merged[entry["check_id"]] = dict(entry)
    return list(merged.values())

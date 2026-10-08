"""Rule-set persistence and per-scan resolution (DAST-03-040, -050, -060).

Pure resolution lives in `app.dast.domain.ruleset`; this module reads and writes the two stored
configuration levels (global: `dast_global_config["rules"]`, project: `Project.dast_rules_config`),
manages custom rules, and builds the snapshot a scan stores at start.

The snapshot (`metadata_json["dast_rule_set"]`) is the only thing a running or finished scan
reads. It embeds every check's full definition, custom ones included, so editing configuration or
deleting a custom rule afterwards cannot change what a past scan ran or how it reports.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Mapping

from sqlalchemy.orm import Session

from app.dast.domain.catalog import Catalog, PackDef, check_to_dict
from app.dast.domain.entities import Check
from app.dast.domain.ruleset import (
    EMPTY_CONFIG,
    EffectiveRuleSet,
    RuleConfig,
    RuleConfigError,
    ScanInputs,
    effective_to_dict,
    evaluate_dependencies,
    parse_rule_config,
    resolve_effective_rule_set,
)
from app.models import DastCustomRule, DastGlobalConfig, Project
from app.services.dast_catalog import (
    catalog_version,
    default_catalog,
    parse_check_yaml,
)

logger = logging.getLogger(__name__)

# `Scan.metadata_json` keys written at scan start (see DAST-03-040 / -060).
RULE_SET_KEY = "dast_rule_set"
SKIPPED_DEGRADED_KEY = "dast_skipped_degraded"

GLOBAL_CONFIG_KEY = "rules"
CUSTOM_PACK_ID = "custom-rules"


class CustomRuleError(ValueError):
    """A custom rule failed validation. `errors` lists every problem."""

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("; ".join(errors))


# ---- stored configuration ---------------------------------------------------------------------


def get_global_config(db: Session, catalog: Catalog | None = None) -> RuleConfig:
    row = db.get(DastGlobalConfig, GLOBAL_CONFIG_KEY)
    return _load_config(row.value if row else None, catalog or active_catalog(db))


def set_global_config(db: Session, config: RuleConfig) -> None:
    row = db.get(DastGlobalConfig, GLOBAL_CONFIG_KEY)
    if row is None:
        db.add(DastGlobalConfig(key=GLOBAL_CONFIG_KEY, value=config.to_dict()))
    else:
        row.value = config.to_dict()
    db.commit()


def get_project_config(project: Project, catalog: Catalog) -> RuleConfig:
    return _load_config(project.dast_rules_config, catalog)


def set_project_config(db: Session, project: Project, config: RuleConfig) -> None:
    project.dast_rules_config = config.to_dict()
    db.commit()


def _load_config(raw: Mapping[str, Any] | None, catalog: Catalog) -> RuleConfig:
    """A stored config may name a pack or check that no longer exists (a deleted custom rule, a
    catalog edit). Drop those entries rather than fail every scan."""
    if not raw:
        return EMPTY_CONFIG
    packs = {p: on for p, on in (raw.get("packs") or {}).items() if catalog.pack(p) is not None}
    checks = {c: ov for c, ov in (raw.get("checks") or {}).items() if catalog.get(c) is not None}
    try:
        return parse_rule_config({"packs": packs, "checks": checks}, catalog)
    except RuleConfigError:
        logger.warning("stored DAST rule configuration is invalid; ignoring it")
        return EMPTY_CONFIG


def update_config(current: RuleConfig, patch_raw: Any, catalog: Catalog) -> RuleConfig:
    """PATCH semantics: validate `patch_raw`, then merge it over `current`."""
    return parse_rule_config(patch_raw, catalog).merged_over(current)


# ---- custom rules -----------------------------------------------------------------------------


def _load_custom_checks(db: Session) -> tuple[list[Check], list[dict[str, Any]]]:
    """Valid custom checks (re-validated on load), plus a description of any that no longer are."""
    checks: list[Check] = []
    broken: list[dict[str, Any]] = []
    for row in db.query(DastCustomRule).order_by(DastCustomRule.check_id):
        if not row.enabled:
            continue
        check, errors, _ = parse_check_yaml(row.yaml_text, version=row.version)
        if check is None:
            broken.append({"check_id": row.check_id, "errors": [str(e) for e in errors]})
            logger.warning("custom rule %s no longer validates and is skipped: %s", row.check_id, errors)
            continue
        checks.append(check)
    return checks, broken


def active_catalog(db: Session) -> Catalog:
    """The shipped catalog plus the enabled custom rules, which form their own pack
    (`custom-rules`, on by default) so they run without being edited into a shipped pack."""
    base = default_catalog()
    custom, _ = _load_custom_checks(db)
    if not custom:
        return base
    merged = base.with_checks(custom)
    pack = PackDef(
        pack_id=CUSTOM_PACK_ID,
        title="Custom rules",
        description="Checks added by your team.",
        enabled_by_default=True,
        ids=tuple(c.check_id for c in custom),
    )
    return Catalog(merged.checks, merged.packs + (pack,), merged.issues)


def _validate_custom(db: Session, yaml_text: str, *, existing_id: str | None, version: int) -> Check:
    check, errors, _ = parse_check_yaml(yaml_text, version=version)
    if check is None:
        raise CustomRuleError([str(e) for e in errors])
    base = default_catalog()
    taken = {c.check_id for c in base.checks} | {a for c in base.checks for a in c.aliases}
    if check.check_id in taken:
        raise CustomRuleError([f"id {check.check_id!r} is already used by a shipped check"])
    if existing_id is not None and check.check_id != existing_id:
        raise CustomRuleError([f"the id of an existing rule cannot change ({existing_id!r} -> {check.check_id!r})"])
    if existing_id is None and db.query(DastCustomRule).filter(DastCustomRule.check_id == check.check_id).first():
        raise CustomRuleError([f"a custom rule with id {check.check_id!r} already exists"])
    clash = [a for a in check.aliases if a in taken]
    if clash:
        raise CustomRuleError([f"alias {clash[0]!r} collides with a shipped check id"])
    return check


def _notes_for(check: Check) -> list[str]:
    notes: list[str] = []
    if "no_resolvable_signal" in check.flags:
        notes.append("names no detector signal, so it can only surface as assist-only or unverified")
    return notes


def create_custom_rule(db: Session, yaml_text: str) -> DastCustomRule:
    check = _validate_custom(db, yaml_text, existing_id=None, version=1)
    row = DastCustomRule(
        check_id=check.check_id, version=1, yaml_text=yaml_text, definition=check_to_dict(check), notes=_notes_for(check)
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def update_custom_rule(db: Session, check_id: str, yaml_text: str) -> DastCustomRule | None:
    row = db.query(DastCustomRule).filter(DastCustomRule.check_id == check_id).first()
    if row is None:
        return None
    check = _validate_custom(db, yaml_text, existing_id=check_id, version=row.version + 1)
    row.version += 1
    row.yaml_text = yaml_text
    row.definition = check_to_dict(check)
    row.notes = _notes_for(check)
    db.commit()
    db.refresh(row)
    return row


def delete_custom_rule(db: Session, check_id: str) -> bool:
    row = db.query(DastCustomRule).filter(DastCustomRule.check_id == check_id).first()
    if row is None:
        return False
    db.delete(row)
    db.commit()
    return True


# ---- per-scan resolution ----------------------------------------------------------------------


@dataclass(frozen=True)
class ScanRuleSet:
    rule_set: EffectiveRuleSet
    snapshot: dict[str, Any]  # what to store under RULE_SET_KEY
    skipped_degraded: list[dict[str, Any]] = field(default_factory=list)  # store under SKIPPED_DEGRADED_KEY


def resolve_for_scan(
    db: Session,
    project: Project,
    scan_selection: Mapping[str, Any] | None,
    inputs: ScanInputs,
) -> ScanRuleSet:
    """Resolve global -> project -> per-scan into the scan's effective rule set, evaluate
    dependencies against the scan's inputs, and build the snapshot to store. Raises
    `RuleConfigError` when the per-scan selection names an unknown pack or check."""
    catalog = active_catalog(db)
    scan_config = parse_rule_config(scan_selection, catalog)
    rule_set = resolve_effective_rule_set(
        catalog, get_global_config(db, catalog), get_project_config(project, catalog), scan_config
    )
    snapshot = effective_to_dict(rule_set, catalog_version())
    return ScanRuleSet(rule_set, snapshot, evaluate_dependencies(rule_set, inputs))


def catalog_overview(db: Session) -> dict[str, Any]:
    """Catalog, packs and any custom rules that failed validation, for the settings API."""
    catalog = active_catalog(db)
    _, broken = _load_custom_checks(db)
    return {
        "catalog_version": catalog_version(),
        "packs": [
            {
                "id": p.pack_id,
                "title": p.title,
                "description": p.description,
                "enabled_by_default": p.enabled_by_default,
                "check_ids": [c.check_id for c in catalog.pack_checks(p.pack_id)],
            }
            for p in catalog.packs
        ],
        "checks": [check_to_dict(c) for c in catalog.checks],
        "invalid_custom_rules": broken,
    }



# ---- validation without saving, and the settings-page view --------------------------------------------


def validate_custom_yaml(db: Session, yaml_text: str, *, existing_id: str | None = None) -> dict[str, Any]:
    """`{valid, errors: [{field, message}], notes}` for a rule's YAML, without saving anything. Each
    error names the field it concerns where the validator knows it (an unknown signal, a fixed
    payload string, missing tags)."""
    check, issues, notes = parse_check_yaml(yaml_text, version=1)
    errors = [_error_dict(str(i.message)) for i in issues]
    if check is not None:
        try:
            _validate_custom(db, yaml_text, existing_id=existing_id, version=1)
        except CustomRuleError as exc:
            errors = [_error_dict(e) for e in exc.errors]
        else:
            notes = [*notes, *_notes_for(check)]
    return {"valid": not errors, "errors": errors, "notes": list(dict.fromkeys(notes))}


_FIELD_WORDS = (
    "signal", "payload", "standard", "owasp", "cwe", "apisec", "wstg", "severity", "mode", "location", "remediation_ref", "remediation", "dependencies",
    "applies_to", "aliases", "alias", "title", "description", "id", "passive", "enabled", "tags",
)
_FIELD_ALIASES = {"standard": "standards", "alias": "aliases", "tags": "standards"}


def _error_dict(message: str) -> dict[str, str]:
    """Split an error into the field it names and the reason. The validator's messages name the field
    in plain words ("unknown detector signal(s): x", "fixed payload ...", "needs a standard tag"); the
    field is the first known word in the message, else "rule" (a problem with the rule as a whole)."""
    lowered = message.lower()
    if lowered.startswith(("invalid yaml", "a rule must be")):  # about the document, not one field (and a YAML error quotes the text)
        return {"field": "rule", "message": message}
    found = []
    for word in _FIELD_WORDS:
        match = re.search(rf"\b{re.escape(word)}(?:s|\(s\))?(?![\w-])", lowered)
        if match:
            found.append((match.start(), -len(word), word))
    if not found:
        return {"field": "rule", "message": message}
    word = min(found)[2]
    return {"field": _FIELD_ALIASES.get(word, word), "message": message}


def rule_settings_view(db: Session, project: Project | None) -> dict[str, Any]:
    """Every pack and check with its effective value at the global level, or the project level when
    `project` is given, and where each value comes from: `default` (the catalog), `global` or
    `project`. Resolution is the same pure code scans use; sources are read off the stored levels."""
    catalog = active_catalog(db)
    global_cfg = get_global_config(db, catalog)
    project_cfg = get_project_config(project, catalog) if project is not None else EMPTY_CONFIG
    rule_set = resolve_effective_rule_set(catalog, global_cfg, project_cfg)
    by_id = {ec.check_id: ec for ec in rule_set.checks}

    def source_of(field: str, check_id: str) -> str:
        for level, cfg in (("project", project_cfg), ("global", global_cfg)):
            override = cfg.checks.get(check_id)
            if override is not None and getattr(override, field) is not None:
                return level
        return "default"

    def pack_source(pack_id: str) -> str:
        if project is not None and pack_id in project_cfg.packs:
            return "project"
        return "global" if pack_id in global_cfg.packs else "default"

    packs = []
    for p in catalog.packs:
        packs.append(
            {
                "id": p.pack_id, "title": p.title, "description": p.description, "enabled": p.pack_id in rule_set.pack_ids,
                "source": pack_source(p.pack_id), "enabled_by_default": p.enabled_by_default,
                "check_ids": [c.check_id for c in catalog.pack_checks(p.pack_id)],
            }
        )
    checks = []
    for check in catalog.checks:
        ec = by_id.get(check.check_id)
        # A check no enabled pack selects still gets a row: its value is "off, because no pack selects it".
        enabled = ec.enabled if ec is not None else False
        checks.append(
            {
                "check_id": check.check_id, "title": check.title, "description": check.description, "custom": check.source == "custom",
                "version": check.version if check.source == "custom" else None,
                "standards": {k: list(v) for k, v in check.standards.items()}, "passive": check.passive, "load_generating": check.load_generating,
                "requires": list(check.requires), "base_severity": check.base_severity.value, "base_mode": check.mode.value,
                "enabled": {"value": enabled, "source": source_of("enabled", check.check_id) if ec is not None else "default"},
                "severity": {"value": ec.severity.value if ec else check.base_severity.value, "source": source_of("severity", check.check_id)},
                "mode": {"value": ec.mode.value if ec else check.mode.value, "source": source_of("mode", check.check_id)},
                "selected_by_pack": ec is not None, "off_by_default": (not check.enabled_by_default) or check.load_generating or check.mode.value == "opt-in",
                "notes": list(ec.notes) if ec else [],
            }
        )
    return {"level": "project" if project is not None else "global", "catalog_version": catalog_version(), "packs": packs, "checks": checks, "applies_to": "new scans only"}

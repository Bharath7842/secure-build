"""DAST rule-set endpoints (DAST-03-040, -050): the catalog and packs, global and per-project
defaults, custom rules, and a preview of the effective rule set.

The per-scan selection is not here: it arrives in `POST /scans` (`dast.rule_packs`,
`dast.rule_overrides`) and is resolved by `app.services.dast_rules.resolve_for_scan`.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.auth.principal import Principal, require
from app.dast.domain.ruleset import RuleConfigError, ScanInputs
from app.db import get_db
from app.models import DastCustomRule, Project
from app.services import dast_rules, dast_settings
from app.services.dast_catalog import catalog_version
from app.services.dast_coverage import default_coverage

router = APIRouter(tags=["dast-rules"])


class RuleConfigIn(BaseModel):
    """`packs` is a pack id -> bool mapping (or a plain list meaning "exactly these").
    `checks` maps a check id to any of `{enabled, severity, mode}`."""

    packs: dict[str, bool] | list[str] | None = None
    checks: dict[str, dict[str, Any]] | None = None


class CustomRuleIn(BaseModel):
    yaml: str = Field(min_length=1, max_length=20000)


def _config_out(config) -> dict[str, Any]:
    return config.to_dict()


def _custom_out(row: DastCustomRule) -> dict[str, Any]:
    return {
        "id": row.id,
        "check_id": row.check_id,
        "version": row.version,
        "enabled": row.enabled,
        "yaml": row.yaml_text,
        "definition": row.definition,
        "notes": row.notes or [],
        "updated_at": row.updated_at,
    }


def _project_or_404(db: Session, project_id: str) -> Project:
    project = db.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    return project


@router.get("/dast/catalog")
def get_catalog(db: Session = Depends(get_db), principal: Principal = Depends(require("projects.view"))):
    return dast_rules.catalog_overview(db)


@router.get("/dast/vulnerability-coverage")
def get_vulnerability_coverage(principal: Principal = Depends(require("projects.view"))):
    """Coverage of a general web-vulnerability taxonomy against the real check catalog, for the
    settings page's coverage matrix. Read-only; never affects scan behaviour."""
    return default_coverage()


@router.get("/dast/rules")
def get_global_rules(db: Session = Depends(get_db), principal: Principal = Depends(require("projects.view"))):
    catalog = dast_rules.active_catalog(db)
    return {"config": _config_out(dast_rules.get_global_config(db, catalog)), "catalog_version": catalog_version()}


@router.patch("/dast/rules")
def patch_global_rules(body: RuleConfigIn, db: Session = Depends(get_db), principal: Principal = Depends(require("settings.manage"))):
    catalog = dast_rules.active_catalog(db)
    try:
        merged = dast_rules.update_config(dast_rules.get_global_config(db, catalog), body.model_dump(exclude_none=True), catalog)
    except RuleConfigError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    dast_rules.set_global_config(db, merged)
    return {"config": _config_out(merged), "catalog_version": catalog_version()}


@router.get("/projects/{project_id}/dast-rules")
def get_project_rules(project_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require("projects.view"))):
    project = _project_or_404(db, project_id)
    catalog = dast_rules.active_catalog(db)
    return {
        "config": _config_out(dast_rules.get_project_config(project, catalog)),
        "inherits_global": not project.dast_rules_config,
    }


@router.patch("/projects/{project_id}/dast-rules")
def patch_project_rules(
    project_id: str, body: RuleConfigIn, db: Session = Depends(get_db), principal: Principal = Depends(require("projects.manage"))
):
    project = _project_or_404(db, project_id)
    catalog = dast_rules.active_catalog(db)
    try:
        merged = dast_rules.update_config(dast_rules.get_project_config(project, catalog), body.model_dump(exclude_none=True), catalog)
    except RuleConfigError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    dast_rules.set_project_config(db, project, merged)
    return {"config": _config_out(merged), "inherits_global": False}


@router.delete("/projects/{project_id}/dast-rules", status_code=status.HTTP_204_NO_CONTENT)
def reset_project_rules(project_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require("projects.manage"))):
    """Drop the project's overrides so it inherits the global defaults again."""
    project = _project_or_404(db, project_id)
    project.dast_rules_config = None
    db.commit()
    return None


@router.get("/dast/rule-settings")
def get_rule_settings(project_id: str | None = Query(default=None), db: Session = Depends(get_db), principal: Principal = Depends(require("projects.view"))):
    """Packs and checks for the settings pages: the effective value of each setting at this level
    (global, or project) and where it comes from (default, global, project)."""
    project = _project_or_404(db, project_id) if project_id else None
    return dast_rules.rule_settings_view(db, project)


@router.get("/dast/rules/effective")
def preview_effective_rule_set(
    project_id: str | None = Query(default=None),
    packs: str | None = Query(default=None, description="Comma separated pack ids chosen for this scan (omit for the defaults)"),
    second_identity: bool = Query(default=False),
    oast: bool | None = Query(default=None, description="Defaults to whether DAST_OAST_CALLBACK_URL is set"),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require("projects.view")),
):
    """What a scan would run with right now (global -> project), without creating one."""
    from app.config import settings

    project = _project_or_404(db, project_id) if project_id else Project(name="(preview)", default_git_url="")
    inputs = ScanInputs(
        has_second_identity=second_identity,
        oast_configured=dast_settings.effective_settings(db).dast_oast_callback_url is not None if oast is None else oast,
    )
    selection = {"packs": [p for p in packs.split(",") if p]} if packs is not None else None
    try:
        resolved = dast_rules.resolve_for_scan(db, project, selection, inputs)
    except RuleConfigError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"rule_set": resolved.snapshot, "skipped_degraded": resolved.skipped_degraded}


# ---- custom rules -------------------------------------------------------------------------------


@router.post("/dast/custom-rules/validate")
def validate_custom_rule(body: CustomRuleIn, db: Session = Depends(get_db), principal: Principal = Depends(require("settings.manage"))):
    """Validate a rule without saving it: every error with its field and reason, and the notes that
    say it can only surface as assist-only or unverified."""
    return dast_rules.validate_custom_yaml(db, body.yaml)


@router.get("/dast/custom-rules")
def list_custom_rules(db: Session = Depends(get_db), principal: Principal = Depends(require("projects.view"))):
    rows = db.query(DastCustomRule).order_by(DastCustomRule.check_id).all()
    return {"rules": [_custom_out(r) for r in rows]}


@router.post("/dast/custom-rules", status_code=status.HTTP_201_CREATED)
def create_custom_rule(body: CustomRuleIn, db: Session = Depends(get_db), principal: Principal = Depends(require("settings.manage"))):
    try:
        return _custom_out(dast_rules.create_custom_rule(db, body.yaml))
    except dast_rules.CustomRuleError as exc:
        raise HTTPException(status_code=422, detail={"errors": exc.errors}) from exc


@router.get("/dast/custom-rules/{check_id}")
def get_custom_rule(check_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require("projects.view"))):
    row = db.query(DastCustomRule).filter(DastCustomRule.check_id == check_id).first()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Custom rule not found")
    return _custom_out(row)


@router.put("/dast/custom-rules/{check_id}")
def update_custom_rule(check_id: str, body: CustomRuleIn, db: Session = Depends(get_db), principal: Principal = Depends(require("settings.manage"))):
    try:
        row = dast_rules.update_custom_rule(db, check_id, body.yaml)
    except dast_rules.CustomRuleError as exc:
        raise HTTPException(status_code=422, detail={"errors": exc.errors}) from exc
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Custom rule not found")
    return _custom_out(row)


@router.delete("/dast/custom-rules/{check_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_custom_rule(check_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require("settings.manage"))):
    if not dast_rules.delete_custom_rule(db, check_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Custom rule not found")
    return None

"""Global DAST settings and model routing endpoints (DAST-15-010, -020, -050).

`GET/PATCH /dast/settings`, `GET/PUT /dast/model-routing`, `POST /dast/model-routing/test` and the
read-only `GET /dast/providers`. Every endpoint needs the bearer token. Edits apply to scans created
afterwards (see `app.services.dast_settings`); provider keys are never accepted or returned here.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, StrictFloat, StrictInt
from sqlalchemy.orm import Session

from app.auth.principal import Principal, require
from app.db import get_db
from app.services import dast_settings

router = APIRouter(prefix="/dast", tags=["dast-settings"])


class SettingsPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Strict types: `true` is not 1, and "5" is not 5; a wrong type is a 422 naming the field.
    max_runtime_minutes: StrictFloat | StrictInt | None = None
    max_depth: StrictInt | None = None
    max_pages: StrictInt | None = None
    max_per_pattern: StrictInt | None = None
    same_domain_mode: str | None = None
    safe_mode_default: bool | None = None
    browser_probe_enabled: bool | None = None
    browser_marker_posts: bool | None = None
    browser_probe_max_inputs: StrictInt | None = None
    rate_limit_per_sec: StrictFloat | StrictInt | None = None
    max_targets: StrictInt | None = None
    max_tests_per_target: StrictInt | None = None
    # Write-only: an empty string clears it. The address itself is never returned.
    oast_callback_url: str | None = None
    # Required to turn the safe-mode default off.
    confirm_unsafe: bool = False


class RouteIn(BaseModel):
    task: str
    provider: str
    model: str = ""


def _raise(exc: dast_settings.SettingsError) -> None:
    raise HTTPException(status_code=422, detail={"errors": exc.errors})


@router.get("/settings")
def get_settings(db: Session = Depends(get_db), principal: Principal = Depends(require("projects.view"))):
    return dast_settings.settings_view(db)


@router.patch("/settings")
def patch_settings(body: SettingsPatch, db: Session = Depends(get_db), principal: Principal = Depends(require("settings.manage"))):
    patch: dict[str, Any] = body.model_dump(exclude_none=True, exclude={"confirm_unsafe"})
    try:
        dast_settings.update_settings(db, patch, confirm_unsafe=body.confirm_unsafe)
    except dast_settings.SettingsError as exc:
        _raise(exc)
    return dast_settings.settings_view(db)


@router.get("/model-routing")
def get_model_routing(db: Session = Depends(get_db), principal: Principal = Depends(require("projects.view"))):
    return dast_settings.routing_view(db)


@router.put("/model-routing")
def put_model_routing(routes: list[RouteIn], db: Session = Depends(get_db), principal: Principal = Depends(require("settings.manage"))):
    try:
        dast_settings.update_routing(db, [r.model_dump() for r in routes])
    except dast_settings.SettingsError as exc:
        _raise(exc)
    return dast_settings.routing_view(db)


@router.post("/model-routing/test")
def test_model_route(route: RouteIn, db: Session = Depends(get_db), principal: Principal = Depends(require("settings.manage"))):
    return dast_settings.test_route(db, route.model_dump())


@router.get("/compliance")
def get_compliance(principal: Principal = Depends(require("projects.view"))):
    """PCI, ISO 27001 and SOC 2 requirements mapped onto catalog checks. Read-only."""
    from app.services.dast_compliance import compliance_view

    return compliance_view()


class ProfileIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    intensity: str = "standard"
    method_policy: str = "safe"
    rule_packs: list[str] = []


class ScheduleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    project_id: str
    name: str = "Scheduled DAST"
    interval_minutes: int = 1440
    request: dict[str, Any]


@router.get("/profiles")
def get_profiles(db: Session = Depends(get_db), principal: Principal = Depends(require("projects.view"))):
    from app.services.dast_schedule import list_profiles

    return {"profiles": list_profiles(db)}


@router.put("/profiles")
def put_profiles(profiles: list[ProfileIn], db: Session = Depends(get_db), principal: Principal = Depends(require("settings.manage"))):
    from app.services.dast_schedule import save_profiles

    saved = save_profiles(db, [p.model_dump() for p in profiles])
    return {"profiles": saved}


@router.post("/schedules", status_code=201)
def create_schedule(body: ScheduleIn, db: Session = Depends(get_db), principal: Principal = Depends(require("scans.create_dast"))):
    from app.services.dast_schedule import save_schedule

    try:
        row = save_schedule(
            db,
            project_id=body.project_id,
            name=body.name,
            interval_minutes=body.interval_minutes,
            request=body.request,
            created_by_user_id=principal.user_id,
        )
    except Exception as exc:
        from pydantic import ValidationError

        if not isinstance(exc, (ValueError, ValidationError)):
            raise
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"id": row.id, "next_run_at": row.next_run_at.isoformat()}


@router.get("/providers")
def get_provider_status(principal: Principal = Depends(require("projects.view"))):
    """Whether each provider has credentials configured in the environment. Read-only: no key is
    ever accepted or returned by this API (see the decision in `app.services.dast_settings`)."""
    return {
        "providers": dast_settings.provider_status(),
        "default_models": dast_settings.default_models(),
        "storage": "environment",
        "writable": False,
    }

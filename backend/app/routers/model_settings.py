"""Which models the model selects offer: `GET/PATCH /settings/models`. See `app.services.model_visibility`."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.auth import verify_bearer
from app.db import get_db
from app.services import model_visibility

router = APIRouter(prefix="/settings/models", tags=["config"])


class ModelSettingsPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hidden: list[str]


@router.get("")
def get_model_settings(db: Session = Depends(get_db), _: None = Depends(verify_bearer)):
    return model_visibility.build_catalog(db)


@router.patch("")
def patch_model_settings(
    body: ModelSettingsPatch, db: Session = Depends(get_db), _: None = Depends(verify_bearer)
):
    try:
        model_visibility.save_hidden(db, body.hidden)
    except model_visibility.ModelSettingsError as exc:
        raise HTTPException(status_code=422, detail={"errors": exc.errors}) from exc
    return model_visibility.build_catalog(db)

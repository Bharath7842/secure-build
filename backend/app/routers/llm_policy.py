"""Which LLM endpoints and models scans may use: `GET/PUT /settings/llm-policy`.
See `app.services.llm_policy`."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.auth.principal import Principal, record as audit_record, require
from app.db import get_db
from app.services import llm_policy

router = APIRouter(prefix="/settings/llm-policy", tags=["config"])


class LlmPolicyPut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # `host` or `host:port`; an approved host may be a private address or use plain http.
    allowed_hosts: list[str] = Field(default_factory=list, max_length=200)
    # Empty = any model; otherwise projects and scans may only use these.
    allowed_models: list[str] = Field(default_factory=list, max_length=200)


def _view(policy: dict) -> dict:
    return {
        "allowed_hosts": policy["admin_hosts"],
        "server_allowed_hosts": policy["env_hosts"],
        "allowed_models": policy["allowed_models"],
        "allow_loopback": policy["allow_loopback"],
    }


@router.get("")
def get_llm_policy(db: Session = Depends(get_db), principal: Principal = Depends(require("projects.view"))):
    return _view(llm_policy.load_policy(db))


@router.put("")
def put_llm_policy(
    body: LlmPolicyPut,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require("llm.approve")),
):
    before = llm_policy.load_policy(db)
    try:
        llm_policy.save_policy(db, allowed_hosts=body.allowed_hosts, allowed_models=body.allowed_models)
    except llm_policy.LlmPolicyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    after = llm_policy.load_policy(db)
    audit_record(
        db, request, "llm_policy.update", principal,
        target_type="llm_policy",
        details={
            "hosts_added": sorted(set(after["admin_hosts"]) - set(before["admin_hosts"])),
            "hosts_removed": sorted(set(before["admin_hosts"]) - set(after["admin_hosts"])),
            "models_before": len(before["allowed_models"]),
            "models_after": len(after["allowed_models"]),
        },
    )
    return _view(after)

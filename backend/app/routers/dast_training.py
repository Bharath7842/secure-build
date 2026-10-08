"""Training-data endpoints (DAST-16-050): switch capture on for a project, list and export examples.

Every endpoint needs the bearer token and the training admin token (`X-Training-Admin-Token`); the
reader names itself in `X-Training-Reader`. Allowed and denied attempts are both audited
(`dast_training_audit`, readable at `GET /dast/training/audit` with the same credentials).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.auth import verify_bearer
from app.db import get_db
from app.models import DastTrainingAudit, Project
from app.services import dast_training

router = APIRouter(tags=["dast-training"])


def _authorize(db: Session, action: str, token: str | None, reader: str | None, detail: str = "") -> str:
    name = (reader or "").strip()
    if not name:
        dast_training.audit(db, "anonymous", action, False, "no reader named" + (f"; {detail}" if detail else ""))
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Name yourself in the X-Training-Reader header.")
    if not dast_training.admin_token_ok(token):
        dast_training.audit(db, name, action, False, "training admin token missing or wrong" + (f"; {detail}" if detail else ""))
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Training data needs the training admin token.")
    return name


class CaptureIn(BaseModel):
    enabled: bool


@router.patch("/projects/{project_id}/dast-training")
def set_project_capture(
    project_id: str,
    body: CaptureIn,
    db: Session = Depends(get_db),
    _: None = Depends(verify_bearer),
    x_training_admin_token: str | None = Header(default=None),
    x_training_reader: str | None = Header(default=None),
):
    reader = _authorize(db, "enable" if body.enabled else "disable", x_training_admin_token, x_training_reader, f"project {project_id}")
    project = db.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    dast_training.set_capture(db, project, body.enabled, reader)
    return {"project_id": project.id, "training_capture_enabled": project.training_capture_enabled}


@router.get("/dast/training/examples")
def list_examples(
    project_id: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    after: str | None = Query(default=None),
    db: Session = Depends(get_db),
    _: None = Depends(verify_bearer),
    x_training_admin_token: str | None = Header(default=None),
    x_training_reader: str | None = Header(default=None),
):
    reader = _authorize(db, "list", x_training_admin_token, x_training_reader)
    rows = dast_training.list_examples(db, project_id=project_id, limit=limit, after=after)
    dast_training.audit(db, reader, "list", True, f"project {project_id or '*'}", len(rows))
    return {"examples": rows, "next_after": rows[-1]["id"] if len(rows) == limit else None}


@router.get("/dast/training/export.jsonl", response_class=PlainTextResponse)
def export_examples(
    project_id: str | None = Query(default=None),
    balance: bool = Query(default=True),
    task: str | None = Query(default=None, pattern="^(rule|construct)$"),
    db: Session = Depends(get_db),
    _: None = Depends(verify_bearer),
    x_training_admin_token: str | None = Header(default=None),
    x_training_reader: str | None = Header(default=None),
):
    reader = _authorize(db, "export", x_training_admin_token, x_training_reader)
    text, info = dast_training.export_jsonl(db, project_id=project_id, balance=balance, task=task)
    dast_training.audit(db, reader, "export", True, f"dataset {info['dataset_version']} (project {project_id or '*'})", info["count"])
    return PlainTextResponse(text, media_type="application/x-ndjson", headers={"X-Dataset-Version": info["dataset_version"], "X-Dataset-Count": str(info["count"])})


@router.get("/dast/training/audit")
def read_audit(
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    _: None = Depends(verify_bearer),
    x_training_admin_token: str | None = Header(default=None),
    x_training_reader: str | None = Header(default=None),
):
    _authorize(db, "audit", x_training_admin_token, x_training_reader)
    rows = db.query(DastTrainingAudit).order_by(DastTrainingAudit.at.desc(), DastTrainingAudit.id).limit(limit).all()
    return {"entries": [{"at": r.at.isoformat(), "reader": r.reader, "action": r.action, "allowed": r.allowed, "detail": r.detail, "count": r.count} for r in rows]}

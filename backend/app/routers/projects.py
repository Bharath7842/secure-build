import shutil
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from pydantic import BaseModel

from app.auth.principal import Principal, require
from app.config import settings
from app.db import get_db
from app.defaults.reference_sources import normalize_sources, sync_legacy_fields
from app.defaults.scan_limitations import SCAN_LIMITATIONS
from app.models import FileSnapshot, Finding, FindingReview, FindingReviewEvent, LlmResultCache, Project, Scan
from app.routers.git_auth import consume_pending_connection
from app.schemas import ProjectCreate, ProjectDeleteOut, ProjectOut, ProjectUpdate
from app.services import scan_log

router = APIRouter(prefix="/projects", tags=["projects"])


def _get_project_or_404(db: Session, project_id: str) -> Project:
    project = db.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    return project


def _commit_or_raise_duplicate(db: Session) -> None:
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Project name already exists",
        )


def _plain_secret(value) -> str | None:
    if value is None:
        return None
    raw = value.get_secret_value() if hasattr(value, "get_secret_value") else str(value)
    return raw.strip() or None


def _apply_reference_sources(data: dict) -> None:
    raw = data.get("reference_sources")
    if raw is not None:
        # Pydantic models → plain dicts
        raw = [
            s.model_dump() if hasattr(s, "model_dump") else s
            for s in raw
        ]
    sources = normalize_sources(
        raw,
        owasp_mode=data.get("owasp_mode") or "top10",
        nvd_mode=data.get("nvd_mode") or "top10",
        owasp_urls=data.get("owasp_urls") or None,
        nvd_urls=data.get("nvd_urls") or None,
    )
    data["reference_sources"] = sources
    sync_legacy_fields(data, sources)


@router.post("", response_model=ProjectOut, status_code=status.HTTP_201_CREATED)
def create_project(
    payload: ProjectCreate,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require("projects.manage")),
):
    data = payload.model_dump()
    data["scan_mode"] = "full"
    data["llm_api_key"] = _plain_secret(data.get("llm_api_key"))
    connection_id = data.pop("git_connection_id", None)
    _apply_reference_sources(data)
    project = Project(**data)
    if connection_id:
        connection = consume_pending_connection(connection_id)
        if connection is not None:
            project.git_provider = connection["provider"]
            project.git_access_token = connection["access_token"]
            project.git_refresh_token = connection["refresh_token"]
            project.git_token_expires_at = connection["expires_at"]
    db.add(project)
    _commit_or_raise_duplicate(db)
    db.refresh(project)
    return project


@router.get("", response_model=list[ProjectOut])
def list_projects(
    db: Session = Depends(get_db),
    principal: Principal = Depends(require("projects.view")),
):
    return db.query(Project).order_by(Project.created_at.desc()).all()


@router.get("/{project_id}", response_model=ProjectOut)
def get_project(
    project_id: str,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require("projects.view")),
):
    return _get_project_or_404(db, project_id)


@router.patch("/{project_id}", response_model=ProjectOut)
def update_project(
    project_id: str,
    payload: ProjectUpdate,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require("projects.manage")),
):
    project = _get_project_or_404(db, project_id)
    updates = payload.model_dump(exclude_unset=True)
    updates["scan_mode"] = "full"
    if "llm_api_key" in updates:
        # Omitted keeps the stored key; "" (or null) clears it.
        updates["llm_api_key"] = _plain_secret(updates["llm_api_key"])
    if "reference_sources" in updates:
        _apply_reference_sources(updates)
    for field, value in updates.items():
        setattr(project, field, value)
    _commit_or_raise_duplicate(db)
    db.refresh(project)
    return project


@router.delete("/{project_id}", response_model=ProjectDeleteOut)
def delete_project(
    project_id: str,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require("projects.manage")),
):
    """Delete a project and everything scoped to it: its scans + findings,
    its on-disk git workspace, its cached file snapshots, and (if connected)
    its GitHub/GitLab authorization. Rejects while any scan is still
    queued/running — same guard as DELETE /scans/{id} — so a background scan
    thread never has its DB rows disappear out from under it mid-run."""
    project = _get_project_or_404(db, project_id)

    scans = db.query(Scan).filter(Scan.project_id == project_id).all()
    active = [s for s in scans if s.status in ("queued", "running", "paused")]
    if active:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"{len(active)} scan(s) are still queued or running. "
                "Stop them first, then delete the project."
            ),
        )

    scan_ids = [s.id for s in scans]
    if scan_ids:
        db.query(Finding).filter(Finding.scan_id.in_(scan_ids)).delete(synchronize_session=False)
        db.query(Scan).filter(Scan.project_id == project_id).delete(synchronize_session=False)
    db.query(FileSnapshot).filter(FileSnapshot.project_id == project_id).delete(synchronize_session=False)
    db.query(LlmResultCache).filter(LlmResultCache.project_id == project_id).delete(synchronize_session=False)
    # Reviews outlive a deleted scan (they are labelled data) but not their project.
    review_ids = db.query(FindingReview.id).filter(FindingReview.project_id == project_id)
    db.query(FindingReviewEvent).filter(FindingReviewEvent.review_id.in_(review_ids)).delete(synchronize_session=False)
    db.query(FindingReview).filter(FindingReview.project_id == project_id).delete(synchronize_session=False)

    for scan_id in scan_ids:
        scan_log.delete(scan_id)

    workspace = Path(settings.workspaces_dir) / project_id
    workspace_removed = workspace.exists()
    if workspace_removed:
        shutil.rmtree(workspace, ignore_errors=True)

    git_disconnected = project.git_connected

    db.delete(project)
    db.commit()

    return ProjectDeleteOut(
        project_id=project_id,
        scans_deleted=len(scan_ids),
        workspace_removed=workspace_removed,
        git_disconnected=git_disconnected,
    )


class UpdateLimitationsPayload(BaseModel):
    enabled_ids: list[str]


@router.patch("/{project_id}/limitations", response_model=ProjectOut)
def update_project_limitations(
    project_id: str,
    payload: UpdateLimitationsPayload,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require("projects.manage")),
):
    """Update which scan limitations are enabled for a project."""
    project = _get_project_or_404(db, project_id)
    all_limitation_ids = {lim.id for lim in SCAN_LIMITATIONS}
    enabled_set = set(payload.enabled_ids)
    if not enabled_set.issubset(all_limitation_ids):
        invalid = enabled_set - all_limitation_ids
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown limitation IDs: {', '.join(sorted(invalid))}",
        )
    project.limitations_config = {lim_id: lim_id in enabled_set for lim_id in all_limitation_ids}
    db.commit()
    db.refresh(project)
    return project

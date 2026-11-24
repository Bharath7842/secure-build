"""`POST /ci/scan`: the one call a CI pipeline needs.

The pipeline sends the repository URL, branch and commit it is running for, and the app URL +
token it already has. The backend finds the project for that repository (creating it on the
first request), then starts or reuses a scan for the commit, exactly as `POST /scans` does.
Nothing is set up in the web app beforehand and the pipeline never learns a project id.
"""

from __future__ import annotations

import logging
import threading

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.auth.principal import Principal, record, require
from app.authz.scope import can_see_project
from app.config import settings
from app.db import get_db
from app.models import Project, Scan
from app.routers.projects import create_project
from app.routers.scans import create_scan
from app.schemas import CiScanItemOut, CiScanOut, CiScanRequest, ProjectCreate, ScanCreate
from app.services import git_workspace
from app.services.repo_key import normalize_repo_key, repo_display_name

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ci", tags=["ci"])

# Two pipelines of a new repository can arrive together; without this both would create it.
_PROJECT_LOCK = threading.Lock()

_ENABLE_FLAG = {"sast": "enable_sast", "sca": "enable_sca", "sbom": "enable_sbom"}


def _find_project(db: Session, principal: Principal, repo_key: str) -> Project | None:
    """The oldest project for this repository that the caller may use."""
    candidates = (
        db.query(Project).filter(Project.repo_key == repo_key).order_by(Project.created_at.asc()).all()
    )
    return next((p for p in candidates if can_see_project(principal, p)), None)


def _find_or_create_project(
    db: Session, principal: Principal, repo_url: str, repo_key: str, branch: str | None
) -> tuple[Project, bool]:
    with _PROJECT_LOCK:
        project = _find_project(db, principal, repo_key)
        if project is not None:
            return project, False
        project = create_project(
            ProjectCreate(
                name=repo_display_name(repo_url),
                description="Created automatically from a CI pipeline.",
                default_git_url=repo_url,
                default_branch=branch or "main",
            ),
            db,
            principal,
        )
        return project, True


@router.post("/scan", response_model=CiScanOut, status_code=status.HTTP_202_ACCEPTED)
def ci_scan(
    payload: CiScanRequest,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require("projects.manage", "scans.create")),
):
    # Never keep or echo credentials from the URL; the job token travels in its own field.
    repo_url = git_workspace.redact_git_url(payload.repo_url)
    repo_key = normalize_repo_key(repo_url)
    if not repo_key:
        raise HTTPException(status_code=422, detail="repo_url is not a repository URL.")

    branch = (payload.branch or "").strip() or None
    project, created = _find_or_create_project(db, principal, repo_url, repo_key, branch)

    # A project made in the web app may have a scan type switched off; say so before any scan
    # starts, instead of starting the first type and failing on the second.
    disabled = [t for t in payload.scan_types if not getattr(project, _ENABLE_FLAG[t], True)]
    if disabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"{', '.join(t.upper() for t in disabled)} scanning is disabled for the project "
                f"'{project.name}'. Enable it in the project's settings, or drop it from scan_types."
            ),
        )

    metadata = {k: v for k, v in (payload.metadata or {}).items() if "token" not in str(k).lower()}
    metadata.setdefault("source", "ci")
    clone_token = payload.job_token.get_secret_value().strip() if payload.job_token else None

    scans: list[CiScanItemOut] = []
    web_url = settings.public_app_url.rstrip("/")
    for scan_type in payload.scan_types:
        use_llm = payload.use_llm and scan_type == "sast"
        triggered = create_scan(
            ScanCreate(
                project_id=project.id,
                git_url=repo_url,
                repo_path=payload.path,
                branch=branch,
                commit_sha=payload.commit_sha,
                metadata=dict(metadata),
                force=payload.force,
                scan_type=scan_type,
                use_llm=use_llm,
                llm_provider=payload.llm_provider if use_llm else None,
                llm_model=payload.llm_model if use_llm else None,
            ),
            request,
            db,
            principal,
            clone_token=clone_token,
        )
        scan = db.get(Scan, triggered.scan_id)
        scans.append(
            CiScanItemOut(
                **triggered.model_dump(),
                scan_type=scan_type,
                version=scan.version if scan is not None else None,
                scan_url=f"{web_url}/scans/{triggered.scan_id}",
            )
        )

    record(
        db,
        request,
        "ci.scan_requested",
        principal,
        target_type="project",
        target_id=project.id,
        details={
            "repo": repo_key,
            "branch": branch,
            "commit": (payload.commit_sha or "")[:12] or None,
            "scan_types": payload.scan_types,
            "project_created": created,
            "reused": [s.scan_id for s in scans if s.reused],
        },
    )
    return CiScanOut(
        project_id=project.id,
        project_name=project.name,
        project_created=created,
        scans=scans,
    )

"""A project's issues by short id, and the Claude skill that uses them.

    GET /projects/{id}/issues                list the priority issues of the latest finished SAST scan
    GET /projects/{id}/issues/{short_id}     one issue with everything needed to fix it
    GET /projects/{id}/claude-skill          the `secure-fix` SKILL.md for this project

The short id (`SB-7F3A9C21`) is derived from the occurrence id, so it survives rescans.
The CI bearer token can call all three: a developer's machine needs only that token and
the project id (the skill file carries the id; the token stays in an environment variable).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy.orm import Session

from app.auth.principal import Principal, require
from app.authz.scope import authorize_scan, can_see_project
from app.db import get_db
from app.models import Project, Scan
from app.routers.projects import resolve_public_api_url
from app.schemas import FindingOut, IssueScanOut, IssueSummaryOut, ProjectIssueOut, ProjectIssuesOut
from app.services import claude_skill, issue_lookup
from app.services.occurrence import group_short_id, normalize_short_id

router = APIRouter(prefix="/projects", tags=["issues"])


def _project_or_404(db: Session, project_id: str, principal: Principal) -> Project:
    project = db.get(Project, project_id)
    if project is None or not can_see_project(principal, project):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    return project


def _scan_for(db: Session, principal: Principal, project: Project, scan_id: str | None) -> Scan:
    """The named scan, or the project's latest finished SAST scan."""
    if scan_id:
        scan = authorize_scan(db, principal, scan_id)
        if scan.project_id != project.id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
        if (scan.scan_type or "sast") != "sast":
            raise HTTPException(status_code=422, detail="Issue ids are for SAST scans")
        if scan.status != "success":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Scan is {scan.status}")
        return scan
    scan = issue_lookup.latest_finished_scan(db, principal, project.id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="This project has no finished SAST scan yet")
    return scan


def _scan_out(scan: Scan) -> IssueScanOut:
    return IssueScanOut(
        id=scan.id,
        version=scan.version,
        status=scan.status,
        branch=scan.branch,
        commit_sha=scan.commit_sha,
        created_at=scan.created_at,
    )


@router.get("/{project_id}/issues", response_model=ProjectIssuesOut)
def list_issues(
    project_id: str,
    verdict: str = Query(
        default="true_positive",
        pattern="^(true_positive|unverified|false_positive|all)$",
        description="Which issues to list; confirmed true positives by default",
    ),
    limit: int = Query(default=10, ge=1, le=100),
    scan_id: str | None = Query(default=None, description="A finished SAST scan of this project; default the latest"),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require("projects.view")),
):
    project = _project_or_404(db, project_id, principal)
    scan = _scan_for(db, principal, project, scan_id)
    matching = issue_lookup.filter_groups(
        issue_lookup.issue_groups(db, scan), issue_lookup.IssueFilter(verdict=verdict, limit=limit)
    )
    return ProjectIssuesOut(
        project_id=project.id,
        project_name=project.name,
        repo_url=project.default_git_url or None,
        scan=_scan_out(scan),
        total=len(matching),
        issues=[
            IssueSummaryOut(
                short_id=group_short_id(g.occurrence_id, getattr(g, "member_occurrence_ids", None)),
                severity=g.severity,
                cvss=g.cvss,
                cwe=g.cwe,
                title=g.title,
                verdict=g.verdict,
                file_path=g.file_path,
                line=g.line,
                occurrence_count=getattr(g, "occurrence_count", None) or 1,
                affected_files=getattr(g, "affected_files", None),
            )
            for g in matching[:limit]
        ],
    )


@router.get("/{project_id}/issues/{short_id}", response_model=ProjectIssueOut)
def get_issue(
    project_id: str,
    short_id: str,
    scan_id: str | None = Query(default=None, description="A finished SAST scan of this project; default the latest"),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require("projects.view")),
):
    wanted = normalize_short_id(short_id)
    if wanted is None:
        raise HTTPException(
            status_code=422,
            detail="An issue id looks like SB-7F3A9C21 (SB- and 8 hex characters)",
        )
    project = _project_or_404(db, project_id, principal)
    scan = _scan_for(db, principal, project, scan_id)
    try:
        group = issue_lookup.find_group(issue_lookup.issue_groups(db, scan), wanted)
    except issue_lookup.IssueLookupError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    return ProjectIssueOut(
        project_id=project.id,
        project_name=project.name,
        repo_url=project.default_git_url or None,
        scan=_scan_out(scan),
        issue=FindingOut.model_validate(group),
    )


@router.get("/{project_id}/claude-skill")
def download_claude_skill(
    project_id: str,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require("projects.view")),
):
    """`SKILL.md` for `.claude/skills/secure-fix/`: the project id and API address are filled in,
    the token is not (it is read from `SAST_API_TOKEN`)."""
    project = _project_or_404(db, project_id, principal)
    api_url, _source = resolve_public_api_url(request)
    body = claude_skill.render_skill(
        project_id=project.id,
        project_name=project.name,
        repo_url=project.default_git_url or None,
        api_url=api_url,
    )
    return Response(
        content=body,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="SKILL.md"', "Cache-Control": "no-store"},
    )

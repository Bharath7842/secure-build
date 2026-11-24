import json
import shutil
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from pydantic import BaseModel

from app.auth.principal import Principal, record as audit_record, require
from app.authz.scope import can_see_project
from app.config import settings
from app.db import get_db
from app.defaults.reference_sources import normalize_sources, sync_legacy_fields
from app.defaults.scan_limitations import SCAN_LIMITATIONS
from app.models import FileSnapshot, Finding, FindingReview, FindingReviewEvent, LlmResultCache, Project, Scan
from app.routers.git_auth import consume_pending_connection
from app.schemas import (
    FindingExplainModelsOut,
    ProjectCreate,
    ProjectDeleteOut,
    ProjectOut,
    ProjectUpdate,
    VulnerabilityInsightsIn,
)
from app.services import finding_explain, llm_policy, scan_log, vulnerability_insights, vulnerability_report

router = APIRouter(prefix="/projects", tags=["projects"])

_LLM_FIELDS = ("llm_provider", "llm_model", "llm_base_url", "fallback_llm_provider", "fallback_llm_model")


def _enforce_llm_policy(db: Session, values: dict) -> None:
    """422 when the project's LLM endpoint or model is not allowed (LLM03)."""
    try:
        llm_policy.check_config(
            provider=values.get("llm_provider"),
            model=values.get("llm_model"),
            base_url=values.get("llm_base_url"),
            fallback_provider=values.get("fallback_llm_provider"),
            fallback_model=values.get("fallback_llm_model"),
            policy=llm_policy.load_policy(db),
        )
    except llm_policy.LlmPolicyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _get_project_or_404(db: Session, project_id: str, principal: Principal) -> Project:
    """A project outside the caller's view answers 404, like one that doesn't exist."""
    project = db.get(Project, project_id)
    if project is None or not can_see_project(principal, project):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    return project


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
    _enforce_llm_policy(db, data)
    connection_id = data.pop("git_connection_id", None)
    _apply_reference_sources(data)
    project = Project(**data, created_by_user_id=principal.user_id)
    if connection_id:
        connection = consume_pending_connection(connection_id)
        if connection is not None:
            project.git_provider = connection["provider"]
            project.git_access_token = connection["access_token"]
            project.git_refresh_token = connection["refresh_token"]
            project.git_token_expires_at = connection["expires_at"]
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


@router.get("", response_model=list[ProjectOut])
def list_projects(
    db: Session = Depends(get_db),
    principal: Principal = Depends(require("projects.view")),
):
    query = db.query(Project)
    if not principal.can("projects.view_all"):
        query = query.filter(Project.created_by_user_id == principal.user_id)
    return query.order_by(Project.created_at.desc()).all()


@router.get("/{project_id}", response_model=ProjectOut)
def get_project(
    project_id: str,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require("projects.view")),
):
    return _get_project_or_404(db, project_id, principal)


@router.patch("/{project_id}", response_model=ProjectOut)
def update_project(
    project_id: str,
    payload: ProjectUpdate,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require("projects.manage")),
):
    project = _get_project_or_404(db, project_id, principal)
    updates = payload.model_dump(exclude_unset=True)
    updates["scan_mode"] = "full"
    if any(field in updates for field in _LLM_FIELDS):
        # Only when an LLM field changes: an unrelated edit of a project saved
        # under an older policy is not blocked by it.
        _enforce_llm_policy(db, {f: updates.get(f, getattr(project, f, None)) for f in _LLM_FIELDS})
    if "llm_api_key" in updates:
        # Omitted keeps the stored key; "" (or null) clears it.
        updates["llm_api_key"] = _plain_secret(updates["llm_api_key"])
    if "reference_sources" in updates:
        _apply_reference_sources(updates)
    for field, value in updates.items():
        setattr(project, field, value)
    db.commit()
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
    project = _get_project_or_404(db, project_id, principal)

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
    project = _get_project_or_404(db, project_id, principal)
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


# --- GitLab CI setup guide ---------------------------------------------------

_NGROK_API = "http://127.0.0.1:4040/api/tunnels"


class CiSetupOut(BaseModel):
    project_id: str
    project_name: str
    repo_url: str | None
    branch: str | None
    # SAST_API_URL: the backend's public URL, or None when none is known.
    api_url: str | None
    api_url_source: str | None  # "setting" | "ngrok" | None
    web_url: str
    # SAST_API_TOKEN: only for admins; None for everyone else.
    token: str | None
    token_visible: bool
    scan_types: list[str]


def _ngrok_backend_url(port: int) -> str | None:
    """The public HTTPS URL of a local ngrok tunnel to `port`, if one is running."""
    import json
    import urllib.request

    try:
        with urllib.request.urlopen(_NGROK_API, timeout=0.5) as resp:  # fixed loopback URL
            tunnels = json.load(resp).get("tunnels") or []
    except Exception:
        return None
    for tunnel in tunnels:
        url = str(tunnel.get("public_url") or "")
        addr = str((tunnel.get("config") or {}).get("addr") or "")
        if url.startswith("https://") and (addr == str(port) or addr.endswith(f":{port}")):
            return url.rstrip("/")
    return None


def resolve_public_api_url(request: Request) -> tuple[str | None, str | None]:
    """(url, source) a pipeline or a developer's machine can reach this backend at:
    the `PUBLIC_API_URL` setting, else a running ngrok tunnel; (None, None) when neither."""
    if settings.public_api_url and settings.public_api_url.strip():
        return settings.public_api_url.strip().rstrip("/"), "setting"
    found = _ngrok_backend_url(request.url.port or 8000)
    if found:
        return found, "ngrok"
    return None, None


@router.get("/{project_id}/vulnerability-report")
def get_vulnerability_report(
    project_id: str,
    branch: str | None = Query(default=None, description="Branch to report on; '' = every branch"),
    scan_type: str | None = Query(default=None, pattern="^(sast|sca|sbom|dast)$"),
    max_scans: int = Query(default=vulnerability_report.DEFAULT_MAX_SCANS, ge=1, le=200),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require("scans.view_own")),
):
    """Every vulnerability the project's scans found, followed across scans."""
    project = _get_project_or_404(db, project_id, principal)
    return vulnerability_report.build_report(
        db, project, principal, branch=branch, scan_type=scan_type, max_scans=max_scans
    )


@router.get("/{project_id}/vulnerability-report/insights/models", response_model=FindingExplainModelsOut)
def list_vulnerability_insights_models(
    project_id: str,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require("scans.view_own")),
):
    """Models pulled on the local Ollama server that Netra's Insights can use."""
    _get_project_or_404(db, project_id, principal)
    return FindingExplainModelsOut(**finding_explain.explain_models_payload())


@router.post("/{project_id}/vulnerability-report/insights/stream")
def stream_vulnerability_insights(
    project_id: str,
    body: VulnerabilityInsightsIn,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require("scans.view_own")),
):
    """Stream Netra's prioritised fix plan for the project from local Ollama (SSE)."""
    project = _get_project_or_404(db, project_id, principal)
    report = vulnerability_report.build_report(
        db, project, principal, branch=body.branch, scan_type=body.scan_type
    )
    brief, refs = vulnerability_insights.build_brief(report)
    messages = [{"role": m.role, "content": m.content} for m in body.messages]
    prompt = vulnerability_insights.build_user_prompt(brief, messages)
    model = finding_explain.resolve_model(body.model)

    def event_generator():
        ollama_err = finding_explain.preflight_error(model)
        if ollama_err:
            yield f"event: error\ndata: {json.dumps({'message': ollama_err})}\n\n"
            return
        yield f"event: meta\ndata: {json.dumps({'provider': 'ollama', 'model': model, 'refs': refs})}\n\n"
        try:
            for kind, content in finding_explain.stream_explain(
                prompt,
                model,
                system=vulnerability_insights.system_prompt(),
                max_tokens=vulnerability_insights.MAX_TOKENS,
            ):
                event = "thinking" if kind == "thinking" else "chunk"
                yield f"event: {event}\ndata: {json.dumps({'content': content})}\n\n"
            yield "event: done\ndata: {}\n\n"
        except Exception as exc:  # noqa: BLE001 — stream must not break the connection abruptly
            yield f"event: error\ndata: {json.dumps({'message': str(exc)})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.get("/{project_id}/ci-setup", response_model=CiSetupOut)
def get_ci_setup(
    project_id: str,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require("projects.view")),
):
    """Values a user copies into GitLab CI/CD variables for this project.
    The backend CI token is returned to admins only, and each reveal is audited."""
    project = _get_project_or_404(db, project_id, principal)

    api_url, source = resolve_public_api_url(request)

    is_admin = principal.kind == "user" and principal.role == "admin"
    if is_admin:
        audit_record(db, request, "ci.token_viewed", principal, target_type="project", target_id=project.id)

    scan_types = [t for t, on in (("sast", project.enable_sast), ("sca", project.enable_sca), ("sbom", project.enable_sbom)) if on]
    return CiSetupOut(
        project_id=project.id,
        project_name=project.name,
        repo_url=project.default_git_url,
        branch=project.default_branch,
        api_url=api_url,
        api_url_source=source,
        web_url=settings.public_app_url.rstrip("/"),
        token=settings.sast_api_token if is_admin else None,
        token_visible=is_admin,
        scan_types=scan_types or ["sast"],
    )

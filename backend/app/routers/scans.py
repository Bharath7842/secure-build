from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func
from sqlalchemy.orm import Session
import json
import re
import threading
from pathlib import Path

from app.auth import verify_bearer
from app.config import settings
from app.db import get_db
from app.dast.domain.curl import to_curl
from app.models import UNVERIFIED_VERDICT, DastRequestAudit, Finding, Project, Scan
from app.schemas import (
    DastRequestAuditEntryOut,
    DastAuthzMatrixOut,
    DastRequestAuditPageOut,
    DastScanFindingsOut,
    FindingOut,
    ScanCreate,
    ScanFindingsOut,
    ScanLogsOut,
    ScanOut,
    ScanResultsOut,
    ScanStatusOut,
    ScanTriggerOut,
)
from app.services import dast_narration, git_workspace, scan_log, scan_runner
from app.services import dast_settings
from app.services.dast_authz import build_authz_matrix
from app.services.dast_diff import build_diff
from app.services.dast_report import build_dast_report
from app.services.dast_summary import build_summary
from app.services.dast_findings_query import build_dast_findings
from app.services.dast_scan_setup import DastSetupError, prepare_dast_scan
from app.services.scan_export import build_excel_report, build_pdf_report, export_filenames, group_findings_by_issue
from app.services.scan_progress import infer_progress_from_lines

router = APIRouter(prefix="/scans", tags=["scans"])

# A paused scan is still in flight: its worker is waiting, and its rows must not be deleted.
_IN_PROGRESS = ("queued", "running", "paused")

# Scans in these statuses represent "already handled" work for a commit;
# a previous "failed" attempt is deliberately excluded so the same commit
# gets a fresh retry instead of being stuck behind a stale failure forever.
_REUSABLE_STATUSES = ("queued", "running", "success")

_LLM_FROM_LOG = re.compile(r"llm=([a-zA-Z0-9_-]+)/([^\s|]+)")


def _resolve_triggered_by(metadata: dict | None) -> str:
    """Classify who triggered the scan for history display (App vs Jenkins)."""
    meta = metadata or {}
    explicit = str(meta.get("source") or meta.get("triggered_by") or "").strip().lower()
    if explicit in ("jenkins", "app"):
        return explicit
    if explicit in ("ci", "github", "github-actions", "gitlab"):
        return "jenkins"
    if meta.get("jenkins_build") or meta.get("jenkins_url") or meta.get("BUILD_URL"):
        return "jenkins"
    if meta.get("pipeline") or meta.get("build_url") or meta.get("ci"):
        return "jenkins"
    if meta.get("github_run_id") or meta.get("github_run_url"):
        return "jenkins"
    return "app"


def _dast_display_model(routing: dict) -> tuple[str | None, str | None]:
    """The provider/model used most often across DAST tasks (usually they all match)."""
    counts: dict[tuple[str, str], int] = {}
    for pair in routing.values():
        if not pair:
            continue
        provider = str(pair[0])
        model = str(pair[1]) if len(pair) > 1 else ""
        counts[(provider, model)] = counts.get((provider, model), 0) + 1
    if not counts:
        return None, None
    (provider, model), _ = max(counts.items(), key=lambda item: item[1])
    return provider, model or None


def _get_scan_or_404(db: Session, scan_id: str) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan


def _backfill_llm_from_log(db: Session, scan: Scan) -> None:
    """If this scan has no LLM snapshot (created before those columns existed),
    try to recover it once from the durable engine log line:
      Project: ... | llm=<provider>/<model> | ...
    """
    dirty = False
    if not scan.triggered_by:
        scan.triggered_by = _resolve_triggered_by(scan.metadata_json)
        dirty = True
    # Scans that opted out of LLM intentionally leave provider/model null.
    if (scan.metadata_json or {}).get("use_llm") is False:
        if dirty:
            try:
                db.commit()
                db.refresh(scan)
            except Exception:  # noqa: BLE001
                db.rollback()
        return
    if scan.llm_provider and scan.llm_model:
        if dirty:
            try:
                db.commit()
                db.refresh(scan)
            except Exception:  # noqa: BLE001
                db.rollback()
        return
    lines, _ = scan_log.get_logs(scan.id, after=0)
    for row in lines:
        match = _LLM_FROM_LOG.search(row.get("line") or "")
        if not match:
            continue
        scan.llm_provider = match.group(1)
        scan.llm_model = match.group(2)
        dirty = True
        break
    if dirty:
        try:
            db.commit()
            db.refresh(scan)
        except Exception:  # noqa: BLE001 - listing must not fail on backfill
            db.rollback()


_VALID_SCAN_TYPES = ("sast", "sca", "sbom", "dast")


def _find_existing_scan(
    db: Session, project_id: str, commit_sha: str | None, scan_type: str = "sast"
) -> Scan | None:
    if not commit_sha:
        return None
    return (
        db.query(Scan)
        .filter(
            Scan.project_id == project_id,
            Scan.commit_sha == commit_sha,
            Scan.status.in_(_REUSABLE_STATUSES),
            Scan.scan_type == scan_type,
        )
        .order_by(Scan.created_at.desc())
        .first()
    )


@router.post("", status_code=status.HTTP_202_ACCEPTED, response_model=ScanTriggerOut)
def trigger_scan(
    payload: ScanCreate,
    db: Session = Depends(get_db),
    _: None = Depends(verify_bearer),
):
    project = db.get(Project, payload.project_id)
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    scan_type = (payload.scan_type or "sast").strip().lower()
    if scan_type not in _VALID_SCAN_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid scan_type '{scan_type}'; must be one of {_VALID_SCAN_TYPES}.",
        )
    if scan_type == "sca" and not project.enable_sca:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="SCA scanning is disabled for this project. Enable it in project settings first.",
        )
    if scan_type == "sbom" and not project.enable_sbom:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="SBOM scanning is disabled for this project. Enable it in project settings first.",
        )

    is_dast = scan_type == "dast"
    dast_input = payload.dast
    prepared = None
    if is_dast:
        if dast_input is None or not dast_input.target_url:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="DAST scans require a dast.target_url.",
            )
        if not dast_input.authorized:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Confirm you are authorized to test this target (dast.authorized).",
            )
        if dast_input.login_url and not (dast_input.username and dast_input.password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="A login URL needs both a username and a password.",
            )
        try:
            prepared = prepare_dast_scan(db, project, dast_input)
        except DastSetupError as exc:
            raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc

    # DAST has no repository: the Scan row's git_url column carries the target
    # URL so history lists show what was scanned.
    git_url = dast_input.target_url if is_dast else (payload.git_url or project.default_git_url)
    branch = payload.branch or project.default_branch
    commit_sha = None if is_dast else payload.commit_sha
    resolved_from_git = False

    # No explicit commit pinned by the caller (the normal "New Scan" button
    # flow): ask git what the latest commit on this branch actually is, so
    # "scan again" with no changes can be recognized as a no-op below instead
    # of always kicking off a brand-new full scan.
    if not commit_sha and not payload.force and not is_dast:
        commit_sha = git_workspace.resolve_remote_head(
            git_url, branch, project.git_provider, project.git_access_token
        )
        resolved_from_git = commit_sha is not None

    if not payload.force and not is_dast:
        existing = _find_existing_scan(db, payload.project_id, commit_sha, scan_type)
        if existing is not None:
            reused_reason = None
            if resolved_from_git:
                reused_reason = (
                    f"No changes since the last scan — {branch} is still at "
                    f"commit {commit_sha[:12]}."
                )
            return ScanTriggerOut(
                scan_id=existing.id,
                status=existing.status,
                status_url=f"/scans/{existing.id}/status",
                reused=True,
                reused_reason=reused_reason,
            )

    last_version = (
        db.query(func.max(Scan.version)).filter(Scan.project_id == project.id).scalar() or 0
    )
    # The SCA/SBOM engines (deterministic manifest parsing, no LLM) never
    # call an LLM — force this off regardless of what the payload sent so
    # Scan.llm_provider/model stay null instead of showing a value that was
    # never actually used.
    use_llm = bool(payload.use_llm) and scan_type not in ("sca", "sbom", "dast")
    if use_llm:
        llm_provider = payload.llm_provider or getattr(project, "llm_provider", None) or "bedrock"
        llm_model = (
            payload.llm_model
            or getattr(project, "llm_model", None)
            or "us.anthropic.claude-haiku-4-5-20251001-v1:0"
        )
        if (llm_provider or "").strip().lower() == "ollama":
            fallback_llm_provider = None
            fallback_llm_model = None
        else:
            fallback_llm_provider = (
                payload.fallback_llm_provider
                or getattr(project, "fallback_llm_provider", None)
                or "ollama"
            )
            fallback_llm_model = (
                payload.fallback_llm_model
                or getattr(project, "fallback_llm_model", None)
                or "granite-code:3b"
            )
    elif is_dast:
        # DAST does not use the SAST LLM path (`use_llm` stays false) but still
        # calls models through the gateway. Snapshot the routing so the scan
        # header can show which LLM ran.
        llm_provider, llm_model = _dast_display_model((prepared.effective if prepared else {}).get("model_routing") or {})
        fallback_llm_provider = None
        fallback_llm_model = None
    else:
        llm_provider = None
        llm_model = None
        fallback_llm_provider = None
        fallback_llm_model = None
    metadata = dict(payload.metadata or {})
    metadata["use_llm"] = use_llm
    if is_dast:
        # Non-secret record of the request plus the frozen effective settings, rule set and the
        # checks that cannot run as designed. Credentials are not in here: they go to
        # scan_runner's in-memory hand-over below.
        metadata.update(prepared.metadata(dast_settings.effective_settings(db).dast_effective_settings()))
    repo_path = (
        None
        if is_dast
        else (payload.repo_path or "").strip() or (project.monorepo_path or "").strip() or None
    )
    if repo_path:
        metadata["repo_path"] = repo_path
    scan = Scan(
        project_id=project.id,
        git_url=git_url,
        branch=branch,
        commit_sha=commit_sha,
        scan_type=scan_type,
        metadata_json=metadata,
        version=last_version + 1,
        llm_provider=llm_provider,
        llm_model=llm_model,
        fallback_llm_provider=fallback_llm_provider,
        fallback_llm_model=fallback_llm_model,
        triggered_by=_resolve_triggered_by(metadata),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    if is_dast and prepared.credentials:
        scan_runner.set_dast_credentials(scan.id, prepared.credentials)
    scan_runner.start_scan_background(scan.id)
    db.refresh(scan)

    return ScanTriggerOut(scan_id=scan.id, status=scan.status, status_url=f"/scans/{scan.id}/status")


@router.get("", response_model=list[ScanOut])
def list_scans(
    project_id: str | None = Query(default=None),
    scan_type: str | None = Query(default=None, description="Filter by sast|sca|sbom|dast"),
    db: Session = Depends(get_db),
    _: None = Depends(verify_bearer),
):
    query = db.query(Scan)
    if project_id:
        query = query.filter(Scan.project_id == project_id)
    if scan_type:
        query = query.filter(Scan.scan_type == scan_type)
    scans = query.order_by(Scan.created_at.desc()).all()
    for scan in scans:
        _backfill_llm_from_log(db, scan)
    _attach_dast_counts(db, scans)
    return scans


def _attach_dast_counts(db: Session, scans: list[Scan]) -> None:
    """One grouped query for every listed DAST scan: confirmed findings by severity and the unverified
    count (`ScanOut.dast_counts`). No per-scan requests from the page."""
    ids = [s.id for s in scans if (s.scan_type or "sast") == "dast"]
    if not ids:
        return
    base = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unverified": 0}
    counts = {i: dict(base) for i in ids}
    rows = (
        db.query(Finding.scan_id, Finding.severity, Finding.verdict, func.count())
        .filter(Finding.scan_id.in_(ids), Finding.kind == "dast")
        .group_by(Finding.scan_id, Finding.severity, Finding.verdict)
        .all()
    )
    for scan_id, severity, verdict, n in rows:
        if verdict == UNVERIFIED_VERDICT:
            counts[scan_id]["unverified"] += n
        elif verdict == "true_positive":
            key = (severity or "info").lower()
            counts[scan_id][key if key in base else "info"] += n
    for scan in scans:
        if scan.id in counts:
            scan._dast_counts = counts[scan.id]  # read by ScanOut


def _effective_progress(scan: Scan) -> int:
    """Use stored progress, or infer from live logs when the DB row is stale."""
    stored = int(scan.progress or 0)
    if scan.status not in _IN_PROGRESS:
        return stored
    lines, _ = scan_log.get_logs(scan.id, after=0)
    inferred = infer_progress_from_lines([row["line"] for row in lines], floor=max(stored, 10))
    return max(stored, inferred)


@router.get("/{scan_id}/status", response_model=ScanStatusOut)
def get_scan_status(
    scan_id: str,
    db: Session = Depends(get_db),
    _: None = Depends(verify_bearer),
):
    scan = _get_scan_or_404(db, scan_id)
    progress = _effective_progress(scan)
    if scan.status == "running" and progress > (scan.progress or 0):
        scan.progress = progress
        try:
            db.commit()
        except Exception:  # noqa: BLE001
            db.rollback()
    return ScanStatusOut(
        scan_id=scan.id,
        project_id=scan.project_id,
        status=scan.status,
        scan_type=scan.scan_type or "sast",
        progress=progress,
        message=scan.message,
    )


@router.get("/{scan_id}/logs", response_model=ScanLogsOut)
def get_scan_logs(
    scan_id: str,
    after: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _: None = Depends(verify_bearer),
):
    """Incremental live log tail: pass back `next_after` as `after` on the
    next poll to fetch only lines appended since the last call."""
    scan = _get_scan_or_404(db, scan_id)
    lines, next_after = scan_log.get_logs(scan_id, after)
    return ScanLogsOut(scan_id=scan.id, status=scan.status, lines=lines, next_after=next_after)


@router.get("/{scan_id}/results", response_model=ScanResultsOut)
def get_scan_results(
    scan_id: str,
    db: Session = Depends(get_db),
    _: None = Depends(verify_bearer),
):
    scan = _get_scan_or_404(db, scan_id)
    meta = scan.metadata_json or {}
    discovery = meta.get("discovery")

    # While still running, allow partial results once discovery has been
    # persisted (after Mapping module risk) so the UI can show Discovery
    # before CRITICAL-file scanning finishes.
    if scan.status in _IN_PROGRESS and not discovery:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan is still {scan.status}",
        )

    return ScanResultsOut(
        scan_id=scan.id,
        status=scan.status,
        discovery=discovery,
        usage_summary=meta.get("usage_summary"),
        dast_effective=meta.get("dast_effective"),
        dast_rule_set=meta.get("dast_rule_set"),
        dast_skipped_degraded=meta.get("dast_skipped_degraded"),
    )


@router.get("/{scan_id}/narration")
def get_dast_narration(
    scan_id: str,
    db: Session = Depends(get_db),
    _: None = Depends(verify_bearer),
):
    """Chat-style DAST timeline: per-step status, LLM narration and reasoning
    (template fallback when the model is unreachable). Poll while `pending`."""
    scan = _get_scan_or_404(db, scan_id)
    if (scan.scan_type or "sast") != "dast":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Narration is only available for DAST scans."
        )
    meta = dict(scan.metadata_json or {})
    lines, _next = scan_log.get_logs(scan_id, 0)
    payload = dast_narration.get_narration(
        scan_id=scan.id,
        scan_status=scan.status,
        log_lines=[entry["line"] for entry in lines],
        discovery=meta.get("discovery"),
        dast_input=dict(meta.get("dast_input") or {}),
        persisted=meta.get("dast_narration"),
    )
    if scan.status not in _IN_PROGRESS and not payload["pending"]:
        compact = dast_narration.persistable(payload)
        if compact and compact != meta.get("dast_narration"):
            meta["dast_narration"] = compact
            scan.metadata_json = meta
            db.commit()
    return payload


@router.get("/{scan_id}/findings", response_model=ScanFindingsOut | DastScanFindingsOut)
def get_scan_findings(
    scan_id: str,
    verdict: str | None = Query(
        default=None, description="Filter by true_positive|false_positive|unverified (DAST: comma separated)"
    ),
    severity: str | None = Query(default=None, description="DAST only: comma separated severities"),
    role: str | None = Query(default=None, description="DAST only: a role label, or owner:actor for a role pair"),
    check: str | None = Query(default=None, description="DAST only: comma separated check ids"),
    db: Session = Depends(get_db),
    _: None = Depends(verify_bearer),
):
    scan = _get_scan_or_404(db, scan_id)
    if (scan.scan_type or "sast") == "dast":
        # Unverified findings are returned unless the caller filters them out explicitly.
        return build_dast_findings(db, scan, severity=severity, verdict=verdict, role=role, check=check)
    query = db.query(Finding).filter(Finding.scan_id == scan.id)
    if verdict:
        query = query.filter(Finding.verdict == verdict)
    findings = query.order_by(Finding.file_path, Finding.line).all()
    all_findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    tp_count = sum(1 for f in all_findings if f.verdict == "true_positive")
    fp_count = sum(1 for f in all_findings if f.verdict == "false_positive")
    # Regex-only findings — counted separately so the confirmed total stays
    # meaningful and they don't disappear from the summary entirely.
    unverified_count = sum(1 for f in all_findings if f.verdict == UNVERIFIED_VERDICT)
    files_scanned = len({f.file_path for f in all_findings if f.file_path})
    grouped_findings = group_findings_by_issue(findings)
    return ScanFindingsOut(
        scan_id=scan.id,
        tp_count=tp_count,
        fp_count=fp_count,
        unverified_count=unverified_count,
        files_scanned=files_scanned,
        findings=[FindingOut.model_validate(f) for f in grouped_findings],
    )


@router.get("/{scan_id}/requests", response_model=DastRequestAuditPageOut)
def get_scan_request_audit(
    scan_id: str,
    after: int = Query(default=0, ge=0, description="Return rows with seq greater than this"),
    limit: int = Query(default=100, ge=1, le=500),
    allowed: bool | None = Query(default=None, description="true = sent, false = denied; omit for both"),
    db: Session = Depends(get_db),
    _: None = Depends(verify_bearer),
):
    """The scan's request audit log, ordered and paginated by sequence number."""
    scan = _get_scan_or_404(db, scan_id)
    query = db.query(DastRequestAudit).filter(DastRequestAudit.scan_id == scan.id, DastRequestAudit.seq > after)
    if allowed is not None:
        query = query.filter(DastRequestAudit.allowed == allowed)
    rows = query.order_by(DastRequestAudit.seq).limit(limit + 1).all()
    page, has_more = rows[:limit], len(rows) > limit
    entries = []
    for row in page:
        item = DastRequestAuditEntryOut.model_validate(row)
        item.curl = to_curl(row.method, row.url, row.request_headers or {}, row.request_body)
        entries.append(item)
    return DastRequestAuditPageOut(
        scan_id=scan.id,
        entries=entries,
        next_after=page[-1].seq if has_more else None,
    )


def _require_dast_scan(db: Session, scan_id: str, what: str) -> Scan:
    scan = _get_scan_or_404(db, scan_id)
    if (scan.scan_type or "sast") != "dast":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"{what} is only available for DAST scans.")
    return scan


@router.get("/{scan_id}/authz-matrix", response_model=DastAuthzMatrixOut)
def get_scan_authz_matrix(scan_id: str, db: Session = Depends(get_db), _: None = Depends(verify_bearer)):
    """The role-by-role authorization matrix, derived from the scan's replay summaries and findings
    (so it is available while the scan runs and cannot drift from the findings)."""
    return build_authz_matrix(db, _require_dast_scan(db, scan_id, "The authorization matrix"))


@router.get("/{scan_id}/diff")
def get_scan_diff(
    scan_id: str,
    against: str | None = Query(default=None, description="Compare with this earlier scan of the project instead of the previous one"),
    db: Session = Depends(get_db),
    _: None = Depends(verify_bearer),
):
    """New / still-open / fixed findings against the previous successful scan of the same target."""
    return build_diff(db, _require_dast_scan(db, scan_id, "The scan comparison"), against)


@router.get("/{scan_id}/summary")
def get_scan_summary(scan_id: str, db: Session = Depends(get_db), _: None = Depends(verify_bearer)):
    """Live counters for a DAST scan (pages, endpoints, requests, tests, findings by severity and verdict,
    skipped checks, model calls and cost). Cheap enough to poll every two seconds."""
    return build_summary(db, _require_dast_scan(db, scan_id, "The scan summary"))


@router.get("/{scan_id}/report")
def get_scan_report(
    scan_id: str,
    against: str | None = Query(default=None, description="Compare with this earlier scan instead of the previous one"),
    db: Session = Depends(get_db),
    _: None = Depends(verify_bearer),
):
    """The DAST report data: confirmed severity counts, unverified findings apart, evidence and remediation,
    rule packs, skipped/degraded checks and the comparison with the previous scan."""
    scan = _require_dast_scan(db, scan_id, "The DAST report")
    return build_dast_report(db, scan, db.get(Project, scan.project_id), against)


def _require_finished_scan(db: Session, scan_id: str) -> tuple[Scan, Project]:
    scan = _get_scan_or_404(db, scan_id)
    if scan.status in _IN_PROGRESS:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan is still {scan.status}",
        )
    project = db.get(Project, scan.project_id)
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    return scan, project


@router.get("/{scan_id}/export.pdf")
def export_scan_pdf(
    scan_id: str,
    db: Session = Depends(get_db),
    _: None = Depends(verify_bearer),
):
    scan, project = _require_finished_scan(db, scan_id)
    payload = build_pdf_report(project, scan, group_findings_by_issue(list(scan.findings or [])))
    filename = export_filenames(project, scan)["pdf"]
    return Response(
        content=payload,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{scan_id}/export.xlsx")
def export_scan_excel(
    scan_id: str,
    db: Session = Depends(get_db),
    _: None = Depends(verify_bearer),
):
    scan, project = _require_finished_scan(db, scan_id)
    payload = build_excel_report(project, scan, group_findings_by_issue(list(scan.findings or [])))
    filename = export_filenames(project, scan)["xlsx"]
    return Response(
        content=payload,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{scan_id}/export.sarif")
def export_scan_sarif(
    scan_id: str,
    db: Session = Depends(get_db),
    _: None = Depends(verify_bearer),
):
    from app.services.sarif_export import sarif_document

    scan, _project = _require_finished_scan(db, scan_id)
    payload = json.dumps(sarif_document(list(scan.findings or [])), indent=2).encode()
    return Response(
        content=payload,
        media_type="application/sarif+json",
        headers={"Content-Disposition": f'attachment; filename="{scan_id}.sarif.json"'},
    )


@router.get("/{scan_id}/export.junit")
def export_scan_junit(
    scan_id: str,
    db: Session = Depends(get_db),
    _: None = Depends(verify_bearer),
):
    from app.services.sarif_export import junit_xml

    scan, project = _require_finished_scan(db, scan_id)
    payload = junit_xml(list(scan.findings or []), name=project.name or scan_id).encode()
    return Response(
        content=payload,
        media_type="application/xml",
        headers={"Content-Disposition": f'attachment; filename="{scan_id}.junit.xml"'},
    )


class FindingTriageIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str | None = None
    assignee: str | None = None
    note: str | None = None


class ReplayIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    method: str = "GET"
    url: str
    headers: dict[str, str] = {}
    body: str | None = None


@router.patch("/{scan_id}/findings/{finding_id}", response_model=FindingOut)
def triage_finding(
    scan_id: str,
    finding_id: str,
    body: FindingTriageIn,
    db: Session = Depends(get_db),
    _: None = Depends(verify_bearer),
):
    from app.services.dast_triage import TriageError, apply_triage

    _get_scan_or_404(db, scan_id)
    finding = db.get(Finding, finding_id)
    if finding is None or finding.scan_id != scan_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    try:
        updated = apply_triage(db, finding, status=body.status, assignee=body.assignee, note=body.note)
    except TriageError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return FindingOut.model_validate(updated)


@router.post("/{scan_id}/pause", response_model=ScanStatusOut)
def pause_scan(scan_id: str, db: Session = Depends(get_db), _: None = Depends(verify_bearer)):
    scan = _get_scan_or_404(db, scan_id)
    if scan.status != "running":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Scan is {scan.status}, not running")
    scan_runner.request_pause(scan_id)
    scan.status = "paused"
    scan.message = "Paused"
    db.commit()
    scan_log.log(scan_id, "Pause requested from API.")
    return ScanStatusOut(scan_id=scan.id, project_id=scan.project_id, status=scan.status, progress=scan.progress, message=scan.message)


@router.post("/{scan_id}/resume", response_model=ScanStatusOut)
def resume_scan(scan_id: str, db: Session = Depends(get_db), _: None = Depends(verify_bearer)):
    scan = _get_scan_or_404(db, scan_id)
    if scan.status != "paused":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Scan is {scan.status}, not paused")
    scan.status = "running"
    scan.message = None
    db.commit()
    scan_runner.request_resume(scan_id)
    scan_log.log(scan_id, "Resumed from API.")
    return ScanStatusOut(scan_id=scan.id, project_id=scan.project_id, status=scan.status, progress=scan.progress, message=scan.message)


@router.post("/{scan_id}/replay")
def replay_request(scan_id: str, body: ReplayIn, db: Session = Depends(get_db), _: None = Depends(verify_bearer)):
    from app.services.dast_replay import ReplayError, replay

    scan = _require_dast_scan(db, scan_id, "Replay")
    if scan.status in _IN_PROGRESS:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Wait until the scan finishes before replaying a request")
    try:
        return replay(scan, method=body.method, url=body.url, headers=body.headers, body=body.body)
    except ReplayError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.get("/queue")
def scan_queue(db: Session = Depends(get_db), _: None = Depends(verify_bearer)):
    from app.services.dast_schedule import queue_view

    return queue_view(db)


_SCREENSHOT_FILENAME_RE = re.compile(r"\A(?:\d+|login)\.jpg\Z")


@router.get("/{scan_id}/screenshots/{filename}")
def get_dast_screenshot(
    scan_id: str,
    filename: str,
    db: Session = Depends(get_db),
    _: None = Depends(verify_bearer),
):
    """One screenshot (`dast_screenshots_dir/{scan_id}/{n|login}.jpg`), referenced from the log
    (`[screenshot: …]`) and `discovery.pages[].screenshot`. The strict filename pattern is the
    path-traversal guard — anything not `login.jpg` or `<digits>.jpg` is rejected before a `Path` join."""
    _get_scan_or_404(db, scan_id)
    if not _SCREENSHOT_FILENAME_RE.match(filename):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    path = Path(settings.dast_screenshots_dir) / scan_id / filename
    if not path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return Response(content=path.read_bytes(), media_type="image/jpeg")


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    _: None = Depends(verify_bearer),
):
    """Remove a scan and its findings. Rejects while the scan is still running."""
    scan = _get_scan_or_404(db, scan_id)
    if scan.status in _IN_PROGRESS:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot delete a scan that is still {scan.status}. Stop it first.",
        )
    db.query(Finding).filter(Finding.scan_id == scan.id).delete(synchronize_session=False)
    db.delete(scan)
    db.commit()
    return None


@router.post("/{scan_id}/cancel", response_model=ScanStatusOut)
def cancel_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    _: None = Depends(verify_bearer),
):
    """Stop a queued or running scan. Marks it cancelled so it can be deleted."""
    scan = _get_scan_or_404(db, scan_id)
    if scan.status not in _IN_PROGRESS and (scan.scan_type or "sast") == "dast":
        # Cancelling a DAST scan that already ended is a harmless no-op, not an error: a second
        # click, or a cancel that raced the scan's own completion, must not look like a failure.
        return ScanStatusOut(
            scan_id=scan.id, project_id=scan.project_id, status=scan.status, scan_type="dast",
            progress=scan.progress, message=f"Nothing to cancel: the scan is already {scan.status}.",
        )
    if scan.status not in _IN_PROGRESS:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan is already {scan.status}",
        )
    scan_runner.request_cancel(scan_id)
    scan.status = "cancelled"
    scan.progress = 100
    scan.message = "Cancelled by user"
    db.commit()
    scan_runner.sync_findings_report_to_metadata(db, scan_id)
    scan_log.log(scan_id, "Cancellation requested from API.")
    # Fire-and-forget: sweep any findings left `unverified` by the abort,
    # capped since a mid-run cancellation can leave a much larger backlog
    # than a normal end-of-scan residual. Runs off the request thread so
    # "Stop scan" keeps returning immediately.
    threading.Thread(
        target=scan_runner.reconcile_unverified_findings,
        args=(scan_id,),
        kwargs={"capped": True},
        daemon=True,
    ).start()
    return ScanStatusOut(
        scan_id=scan.id,
        project_id=scan.project_id,
        status=scan.status,
        progress=scan.progress,
        message=scan.message,
    )


@router.get("/{scan_id}/narration/stream")
def stream_dast_narration(
    scan_id: str,
    step: str = Query(..., description="Step ID: connection|auth|discovery|analysis"),
    db: Session = Depends(get_db),
    _: None = Depends(verify_bearer),
):
    """Stream thinking + narration for a specific step as Server-Sent Events.
    The frontend opens this stream while the step is running or narration is pending."""
    from fastapi.responses import StreamingResponse

    scan = _get_scan_or_404(db, scan_id)
    if (scan.scan_type or "sast") != "dast":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Narration is only available for DAST scans.")
    
    meta = dict(scan.metadata_json or {})
    lines, _ = scan_log.get_logs(scan_id, 0)
    preamble, evidence_by_step, _ = dast_narration._split_log([entry["line"] for entry in lines])
    evidence = evidence_by_step.get(step, [])
    
    discovery = meta.get("discovery")
    dast_input = dict(meta.get("dast_input") or {})
    title = next((t for sid, t, _ in dast_narration._STEP_DEFS if sid == step), "Step")
    
    def event_generator():
        # The model is asked to respond with strict JSON (`{"narration": ...,
        # "reasoning": [...]}`), so its raw `content` tokens are JSON syntax
        # and, until the closing quote arrives, a truncated string — showing
        # that verbatim as it streams would put things like `{"narration":
        # "We need to classify...` or a mid-string cutoff on screen. Thinking
        # tokens are genuinely free-form reasoning and stream live as-is;
        # response tokens are buffered and only ever shown once fully parsed.
        response_parts: list[str] = []
        try:
            prompt = dast_narration._build_prompt(title, evidence, discovery, step)
            for token_type, content in dast_narration.stream_llm(prompt):
                if token_type == "thinking":
                    yield f"event: thinking\ndata: {json.dumps({'content': content})}\n\n"
                elif token_type == "response":
                    response_parts.append(content)
                elif token_type == "error":
                    yield f"event: error\ndata: {json.dumps({'message': content})}\n\n"
                    return
                elif token_type == "done":
                    break

            parsed = dast_narration.parse_narration_response("".join(response_parts))
            if parsed is None:
                yield f"event: error\ndata: {json.dumps({'message': 'Could not parse a narration from the model response'})}\n\n"
                return
            yield f"event: response\ndata: {json.dumps({'content': parsed['narration']})}\n\n"
            yield "event: done\ndata: {}\n\n"
        except Exception as e:
            yield f"event: error\ndata: {json.dumps({'message': str(e)})}\n\n"
    
    return StreamingResponse(event_generator(), media_type="text/event-stream")

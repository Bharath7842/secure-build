"""Reviewer feedback on SAST findings: decisions, history, the review list and the learning export."""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from app.auth.principal import Principal, require
from app.authz.scope import authorize_scan, can_see_scan, scope_scans
from app.db import get_db
from app.models import Finding, FindingReview, Scan
from app.schemas import FeedbackListOut, FeedbackRowOut, LearningActionIn, LearningActionOut, ReviewIn
from app.services import feedback as svc

router = APIRouter(tags=["feedback"])


def _http(exc: svc.ReviewError) -> HTTPException:
    return HTTPException(status_code=exc.status, detail=str(exc))


def _sast_scan_and_finding(db: Session, scan_id: str, finding_id: str, principal: Principal) -> tuple[Scan, Finding]:
    scan = authorize_scan(db, principal, scan_id)
    if (scan.scan_type or "sast") != "sast":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Reviewer feedback is for SAST scans.")
    finding = db.get(Finding, finding_id)
    if finding is None or finding.scan_id != scan_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return scan, finding


@router.post("/scans/{scan_id}/findings/{finding_id}/review", response_model=FeedbackRowOut)
def submit_review(
    scan_id: str,
    finding_id: str,
    body: ReviewIn,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require("findings.review")),
):
    scan, finding = _sast_scan_and_finding(db, scan_id, finding_id, principal)
    try:
        review = svc.submit_review(
            db, scan, finding, decision=body.decision, reviewer=principal.label,
            comment=body.comment, resolution_notes=body.resolution_notes,
            apply_to=body.apply_to, member_ids=body.member_ids,
        )
    except svc.ReviewError as exc:
        raise _http(exc) from exc
    return svc.review_out(review)


@router.get("/scans/{scan_id}/findings/{finding_id}/review", response_model=FeedbackRowOut)
def get_review(
    scan_id: str,
    finding_id: str,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require("findings.review")),
):
    _sast_scan_and_finding(db, scan_id, finding_id, principal)
    review = svc.find_review(db, scan_id, finding_id)
    if review is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="This finding has not been reviewed")
    return svc.review_out(review)


@router.get("/feedback", response_model=FeedbackListOut)
def list_feedback(
    project_id: str | None = None,
    scan_id: str | None = Query(default=None, description="Omit to list reviewed items across scans"),
    reviewer_verdict: str | None = None,
    llm_verdict: str | None = None,
    override: bool | None = None,
    severity: str | None = None,
    rule_id: str | None = None,
    cwe: str | None = None,
    reviewer: str | None = None,
    review_status: str | None = Query(default=None, pattern="^(unreviewed|needs_info|reviewed)$"),
    resolution_status: str | None = Query(default=None, pattern="^(open|resolved|risk_accepted)$"),
    issue_status: str | None = None,
    closed: bool | None = None,
    learning_status: str | None = Query(default=None, pattern="^(pending_learning|approved_for_learning|processed)$"),
    reviewed_from: str | None = Query(default=None, description="YYYY-MM-DD or ISO timestamp"),
    reviewed_to: str | None = Query(default=None, description="YYYY-MM-DD (inclusive) or ISO timestamp"),
    q: str | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require("findings.review")),
):
    filters = {
        "reviewer_verdict": reviewer_verdict, "llm_verdict": llm_verdict, "override": override,
        "severity": severity, "rule_id": rule_id, "cwe": cwe, "reviewer": reviewer,
        "review_status": review_status, "resolution_status": resolution_status,
        "issue_status": issue_status, "closed": closed, "learning_status": learning_status,
        "reviewed_from": reviewed_from, "reviewed_to": reviewed_to, "q": q,
    }
    if scan_id:
        authorize_scan(db, principal, scan_id)
    visible = None if principal.can("scans.view_all") else [s.id for s in scope_scans(db.query(Scan), principal)]
    try:
        return svc.list_feedback(db, scan_id=scan_id, project_id=project_id, filters=filters,
                                 limit=limit, offset=offset, visible_scan_ids=visible)
    except svc.ReviewError as exc:
        raise _http(exc) from exc


@router.post("/feedback/learning/approve", response_model=LearningActionOut)
def approve_for_learning(body: LearningActionIn, db: Session = Depends(get_db), principal: Principal = Depends(require("feedback.manage"))):
    try:
        return svc.approve_for_learning(db, body.review_ids, principal.label)
    except svc.ReviewError as exc:
        raise _http(exc) from exc


@router.post("/feedback/learning/mark-processed", response_model=LearningActionOut)
def mark_processed(body: LearningActionIn, db: Session = Depends(get_db), principal: Principal = Depends(require("feedback.manage"))):
    try:
        return svc.mark_processed(db, body.review_ids, principal.label)
    except svc.ReviewError as exc:
        raise _http(exc) from exc


@router.get("/feedback/export")
def export_feedback(
    format: str = Query(default="jsonl", pattern="^(jsonl|csv)$"),
    learning_status: str | None = Query(default=None, pattern="^(pending_learning|approved_for_learning|processed)$"),
    project_id: str | None = None,
    mark_processed: bool = Query(default=False, description="Move exported approved items to 'processed'"),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require("feedback.manage")),
):
    """Labelled data for the learning phase. Nothing changes state unless `mark_processed` is set."""
    records = svc.export_records(db, learning_status=learning_status, project_id=project_id)
    body, media_type = svc.render_export(records, format)
    if mark_processed:
        approved = [r["review_id"] for r in records if r["learning_status"] == svc.LEARNING_APPROVED]
        if approved:
            svc.mark_processed(db, approved, principal.label)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return Response(
        content=body,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="sast-feedback-{stamp}.{format}"'},
    )


@router.get("/feedback/{review_id}", response_model=FeedbackRowOut)
def get_feedback(review_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require("findings.review"))):
    review = db.get(FindingReview, review_id)
    # Reviews outlive their scan; once it's deleted, only view_all can see them.
    scan = db.get(Scan, review.scan_id) if review else None
    visible = principal.can("scans.view_all") if scan is None else can_see_scan(principal, scan)
    if review is None or not visible:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Review not found")
    return svc.review_out(review)

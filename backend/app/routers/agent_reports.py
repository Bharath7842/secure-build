"""Inbox for Claude / Codex schedulers: a summary and a priority list, not a full scan report.

    POST /agent-reports              push a summary + ordered items
    GET  /agent-reports              list
    GET  /agent-reports/{id}         one
    GET  /agent-reports/skill        SKILL.md for the scheduler

Netra shows the list as posted. Existing scan, findings and vulnerability-report
routes are untouched.
"""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app.auth.principal import Principal, require
from app.authz.scope import can_see_project
from app.config import settings
from app.db import get_db
from app.models import AgentReport, Project
from app.routers.projects import resolve_public_api_url

router = APIRouter(prefix="/agent-reports", tags=["agent-reports"])

_MAX_ITEMS = 50
_SKILL = """\
# Netra inbox — push a priority list

Claude Code or Codex, on a schedule: read this project's issue list, write a
short summary, and POST that summary plus the ordered items. Do **not** upload
the full vulnerability report.

## Setup

```bash
export SAST_API_TOKEN="<token>"
export SAST_API_URL="{{API_URL}}"
export SAST_PROJECT_ID="{{PROJECT_ID}}"
AUTH="Authorization: Bearer ${SAST_API_TOKEN:?set SAST_API_TOKEN first}"
```

## 1. Read the current priority issues (existing API, unchanged)

```bash
curl -sS -H "$AUTH" "$SAST_API_URL/projects/$SAST_PROJECT_ID/issues?limit=10"
```

## 2. Push a summary + ordered list (this API)

`context` is optional notes from you. `items` keep the order you chose.

```bash
curl -sS -H "$AUTH" -H "Content-Type: application/json" \\
  -X POST "$SAST_API_URL/agent-reports" \\
  -d '{
    "source": "claude",
    "project_id": "'"$SAST_PROJECT_ID"'",
    "summary": "Fix the confirmed SQL injection in Dao first; then the overdue XSS.",
    "context": "Optional notes. Not the full report.",
    "items": [
      {"short_id": "SB-XXXXXXXX", "title": "SQL injection", "severity": "HIGH", "reason": "Confirmed, reachable"},
      {"short_id": "SB-YYYYYYYY", "title": "Reflected XSS", "severity": "MEDIUM", "reason": "Overdue"}
    ]
  }'
```

Netra shows the summary and the list in the order you sent.
"""


class AgentPriorityItem(BaseModel):
    short_id: str | None = Field(default=None, max_length=20)
    title: str = Field(min_length=1, max_length=500)
    severity: str | None = Field(default=None, max_length=20)
    reason: str | None = Field(default=None, max_length=2000)
    file_path: str | None = Field(default=None, max_length=500)
    rank: int | None = Field(default=None, ge=1, le=_MAX_ITEMS)


class AgentReportIn(BaseModel):
    source: Literal["claude", "codex", "scheduler", "other"] = "claude"
    project_id: str | None = Field(default=None, max_length=36)
    title: str | None = Field(default=None, max_length=500)
    summary: str = Field(min_length=1, max_length=8000)
    context: str = Field(default="", max_length=8000)
    items: list[AgentPriorityItem] = Field(min_length=1, max_length=_MAX_ITEMS)

    @field_validator("summary", "context", "title", mode="before")
    @classmethod
    def _strip(cls, value: Any) -> Any:
        if isinstance(value, str):
            return value.strip()
        return value


class AgentPriorityItemOut(BaseModel):
    rank: int
    short_id: str | None = None
    title: str
    severity: str | None = None
    reason: str | None = None
    file_path: str | None = None


class AgentReportSummaryOut(BaseModel):
    id: str
    source: str
    title: str
    project_id: str | None
    actor_label: str
    created_at: Any
    summary: str
    item_count: int


class AgentReportOut(AgentReportSummaryOut):
    context: str
    items: list[AgentPriorityItemOut]


def _items_payload(items: list[AgentPriorityItem]) -> list[dict[str, Any]]:
    """Keep POST order so Netra can show the list as the agent ranked it."""
    return [
        {
            "rank": i,
            "short_id": item.short_id,
            "title": item.title,
            "severity": item.severity,
            "reason": item.reason,
            "file_path": item.file_path,
        }
        for i, item in enumerate(items, start=1)
    ]


def _title(body: AgentReportIn) -> str:
    if body.title:
        return body.title
    first = body.summary.split(". ", 1)[0].strip()
    return (first[:120] + "…") if len(first) > 120 else first or "Priority list"


def _project_or_none(db: Session, principal: Principal, project_id: str | None) -> str | None:
    if not project_id:
        return None
    project = db.get(Project, project_id)
    if project is None or not can_see_project(principal, project):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    return project.id


def _visible(db: Session, principal: Principal):
    q = db.query(AgentReport)
    if principal.kind == "service" or principal.can("scans.view_all"):
        return q
    owned = db.query(Project.id).filter(Project.created_by_user_id == principal.user_id)
    return q.filter(
        (AgentReport.created_by_user_id == principal.user_id) | (AgentReport.project_id.in_(owned))
    )


def _get_or_404(db: Session, principal: Principal, report_id: str) -> AgentReport:
    row = _visible(db, principal).filter(AgentReport.id == report_id).first()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    return row


def _items_out(row: AgentReport) -> list[AgentPriorityItemOut]:
    raw = (row.report_json or {}).get("items") or []
    items = []
    for i, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            continue
        items.append(
            AgentPriorityItemOut(
                rank=int(item.get("rank") or i),
                short_id=item.get("short_id"),
                title=str(item.get("title") or "Untitled"),
                severity=item.get("severity"),
                reason=item.get("reason"),
                file_path=item.get("file_path"),
            )
        )
    return items


def _summary_out(row: AgentReport) -> AgentReportSummaryOut:
    payload = row.report_json or {}
    return AgentReportSummaryOut(
        id=row.id,
        source=row.source,
        title=row.title,
        project_id=row.project_id,
        actor_label=row.actor_label,
        created_at=row.created_at,
        summary=str(payload.get("summary") or ""),
        item_count=len(_items_out(row)),
    )


def _full_out(row: AgentReport) -> AgentReportOut:
    base = _summary_out(row)
    return AgentReportOut(
        **base.model_dump(),
        context=row.context or "",
        items=_items_out(row),
    )


@router.get("/skill", response_class=PlainTextResponse)
def agent_report_skill(
    request: Request,
    project_id: str | None = Query(default=None),
    principal: Principal = Depends(require("projects.view")),
):
    """Markdown instructions for Claude / Codex. Project id is filled in when given."""
    api, _source = resolve_public_api_url(request)
    base = (api or settings.public_app_url or "http://localhost:8000").rstrip("/")
    text = _SKILL.replace("{{API_URL}}", base)
    text = text.replace("{{PROJECT_ID}}", project_id or "<project-id>")
    return PlainTextResponse(text, media_type="text/markdown; charset=utf-8")


@router.post("", response_model=AgentReportOut, status_code=status.HTTP_201_CREATED)
def create_agent_report(
    body: AgentReportIn,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require("scans.create")),
):
    project_id = _project_or_none(db, principal, body.project_id)
    items = _items_payload(body.items)
    row = AgentReport(
        project_id=project_id,
        created_by_user_id=principal.user_id,
        source=body.source,
        title=_title(body),
        context=body.context,
        report_json={"summary": body.summary, "items": items},
        actor_label=principal.label,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return _full_out(row)


@router.get("", response_model=list[AgentReportSummaryOut])
def list_agent_reports(
    project_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require("scans.view_own")),
):
    q = _visible(db, principal).order_by(AgentReport.created_at.desc())
    if project_id:
        q = q.filter(AgentReport.project_id == project_id)
    return [_summary_out(row) for row in q.limit(limit).all()]


@router.get("/{report_id}", response_model=AgentReportOut)
def get_agent_report(
    report_id: str,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require("scans.view_own")),
):
    return _full_out(_get_or_404(db, principal, report_id))

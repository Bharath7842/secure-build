"""Streamed per-finding explanations via local Ollama (Explain with AI drawer)."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Iterator, Literal

from sqlalchemy.orm import Session

from app.config import settings
from app.models import Finding, FindingReview, Project, Scan
from app.services import secret_masking
from app.services.model_gateway import ollama_reasoning
from app.services.model_gateway.adapters import OllamaAdapter
from app.services.occurrence import short_id
from app.services.ollama_check import ollama_model_error

_PROMPT_DIR = Path(__file__).resolve().parent.parent / "data" / "prompts"
_PROMPT_PATH = _PROMPT_DIR / "sast_finding_explain.md"
_JIRA_PROMPT_PATH = _PROMPT_DIR / "jira_issue.md"
_FOLLOW_UP_CONTEXT_CHARS = 2500
_FILE_SLICE_MAX_BYTES = 12_000

ExplainPurpose = Literal["explain", "jira"]


def system_prompt(purpose: ExplainPurpose = "explain") -> str:
    path = _JIRA_PROMPT_PATH if purpose == "jira" else _PROMPT_PATH
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        if purpose == "jira":
            return (
                "Write a Jira ticket from the supplied finding. Use markdown headings "
                "Summary, Issue type, Priority, Labels, Description. Invent nothing."
            )
        return (
            "You are a senior application security engineer. Explain the supplied SAST finding "
            "with sections Issue, Why it matters, and Remediation, using only the provided context."
        )


def _json_block(label: str, data: Any) -> str:
    text = json.dumps(data, indent=2, default=str, ensure_ascii=False)
    return f"{label}:\n{secret_masking.mask_text(text)}\n"


def _safe_workspace_file(workspace: Path, rel_path: str) -> Path | None:
    if not rel_path or not rel_path.strip():
        return None
    rel = Path(rel_path.strip())
    if rel.is_absolute() or ".." in rel.parts:
        return None
    root = workspace.resolve()
    candidate = (root / rel).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    if not candidate.is_file():
        return None
    return candidate


def _file_window(path: Path, line: int | None, half: int) -> str | None:
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    if len(raw.encode("utf-8")) > _FILE_SLICE_MAX_BYTES:
        raw = raw[:_FILE_SLICE_MAX_BYTES]
    lines = raw.splitlines()
    if not lines:
        return None
    anchor = max(1, line or 1)
    start = max(1, anchor - half)
    end = min(len(lines), anchor + half)
    rows = []
    for num in range(start, end + 1):
        rows.append(f"{num:5d}| {lines[num - 1]}")
    body = "\n".join(rows)
    return secret_masking.mask_text(f"File: {path.name} (lines {start}-{end}, anchor {anchor})\n{body}")


def _discovery_slice(scan: Scan) -> dict[str, Any]:
    discovery = (scan.metadata_json or {}).get("discovery") or {}
    llm = discovery.get("llm_analysis") or {}
    top = {
        k: discovery.get(k)
        for k in ("tech_stack", "project_type", "languages", "frameworks")
        if discovery.get(k)
    }
    if top:
        return top
    return {k: v for k, v in {"tech_stack": llm.get("tech_stack"), "confidence": llm.get("confidence")}.items() if v}


def _finding_fields(finding: Finding, review: FindingReview | None) -> dict[str, Any]:
    data: dict[str, Any] = {
        "title": finding.title,
        "rule_id": finding.rule_id,
        "cwe": finding.cwe,
        "severity": finding.severity,
        "cvss": finding.cvss,
        "cvss_vector": finding.cvss_vector,
        "issue_class": finding.issue_class,
        "verdict": finding.verdict,
        "confidence": finding.confidence,
        "verdict_reason": finding.verdict_reason,
        "unresolved_reason": finding.unresolved_reason,
        "ai_fix": finding.ai_fix,
        "file_path": finding.file_path,
        "line": finding.line,
        "snippet": finding.snippet,
        "matched_text": finding.matched_text,
        "source": finding.source,
        "sink": finding.sink,
        "data_flow": finding.data_flow,
        "reachability": finding.reachability,
        "flow_path": finding.flow_path,
        "affected_files": finding.affected_files,
        "facts": finding.facts,
        "occurrence_id": finding.occurrence_id,
        "short_id": short_id(finding.occurrence_id),
    }
    if review is not None:
        data["review"] = {
            "reviewer_verdict": review.reviewer_verdict,
            "reviewer_comment": review.reviewer_comment,
            "issue_status": review.issue_status,
        }
    return {k: v for k, v in data.items() if v is not None and v != "" and v != []}


def build_finding_context(
    db: Session,
    scan: Scan,
    finding: Finding,
    project: Project,
    *,
    compact: bool = False,
) -> str:
    review = (
        db.query(FindingReview)
        .filter(FindingReview.scan_id == scan.id, FindingReview.finding_id == finding.id)
        .order_by(FindingReview.updated_at.desc())
        .first()
    )
    parts = [_json_block("finding", _finding_fields(finding, review))]
    discovery = _discovery_slice(scan)
    if discovery:
        parts.append(_json_block("project_stack", discovery))
    if not compact:
        workspace = Path(settings.workspaces_dir) / project.id
        if workspace.is_dir():
            hit = _safe_workspace_file(workspace, finding.file_path or "")
            if hit is not None:
                window = _file_window(hit, finding.line, settings.sast_explain_file_window_lines)
                if window:
                    parts.append("source_excerpt:\n" + window)
    text = "\n".join(parts).strip()
    cap = _FOLLOW_UP_CONTEXT_CHARS if compact else settings.sast_explain_max_context_chars
    if len(text) > cap:
        text = text[: cap - 40] + "\n…(context truncated)\n"
    return text


def _format_messages(messages: list[dict[str, str]]) -> str:
    lines: list[str] = []
    for msg in messages:
        role = (msg.get("role") or "").strip().lower()
        content = secret_masking.mask_text((msg.get("content") or "").strip())
        if role not in ("user", "assistant") or not content:
            continue
        label = "Developer" if role == "user" else "Assistant"
        lines.append(f"{label}: {content}")
    return "\n\n".join(lines)


def build_user_prompt(
    db: Session,
    scan: Scan,
    finding: Finding,
    project: Project,
    messages: list[dict[str, str]],
    purpose: ExplainPurpose = "explain",
) -> str:
    has_prior = any((m.get("role") or "").lower() == "assistant" for m in messages)
    context = build_finding_context(db, scan, finding, project, compact=has_prior)
    if not has_prior:
        if purpose == "jira":
            return (
                f"{context}\n\n"
                "Write a Jira ticket for this finding using the required headings."
            )
        return (
            f"{context}\n\n"
            "Explain this security finding to the developer: what is wrong, why it matters, "
            "and complete remediation steps."
        )
    transcript = _format_messages(messages[:-1]) if len(messages) > 1 else ""
    last = messages[-1] if messages else {}
    question = secret_masking.mask_text((last.get("content") or "").strip())
    chunks = [f"Finding context (summary):\n{context}"]
    if transcript:
        chunks.append(f"Conversation so far:\n{transcript}")
    chunks.append(f"Developer follow-up:\n{question}")
    return "\n\n".join(chunks)


def merge_explain_models(pulled: list[str]) -> list[str]:
    """Offered Netra chat models first (even if not pulled yet), then the rest of what Ollama has."""
    offered = [m.strip() for m in settings.sast_explain_offered_models if m and m.strip()]
    tail = [m for m in pulled if m not in offered]
    return offered + tail


def list_models(timeout: float = 3.0) -> tuple[list[str], str | None]:
    """Model names pulled on the local Ollama server, or ([], why) when it can't be reached."""
    url = f"{settings.ollama_base_url.rstrip('/')}/api/tags"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            tags = json.load(resp)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return [], f"Ollama is not reachable at {settings.ollama_base_url} ({exc})"
    names = sorted({str(m.get("name") or m.get("model")) for m in tags.get("models", []) if m.get("name") or m.get("model")})
    return merge_explain_models(names), None


def explain_models_payload() -> dict[str, Any]:
    models, error = list_models()
    return {
        "default_model": settings.sast_explain_ollama_model,
        "models": models,
        "no_think": [m for m in models if not ollama_reasoning(m)],
        "error": error,
    }


def resolve_model(requested: str | None) -> str:
    return (requested or "").strip() or settings.sast_explain_ollama_model


def preflight_error(model: str | None = None) -> str | None:
    return ollama_model_error(settings.ollama_base_url, resolve_model(model))


def _adapter(model: str) -> OllamaAdapter:
    return OllamaAdapter(
        settings.ollama_base_url,
        model,
        timeout_s=settings.sast_explain_timeout_s,
        num_ctx=settings.dast_ollama_num_ctx,
        reasoning=ollama_reasoning(model, settings),
    )


class _ThinkTagSplitter:
    """Moves `<think>…</think>` text that a model writes into its answer over to the thinking
    channel. Holds back a partial tag at a chunk boundary until the next chunk completes it."""

    _OPEN, _CLOSE = "<think>", "</think>"

    def __init__(self) -> None:
        self._in_think = False
        self._pending = ""

    def feed(self, text: str) -> Iterator[tuple[Literal["thinking", "response"], str]]:
        buf = self._pending + text
        self._pending = ""
        while buf:
            tag = self._CLOSE if self._in_think else self._OPEN
            kind: Literal["thinking", "response"] = "thinking" if self._in_think else "response"
            idx = buf.find(tag)
            if idx >= 0:
                if idx:
                    yield kind, buf[:idx]
                buf = buf[idx + len(tag):]
                self._in_think = not self._in_think
                continue
            keep = next((n for n in range(len(tag) - 1, 0, -1) if buf.endswith(tag[:n])), 0)
            if keep:
                self._pending = buf[-keep:]
                buf = buf[:-keep]
            if buf:
                yield kind, buf
            break

    def flush(self) -> Iterator[tuple[Literal["thinking", "response"], str]]:
        if self._pending:
            yield ("thinking" if self._in_think else "response"), self._pending
            self._pending = ""


def stream_explain(
    user_prompt: str,
    model: str | None = None,
    *,
    system: str | None = None,
    max_tokens: int | None = None,
) -> Iterator[tuple[Literal["thinking", "response"], str]]:
    adapter = _adapter(resolve_model(model))
    splitter = _ThinkTagSplitter()
    for kind, text, _chunk in adapter.stream(
        system or system_prompt(),
        user_prompt,
        max_tokens=max_tokens or settings.sast_explain_max_tokens,
        temperature=0.2,
    ):
        if not text:
            continue
        if kind == "thinking":
            if adapter.reasoning:
                yield kind, text
            continue
        for sk, st in splitter.feed(text):
            if sk == "thinking" and not adapter.reasoning:
                continue
            yield sk, st
    for sk, st in splitter.flush():
        if sk == "thinking" and not adapter.reasoning:
            continue
        yield sk, st
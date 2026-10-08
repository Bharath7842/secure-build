"""Rebuild the proving HTTP request for a DAST finding from the audit log and the stored row.

Bodies are never stored on the audit log; the injected value is recovered from the finding snippet
(`Input:` / `Payload:`). When the audit row is missing (older scans, grouped representatives without
a seq), method and URL fall back to the finding's `target` / `sink`.
"""

from __future__ import annotations

from typing import Any, Iterable

from sqlalchemy.orm import Session

from app.models import DastRequestAudit, Finding

_PAYLOAD_PREFIXES = ("Input: ", "Payload: ")


def split_target(target: str | None) -> tuple[str, str]:
    parts = (target or "").split(None, 1)
    if len(parts) == 2 and parts[0].isalpha() and 2 <= len(parts[0]) <= 10:
        return parts[0].upper(), parts[1]
    return "", target or ""


def payload_from_snippet(snippet: str | None) -> str:
    for line in (snippet or "").splitlines():
        for prefix in _PAYLOAD_PREFIXES:
            if line.startswith(prefix):
                return line[len(prefix):].strip()
    return ""


def seq_from_ref(audit_ref: str | None) -> int | None:
    try:
        return int(str(audit_ref).strip())
    except (TypeError, ValueError):
        return None


def audits_by_seq(db: Session, scan_id: str, refs: Iterable[str | None]) -> dict[int, DastRequestAudit]:
    numbers = [n for n in (seq_from_ref(r) for r in refs) if n is not None]
    if not numbers:
        return {}
    rows = (
        db.query(DastRequestAudit)
        .filter(DastRequestAudit.scan_id == scan_id, DastRequestAudit.seq.in_(numbers))
        .all()
    )
    return {row.seq: row for row in rows}


def traffic_for(finding: Finding, *, audit: DastRequestAudit | None = None, audit_ref: str | None = None) -> dict[str, Any]:
    """A JSON-ready view of what was sent. Safe to put on the findings API and the report."""
    method, path = split_target(finding.target or finding.file_path)
    seq = audit.seq if audit is not None else seq_from_ref(audit_ref)
    return {
        "method": ((audit.method if audit is not None else "") or method),
        "url": ((audit.url if audit is not None else "") or (finding.sink or "") or path),
        "parameter": finding.param,
        "location": finding.location,
        "payload": payload_from_snippet(finding.snippet),
        "identity_label": audit.identity_label if audit is not None else None,
        "headers": dict(audit.request_headers) if audit is not None and audit.request_headers else None,
        "allowed": audit.allowed if audit is not None else None,
        "deny_reason": audit.deny_reason if audit is not None else None,
        "seq": seq,
        "response_status": audit.response_status if audit is not None else None,
        "response_headers": dict(audit.response_headers) if audit is not None and audit.response_headers else None,
    }


def format_request(traffic: dict[str, Any] | None, *, fallback_target: str = "") -> str:
    """Plain-text request block for the PDF and Excel."""
    req = traffic or {}
    method = (req.get("method") or "").strip()
    url = (req.get("url") or "").strip() or fallback_target
    lines: list[str] = []
    if method and url:
        lines.append(f"{method} {url}")
    elif url:
        lines.append(url)
    if req.get("identity_label"):
        lines.append(f"Identity: {req['identity_label']}")
    if req.get("allowed") is False:
        lines.append(f"Not sent: {req.get('deny_reason') or 'denied'}")
    param = req.get("parameter")
    location = req.get("location")
    if param:
        lines.append(f"Parameter: {param}" + (f" ({location})" if location else ""))
    payload = (req.get("payload") or "").strip()
    if payload:
        lines.append(f"Value sent: {payload}")
    headers = req.get("headers") or {}
    if headers:
        lines.append("Request headers:")
        for key, value in list(headers.items())[:16]:
            lines.append(f"  {key}: {value}")
    return "\n".join(lines)

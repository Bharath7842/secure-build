"""Plain HTTP notifications when a DAST scan finishes. Failures are logged, never raised.

Slack and Jira are the same mechanism as a generic webhook: a JSON POST to a URL
the operator configured. No vendor SDK.
"""

from __future__ import annotations

import logging

import httpx

from app.config import settings

logger = logging.getLogger(__name__)


def _post(url: str, payload: dict) -> None:
    try:
        httpx.post(url, json=payload, timeout=5.0)
    except Exception:  # noqa: BLE001 - a notification must not change the scan result
        logger.exception("webhook post failed")


def notify_scan_finished(scan_id: str, status: str, message: str | None = None) -> None:
    summary = {"scan_id": scan_id, "status": status, "message": message or ""}
    webhook = (getattr(settings, "dast_webhook_url", None) or "").strip()
    slack = (getattr(settings, "dast_slack_webhook_url", None) or "").strip()
    jira = (getattr(settings, "dast_jira_webhook_url", None) or "").strip()
    if webhook:
        _post(webhook, summary)
    if slack:
        _post(slack, {"text": f"DAST scan {scan_id} {status}. {message or ''}".strip()})
    if jira:
        _post(jira, {"summary": f"DAST scan {status}", "description": f"{scan_id}: {message or status}"})

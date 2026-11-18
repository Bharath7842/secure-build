"""Apply suppressions for finding, rule, resource, or file scopes."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable


def apply_suppressions(
    findings: list[dict],
    suppressions: Iterable[dict[str, Any]] | None,
) -> list[dict]:
    active = [s for s in (suppressions or []) if _is_active(s)]
    if not active:
        return findings

    for finding in findings:
        for suppression in active:
            if _matches(finding, suppression):
                finding["status"] = "SUPPRESSED"
                finding["suppression_reason"] = suppression.get("reason")
                break
    return findings


def _is_active(suppression: dict[str, Any]) -> bool:
    expires = suppression.get("expires_at")
    if not expires:
        return True
    if isinstance(expires, str):
        try:
            expires_dt = datetime.fromisoformat(expires.replace("Z", "+00:00"))
        except ValueError:
            return True
    else:
        expires_dt = expires
    if expires_dt.tzinfo is None:
        expires_dt = expires_dt.replace(tzinfo=timezone.utc)
    return expires_dt > datetime.now(timezone.utc)


def _matches(finding: dict, suppression: dict) -> bool:
    fingerprint = suppression.get("finding_fingerprint") or suppression.get("fingerprint")
    if fingerprint and finding.get("fingerprint") == fingerprint:
        return True
    if suppression.get("rule_id") and finding.get("rule_id") == suppression.get("rule_id"):
        if suppression.get("resource") and finding.get("resource") != suppression.get("resource"):
            return False
        if suppression.get("file_path") and finding.get("file_path") != suppression.get("file_path"):
            return False
        return True
    if suppression.get("resource") and finding.get("resource") == suppression.get("resource"):
        return True
    if suppression.get("file_path") and finding.get("file_path") == suppression.get("file_path"):
        return True
    return False

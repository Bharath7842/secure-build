"""One in-scope request through the same guard a scan uses. The response is returned
to the caller and written to that scan's audit log with check id `replay`."""

from __future__ import annotations

from app.dast.domain.interfaces import RequestSpec
from app.models import DAST_SETTINGS_SNAPSHOT_KEY, Scan
from app.services.guarded_executor import GuardedExecutor
from app.services.request_audit import DbAuditWriter
from app.services.safety_guard import SafetyGuard


class ReplayError(ValueError):
    pass


def replay(scan: Scan, *, method: str, url: str, headers: dict | None = None, body: str | None = None) -> dict:
    meta = scan.metadata_json or {}
    dast_input = meta.get("dast_input") or {}
    target = dast_input.get("target_url") or scan.git_url
    if not target:
        raise ReplayError("this scan has no target")
    effective = meta.get(DAST_SETTINGS_SNAPSHOT_KEY) or meta.get("dast_effective") or {}
    if "rate_limit_per_sec" not in effective:
        raise ReplayError("this scan has no recorded safety settings")
    guard = SafetyGuard.from_settings(str(target), effective, is_cancelled=lambda: False)
    audit = DbAuditWriter(scan.id)
    executor = GuardedExecutor(guard, audit)
    try:
        decision = executor.execute(
            RequestSpec(
                method=(method or "GET").upper(),
                url=url,
                headers=dict(headers or {}),
                body=body,
                check_id="replay",
                identity_label="repeater",
            )
        )
    finally:
        audit.flush()
        executor.close()
    response = decision.response
    return {
        "allowed": decision.allowed,
        "deny_reason": decision.deny_reason,
        "status": None if response is None else response.status,
        "headers": {} if response is None else dict(response.headers or {}),
        "body": None if response is None else response.body_excerpt,
    }

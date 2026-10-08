"""The composition root for a DAST scan: builds the `ScanRuntime` the engine runs on.

This is the one place that puts infrastructure behind the engine's interfaces: the safety guard
from the scan's frozen effective settings, the guarded executor, the audit sink, the browser
factory (launching nothing until a stage asks for a browser), the model gateway and the credential
holder. `engine_adapter.run_dast_scan` calls it for API-started scans; the standalone CLI and Flask
entry points call `build_standalone_runtime`.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping, Sequence

import httpx

from app.config import settings as app_settings
from app.dast.domain.identities import IdentitySpec, build_identities
from app.dast.domain.ruleset import effective_from_dict
from app.dast.runtime import ScanRuntime
from app.services.credential_holder import InMemoryCredentialHolder
from app.services.dast_browser import PlaywrightBrowserFactory
from app.services.guarded_executor import GuardedExecutor
from app.services.request_audit import AuditSink, DbAuditWriter, MemoryAuditSink
from app.services.safety_guard import SafetyGuard


def build_runtime(
    *,
    scan_id: str,
    target_url: str,
    effective: Mapping[str, Any],
    identities: Sequence[IdentitySpec],
    gateway: Any,
    credentials: InMemoryCredentialHolder,
    is_cancelled: Callable[[], bool] | None = None,
    findings_writer: Callable[[str, list[dict]], None] | None = None,
    rule_set: Mapping[str, Any] | None = None,
    skipped_degraded: list[dict] | None = None,
    audit: AuditSink | None = None,
    transport: httpx.BaseTransport | None = None,
    browser_factory: Any = None,
    oast: Any = None,
    oast_url: str | None = None,
    oast_poll_url: str | None = None,
    oast_transport: httpx.BaseTransport | None = None,
    training_capture: Callable[[Any, Any], None] | None = None,
    log: Callable[[str], None] = print,
) -> ScanRuntime:
    """Wire one scan. Nothing here sends a request or launches a browser."""
    guard = SafetyGuard.from_settings(
        target_url,
        effective,
        target_disposable=bool(effective.get("target_disposable", False)),
        allow_state_changing=bool(effective.get("allow_state_changing", False)),
        is_cancelled=is_cancelled,
    )
    audit = audit or DbAuditWriter(scan_id)
    executor = GuardedExecutor(
        guard, audit, transport=transport, max_body_bytes=int(effective.get("max_response_body_bytes") or 65536), secrets=credentials.secrets
    )
    traffic: list = []

    def _denied(url: str, reason: str, navigation: bool) -> None:
        if navigation:
            log(f"    Navigation to {url} was blocked ({reason}).")

    browser = browser_factory or PlaywrightBrowserFactory(
        guard, audit, traffic=traffic, headless=bool(effective.get("headless", True)), secrets=credentials.secrets, on_denied=_denied
    )
    runtime = ScanRuntime(
        gateway=gateway,
        executor=executor,
        identities=list(identities),
        credentials=credentials,
        browser=browser,
        effective=dict(effective),
        target_url=target_url,
        scan_id=scan_id,
        is_cancelled=is_cancelled or (lambda: False),
        findings_writer=findings_writer,
        log=log,
        rule_set=effective_from_dict(rule_set) if rule_set else None,
        skipped_degraded=list(skipped_degraded or []),
        traffic=traffic if browser_factory is None else getattr(browser_factory, "traffic", traffic),
    )
    if oast is None and oast_url:
        from app.services.oast import HttpOastCollaborator

        oast = HttpOastCollaborator(scan_id, oast_url, poll_url=oast_poll_url, audit=audit, transport=oast_transport)
        runtime.closers.append(oast.close)
    runtime.oast = oast
    runtime.training_capture = training_capture
    if scan_id and scan_id != "standalone":
        from app.services import dast_summary

        usage = getattr(getattr(gateway, "usage", None), "summary", None)
        dast_summary.registry.register(
            scan_id,
            dast_summary.LiveScan(
                counters=runtime.counters.snapshot,
                audit_counts=audit.counts if hasattr(audit, "counts") else (lambda: {"sent": 0, "denied": 0}),
                usage=usage if callable(usage) else (lambda: {}),
            ),
        )
    runtime.login_window = guard.login_window
    runtime.marker_window = guard.marker_window
    if scan_id and scan_id != "standalone":
        from app.services import scan_log

        runtime.task_log = lambda label: scan_log.buffered_capture(scan_id, prefix=f"[{label}] ")
    runtime.closers.extend([executor.close, browser.close if hasattr(browser, "close") else (lambda: None)])
    return runtime


def build_standalone_runtime(
    *,
    target_url: str,
    login_url: str = "",
    username: str = "",
    password: str = "",
    storage_state: Mapping[str, Any] | None = None,
    headless: bool = True,
    ollama_model: str | None = None,
    ollama_base_url: str | None = None,
    budgets: Mapping[str, Any] | None = None,
    log: Callable[[str], None] = print,
) -> ScanRuntime:
    """A runtime for the standalone CLI / Flask tool: one identity from the command line, the
    standard intensity, safe method policy, requests audited in memory."""
    from app.dast.domain.presets import build_effective_settings
    from app.services.model_gateway import build_local_gateway

    cfg = app_settings
    raw: list[dict[str, Any]] = []
    secret: dict[str, str] = {}
    if storage_state:
        raw.append({"label": "default", "role": "User", "auth_method": "preauth"})
    elif login_url:
        raw.append({"label": "default", "role": "User", "auth_method": "form"})
    specs = build_identities(raw)
    effective = build_effective_settings(
        request={"intensity": "standard", "headless": headless, **{k: v for k, v in (budgets or {}).items() if v is not None}},
        base=cfg.dast_effective_settings(),
        presets=cfg.dast_presets,
        identities=specs,
        rule_set={},
        model_routing=cfg.dast_model_routing,
        oast_configured=cfg.dast_oast_callback_url is not None,
    )
    holder = InMemoryCredentialHolder("standalone")
    default = next((s for s in specs if s.label == "default"), None)
    if default is not None:
        import json

        secret = {"storage_state": json.dumps(storage_state)} if storage_state else {"login_url": login_url, "username": username, "password": password}
        holder.store(default.to_identity(), secret)
    gateway = build_local_gateway(ollama_model, ollama_base_url)
    return build_runtime(
        scan_id="standalone", target_url=target_url, effective=effective, identities=specs, gateway=gateway,
        credentials=holder, audit=MemoryAuditSink(), log=log,
    )

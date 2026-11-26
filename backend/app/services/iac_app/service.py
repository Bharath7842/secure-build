"""IaC security scan service entry point.

Collects IaC files from a workspace, classifies them, runs the
internal query engine, and scores findings with the risk engine.
"""

from __future__ import annotations

import logging

logger = logging.getLogger("iac.service")


def run_iac_scan(workspace_path: str, log_fn=None) -> dict:
    """Scan *workspace_path* for IaC security issues.

    Args:
        workspace_path: Absolute path to the checked-out repo root.
        log_fn: Optional ``(message: str) -> None`` callback for scan-log lines
            (e.g. ``scan_log.log`` bound to the scan id).  When omitted,
            messages go to the ``iac.service`` logger only.

    Returns a dict::

        {
            "findings": [<finding dict>, ...],
            "risk_summary": {...},
            "file_count": int,
            "terraform_file_count": int,
            "docker_file_count": int,
            "files_by_type": {iac_type: count, ...},
            "rules_executed": int,
        }

    On unhandled failure returns ``{"error": <message>, "findings": []}``.
    """
    def _log(msg: str) -> None:
        logger.info(msg)
        if log_fn is not None:
            try:
                log_fn(msg)
            except Exception:  # noqa: BLE001
                pass

    try:
        from app.services.iac_app.scanner.collector.file_collector import FileCollector
        from app.services.iac_app.scanner.collector.classifier import classify_iac_files
        from app.services.iac_app.scanner.engines.internal_adapter import InternalQueryAdapter
        from app.services.iac_app.scanner.processing.risk_engine import calculate_risk

        _log("### IaC Stage 1 — Collecting and classifying infrastructure files…")
        files = FileCollector().collect(workspace_path)
        classified = classify_iac_files(files)

        # Build a human-readable breakdown of what was found.
        files_by_type: dict[str, int] = {
            iac_type: len(entries)
            for iac_type, entries in classified.items()
            if entries
        }
        type_summary = ", ".join(f"{t}={n}" for t, n in sorted(files_by_type.items()))
        _log(
            f"  Collected {len(files)} file(s) across {len(files_by_type)} IaC type(s)"
            + (f": {type_summary}" if type_summary else "") + "."
        )

        _log("### IaC Stage 2 — Running security policy queries…")
        adapter = InternalQueryAdapter()
        raw_findings = adapter.scan(workspace_path, {"classified_files": classified})
        rules_executed = len(adapter.engine.queries) if hasattr(adapter, "engine") else 0
        _log(
            f"  Executed {rules_executed} rule(s), found {len(raw_findings)} raw finding(s)."
        )

        _log("### IaC Stage 3 — Scoring findings and computing risk summary…")
        risk_summary = calculate_risk(raw_findings)
        _log(
            f"  Risk score: {risk_summary.get('risk_score', 0):.1f} "
            f"({risk_summary.get('risk_level', 'UNKNOWN')}) — "
            f"CRITICAL={risk_summary.get('critical_count', 0)}, "
            f"HIGH={risk_summary.get('high_count', 0)}, "
            f"MEDIUM={risk_summary.get('medium_count', 0)}, "
            f"LOW={risk_summary.get('low_count', 0)}."
        )

        tf_count = len(classified.get("terraform", []))
        docker_count = (
            len(classified.get("docker", []))
            + len(classified.get("docker_compose", []))
        )
        return {
            "findings": raw_findings,
            "risk_summary": risk_summary,
            "file_count": len(files),
            "terraform_file_count": tf_count,
            "docker_file_count": docker_count,
            "files_by_type": files_by_type,
            "rules_executed": rules_executed,
        }
    except Exception as exc:
        logger.exception("IaC scan failed for %s: %s", workspace_path, exc)
        return {"error": str(exc), "findings": [], "risk_summary": {}, "file_count": 0}

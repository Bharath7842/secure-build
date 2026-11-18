"""IaC security scan service entry point.

Collects IaC files from a workspace, classifies them, runs the
internal query engine, and scores findings with the risk engine.
"""

from __future__ import annotations

import logging

logger = logging.getLogger("iac.service")


def run_iac_scan(workspace_path: str) -> dict:
    """Scan *workspace_path* for IaC security issues.

    Returns a dict::

        {
            "findings": [<finding dict>, ...],
            "risk_summary": {...},
            "file_count": int,
        }

    On unhandled failure returns ``{"error": <message>, "findings": []}``.
    """
    try:
        from app.services.iac_app.scanner.collector.file_collector import FileCollector
        from app.services.iac_app.scanner.collector.classifier import classify_iac_files
        from app.services.iac_app.scanner.engines.internal_adapter import InternalQueryAdapter
        from app.services.iac_app.scanner.processing.risk_engine import calculate_risk

        files = FileCollector().collect(workspace_path)
        classified = classify_iac_files(files)
        adapter = InternalQueryAdapter()
        raw_findings = adapter.scan(workspace_path, {"classified_files": classified})
        risk_summary = calculate_risk(raw_findings)

        tf_count = len(classified.get("terraform", []))
        docker_count = len(classified.get("docker", [])) + len(classified.get("docker_compose", []))
        return {
            "findings": raw_findings,
            "risk_summary": risk_summary,
            "file_count": len(files),
            "terraform_file_count": tf_count,
            "docker_file_count": docker_count,
        }
    except Exception as exc:
        logger.exception("IaC scan failed for %s: %s", workspace_path, exc)
        return {"error": str(exc), "findings": [], "risk_summary": {}, "file_count": 0}

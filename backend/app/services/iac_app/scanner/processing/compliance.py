"""Metadata-driven compliance mapping.

Queries declare framework/control metadata. This module never hard-codes
control logic into the scanning engine.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from app.services.iac_app.scanner.compliance.mappings import enrich_compliance


BUILTIN_FRAMEWORKS = [
    {"id": "CIS_AWS", "name": "CIS Amazon Web Services", "version": "1.5"},
    {"id": "CIS_KUBERNETES", "name": "CIS Kubernetes", "version": "1.8"},
    {"id": "CIS_DOCKER", "name": "CIS Docker", "version": "1.6"},
    {"id": "PCI_DSS", "name": "PCI DSS", "version": "4.0"},
    {"id": "SOC2", "name": "SOC 2", "version": "2017"},
    {"id": "ISO27001", "name": "ISO/IEC 27001", "version": "2022"},
    {"id": "NIST", "name": "NIST SP 800-53", "version": "Rev 5"},
    {"id": "HIPAA", "name": "HIPAA Security Rule", "version": "2013"},
    {"id": "GDPR", "name": "GDPR", "version": "2016"},
]


def map_compliance(findings: list[dict]) -> dict[str, Any]:
    by_framework: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"failed_controls": set(), "findings": 0, "controls": []}
    )

    for finding in findings:
        mappings = enrich_compliance(finding)
        normalized = []
        for item in mappings:
            if isinstance(item, str):
                entry = {"framework": item, "control": ""}
            else:
                entry = {
                    "framework": str(item.get("framework") or ""),
                    "control": str(item.get("control") or ""),
                }
            if not entry["framework"]:
                continue
            normalized.append(entry)
            bucket = by_framework[entry["framework"]]
            bucket["findings"] += 1
            if entry["control"]:
                bucket["failed_controls"].add(entry["control"])
                bucket["controls"].append(entry["control"])
        finding["compliance"] = normalized

    summary = {}
    for framework in BUILTIN_FRAMEWORKS:
        fid = framework["id"]
        data = by_framework.get(fid)
        failed = len(data["failed_controls"]) if data else 0
        findings_count = data["findings"] if data else 0
        # Coverage is metadata-driven: failed vs observed mappings for this scan.
        total = max(failed, 1) if findings_count else 0
        passed = 0
        na = 0
        compliance_pct = 0 if failed else 100
        summary[fid] = {
            "framework": fid,
            "name": framework["name"],
            "version": framework["version"],
            "passed": passed,
            "failed": failed,
            "not_applicable": na,
            "findings": findings_count,
            "coverage": compliance_pct if findings_count else None,
            "controls": sorted(data["failed_controls"]) if data else [],
        }

    return {
        "frameworks": summary,
        "failed_findings": sum(1 for f in findings if f.get("compliance")),
    }

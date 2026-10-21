"""Severity summary for a completed scan's findings.

`gate_failed` stays false unless the project sets `gate_max_critical` and/or
`gate_max_high`. Those limits count findings that are not a false positive and
not unverified. With both limits unset, CI still gets the counts and the gate
does not fail — the previous behaviour.

Counts always match the findings list length — every finding is included in
`vulnerabilities_found`, `total_findings`, and `by_severity` (not only
TRUE_POSITIVE). They are not counted here: `scan_export.count_findings` is the one
counting function and this reads its result, so the gate, the API, both exports
and the UI chips cannot disagree.
"""

from app.models import Finding, Project

SEVERITIES = ("critical", "high", "medium", "low", "info")


def _finding_source(finding: Finding) -> str:
    kind = (finding.kind or "").lower()
    if kind in ("semgrep_code", "semgrep_secrets", "sca"):
        return kind
    return kind or "unknown"


def build_gate_summary(project: Project, findings: list[Finding], counts: dict | None = None) -> dict:
    """`findings` are grouped (or plain) findings; `counts` is their
    `scan_export.count_findings`, passed in when the caller already has it."""
    if counts is None:
        # Lazy: scan_export imports this module.
        from app.services.scan_export import count_findings

        counts = count_findings(findings)

    by_severity = {
        sev: counts["actionable"][sev]["groups"] + counts["by_verdict"]["false_positive"][sev]["groups"]
        for sev in SEVERITIES
    }
    by_verdict = {
        bucket.upper(): cell["groups"] for bucket, cell in counts["totals"].items() if cell["groups"]
    }
    by_source: dict[str, int] = {}
    for finding in findings:
        source = _finding_source(finding)
        by_source[source] = by_source.get(source, 0) + 1

    total = sum(by_verdict.values())
    # Confirmed groups per severity, less those a reviewer resolved or risk-accepted
    # (see services/feedback): no longer blocking.
    gated = {sev: counts["by_verdict"]["true_positive"][sev]["groups"] for sev in SEVERITIES}
    for finding in findings:
        if (finding.verdict or "").lower() != "true_positive":
            continue
        if (getattr(finding, "review", None) or {}).get("resolution_status") not in ("resolved", "risk_accepted"):
            continue
        severity = (finding.severity or "info").lower()
        if severity not in gated:
            severity = "info"
        gated[severity] -= 1
    max_critical = getattr(project, "gate_max_critical", None)
    max_high = getattr(project, "gate_max_high", None)
    reasons = []
    if max_critical is not None and gated["critical"] > int(max_critical):
        reasons.append(f"{gated['critical']} critical finding(s) exceed the limit of {int(max_critical)}")
    if max_high is not None and gated["high"] > int(max_high):
        reasons.append(f"{gated['high']} high finding(s) exceed the limit of {int(max_high)}")
    return {
        "vulnerabilities_found": total,
        "total_findings": total,
        "by_severity": by_severity,
        "by_verdict": by_verdict,
        "by_source": by_source,
        "gate_failed": bool(reasons),
        "gate_reason": "; ".join(reasons) or None,
    }

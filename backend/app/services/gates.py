"""Severity summary for a completed scan's findings.

`gate_failed` stays false unless the project sets `gate_max_critical` and/or
`gate_max_high`. Those limits count findings that are not a false positive and
not unverified. With both limits unset, CI still gets the counts and the gate
does not fail — the previous behaviour.

Counts always match the findings list length — every finding is included in
`vulnerabilities_found`, `total_findings`, and `by_severity` (not only
TRUE_POSITIVE).
"""

from app.models import Finding, Project

SEVERITIES = ("critical", "high", "medium", "low", "info")


def _finding_source(finding: Finding) -> str:
    kind = (finding.kind or "").lower()
    if kind in ("semgrep_code", "semgrep_secrets", "sca"):
        return kind
    return kind or "unknown"


def build_gate_summary(project: Project, findings: list[Finding]) -> dict:
    by_severity = {sev: 0 for sev in SEVERITIES}
    by_verdict: dict[str, int] = {}
    by_source: dict[str, int] = {}

    for finding in findings:
        verdict = (finding.verdict or "UNVERIFIED").upper()
        by_verdict[verdict] = by_verdict.get(verdict, 0) + 1
        source = _finding_source(finding)
        by_source[source] = by_source.get(source, 0) + 1

        severity = (finding.severity or "info").lower()
        if severity not in by_severity:
            severity = "info"
        by_severity[severity] += 1

    total = len(findings)
    gated = {sev: 0 for sev in SEVERITIES}
    for finding in findings:
        verdict = (finding.verdict or "").lower()
        if verdict in ("false_positive", "unverified"):
            continue
        severity = (finding.severity or "info").lower()
        if severity not in gated:
            severity = "info"
        gated[severity] += 1
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

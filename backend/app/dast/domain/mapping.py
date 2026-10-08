"""Domain `Finding` <-> the finding-row dict the platform persists (DAST-04-010).

The row dict is the shape `scan_runner._make_findings_writer` already consumes for every scan
type (`kind="dast"` here); the writer turns it into a `Finding` ORM row plus a `DastEvidence`
row. Keeping the mapping here, as plain dicts, keeps the domain free of SQLAlchemy while
still pinning exactly which columns a DAST finding fills:

    rule_id <- check id            severity, title, verdict, verdict_reason
    source  <- the detector that surfaced it (or "" when passive)
    sink    <- the API URL or form action
    target ("METHOD path"), param, location, confidence_label, remediation_ref, standards
    cwe / owasp_category / owasp_ref <- derived from `standards`
"""

from __future__ import annotations

import re
from typing import Any, Mapping, Sequence

from .entities import (
    Confidence,
    DetectorSignal,
    Evidence,
    Finding,
    FindingVerdict,
    Location,
    Severity,
)

KIND = "dast"
_CONFIDENCE_FLOAT = {Confidence.HIGH: 0.9, Confidence.MEDIUM: 0.6, Confidence.LOW: 0.3}
_CWE = re.compile(r"^CWE-\d+$", re.IGNORECASE)
_OWASP_WEB = re.compile(r"^OWASP (A\d{2}:\d{4})$", re.IGNORECASE)
_OWASP_API = re.compile(r"^OWASP (API\d{1,2}:\d{4})$", re.IGNORECASE)

# Midpoint of each CVSS v3.1 qualitative-severity band (the spec's own bands: None 0.0,
# Low 0.1-3.9, Medium 4.0-6.9, High 7.0-8.9, Critical 9.0-10.0) - a deliberately approximate
# stand-in, not a computed per-finding vector. A real vector needs a security-reviewed judgment
# of attack vector/complexity/privileges/impact per check, which this catalog does not carry yet;
# this gives every DAST finding a score consistent with the shared `Finding.cvss` column (used for
# sorting/representative-picking in scan_export.py the same way SCA findings' real OSV CVSS score
# is) without overstating precision it doesn't have.
_CVSS_BAND_MIDPOINT = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 8.0,
    Severity.MEDIUM: 5.5,
    Severity.LOW: 2.0,
    Severity.INFO: 0.0,
}


def cvss_of(severity: Severity) -> float:
    return _CVSS_BAND_MIDPOINT[severity]


def _mentions(text: str, needle: str) -> bool:
    return bool(needle) and needle.lower() in text.lower()


def validated_reason(reason: str, signals: Sequence[DetectorSignal], param: str | None) -> str:
    """`reason` as given, if it plausibly names the evidence that actually fired; otherwise a
    plain reason built directly from the structured signal(s) and parameter.

    A model-authored explanation is free text and can drift from what the structured data says -
    naming a different parameter, or not mentioning the signal that fired at all - and an operator
    reads this text to decide what to do next, so it must be trustworthy. This does not second-
    guess the verdict itself (the guardrail already decided that); it only keeps the shown
    *reason* honest about the evidence behind it. A reason with no structured signal to check
    against (e.g. a model-only FAIL with no detector signal) passes through unchanged - there is
    nothing here to contradict it."""
    if not reason:
        return reason
    names = {s.name for s in signals}
    if not names:
        return reason
    mentions_signal = any(_mentions(reason, name) for name in names) or any(_mentions(reason, s.detail) for s in signals if s.detail)
    mentions_param = param is None or _mentions(reason, param)
    if mentions_signal and mentions_param:
        return reason
    parts = [f"{', '.join(sorted(names))} observed"]
    if param:
        parts.append(f"on parameter {param!r}")
    return "; ".join(parts) + " (the model's explanation did not reference the evidence and was replaced)."


def cwe_of(standards: "list[str] | tuple[str, ...]") -> str | None:
    return next((s.upper() for s in standards if _CWE.match(s)), None)


def owasp_category_of(standards: "list[str] | tuple[str, ...]") -> str | None:
    """First OWASP Top 10 (web) tag, e.g. "A03:2021"; falls back to an API Top 10 tag."""
    for pattern in (_OWASP_WEB, _OWASP_API):
        for standard in standards:
            match = pattern.match(standard)
            if match:
                return match.group(1).upper()
    return None


def evidence_to_dict(evidence: Evidence | None) -> dict[str, Any] | None:
    if evidence is None:
        return None
    return {
        "baseline_excerpt": evidence.baseline_excerpt,
        "test_excerpt": evidence.test_excerpt,
        "signals": [{"name": s.name, "detail": s.detail} for s in evidence.signals],
        "audit_ref": evidence.audit_ref,
    }


def evidence_from_dict(data: Mapping[str, Any]) -> Evidence:
    return Evidence(
        baseline_excerpt=data.get("baseline_excerpt") or "",
        test_excerpt=data.get("test_excerpt") or "",
        signals=tuple(DetectorSignal(name=s["name"], detail=s.get("detail", "")) for s in data.get("signals") or ()),
        audit_ref=str(data.get("audit_ref") or ""),
    )


def finding_to_row(
    finding: Finding,
    *,
    title: str,
    source: str = "",
    sink: str = "",
    verdict_reason: str = "",
    snippet: str = "",
) -> dict[str, Any]:
    """The persisted row for `finding`. `title` comes from the catalog check, never the model."""
    standards = list(finding.standards)
    signals = finding.evidence.signals if finding.evidence else ()
    verdict_reason = validated_reason(verdict_reason, signals, finding.param)
    return {
        "kind": KIND,
        "rule_id": finding.check_id,
        "severity": finding.severity.value,
        "title": title,
        "verdict": finding.verdict.value,
        "verdict_reason": verdict_reason,
        "source": source,
        "sink": sink,
        "cwe": cwe_of(standards),
        "cvss": cvss_of(finding.severity),
        "owasp_category": owasp_category_of(standards),
        "owasp_ref": ", ".join(s for s in standards if s.upper().startswith("OWASP")) or None,
        "file_path": finding.target,  # the existing panels key a finding by this label
        "line": None,
        "snippet": snippet,
        "confidence": _CONFIDENCE_FLOAT[finding.confidence],
        "confidence_label": finding.confidence.value,
        "target": finding.target,
        "param": finding.param,
        "location": finding.location.value if finding.location else None,
        "remediation_ref": finding.remediation_ref or None,
        "standards": standards,
        "affected_files": list(finding.affected_targets) or None,
        "roles": list(finding.roles),
        "first_seen_scan_id": finding.first_seen_scan_id,
        "last_seen_scan_id": finding.last_seen_scan_id,
        "evidence": evidence_to_dict(finding.evidence),
    }


def finding_from_row(row: Mapping[str, Any], *, require_signal: bool = False) -> Finding:
    """Build the domain `Finding` for a row. Raises on an invalid enum value. A true
    positive may come from a detector signal or from the model's FAIL; pass
    `require_signal=True` to reject a TP with no detector evidence."""
    location = row.get("location")
    evidence = evidence_from_dict(row["evidence"]) if row.get("evidence") else None
    finding = Finding(
        check_id=row["rule_id"],
        severity=Severity(row["severity"]),
        confidence=Confidence(row["confidence_label"]),
        verdict=FindingVerdict(row["verdict"]),
        target=row["target"],
        param=row.get("param"),
        location=Location(location) if location else None,
        standards=tuple(row.get("standards") or ()),
        remediation_ref=row.get("remediation_ref") or "",
        evidence=evidence,
        first_seen_scan_id=row.get("first_seen_scan_id"),
        last_seen_scan_id=row.get("last_seen_scan_id"),
        affected_targets=tuple(row.get("affected_files") or ()),
        roles=tuple(row.get("roles") or ()),
    )
    if require_signal and finding.verdict is FindingVerdict.TRUE_POSITIVE and not (evidence and evidence.signals):
        raise ValueError(f"true-positive finding {row['rule_id']} on {row['target']} has no detector signal")
    return finding

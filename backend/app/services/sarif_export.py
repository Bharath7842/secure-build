"""SARIF 2.1.0 and JUnit XML for a scan's findings. Hand-built; no SARIF library."""

from __future__ import annotations

from xml.sax.saxutils import escape


def _level(severity: str | None) -> str:
    return {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}.get(
        (severity or "info").lower(), "warning"
    )


def sarif_document(findings: list) -> dict:
    rules = {}
    results = []
    for finding in findings:
        rule_id = finding.rule_id or "unspecified"
        rules.setdefault(
            rule_id,
            {"id": rule_id, "shortDescription": {"text": (finding.title or rule_id)[:200]}, "defaultConfiguration": {"level": _level(finding.severity)}},
        )
        location = finding.file_path or finding.target or finding.sink or ""
        results.append(
            {
                "ruleId": rule_id,
                "level": _level(finding.severity),
                "message": {"text": finding.title or rule_id},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": location or "unknown"},
                            "region": {"startLine": finding.line or 1},
                        }
                    }
                ],
                "properties": {
                    "severity": finding.severity,
                    "verdict": finding.verdict,
                    "cwe": finding.cwe,
                },
            }
        )
    return {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "augmented-secure-build", "rules": list(rules.values())}},
                "results": results,
            }
        ],
    }


def junit_xml(findings: list, *, name: str = "scan") -> str:
    cases = []
    failures = 0
    for finding in findings:
        verdict = (finding.verdict or "").lower()
        title = escape(finding.title or finding.rule_id or "finding")
        classname = escape(finding.rule_id or "finding")
        body = escape((finding.snippet or finding.verdict_reason or "")[:2000])
        if verdict == "false_positive":
            cases.append(f'<testcase classname="{classname}" name="{title}"/>')
        else:
            failures += 1
            cases.append(
                f'<testcase classname="{classname}" name="{title}"><failure message="{escape(finding.severity or "")}">{body}</failure></testcase>'
            )
    inner = "".join(cases)
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<testsuite name="{escape(name)}" tests="{len(findings)}" failures="{failures}">{inner}</testsuite>'
    )

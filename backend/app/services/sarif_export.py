"""SARIF 2.1.0 and JUnit XML for a scan's findings. Hand-built; no SARIF library."""

from __future__ import annotations

import re
from xml.sax.saxutils import escape, quoteattr

from app.services import secret_masking

# Characters XML 1.0 cannot carry at all (a snippet from a binary file, a model's
# stray escape): one of them makes the whole report unparseable.
_XML_ILLEGAL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ufffe\uffff]")


def _xml_text(value: object) -> str:
    return _XML_ILLEGAL.sub("", "" if value is None else str(value))


def _level(severity: str | None) -> str:
    return {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}.get(
        (severity or "info").lower(), "warning"
    )


def _result_level(finding) -> str:
    """An undecided finding is a note, whatever its severity: nobody has confirmed it,
    so it must not gate a pipeline as an error."""
    if (finding.verdict or "").lower() == "unverified":
        return "note"
    return _level(finding.severity)


def _ai_assisted(finding) -> bool:
    """False only for a regex hit nobody has reviewed; everything else was read or
    decided by a model somewhere along the way."""
    return not ((finding.kind or "") == "regex" and (finding.verdict or "").lower() == "unverified")


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
                "level": _result_level(finding),
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
                    # Model-generated analysis: a reviewer should confirm it (LLM05/LLM09).
                    "aiAssisted": _ai_assisted(finding),
                },
                # A dismissed finding is reported as suppressed, so a code-scanning
                # dashboard does not show it as an open alert.
                **(
                    {"suppressions": [{
                        "kind": "external", "status": "accepted",
                        "justification": "Scanner verdict: false positive",
                    }]}
                    if (finding.verdict or "").lower() == "false_positive" else {}
                ),
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
        # quoteattr, not escape: escape() leaves a double quote alone, so a title with
        # one would end the attribute and let the rest of the text become markup.
        title = quoteattr(_xml_text(finding.title or finding.rule_id or "finding"))
        classname = quoteattr(_xml_text(finding.rule_id or "finding"))
        body = escape(_xml_text(secret_masking.mask_text(finding.snippet or finding.verdict_reason or "")[:2000]))
        if verdict == "false_positive":
            cases.append(f"<testcase classname={classname} name={title}/>")
        else:
            failures += 1
            cases.append(
                f"<testcase classname={classname} name={title}>"
                f"<failure message={quoteattr(_xml_text(finding.severity or ''))}>{body}</failure></testcase>"
            )
    inner = "".join(cases)
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f"<testsuite name={quoteattr(_xml_text(name))} tests=\"{len(findings)}\" failures=\"{failures}\">{inner}</testsuite>"
    )

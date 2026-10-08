"""Findings from the inventory diff (DAST-07-060): API9 "improper inventory management".

An endpoint seen live but absent from the API description is evidence of an undocumented
(shadow, old-version or debug) surface. With a stronger detector signal behind it, that
observation is proof enough to record `true_positive`; on its own (no `stronger_signals`,
`Confidence.LOW`) being merely undocumented is suggestive, not proof, so it is recorded
`unverified` instead. Operations the schema lists but nothing exercised are informational
only and produce no finding.
"""

from __future__ import annotations

from typing import Any, Mapping

from .domain.catalog import standards_for
from .domain.dedupe import target_path_template
from .domain.entities import Check, Confidence, DetectorSignal, Evidence, Finding, FindingVerdict, Location, Severity
from .domain.inventory import InventoryDiff
from .domain.mapping import finding_to_row

CHECK_ID = "dast-api-inventory"


def undocumented_findings(diff: InventoryDiff, check: Check, *, stronger_signals: Mapping[str, list[DetectorSignal]] | None = None) -> list[dict[str, Any]]:
    """One row per undocumented endpoint. `stronger_signals` maps an endpoint label to detector
    signals already observed for it; with any, the finding is a confirmed `true_positive`."""
    rows: list[dict[str, Any]] = []
    for endpoint in diff.undocumented:
        dest = (endpoint.url or target_path_template(endpoint.path_template)).partition("#")[0]
        label = f"{endpoint.method} {dest}"
        signals = tuple((stronger_signals or {}).get(endpoint.label, ()))
        verdict = FindingVerdict.TRUE_POSITIVE if signals else FindingVerdict.UNVERIFIED
        status = f" (HTTP {endpoint.last_status})" if endpoint.last_status is not None else ""
        finding = Finding(
            check_id=check.check_id,
            severity=check.base_severity if isinstance(check.base_severity, Severity) else Severity(str(check.base_severity)),
            confidence=Confidence.MEDIUM if signals else Confidence.LOW,
            verdict=verdict,
            target=label,
            param=None,
            location=Location.RESPONSE,
            standards=tuple(standards_for(check)),
            remediation_ref=check.remediation_ref,
            evidence=Evidence("", f"observed {endpoint.label}{status}; the API description does not list it", signals, ""),
        )
        rows.append(
            finding_to_row(
                finding,
                title=f"{check.title}: {label}",
                source="inventory diff",
                sink=endpoint.url or endpoint.path_template,
                verdict_reason="The endpoint was observed during discovery but is absent from the published API description.",
                snippet=f"Check: {check.title}\nObserved: {endpoint.label}{status}\nDocumented: no",
            )
        )
    return rows

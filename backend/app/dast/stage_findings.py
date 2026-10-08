"""Finding rows for stages outside the active loop (preflight, discovery, login).

Same shape as `tls_probe.finding_rows`: the effective rule set decides whether a
check is on, and a missing writer never fails the scan.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

from .domain.catalog import standards_for
from .domain.entities import Confidence, DetectorSignal, Evidence, Finding, FindingVerdict, Location, Severity
from .domain.mapping import finding_to_row
from .domain.redaction import redact_text


def enabled_checks(rule_set: Any, check_ids: Iterable[str], skipped: Sequence[Any] = ()) -> dict[str, Any]:
    if rule_set is None:
        return {}
    wanted = set(check_ids)
    skipped_ids = {item.get("check_id") for item in skipped if isinstance(item, Mapping) and item.get("status") == "skipped"}
    return {
        ec.check_id: ec
        for ec in rule_set.enabled_checks()
        if ec.check_id in wanted and ec.check_id not in skipped_ids
    }


def one_row(
    ec: Any,
    *,
    signal: str,
    detail: str,
    target: str,
    title: str,
    source: str,
    sink: str,
    secrets: Sequence[str] = (),
    param: str | None = None,
    location: Location = Location.RESPONSE,
    confidence: Confidence = Confidence.HIGH,
) -> dict[str, Any]:
    check = ec.check
    text = redact_text(detail, secrets)
    finding = Finding(
        check_id=check.check_id,
        severity=Severity(ec.severity.value),
        confidence=confidence,
        verdict=FindingVerdict.TRUE_POSITIVE,
        target=target,
        param=param,
        location=location,
        standards=tuple(standards_for(check)),
        remediation_ref=check.remediation_ref,
        evidence=Evidence("", text, (DetectorSignal(signal, text),), ""),
    )
    reason = text[:1].upper() + text[1:]
    if reason and not reason.endswith("."):
        reason += "."
    return finding_to_row(
        finding,
        title=title,
        source=source,
        sink=sink,
        verdict_reason=reason,
        snippet=f"Check: {check.title}\nTarget: {target}\nDetail: {text}",
    )


def publish(state: dict, runtime: Any, label: str, rows: list[dict]) -> None:
    if not rows or runtime is None:
        return
    writer = state.get("findings_writer") or getattr(runtime, "findings_writer", None)
    if writer is None:
        return
    try:
        writer(label, rows)
    except Exception as exc:  # noqa: BLE001 - a storage hiccup must not stop the scan
        print(f"    Could not persist {label} findings: {exc}")

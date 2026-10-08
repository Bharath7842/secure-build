"""Passive analysis, engine side (DAST-08-010 .. -030): load the pattern data, turn the pure
checks' hits into finding rows, and run the whole pass over a scan's recorded traffic.

Sends nothing and calls no model; `domain/passive.py` holds the checks.
"""

from __future__ import annotations

import json
from dataclasses import replace
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable, Sequence
from urllib.parse import urlsplit

from .domain.catalog import standards_for
from .domain.entities import Check, Confidence, DetectorSignal, Evidence, Finding, FindingVerdict, Location, Severity
from .domain.mapping import finding_to_row
from .domain.passive import (
    PASSIVE_CHECK_IDS,
    TRUE_POSITIVE,
    UNVERIFIED,
    CorsAssessment,
    DedupedHit,
    PatternSet,
    analyze_traffic,
    dedupe_hits,
    parse_pattern_set,
    shift_severity,
)
from .domain.redaction import redact_headers, redact_text
from .domain.ruleset import EffectiveRuleSet
from .domain.traffic import RecordedExchange

PATTERNS_PATH = Path(__file__).resolve().parent / "data" / "passive_patterns.json"
SOURCE = "passive analysis"


def load_patterns(path: Path | str | None = None) -> PatternSet:
    with open(path or PATTERNS_PATH, encoding="utf-8") as handle:
        return parse_pattern_set(json.load(handle))


@lru_cache(maxsize=1)
def default_patterns() -> PatternSet:
    return load_patterns()


def root_exchange(url: str, root: Any) -> RecordedExchange | None:
    """The preflight's response as a recorded exchange, so a scan with no browser traffic (an
    API-only target) still has its root response to analyse."""
    if root is None or getattr(root, "status", None) is None:
        return None
    headers = dict(getattr(root, "headers", None) or {})
    content_type = next((str(v) for k, v in headers.items() if str(k).lower() == "content-type"), "")
    return RecordedExchange(
        method="GET", url=url, status=root.status, resource_type="document", content_type=content_type,
        response_headers=redact_headers(headers, keep_cookie_attributes=True), response_body=getattr(root, "body_excerpt", "") or "",
    )


def enabled_passive_checks(rule_set: EffectiveRuleSet | None, skipped: Iterable[dict] = ()) -> dict[str, Any]:
    """`{check_id: EffectiveCheck}` for the passive checks this stage implements that the effective
    rule set has switched on and that were not skipped for a missing dependency."""
    if rule_set is None:
        return {}
    skipped_ids = {s.get("check_id") for s in skipped if s.get("status") == "skipped"}
    return {
        ec.check_id: ec
        for ec in rule_set.enabled_checks()
        if ec.check_id in PASSIVE_CHECK_IDS and ec.check.passive and ec.mode.value != "assist-only" and ec.check_id not in skipped_ids
    }


def _severity(ec: Any, shift: int) -> Severity:
    if ec.overrides.get("severity") or not shift:  # an explicit override is never second-guessed
        return Severity(ec.severity.value)
    return Severity(shift_severity(ec.severity.value, shift))


def hit_to_row(item: DedupedHit, check: Check, ec: Any, secrets: Sequence[str] = ()) -> dict[str, Any]:
    hit = item.hit
    if secrets:  # the response may echo what the scan sent (a token in an error page): never store it
        hit = replace(hit, detail=redact_text(hit.detail, secrets), excerpt=redact_text(hit.excerpt, secrets), url=redact_text(hit.url, secrets), note=redact_text(hit.note, secrets))
    verdict = FindingVerdict(hit.verdict)
    raw = (hit.url or "").partition("#")[0].partition("?")[0]
    dest = raw if raw.startswith(("http://", "https://")) else (urlsplit(raw).path or "/")
    target = f"{hit.method} {dest}"
    reason = hit.detail[0].upper() + hit.detail[1:] + "."
    if hit.note:
        reason += f" {hit.note}."
    if item.occurrences > 1:
        reason += f" Observed on {item.occurrences} responses."
    finding = Finding(
        check_id=check.check_id,
        severity=_severity(ec, hit.severity_shift),
        confidence=Confidence.HIGH if verdict is FindingVerdict.TRUE_POSITIVE else Confidence.LOW,
        verdict=verdict,
        target=target,
        param=hit.param,
        location=Location(check.location) if isinstance(check.location, str) else check.location,
        standards=tuple(standards_for(check)),
        remediation_ref=check.remediation_ref,
        evidence=Evidence("", f"{hit.excerpt}".strip(), (DetectorSignal(hit.signal, hit.detail),), ""),
        affected_targets=item.affected if len(item.affected) > 1 else (),
    )
    return finding_to_row(
        finding, title=f"{check.title}: {hit.param}", source=SOURCE, sink=hit.url, verdict_reason=reason,
        snippet=f"Check: {check.title}\nObserved on: {target} (HTTP {hit.status})\nEvidence: {hit.excerpt}",
    )


def run_passive(
    traffic: Sequence[RecordedExchange], rule_set: EffectiveRuleSet | None, skipped: Iterable[dict] = (), patterns: PatternSet | None = None, secrets: Sequence[str] = ()
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """`(finding rows, summary)` for `traffic` under `rule_set`. Pure over its inputs."""
    enabled = enabled_passive_checks(rule_set, skipped)
    summary: dict[str, Any] = {"checks_run": len(enabled), "exchanges": len(traffic), "findings": 0, "unverified": 0, "finding_keys": [], "cors": {"assessable": True, "note": ""}}
    if not enabled:
        return [], summary
    hits, cors = analyze_traffic(traffic, enabled, patterns or default_patterns())
    rows: list[dict[str, Any]] = []
    for item in dedupe_hits(hits):
        ec = enabled[item.hit.check_id]
        rows.append(hit_to_row(item, ec.check, ec, secrets))
    rows.sort(key=lambda r: (r["rule_id"], r["param"] or ""))  # deterministic order
    summary["findings"] = len(rows)
    summary["unverified"] = sum(1 for r in rows if r["verdict"] == UNVERIFIED)
    summary["finding_keys"] = [f"{r['rule_id']}|{r['param']}" for r in rows]
    summary["cors"] = _cors_summary(cors, "dast-passive-cors-permissive" in enabled)
    return rows, summary


def _cors_summary(cors: CorsAssessment, enabled: bool) -> dict[str, Any]:
    if not enabled:
        return {"assessable": None, "note": "the CORS check is not enabled"}
    return {"assessable": cors.assessable, "note": cors.note}

"""Review items for checks a scan cannot test (DAST-09-050): sensitive business flows (API6),
unsafe consumption of upstream APIs (API10), and SSRF when no OAST address is configured.

They run no test and send no request. Each match becomes a finding with verdict `false_positive`, a
distinct source (`assist-only review`) and text that says human review is required, so it appears in
the report but is never labelled confirmed.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .domain.active import target_label
from .domain.catalog import standards_for
from .domain.entities import Confidence, Endpoint, Evidence, Finding, FindingVerdict, Location, Severity
from .domain.mapping import finding_to_row
from .domain.ruleset import EffectiveRuleSet

HEURISTICS_PATH = Path(__file__).resolve().parent / "data" / "review_heuristics.json"
SOURCE = "assist-only review"
MAX_ITEMS_PER_CHECK = 30
FLOWS_CHECK, UNSAFE_CHECK, SSRF_CHECK = "dast-business-flows", "dast-unsafe-consumption", "dast-ssrf"


@lru_cache(maxsize=1)
def load_heuristics(path: str | None = None) -> dict[str, Any]:
    with open(path or HEURISTICS_PATH, encoding="utf-8") as handle:
        data = json.load(handle)
    if data.get("schema_version") != 1:
        raise ValueError("unsupported review heuristics schema_version")
    for group in ("sensitive_flows", "unsafe_consumption"):
        for item in data.get(group, ()):
            item["_re"] = re.compile(item["path"])
    return data


def _assist_checks(rule_set: EffectiveRuleSet | None, skipped: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Checks that should produce review items: enabled and assist-only, either by their own mode
    or because a missing dependency (no OAST address) downgraded them."""
    if rule_set is None:
        return {}
    downgraded = {s["check_id"] for s in skipped if s.get("status") == "degraded" and s.get("effective_mode") == "assist-only"}
    return {
        ec.check_id: ec
        for ec in rule_set.enabled_checks()
        if ec.check_id in (FLOWS_CHECK, UNSAFE_CHECK, SSRF_CHECK) and (ec.mode.value == "assist-only" or ec.check_id in downgraded)
    }


def _row(ec: Any, endpoint: Endpoint, param: str | None, headline: str, why: str) -> dict[str, Any]:
    check = ec.check
    finding = Finding(
        check_id=check.check_id, severity=Severity(ec.severity.value), confidence=Confidence.LOW, verdict=FindingVerdict.FALSE_POSITIVE,
        target=target_label(endpoint), param=param, location=Location.RESPONSE, standards=tuple(standards_for(check)),
        remediation_ref=check.remediation_ref, evidence=Evidence("", f"Review item: {headline}", (), ""),
    )
    return finding_to_row(
        finding, title=f"{check.title}: {target_label(endpoint)}", source=SOURCE, sink=endpoint.url,
        verdict_reason=f"{headline}. {why} Human review is required; this is not a confirmed vulnerability.",
        snippet=f"Check: {check.title}\nEndpoint: {target_label(endpoint)}\nWhy listed: {headline}\nStatus: review required (nothing was tested)",
    )


def review_rows(
    endpoints: Iterable[Endpoint],
    rule_set: EffectiveRuleSet | None,
    skipped: Iterable[Mapping[str, Any]] = (),
    heuristics: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    checks = _assist_checks(rule_set, skipped)
    if not checks:
        return []
    data = heuristics or load_heuristics()
    url_names = {n.lower() for n in data.get("url_parameter_names", ())}
    rows: dict[str, list[dict[str, Any]]] = {cid: [] for cid in checks}
    for endpoint in sorted((e for e in endpoints if e.kind != "asset"), key=lambda e: (e.path_template, e.method)):
        path = endpoint.path_template.partition("#")[0]
        if FLOWS_CHECK in checks:
            for item in data.get("sensitive_flows", ()):
                if item["_re"].search(path):
                    rows[FLOWS_CHECK].append(_row(checks[FLOWS_CHECK], endpoint, None, f"This looks like a {item['label']} flow", "Abuse of a legitimate flow (automation, enumeration, replay) is business logic that a scanner cannot judge."))
                    break
        if UNSAFE_CHECK in checks:
            for item in data.get("unsafe_consumption", ()):
                if item["_re"].search(path):
                    rows[UNSAFE_CHECK].append(_row(checks[UNSAFE_CHECK], endpoint, None, f"This endpoint {item['label']}", "Trust placed in an upstream API is not visible from outside."))
                    break
        if SSRF_CHECK in checks:
            for param in endpoint.parameters:
                if param.name.lower() in url_names or any(v.startswith(("http://", "https://")) for v in param.observed_values):
                    rows[SSRF_CHECK].append(_row(checks[SSRF_CHECK], endpoint, param.name, f"Parameter {param.name!r} may accept a URL", "No out-of-band (OAST) address is configured, so server-side request forgery cannot be confirmed here."))
    return [row for cid in checks for row in rows[cid][:MAX_ITEMS_PER_CHECK]]

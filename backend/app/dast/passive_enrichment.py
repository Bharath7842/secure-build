"""LLM enrichment for deterministic passive DAST findings.

The detector remains authoritative about whether a finding exists and what evidence fired.
The model is only asked to recommend a severity and explain how an operator can reproduce the
already-observed condition. Invalid or unavailable model output falls back to the catalog result.
"""

from __future__ import annotations

import json
from typing import Any, Mapping, Sequence

from .domain.interfaces import ModelGateway

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
_REVIEW_SCHEMA = {
    "type": "object",
    "properties": {
        "severity": {"type": "string", "enum": list(SEVERITIES)},
        "reproduction": {"type": "string", "minLength": 20, "maxLength": 2000},
    },
    "required": ["severity", "reproduction"],
    "additionalProperties": False,
}

_SYSTEM = """You review one deterministic DAST finding for a security engineer.
The detector has already established that the finding exists. Do not dispute the finding, invent
new evidence, or include secrets. Choose the severity from the supplied evidence and write concise,
numbered reproduction steps using only the supplied method, URL, parameter, response status, and
detector signal. If a request is needed, show a safe curl command; never invent credentials or
payloads. Return only the requested JSON object."""


def _fallback_reproduction(row: Mapping[str, Any]) -> str:
    target = str(row.get("target") or "the recorded endpoint")
    param = str(row.get("param") or "the affected parameter")
    evidence = row.get("evidence") or {}
    signals = evidence.get("signals") or []
    signal = str((signals[0] or {}).get("name") or "the detector signal") if signals else "the detector signal"
    return (
        f"1. Send the recorded {target} request to the authorized target.\n"
        f"2. Inspect the response for {param} and confirm the detector signal `{signal}`.\n"
        "3. Compare the result with the evidence shown above and confirm the same condition is present."
    )


def _prompt(row: Mapping[str, Any]) -> str:
    evidence = row.get("evidence") or {}
    payload = {
        "rule_id": row.get("rule_id"),
        "title": row.get("title"),
        "catalog_severity": row.get("severity"),
        "target": row.get("target"),
        "parameter": row.get("param"),
        "location": row.get("location"),
        "standards": row.get("standards") or [],
        "detector_signals": evidence.get("signals") or [],
        "response_excerpt": evidence.get("test_excerpt") or "",
    }
    return "Review this observed finding. The catalog severity is a starting point, not a constraint.\n" + json.dumps(payload, ensure_ascii=False, sort_keys=True)


def enrich_passive_rows(rows: Sequence[dict[str, Any]], gateway: ModelGateway | None) -> list[dict[str, Any]]:
    """Return rows enriched by the model, without allowing it to create or remove findings."""
    enriched: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        evidence = dict(item.get("evidence") or {})
        item["evidence"] = evidence
        fallback = _fallback_reproduction(item)
        item["evidence"]["reproduction"] = fallback
        item["evidence"]["severity_source"] = "catalog fallback"
        if gateway is not None:
            try:
                reply = gateway.complete("rule", _SYSTEM, _prompt(item), _REVIEW_SCHEMA, max_tokens=700, temperature=0)
                data = reply.data if isinstance(reply.data, Mapping) else {}
                severity = str(data.get("severity") or "").upper()
                reproduction = str(data.get("reproduction") or "").strip()
                if severity in SEVERITIES:
                    item["severity"] = severity
                    item["evidence"]["severity_source"] = "LLM review"
                if len(reproduction) >= 20:
                    item["evidence"]["reproduction"] = reproduction[:2000]
            except Exception:
                # The gateway already has its own fallback. This guard also keeps test doubles
                # and provider integration errors from turning a passive scan into a hard failure.
                pass
        enriched.append(item)
    return enriched

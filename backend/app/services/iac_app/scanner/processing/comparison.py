"""Compare two scans: new, resolved, changed severity, unchanged, regressed."""

from __future__ import annotations

from typing import Any


def compare_findings(current: list[dict], baseline: list[dict]) -> dict[str, Any]:
    current_map = {f.get("fingerprint"): f for f in current if f.get("fingerprint")}
    baseline_map = {f.get("fingerprint"): f for f in baseline if f.get("fingerprint")}

    current_keys = set(current_map)
    baseline_keys = set(baseline_map)

    new_keys = current_keys - baseline_keys
    resolved_keys = baseline_keys - current_keys
    shared = current_keys & baseline_keys

    changed_severity = []
    unchanged = []
    regressed = []
    existing = []

    for key in shared:
        cur = current_map[key]
        old = baseline_map[key]
        existing.append(cur)
        if cur.get("severity") != old.get("severity"):
            changed_severity.append(
                {
                    "fingerprint": key,
                    "from": old.get("severity"),
                    "to": cur.get("severity"),
                    "rule_id": cur.get("rule_id"),
                    "title": cur.get("title"),
                }
            )
        else:
            unchanged.append(cur)
        if _rank(cur.get("severity")) > _rank(old.get("severity")):
            regressed.append(cur)

    return {
        "new": [current_map[k] for k in new_keys],
        "existing": existing,
        "resolved": [baseline_map[k] for k in resolved_keys],
        "regressed": regressed,
        "changed_severity": changed_severity,
        "unchanged": unchanged,
        "counts": {
            "new": len(new_keys),
            "existing": len(existing),
            "resolved": len(resolved_keys),
            "regressed": len(regressed),
            "changed_severity": len(changed_severity),
            "unchanged": len(unchanged),
        },
    }


def _rank(severity: str | None) -> int:
    order = {"INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
    return order.get(str(severity or "").upper(), 0)

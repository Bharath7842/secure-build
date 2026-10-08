"""Run-to-run comparison for the live determinism check (DAST-16-030). Pure.

The same practice target scanned twice should give the same verdicts. The model can propose
different inputs from one run to the next, so a live pair is allowed to differ by a small, recorded
share of findings (`ALLOWED_VARIANCE`); the offline pair against the fake target must be identical.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

# Share of the union of findings (by diff key and verdict) that may differ between two live runs.
# Recorded here so loosening it is a visible, reviewed change.
ALLOWED_VARIANCE = 0.10


def comparable(findings: Iterable[Mapping[str, Any]]) -> set[tuple]:
    """Findings reduced to what must repeat: `(check, endpoint template, parameter, verdict)`."""
    from app.dast.domain.dedupe import key_for

    return {(*key_for(f["rule_id"], f.get("target") or "", f.get("param") or None), f.get("verdict")) for f in findings}


def compare_runs(first: Iterable[Mapping[str, Any]], second: Iterable[Mapping[str, Any]], *, allowed: float = ALLOWED_VARIANCE) -> dict[str, Any]:
    a, b = comparable(first), comparable(second)
    union = a | b
    only_first, only_second = sorted(a - b), sorted(b - a)
    variance = len(only_first + only_second) / len(union) if union else 0.0
    return {
        "variance": round(variance, 4), "allowed": allowed, "ok": variance <= allowed,
        "only_in_first": [list(x) for x in only_first], "only_in_second": [list(x) for x in only_second], "findings": len(union),
    }

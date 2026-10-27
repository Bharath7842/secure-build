"""CVSS v3.1 base scores (FIRST, https://www.first.org/cvss/v3.1/specification-document).

The vector is the source of truth and the score is derived from it with the
specification's own formula, including its integer-based Roundup (a plain
`ceil(x * 10) / 10` turns 4.000000000000001 into 4.1). Severity is the
specification's qualitative rating of the score.
"""

from __future__ import annotations

import math

PREFIX = "CVSS:3.1"
METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_ALLOWED = {
    "AV": _AV, "AC": _AC, "PR": _PR_UNCHANGED, "UI": _UI, "S": {"U": 0, "C": 0},
    "C": _CIA, "I": _CIA, "A": _CIA,
}


class CvssError(ValueError):
    """A vector that is not a complete, well-formed CVSS v3.x base vector."""


def parse(vector: str) -> dict[str, str]:
    """{metric: value} for the eight base metrics; the `CVSS:3.x` prefix is optional."""
    parts: dict[str, str] = {}
    for segment in (vector or "").strip().split("/"):
        if not segment or segment.startswith("CVSS:"):
            continue
        key, sep, value = segment.partition(":")
        if not sep or key not in _ALLOWED or value not in _ALLOWED[key] or key in parts:
            raise CvssError(f"bad CVSS segment {segment!r} in {vector!r}")
        parts[key] = value
    missing = [m for m in METRICS if m not in parts]
    if missing:
        raise CvssError(f"CVSS vector {vector!r} lacks {', '.join(missing)}")
    return parts


def format_vector(parts: dict[str, str]) -> str:
    return PREFIX + "/" + "/".join(f"{m}:{parts[m]}" for m in METRICS)


def with_metrics(vector: str, **changes: str) -> str:
    """`vector` with some base metrics replaced, e.g. `with_metrics(v, PR="L")`."""
    parts = parse(vector)
    parts.update(changes)
    return format_vector(parse(format_vector(parts)))


def roundup(value: float) -> float:
    """The specification's Roundup: the smallest one-decimal number >= value."""
    as_int = int(round(value * 100000))
    if as_int % 10000 == 0:
        return as_int / 100000.0
    return (math.floor(as_int / 10000) + 1) / 10.0


def base_score(vector: str) -> float:
    p = parse(vector)
    changed = p["S"] == "C"
    iss = 1 - (1 - _CIA[p["C"]]) * (1 - _CIA[p["I"]]) * (1 - _CIA[p["A"]])
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    pr = (_PR_CHANGED if changed else _PR_UNCHANGED)[p["PR"]]
    exploitability = 8.22 * _AV[p["AV"]] * _AC[p["AC"]] * pr * _UI[p["UI"]]
    if changed:
        return roundup(min(1.08 * (impact + exploitability), 10.0))
    return roundup(min(impact + exploitability, 10.0))


def band(score: float | None) -> str:
    """The specification's qualitative rating (`INFO` stands in for its "None")."""
    if score is None or score <= 0.0:
        return "INFO"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"

"""Shannon entropy helpers for unknown-secret detection."""

from __future__ import annotations

import math
import re

HIGH_ENTROPY_ASSIGNMENT = re.compile(
    r"(?i)(secret|password|token|credential|api[_-]?key|apikey|private[_-]?key|access[_-]?key)\s*[=:]\s*['\"]?([A-Za-z0-9/+._~-]{16,})",
)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def looks_high_entropy(value: str, threshold: float = 4.2) -> bool:
    if len(value) < 16:
        return False
    return shannon_entropy(value) >= threshold


def extract_high_entropy_assignments(line: str) -> list[tuple[str, str]]:
    matches = []
    for match in HIGH_ENTROPY_ASSIGNMENT.finditer(line):
        key, value = match.group(1), match.group(2).strip("'\"")
        if looks_high_entropy(value):
            matches.append((key, value))
    return matches

"""Search outcome classification and the hunt's refinement rules.

After every search the engine — not the model — decides what happened, so
the model gets the same, structured feedback every time:

  INVALID   rg rejected the pattern      -> its error + a concrete fix hint
  ZERO      no matches                    -> one relaxed variant is tried
                                             automatically and reported
  TOO_MANY  more than TOO_MANY_THRESHOLD  -> totals + a per-module histogram
                                             only; the model must narrow
  NOISY     most matches in comments,     -> those are filtered out and the
            tests or generated code          filtering is stated
  OK        a usable, sampled result
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

OUTCOME_OK = "OK"
OUTCOME_INVALID = "INVALID"
OUTCOME_ZERO = "ZERO"
OUTCOME_TOO_MANY = "TOO_MANY"
OUTCOME_NOISY = "NOISY"

TOO_MANY_THRESHOLD = 300
NOISY_FRACTION = 0.70


@dataclass
class SearchStats:
    raw_matches: int  # before filtering
    kept_matches: int  # after dropping comment/test/generated per policy
    comment: int = 0
    test: int = 0
    generated: int = 0
    error: Optional[str] = None


def classify_search(stats: SearchStats) -> str:
    if stats.error:
        return OUTCOME_INVALID
    if stats.raw_matches == 0:
        return OUTCOME_ZERO
    if stats.kept_matches > TOO_MANY_THRESHOLD:
        return OUTCOME_TOO_MANY
    noise = stats.comment + stats.test + stats.generated
    if stats.raw_matches and noise / stats.raw_matches >= NOISY_FRACTION:
        return OUTCOME_NOISY
    return OUTCOME_OK


def relaxed_variants(pattern: str) -> List[str]:
    """Broader rewrites of a pattern that found nothing, most conservative
    first: drop word boundaries/anchors, loosen whitespace around
    punctuation, and fall back to the longest literal identifier in it."""
    variants: List[str] = []
    stripped = re.sub(r"\\b|\^|\$", "", pattern)
    if stripped and stripped != pattern:
        variants.append(stripped)
    loosened = re.sub(r"(\\[.(])", r"\\s*\1", stripped or pattern)
    if loosened not in variants and loosened != pattern:
        variants.append(loosened)
    identifiers = sorted(re.findall(r"[A-Za-z_][A-Za-z0-9_]{3,}", pattern), key=len, reverse=True)
    if identifiers and identifiers[0] not in variants:
        variants.append(identifiers[0])
    return variants[:3]

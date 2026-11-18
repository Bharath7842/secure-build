"""Version comparison and OSV range evaluation (shared by SCA and VEX).

Deliberately dependency-free: a pragmatic tokenizer that orders numeric
segments numerically and treats bare alpha segments (``rc``, ``SNAPSHOT``)
as pre-release markers that sort below the corresponding release.  Every
function returns ``None`` when a version cannot be evaluated — callers must
treat ``None`` as "unknown", never as "not affected" (SSOT §22/§44).
"""

from __future__ import annotations

import re

_SPLIT_RE = re.compile(r"[.\-+_~]|(?<=\d)(?=[A-Za-z])|(?<=[A-Za-z])(?=\d)")

# OSV range types whose ``events`` are version-based (GIT/COMMIT are not).
SEMVER_RANGE_TYPES = frozenset({"SEMVER", "ECOSYSTEM"})


def parse_version(version: str) -> list | None:
    """Tokenize a version into comparable ``int``/``str`` chunks.

    Returns ``None`` for empty or unusable input — constraint strings
    (``">=1.2 <2"``, ``"^1.2.3"``, ``"x.y.*"``) are rejected so callers
    never compare ranges as if they were concrete versions.
    """
    raw = str(version or "").strip()
    if not raw or len(raw) > 200 or " " in raw:
        return None
    if any(ch in raw for ch in "<>!=|^&*"):
        return None
    raw = raw.split("+", 1)[0]  # build metadata never affects ordering
    raw = raw.strip()
    if not raw:
        return None
    tokens: list = []
    for chunk in _SPLIT_RE.split(raw):
        if not chunk:
            continue
        if chunk.isdigit() and len(chunk) <= 12:
            tokens.append(int(chunk))
        else:
            tokens.append(chunk.lower())
    if not tokens:
        return None
    if "*" in raw or raw[0] in "xX":
        return None
    return tokens


def compare_versions(a: str, b: str) -> int | None:
    """-1 / 0 / 1 for ``a`` vs ``b``; ``None`` when either side is unparseable."""
    ta, tb = parse_version(a), parse_version(b)
    if ta is None or tb is None:
        return None
    for x, y in zip(ta, tb):
        if x == y:
            continue
        if isinstance(x, int) and isinstance(y, int):
            return -1 if x < y else 1
        # str vs int: a pre-release marker sorts below a numeric segment.
        if isinstance(x, str) and isinstance(y, int):
            return -1
        return 1
    # One side ran out of tokens: a remaining numeric segment makes the
    # longer version greater (1.2.1 > 1.2); a remaining alpha segment is a
    # pre-release (1.2-rc1 < 1.2).
    if len(ta) == len(tb):
        return 0
    remaining = ta[len(tb):] if len(ta) > len(tb) else tb[len(ta):]
    if isinstance(remaining[0], int):
        return 1 if len(ta) > len(tb) else -1
    return -1 if len(ta) > len(tb) else 1


def versions_equal(a: str, b: str) -> bool | None:
    """Exact equality with a parse fallback; ``None`` when unparseable."""
    if str(a).strip() == str(b).strip():
        return True
    cmp = compare_versions(a, b)
    if cmp is None:
        return None
    return cmp == 0


def _in_events(installed: str, events: list) -> bool | None:
    """Evaluate one OSV range event list; ``None`` = not evaluable."""
    if not events or not isinstance(events, list):
        return None
    vulnerable = False
    evaluable = False
    broken = False
    introduced: str | None = None

    for event in events:
        if not isinstance(event, dict):
            broken = True
            continue
        if "introduced" in event:
            introduced = str(event.get("introduced") or "")
        elif "fixed" in event or "last_affected" in event:
            bound_key = "fixed" if "fixed" in event else "last_affected"
            bound = str(event.get(bound_key) or "")
            if introduced is not None:
                low = compare_versions(installed, introduced)
                high = compare_versions(installed, bound)
                if low is None or high is None:
                    broken = True
                else:
                    evaluable = True
                    if bound_key == "fixed":
                        if low >= 0 and high < 0:
                            vulnerable = True
                    elif low >= 0 and high <= 0:
                        vulnerable = True
            introduced = None
        elif "limit" in event:
            introduced = None

    if vulnerable:
        return True
    if broken and not evaluable:
        return None
    if broken:
        return None
    return False if evaluable else None


def evaluate_affected(installed: str, affected_entries: list[dict]) -> bool | None:
    """Does any OSV ``affected`` entry cover ``installed``?

    ``True`` = vulnerable, ``False`` = outside every range, ``None`` =
    not evaluable (missing/garbled ranges, GIT-only ranges, unparsable
    version).  Entries with neither ``ranges`` nor ``versions`` affect the
    package at every version (OSV semantics).
    """
    if not affected_entries:
        return None
    version = str(installed or "").strip()
    if not version:
        return None

    any_true = False
    any_broken = False

    for entry in affected_entries:
        if not isinstance(entry, dict):
            any_broken = True
            continue
        versions = entry.get("versions") or []
        if isinstance(versions, list):
            for known in versions:
                eq = versions_equal(version, str(known))
                if eq:
                    any_true = True
                    break
                if eq is None:
                    any_broken = True
            if any_true:
                continue

        ranges = entry.get("ranges") or []
        if not ranges and not versions:
            # Affected at every version — no range information means all.
            any_true = True
            continue
        if not isinstance(ranges, list):
            any_broken = True
            continue

        entry_evaluable = False
        entry_broken = False
        for rng in ranges:
            if not isinstance(rng, dict):
                entry_broken = True
                continue
            if rng.get("type") not in SEMVER_RANGE_TYPES:
                entry_broken = True
                continue
            result = _in_events(version, rng.get("events") or [])
            if result is True:
                any_true = True
                entry_evaluable = True
                break
            if result is None:
                entry_broken = True
            else:
                entry_evaluable = True
        if entry_evaluable:
            any_broken = any_broken and not any_true
        if entry_broken:
            any_broken = True

    if any_true:
        return True
    if any_broken:
        return None
    return False


def fixed_versions_of(affected_entries: list[dict]) -> list[str]:
    """All ``fixed`` boundaries declared for the matching entries, ordered."""
    fixed: list[str] = []
    for entry in affected_entries:
        if not isinstance(entry, dict):
            continue
        for rng in entry.get("ranges") or []:
            if not isinstance(rng, dict):
                continue
            for event in rng.get("events") or []:
                if isinstance(event, dict) and event.get("fixed"):
                    value = str(event["fixed"])
                    if value not in fixed:
                        fixed.append(value)
    return fixed


def first_fixed_above(current: str, fixed_versions: list[str]) -> str | None:
    """Smallest declared fixed version greater than ``current`` (Rule 3)."""
    best: str | None = None
    for candidate in fixed_versions:
        cmp = compare_versions(candidate, current)
        if cmp is None or cmp <= 0:
            continue
        if best is None:
            best = candidate
            continue
        ordering = compare_versions(candidate, best)
        if ordering is not None and ordering < 0:
            best = candidate
    return best

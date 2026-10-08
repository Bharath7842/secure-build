"""Scan-to-scan diff (DAST-11-020): pure.

Findings are compared on `(check id, endpoint path template, parameter)` between a scan and an
earlier one of the same project and target (an authorization finding also carries its role pair, so
two role pairs exposed on one endpoint are two issues). Each finding is labelled:

    new          present now, absent before
    still_open   present in both
    fixed        present before, absent now

A check that did not run in one of the scans must not be read as a fix: a finding from the earlier
scan whose check did not run in this one is listed as `not_comparable`, never as fixed, and a new
finding from a check the earlier scan did not run is marked as such. Unverified findings are diffed
on the same key with their verdict shown; they are not hidden.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Collection, Iterable, Sequence

from .dedupe import DedupeKey, key_for
from .entities import Finding

_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class DiffStatus(str, Enum):
    NEW = "new"
    FIXED = "fixed"
    STILL_OPEN = "still_open"


@dataclass(frozen=True)
class DiffItem:
    """A finding reduced to what the diff needs."""

    check_id: str
    target: str  # "METHOD path"
    param: str | None
    severity: str = ""
    verdict: str = ""
    roles: tuple[str, ...] = ()
    finding_id: str = ""
    title: str = ""


@dataclass(frozen=True)
class DiffEntry:
    key: DedupeKey
    status: DiffStatus
    item: DiffItem | None = None  # the current finding, or for `fixed` the earlier one
    note: str = ""


@dataclass(frozen=True)
class NotComparable:
    item: DiffItem
    reason: str


@dataclass
class DiffResult:
    baseline: bool  # False: no earlier scan, so everything is new
    entries: list[DiffEntry] = field(default_factory=list)
    not_comparable: list[NotComparable] = field(default_factory=list)
    checks_not_run_current: list[str] = field(default_factory=list)  # run before, not now
    checks_not_run_previous: list[str] = field(default_factory=list)  # run now, not before

    def counts(self) -> dict[str, int]:
        return {s.value: sum(1 for e in self.entries if e.status is s) for s in DiffStatus}


DiffFn = Callable[[Sequence[Finding], Sequence[Finding]], Sequence[DiffEntry]]


def item_key(item: DiffItem) -> DedupeKey:
    """`(check, path template, param)`; the role pair is folded into the parameter part for an
    authorization finding."""
    param = item.param or ""
    if item.roles:
        param = f"{param}@{'>'.join(item.roles)}"
    return key_for(item.check_id, item.target, param or None)


def item_from_finding(finding: Finding, finding_id: str = "") -> DiffItem:
    return DiffItem(finding.check_id, finding.target, finding.param, finding.severity.value, finding.verdict.value, tuple(finding.roles), finding_id)


def _order(entry: DiffEntry) -> tuple:
    item = entry.item
    return (_SEVERITY_RANK.get((item.severity if item else "").upper(), 5), entry.key)


def compute_diff(
    current: Iterable[DiffItem],
    previous: Iterable[DiffItem] | None,
    *,
    current_checks_run: Collection[str] | None = None,
    previous_checks_run: Collection[str] | None = None,
) -> DiffResult:
    """Classify `current` against `previous` (None = no earlier scan). `*_checks_run` are the check
    ids each scan actually ran; None means unknown, which is taken as "all of them"."""
    cur = {}
    for item in current:
        cur.setdefault(item_key(item), item)
    if previous is None:
        entries = [DiffEntry(k, DiffStatus.NEW, i, "no earlier scan to compare with") for k, i in cur.items()]
        return DiffResult(False, sorted(entries, key=_order))
    prev = {}
    for item in previous:
        prev.setdefault(item_key(item), item)

    ran_now = None if current_checks_run is None else set(current_checks_run)
    ran_before = None if previous_checks_run is None else set(previous_checks_run)
    result = DiffResult(True)
    if ran_now is not None and ran_before is not None:
        result.checks_not_run_current = sorted(ran_before - ran_now)
        result.checks_not_run_previous = sorted(ran_now - ran_before)

    for key, item in cur.items():
        if key in prev:
            result.entries.append(DiffEntry(key, DiffStatus.STILL_OPEN, item))
        else:
            note = "the earlier scan did not run this check" if ran_before is not None and item.check_id not in ran_before else ""
            result.entries.append(DiffEntry(key, DiffStatus.NEW, item, note))
    for key, item in prev.items():
        if key in cur:
            continue
        if ran_now is not None and item.check_id not in ran_now:
            result.not_comparable.append(NotComparable(item, "this check did not run in the current scan, so the finding cannot be called fixed"))
        else:
            result.entries.append(DiffEntry(key, DiffStatus.FIXED, item))
    result.entries.sort(key=lambda e: (list(DiffStatus).index(e.status), *_order(e)))
    result.not_comparable.sort(key=lambda n: (n.item.check_id, n.item.target))
    return result

"""Verdict roll-up (DAST-04-040): pure functions, no model, no I/O.

Per target: any FAIL -> FAIL; otherwise PASS. INCONCLUSIVE is treated as PASS, so a check the
model did not call a failure is never stored at all. `to_finding_verdict` here only ever maps
FAIL to a confirmed `true_positive`; it is the mapping used when a detector signal itself proved
the check (`guardrail.apply_guardrail`'s signal-present branch). A model FAIL with no supporting
signal is a check-level FAIL too, but the guardrail (not this module) hands that case its own
`FindingVerdict.UNVERIFIED` directly, bypassing this function, so a finding with no proof behind
it still gets stored, but as "needs review" rather than silently absent or auto-confirmed.

    FAIL -> true_positive      PASS / INCONCLUSIVE -> no finding
"""

from __future__ import annotations

from typing import Iterable

from .entities import CheckVerdict, FindingVerdict


def roll_up(verdicts: Iterable[CheckVerdict]) -> CheckVerdict:
    seen = {CheckVerdict(v) for v in verdicts}
    if CheckVerdict.FAIL in seen:
        return CheckVerdict.FAIL
    return CheckVerdict.PASS


def to_finding_verdict(verdict: CheckVerdict) -> FindingVerdict | None:
    """The verdict stored on a finding row, or None when there is no finding to store.

    FAIL is a confirmed issue (the model's FAIL, or a detector signal). PASS
    (and leftover INCONCLUSIVE) is not stored, so nothing sits unverified.
    """
    verdict = CheckVerdict(verdict)
    if verdict is CheckVerdict.FAIL:
        return FindingVerdict.TRUE_POSITIVE
    return None

"""The guardrail (DAST-04-040): detectors can raise a PASS to FAIL; they never hide a FAIL.

The model proposes PASS or FAIL for a check (INCONCLUSIVE is accepted from older replies
and treated as PASS). What is recorded:

* proving signal present                -> FAIL, true_positive (overrides a proposed PASS: a
                                            proving signal is definitionally proof, so it is never
                                            weakened even when the model disagreed)
* proposed FAIL, no proving signal      -> FAIL, but unverified: the model's call stands as the
                                            check's verdict, but nothing proves it, so the finding
                                            needs a human to confirm it rather than being auto-filed
                                            as a true positive
* otherwise the proposal stands as PASS (no finding)

So a `true_positive` always comes from a detector signal; a model FAIL with no signal is recorded
too, but as `unverified`, not silently dropped and not auto-confirmed either. Every override is
returned with its reason so the report can show it, and `override_rate` turns a batch of outcomes
into the model-quality metric EPIC-16 tracks.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

from .entities import CheckVerdict, DetectorSignal, FindingVerdict
from .verdict import to_finding_verdict


@dataclass(frozen=True)
class GuardrailOutcome:
    verdict: CheckVerdict  # the final per-check result
    finding_verdict: FindingVerdict | None  # what is stored; None means no finding
    signals: tuple[DetectorSignal, ...] = ()  # the proving signals that support `verdict`
    proposed: CheckVerdict = CheckVerdict.PASS
    downgraded: bool = False  # unused: a FAIL is never demoted
    overridden: bool = False  # a proposed PASS was raised to FAIL by a signal
    reason: str = ""

    @property
    def changed(self) -> bool:
        return self.downgraded or self.overridden


def apply_guardrail(
    proposed: CheckVerdict,
    observed: Sequence[DetectorSignal],
    proving_signals: Iterable[str],
) -> GuardrailOutcome:
    """Combine the model's proposed verdict with the detectors' observations."""
    proposed = CheckVerdict(proposed)
    if proposed is CheckVerdict.INCONCLUSIVE:
        proposed = CheckVerdict.PASS
    proving = frozenset(proving_signals)
    supporting = tuple(s for s in observed if s.name in proving)

    if supporting:
        names = ", ".join(sorted({s.name for s in supporting}))
        overridden = proposed is not CheckVerdict.FAIL
        reason = (
            f"proposed {proposed.value} but proving signal observed ({names}); recorded as FAIL"
            if overridden
            else f"confirmed by proving signal ({names})"
        )
        return GuardrailOutcome(
            CheckVerdict.FAIL, to_finding_verdict(CheckVerdict.FAIL), supporting, proposed, overridden=overridden, reason=reason
        )

    if proposed is CheckVerdict.FAIL:
        return GuardrailOutcome(
            CheckVerdict.FAIL,
            FindingVerdict.UNVERIFIED,
            (),
            proposed,
            reason="model judged FAIL but no proving signal was observed; needs review",
        )
    return GuardrailOutcome(CheckVerdict.PASS, to_finding_verdict(CheckVerdict.PASS), (), proposed, reason="no proving signal observed")


# The browser probe confirms a finding only when the marker actually ran. A sink hit or stored
# markup that did not run is a lead (`unverified`); neither becomes a true positive here.
_BROWSER_PROVING = frozenset({"marker_executed_in_browser"})
_BROWSER_LEAD = frozenset({"marker_reaches_dom_sink", "marker_persisted_unescaped"})


def browser_finding_verdict(observed: Sequence[DetectorSignal]) -> FindingVerdict | None:
    """Verdict for a browser-probe observation. A true positive needs an execution signal."""
    names = {s.name for s in observed}
    if names & _BROWSER_PROVING:
        return FindingVerdict.TRUE_POSITIVE
    if names & _BROWSER_LEAD:
        return FindingVerdict.UNVERIFIED
    return None


def override_rate(outcomes: Iterable[GuardrailOutcome]) -> float:
    """Share of outcomes where the guardrail changed the model's proposal (0.0 for none)."""
    outcomes = list(outcomes)
    if not outcomes:
        return 0.0
    return sum(1 for o in outcomes if o.changed) / len(outcomes)

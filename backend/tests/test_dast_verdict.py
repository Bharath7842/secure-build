"""DAST-04-040: verdict roll-up and the guardrail."""

from __future__ import annotations

import itertools

import pytest

from app.dast.domain.entities import CheckVerdict as V
from app.dast.domain.entities import DetectorSignal, FindingVerdict
from app.dast.domain.guardrail import apply_guardrail, override_rate
from app.dast.domain.verdict import roll_up, to_finding_verdict

pytestmark = pytest.mark.unit

P, F, I = V.PASS, V.FAIL, V.INCONCLUSIVE


@pytest.mark.parametrize(
    "verdicts, expected",
    [
        ([F], F), ([P, F, I], F), ([I, F], F),
        ([I], P), ([I, I, I], P),
        ([P], P), ([P, P], P), ([P, I], P), ([I, P, I], P),
        ([], P),
    ],
)
def test_roll_up_truth_table(verdicts, expected):
    assert roll_up(verdicts) is expected


def test_mapping_to_stored_verdict():
    assert to_finding_verdict(F) is FindingVerdict.TRUE_POSITIVE
    assert to_finding_verdict(I) is None
    assert to_finding_verdict(P) is None


def sig(*names):
    return [DetectorSignal(n) for n in names]


def test_fail_without_signal_keeps_the_models_fail_but_unverified():
    out = apply_guardrail(F, [], ["db_error_surfaced"])
    # The check-level verdict still stands as FAIL, but with nothing proving it the stored
    # finding is unverified (needs review), not auto-confirmed as a true positive.
    assert out.verdict is F and out.finding_verdict is FindingVerdict.UNVERIFIED
    assert not out.downgraded and not out.overridden and "FAIL" in out.reason


def test_fail_with_an_unrelated_signal_still_keeps_fail():
    out = apply_guardrail(F, sig("stack_trace_leaked"), ["db_error_surfaced"])
    assert out.verdict is F and not out.downgraded and out.signals == ()


def test_pass_with_signal_is_overridden_to_fail():
    out = apply_guardrail(P, sig("db_error_surfaced"), ["db_error_surfaced", "stack_trace_leaked"])
    assert out.verdict is F and out.finding_verdict is FindingVerdict.TRUE_POSITIVE
    assert out.overridden and not out.downgraded and out.signals == tuple(sig("db_error_surfaced"))


def test_inconclusive_with_signal_is_raised_and_confirmed_fail_is_not_flagged():
    assert apply_guardrail(I, sig("time_delta"), ["time_delta"]).overridden
    confirmed = apply_guardrail(F, sig("time_delta"), ["time_delta"])
    assert confirmed.verdict is F and not confirmed.changed and "confirmed" in confirmed.reason


def test_pass_and_inconclusive_without_signals_are_not_findings():
    assert apply_guardrail(P, [], ["x"]).finding_verdict is None
    assert apply_guardrail(I, [], ["x"]).verdict is P and apply_guardrail(I, [], ["x"]).finding_verdict is None


def test_a_check_with_no_proving_signals_can_still_fail_when_the_model_says_so_but_unverified():
    out = apply_guardrail(F, [], [])
    assert out.verdict is F and out.finding_verdict is FindingVerdict.UNVERIFIED


def test_property_true_positive_needs_a_signal_model_alone_is_unverified():
    """Exhaustive: a proving signal always FAILs and is confirmed; a model FAIL with no
    signal still FAILs but is unverified; otherwise the (normalized) proposal stands as PASS."""
    universe = ["a", "b", "c"]
    subsets = [list(c) for n in range(len(universe) + 1) for c in itertools.combinations(universe, n)]
    checked = 0
    for proposed, observed, proving in itertools.product(V, subsets, subsets):
        out = apply_guardrail(proposed, sig(*observed), proving)
        supporting = set(observed) & set(proving)
        if supporting:
            assert out.verdict is F
            assert out.finding_verdict is FindingVerdict.TRUE_POSITIVE
        elif proposed is F:
            assert out.verdict is F and out.finding_verdict is FindingVerdict.UNVERIFIED
        else:
            assert out.verdict is P and out.finding_verdict is None
        checked += 1
    assert checked == 3 * 8 * 8


def test_override_rate():
    outs = [apply_guardrail(F, [], ["a"]), apply_guardrail(P, sig("a"), ["a"]), apply_guardrail(P, [], ["a"]), apply_guardrail(F, sig("a"), ["a"])]
    assert override_rate(outs) == 0.25  # only the PASS-with-signal is an override
    assert override_rate([]) == 0.0

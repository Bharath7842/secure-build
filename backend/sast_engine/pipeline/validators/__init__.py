"""The occurrence validator hook (SAST-01-020).

One place to plug deterministic per-occurrence checks into the pipeline, with a
fixed rule for how their proofs rank against a model verdict. The hook runs on
every occurrence — regex hits after triage creates them, deep-scan findings
after ``normalize_finding``, flow-verify findings before publish — always
*before* grouping and before group confirmation, so a group never has to guess
what a member's own structure says.

PRECEDENCE (fixed, covered by tests)::

    validator          model verdict   result
    -----------------  --------------  -------------------------------------------
    negative proof     any             false_positive; verdict_reason = the proof;
                                       reason_tag set
    positive fact      false_positive  unverified / conflict; both reasons kept
    positive fact      true_positive   unchanged; the proof is kept as evidence
                       or none
    evidence gap       any             unverified / evidence_missing; what is
                                       missing is named
    no opinion         any             unchanged

If several validators answer, the order is negative proof, then positive fact,
then evidence gap. A regex hit with a negative proof is still written as a row
(``kind=regex``, false positive): it is never dropped, so the report shows the
scanner looked at it.

A validator must never return a negative proof based on a rule name, a file
path, a logger spelling or a severity (review §9.4 gate 2) — see ``base`` for
the template.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from llm_client import bump_counter

from .base import (
    GAP,
    NEGATIVE,
    NO_OPINION,
    POSITIVE,
    ValidatorContext,
    ValidatorFn,
    ValidatorResult,
    evidence_gap,
    negative_proof,
    no_opinion,
    positive_fact,
)

VERDICT_TP = "true_positive"
VERDICT_FP = "false_positive"
VERDICT_UNVERIFIED = "unverified"
MAX_OUTCOMES_PER_FINDING = 4

__all__ = [
    "GAP", "NEGATIVE", "NO_OPINION", "POSITIVE", "ValidatorContext", "ValidatorResult",
    "apply_precedence", "apply_validators", "evidence_gap", "negative_proof", "no_opinion",
    "positive_fact", "register", "registered", "reapply_precedence", "render_deterministic_facts",
    "run_validators",
]


@dataclass(frozen=True)
class Validator:
    name: str
    version: int
    fn: ValidatorFn
    rule_ids: Tuple[str, ...] = ()
    rule_prefixes: Tuple[str, ...] = ()
    cwes: Tuple[int, ...] = ()

    @property
    def actor(self) -> str:
        return f"{self.name}@{self.version}"

    def matches(self, finding: Dict[str, Any]) -> bool:
        rule_id = str(finding.get("rule_id") or "")
        if rule_id and (rule_id in self.rule_ids or rule_id.startswith(self.rule_prefixes or ("\0",))):
            return True
        if self.cwes:
            digits = "".join(ch for ch in str(finding.get("cwe") or "") if ch.isdigit())
            if digits and int(digits) in self.cwes:
                return True
        return False


_REGISTRY: List[Validator] = []


def register(
    name: str,
    version: int = 1,
    *,
    rule_ids: Sequence[str] = (),
    rule_prefixes: Sequence[str] = (),
    cwes: Sequence[int] = (),
) -> Callable[[ValidatorFn], ValidatorFn]:
    """Register ``fn`` for findings of the given rule ids (exact), rule id
    prefixes and/or CWE numbers. At least one selector is required: a validator
    that runs on everything would be a rule-blind check."""
    if not (rule_ids or rule_prefixes or cwes):
        raise ValueError(f"validator {name!r} must register for a rule id, a prefix or a CWE")

    def decorator(fn: ValidatorFn) -> ValidatorFn:
        _REGISTRY.append(Validator(
            name=name, version=version, fn=fn, rule_ids=tuple(rule_ids),
            rule_prefixes=tuple(rule_prefixes), cwes=tuple(cwes),
        ))
        return fn

    return decorator


def registered() -> List[Validator]:
    return list(_REGISTRY)


def run_validators(
    finding: Dict[str, Any],
    facts: Optional[Dict[str, Any]],
    ctx: ValidatorContext,
    *,
    validators: Optional[Sequence[Validator]] = None,
) -> List[Tuple[Validator, ValidatorResult]]:
    """Every matching validator's answer for one occurrence, registration order.
    A validator that raises counts as having no opinion: a bug in a check must
    never fail a scan or dismiss a finding."""
    out: List[Tuple[Validator, ValidatorResult]] = []
    for validator in (_REGISTRY if validators is None else validators):
        if not validator.matches(finding):
            continue
        try:
            result = validator.fn(finding, facts, ctx)
        except Exception:  # noqa: BLE001
            result = no_opinion()
        if not isinstance(result, ValidatorResult):
            result = no_opinion()
        out.append((validator, result))
    return out


def _outcome_dict(validator: Validator, result: ValidatorResult) -> Dict[str, Any]:
    out: Dict[str, Any] = {"validator": validator.name, "version": validator.version,
                           "outcome": result.outcome}
    if result.reason_tag:
        out["reason_tag"] = result.reason_tag
    if result.proof:
        out["proof"] = result.proof
    if result.missing:
        out["missing"] = result.missing
    return out


def _settle(finding: Dict[str, Any], outcomes: Sequence[Dict[str, Any]], *, record: bool) -> bool:
    """Apply the precedence table to ``finding`` in place; True if its verdict
    or reason changed. ``record`` appends the step to ``finding["decisions"]``
    (the findings writer turns those into history rows)."""
    verdict = finding.get("verdict")
    negatives = [o for o in outcomes if o["outcome"] == NEGATIVE]
    positives = [o for o in outcomes if o["outcome"] == POSITIVE]
    gaps = [o for o in outcomes if o["outcome"] == GAP]
    changed = False
    decisive: Optional[Dict[str, Any]] = None

    if negatives:
        decisive = negatives[0]
        finding.update(
            verdict=VERDICT_FP, verdict_reason=decisive.get("proof") or "Deterministic proof.",
            reason_tag=decisive.get("reason_tag"), unresolved_reason=None,
            confidence=None, ai_fix=None,
        )
        changed = verdict != VERDICT_FP
    elif positives and verdict == VERDICT_FP:
        decisive = positives[0]
        model_reason = finding.get("verdict_reason") or "No reason provided by the model."
        finding.update(
            verdict=VERDICT_UNVERIFIED, unresolved_reason="conflict", confidence=None, ai_fix=None,
            verdict_reason=(
                f"The model dismissed this ({model_reason}), but a deterministic fact "
                f"disagrees: {decisive.get('proof')}"
            ),
        )
        changed = True
    elif gaps and not positives:
        decisive = gaps[0]
        note = f"Evidence missing: {decisive.get('missing')}"
        prior = (finding.get("verdict_reason") or "").strip()
        finding.update(
            verdict=VERDICT_UNVERIFIED, unresolved_reason="evidence_missing", confidence=None,
            ai_fix=None,
            verdict_reason=note if not prior or verdict == VERDICT_UNVERIFIED and prior.startswith("Regex")
            else f"{prior} — {note}",
        )
        changed = True
    elif positives:
        decisive = positives[0]

    if record and decisive is not None:
        finding.setdefault("decisions", []).append({
            "stage": "validator",
            "actor": f"{decisive.get('validator')}@{decisive.get('version')}",
            "verdict": finding.get("verdict"),
            "confidence": finding.get("confidence"),
            "unresolved_reason": finding.get("unresolved_reason"),
            "verdict_reason": finding.get("verdict_reason"),
            "detail": {k: decisive[k] for k in ("outcome", "reason_tag", "proof", "missing") if k in decisive},
        })
    return changed


def apply_precedence(
    finding: Dict[str, Any],
    results: Sequence[Tuple[Validator, ValidatorResult]],
    *,
    usage: Optional[Dict[str, Any]] = None,
) -> bool:
    """Record the validators' answers on the finding (``facts["validators"]``,
    so group confirmation can re-apply them) and settle its verdict. Counts
    each outcome under ``usage_summary.validators``."""
    outcomes: List[Dict[str, Any]] = []
    for validator, result in results:
        bump_counter(usage, "validators", f"{validator.name}.{result.outcome}")
        if result.outcome != NO_OPINION:
            outcomes.append(_outcome_dict(validator, result))
    if not outcomes:
        return False
    outcomes = outcomes[:MAX_OUTCOMES_PER_FINDING]
    facts = finding.get("facts")
    if not isinstance(facts, dict):
        facts = finding["facts"] = {}
    facts["validators"] = outcomes
    return _settle(finding, outcomes, record=True)


def reapply_precedence(finding: Dict[str, Any]) -> bool:
    """Re-run the precedence table with the outcomes already stored on a finding,
    after a later stage (group confirmation) set a new model verdict. Writes no
    history row of its own: the stage that set the verdict records the change."""
    facts = finding.get("facts")
    outcomes = facts.get("validators") if isinstance(facts, dict) else None
    if not outcomes:
        return False
    return _settle(finding, outcomes, record=False)


def apply_validators(
    findings: Sequence[Dict[str, Any]],
    source_text: str,
    *,
    file_path: str = "",
    usage: Optional[Dict[str, Any]] = None,
    ctx: Optional[ValidatorContext] = None,
) -> int:
    """Run the registry on one file's findings; returns how many were changed."""
    if not _REGISTRY:
        return 0
    path = file_path
    ctx = ctx or ValidatorContext()
    changed = 0
    for finding in findings:
        fpath = finding.get("file_path") or path
        if fpath and fpath not in ctx.file_text:
            ctx.file_text[fpath] = source_text
        facts = finding.get("facts") if isinstance(finding.get("facts"), dict) else None
        results = run_validators(finding, facts, ctx)
        if results and apply_precedence(finding, results, usage=usage):
            changed += 1
    return changed


def render_deterministic_facts(
    findings: Sequence[Dict[str, Any]], *, labels: Optional[Sequence[str]] = None
) -> str:
    """The ``Deterministic facts:`` block for a prompt: what validators proved
    or could not resolve about these occurrences. Empty string when there is
    nothing to say, so a finding with nothing to add keeps a byte-identical
    prompt (and its cache entry). ``labels`` names each finding the way the
    prompt does (m1, m2, ...); the default is its position."""
    lines: List[str] = []
    for position, finding in enumerate(findings):
        label = labels[position] if labels else str(position + 1)
        facts = finding.get("facts") if isinstance(finding.get("facts"), dict) else None
        for outcome in (facts or {}).get("validators") or []:
            if outcome["outcome"] == POSITIVE:
                lines.append(f"- {label}: {outcome.get('proof')}")
            elif outcome["outcome"] == GAP:
                lines.append(f"- {label}: not resolved — {outcome.get('missing')}")
            elif outcome["outcome"] == NEGATIVE:
                lines.append(f"- {label}: ruled out — {outcome.get('proof')}")
        for note in finding.get("contradictions") or []:
            lines.append(f"- {label}: {note['detail'] if isinstance(note, dict) else note}")
    if not lines:
        return ""
    return "Deterministic facts:\n" + "\n".join(lines)


# The shipped validators. Imported last: they register themselves on import.
# Order matters — the first negative proof wins, so `stub_method` (a stub has no
# sink at all) is consulted before `declaration_not_call`.
from . import stub_method as _stub_method  # noqa: E402,F401
from . import declaration_not_call as _declaration_not_call  # noqa: E402,F401

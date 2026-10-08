"""Scoring (DAST-16-010): findings against ground truth. Pure.

* A **confirmed** finding (`true_positive`) that matches an expectation on `(check, endpoint template,
  parameter)` is a true positive; one that matches nothing, and is not in an excluded area, is a false
  positive; an expectation nothing matched is a false negative.
* **Unverified** findings are scored separately and are never true positives: they are counted as
  `unverified_matching` (they point at an expected issue, so a human would find it) or
  `unverified_other`.
* precision = TP / (TP + FP) and recall = TP / (TP + FN); an empty denominator gives 1.0 (nothing was
  claimed wrongly / nothing was expected), a convention the gate relies on and the tests pin.
* guardrail-override rate = how often deterministic code changed the model's proposed verdict.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

from app.dast.domain.dedupe import key_for

from .ground_truth import GroundTruth

RESULT_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class FindingRef:
    check_id: str
    target: str  # "METHOD path"
    param: str | None
    verdict: str
    roles: tuple[str, ...] = ()

    @property
    def key(self) -> tuple:
        return key_for(self.check_id, self.target, self.param or None)

    def label(self) -> str:
        return f"{self.check_id} {self.target}" + (f" [{self.param}]" if self.param else "")


def findings_from_api(payload: Mapping[str, Any]) -> list[FindingRef]:
    """FindingRefs from a `GET /scans/{id}/findings` response (the DAST shape)."""
    out = []
    for f in payload.get("findings") or []:
        out.append(FindingRef(str(f.get("rule_id") or ""), str(f.get("target") or f.get("file_path") or ""), f.get("param"), str(f.get("verdict") or ""), tuple(f.get("roles") or ())))
    return out


@dataclass
class Score:
    target: str
    true_positives: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    false_negatives: list[str] = field(default_factory=list)
    unverified_matching: list[str] = field(default_factory=list)
    unverified_other: list[str] = field(default_factory=list)
    skipped_expectations: list[str] = field(default_factory=list)  # expectations whose needs the scan did not meet

    @property
    def precision(self) -> float:
        tp, fp = len(self.true_positives), len(self.false_positives)
        return tp / (tp + fp) if tp + fp else 1.0

    @property
    def recall(self) -> float:
        tp, fn = len(self.true_positives), len(self.false_negatives)
        return tp / (tp + fn) if tp + fn else 1.0


def score(findings: Sequence[FindingRef], truth: GroundTruth, *, available: Iterable[str] = ("state_changing", "second_identity", "oast", "schema", "browser_probe")) -> Score:
    """Score `findings`. Expectations needing something the scan was not given (`available`) are
    set aside as skipped rather than counted as misses."""
    have = set(available)
    result = Score(truth.target)
    expected = {}
    for e in truth.expected:
        if set(e.needs) - have:
            result.skipped_expectations.append(f"{e.check_id} {e.endpoint}" + (f" [{e.param}]" if e.param else ""))
        else:
            expected[e.key] = e
    matched: set = set()
    seen: set = set()
    for ref in findings:
        key = ref.key
        confirmed = ref.verdict == "true_positive"
        if (key, confirmed) in seen:  # one issue seen several times counts once
            continue
        seen.add((key, confirmed))
        if ref.verdict == "false_positive":
            continue
        if confirmed:
            if key in expected:
                if key not in matched:
                    matched.add(key)
                    result.true_positives.append(ref.label())
            else:
                result.false_positives.append(ref.label())
        else:
            (result.unverified_matching if key in expected else result.unverified_other).append(ref.label())
    result.false_negatives = [f"{e.check_id} {e.endpoint}" + (f" [{e.param}]" if e.param else "") for k, e in expected.items() if k not in matched]
    for bucket in ("true_positives", "false_positives", "false_negatives", "unverified_matching", "unverified_other", "skipped_expectations"):
        getattr(result, bucket).sort()
    return result


def guardrail_override_rate(discovery: Mapping[str, Any]) -> float:
    """Share of tested checks where the guardrail downgraded or overrode the model's proposal."""
    checks = [c for a in discovery.get("api_analysis") or [] for c in a.get("checks") or []]
    if not checks:
        return 0.0
    changed = sum(1 for c in checks if (c.get("guardrail") or {}).get("downgraded") or (c.get("guardrail") or {}).get("overridden"))
    return round(changed / len(checks), 4)


def build_result(
    score_: Score,
    truth: GroundTruth,
    *,
    scan_id: str = "",
    duration_s: float = 0.0,
    cost_usd: float = 0.0,
    override_rate: float = 0.0,
    pack_ids: Sequence[str] = (),
    notes: Sequence[str] = (),
) -> dict[str, Any]:
    """The JSON result the harness writes and the gate reads."""
    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "target": score_.target,
        "image": truth.image,
        "ground_truth_verified": truth.verified,
        "scan_id": scan_id,
        "true_positives": score_.true_positives,
        "false_positives": score_.false_positives,
        "false_negatives": score_.false_negatives,
        "unverified": {"matching_expected": score_.unverified_matching, "other": score_.unverified_other},
        "skipped_expectations": score_.skipped_expectations,
        "counts": {
            "true_positives": len(score_.true_positives), "false_positives": len(score_.false_positives), "false_negatives": len(score_.false_negatives),
            "unverified": len(score_.unverified_matching) + len(score_.unverified_other),
        },
        "precision": round(score_.precision, 4),
        "recall": round(score_.recall, 4),
        "guardrail_override_rate": override_rate,
        "duration_s": round(duration_s, 1),
        "model_cost_usd": round(cost_usd, 6),
        "rule_packs": list(pack_ids),
        "notes": list(notes),
    }


def summary_text(result: Mapping[str, Any]) -> str:
    c = result["counts"]
    lines = [
        f"DAST harness result: {result['target']}" + ("" if result.get("ground_truth_verified") else "  (ground truth NOT verified: indicative only)"),
        f"  true positives  {c['true_positives']:>3}    false positives {c['false_positives']:>3}    false negatives {c['false_negatives']:>3}",
        f"  precision {result['precision']:.2%}   recall {result['recall']:.2%}   unverified (not scored as hits) {c['unverified']}",
        f"  guardrail override rate {result['guardrail_override_rate']:.1%}   duration {result['duration_s']}s   model cost ${result['model_cost_usd']:.4f}",
    ]
    for label, key in (("missed", "false_negatives"), ("false alarms", "false_positives")):
        if result[key]:
            lines.append(f"  {label}:")
            lines += [f"    - {item}" for item in result[key]]
    if result.get("skipped_expectations"):
        lines.append("  not attempted (the scan was not given what they need):")
        lines += [f"    - {item}" for item in result["skipped_expectations"]]
    return "\n".join(lines)

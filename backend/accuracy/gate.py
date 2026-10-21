"""The accuracy release gate (SAST-00-100): the library behind `scripts/accuracy/gate.py`.

Five gates, from the accuracy review's §9.4. Gates 1-3 count only `adjudicated`
cases (a second reviewer agreed with the label) and skip cases marked `xfail` (a
known gap); gates 4 and 5 are about defects, not labels, so they cover every case:

  1. Preservation  — a `positive` case's expected true positive is missing or no
                     longer a true positive.
  2. Negatives     — a `negative` case is not a false positive, its reason tag does
                     not match, or it vanished because the rule stopped firing
                     (unless the case allows `absent`).
  3. Uncertainty   — an `uncertain` case resolved to true or false positive instead
                     of `unverified` with the expected unresolved reason.
  4. Consistency   — `check_report_consistency` reports a contradiction between the
                     API counts, the Excel export and the PDF of a corpus scan.
  5. No regression — against the committed baseline, an occurrence moved from true
                     positive to false positive or to absent. This holds even for an
                     `xfail` case, which is how a known gap is kept from getting worse.

The gate is a thin orchestrator: it scans with `accuracy.runner`, checks with
`scan_export.check_report_consistency` and compares with `decision_diff.diff` — no
logic is duplicated. It makes no live LLM call; a prompt change fails with
"unrecorded LLM call" until responses are re-recorded and a reviewer accepts them.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from accuracy.case import Case
from accuracy.runner import CaseResult

GATES = {
    1: "Preservation",
    2: "Negatives",
    3: "Uncertainty",
    4: "Consistency",
    5: "No positive → false-positive regression",
}
BASELINE_VERSION = 1
_BASELINE_FIELDS = ("occurrence_id", "rule_id", "file_path", "line", "verdict", "issue_class", "unresolved_reason")


@dataclass
class GateFailure:
    gate: int
    case_id: str
    message: str


@dataclass
class GateReport:
    failures: list[GateFailure] = field(default_factory=list)
    gated: list[str] = field(default_factory=list)       # adjudicated, counted by gates 1-3
    not_gated: list[str] = field(default_factory=list)   # dev_label_only: reported, never blocking
    known_gaps: list[str] = field(default_factory=list)  # xfail: reported, not blocking gates 1-3
    notes: list[str] = field(default_factory=list)

    def failed(self, gate: int) -> bool:
        return any(f.gate == gate for f in self.failures)

    @property
    def passed(self) -> bool:
        return not self.failures


# --- baseline -----------------------------------------------------------------

def baseline_from_results(results: list[CaseResult]) -> dict[str, Any]:
    """What a green run looks like, per case, for gate 5."""
    return {
        "version": BASELINE_VERSION,
        "cases": {
            r.case_id: {"findings": [{k: f.get(k) for k in _BASELINE_FIELDS} for f in r.findings]}
            for r in results
            if not r.error and not r.unrecorded
        },
    }


def load_baseline(path: Path | None) -> dict[str, Any] | None:
    if path is None or not path.is_file():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("version") != BASELINE_VERSION:
        raise ValueError(f"{path}: unsupported baseline version {data.get('version')!r}")
    return data


def write_baseline(path: Path, baseline: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(baseline, indent=2, sort_keys=True) + "\n", encoding="utf-8")


# --- the gates ----------------------------------------------------------------

def _cannot_run(result: CaseResult) -> str | None:
    if result.unrecorded:
        return "; ".join(result.unrecorded)
    if result.error:
        return f"the case failed to run: {result.error}"
    return None


def _check_adjudicated(case: Case, result: CaseResult, report: GateReport) -> None:
    """Gates 1-3 for one adjudicated, non-xfail case."""
    reason = _cannot_run(result)
    gate = {"positive": 1, "negative": 2, "uncertain": 3}[case.polarity]
    if reason:
        report.failures.append(GateFailure(gate, case.id, reason))
        return
    for outcome in result.outcomes:
        expected, problems, actual = outcome["expected"], outcome["problems"], outcome["actual"]
        label = outcome["label"]
        if case.polarity == "positive" and expected.verdict == "true_positive":
            if "missing" in problems:
                report.failures.append(GateFailure(1, case.id, f"{label}: the expected true positive is missing"))
            elif "verdict" in problems:
                report.failures.append(GateFailure(
                    1, case.id, f"{label}: expected true_positive, got {actual['verdict']}"))
        elif case.polarity == "negative" and expected.verdict == "false_positive":
            if "missing" in problems:
                if not case.allow_absent:
                    report.failures.append(GateFailure(
                        2, case.id, f"{label}: the rule stopped firing (the case does not allow absent)"))
            elif "verdict" in problems:
                report.failures.append(GateFailure(
                    2, case.id, f"{label}: expected false_positive, got {actual['verdict']}"))
            elif "reason_tag" in problems:
                report.failures.append(GateFailure(
                    2, case.id, f"{label}: the reason does not mention {expected.reason_tag!r}"))
        elif case.polarity == "uncertain" and expected.verdict == "unverified":
            if "missing" in problems:
                report.failures.append(GateFailure(3, case.id, f"{label}: the uncertain finding vanished"))
            elif "verdict" in problems:
                report.failures.append(GateFailure(
                    3, case.id, f"{label}: resolved to {actual['verdict']} instead of staying unverified"))
            elif "unresolved_reason" in problems:
                report.failures.append(GateFailure(
                    3, case.id,
                    f"{label}: unresolved_reason is {actual['unresolved_reason']}, "
                    f"expected {expected.unresolved_reason}"))


def _check_regressions(result: CaseResult, baseline: dict[str, Any], report: GateReport) -> None:
    from app.services.decision_diff import diff

    recorded = (baseline.get("cases") or {}).get(result.case_id)
    if recorded is None:
        report.notes.append(f"{result.case_id}: not in the baseline yet (a new case)")
        return
    if _cannot_run(result):
        return  # reported by the gate that explains it
    old = [r for r in recorded["findings"] if r.get("occurrence_id")]
    new = [f for f in result.findings if f.get("occurrence_id")]
    for entry in diff(old, new)["entries"]:
        was, now = (entry["old"] or {}).get("verdict"), (entry["new"] or {}).get("verdict")
        if was == "true_positive" and (entry["change"] == "removed" or now == "false_positive"):
            where = f"{entry['rule_id']} {entry['file_path']}:{entry['line']}"
            report.failures.append(GateFailure(
                5, result.case_id,
                f"{where}: true_positive in the baseline, now {'absent' if now is None else now}"))


def evaluate(
    cases: list[Case], results: list[CaseResult], baseline: dict[str, Any] | None
) -> GateReport:
    report = GateReport()
    by_id = {c.id: c for c in cases}
    for result in results:
        case = by_id[result.case_id]
        if case.adjudication != "adjudicated":
            report.not_gated.append(case.id)
        elif case.xfail:
            report.known_gaps.append(case.id)
        else:
            report.gated.append(case.id)
            _check_adjudicated(case, result, report)
        for contradiction in result.consistency:
            report.failures.append(GateFailure(4, case.id, contradiction))
        if baseline is not None:
            _check_regressions(result, baseline, report)
    if baseline is None:
        report.notes.append("no baseline: gate 5 was not evaluated")
    return report


# --- rendering ----------------------------------------------------------------

def render_markdown(report: GateReport, results: list[CaseResult], cases: list[Case]) -> str:
    by_id = {c.id: c for c in cases}
    lines = [
        "# Accuracy gate",
        "",
        f"**{'PASSED' if report.passed else 'FAILED'}** — "
        f"{len(report.gated)} gated case(s), {len(report.known_gaps)} known gap(s), "
        f"{len(report.not_gated)} not gated.",
        "",
        "## Gates",
        "",
        "| Gate | Result | Failures |",
        "|---|---|---|",
    ]
    for number, name in GATES.items():
        count = sum(1 for f in report.failures if f.gate == number)
        lines.append(f"| {number}. {name} | {'FAIL' if count else 'pass'} | {count} |")
    if report.failures:
        lines += ["", "## Failures", ""]
        for failure in report.failures:
            lines.append(f"- **gate {failure.gate} · {GATES[failure.gate]}** — `{failure.case_id}`: {failure.message}")
    lines += ["", "## Cases", "", "| Case | Area | Polarity | Adjudication | Status | Note |", "|---|---|---|---|---|---|"]
    for result in results:
        case = by_id[result.case_id]
        note = "; ".join(result.problems[:2]) if result.problems else ""
        lines.append(
            f"| `{case.id}` | {case.area} | {case.polarity} | {case.adjudication} | {result.status}"
            f"{' (' + case.xfail + ')' if case.xfail else ''} | {note} |"
        )
    if report.not_gated:
        lines += [
            "", "## Not gated", "",
            "`dev_label_only` cases: reported so their drift stays visible, never blocking gates 1-3 "
            "(gates 4 and 5 still cover them).", "",
        ]
        for case_id in report.not_gated:
            lines.append(f"- `{case_id}`")
    if report.known_gaps:
        lines += ["", "## Known gaps (xfail)", ""]
        lines += [f"- `{case_id}` → {by_id[case_id].xfail}" for case_id in report.known_gaps]
    if report.notes:
        lines += ["", "## Notes", ""] + [f"- {note}" for note in report.notes]
    return "\n".join(lines) + "\n"


def render_json(report: GateReport, results: list[CaseResult], cases: list[Case]) -> dict[str, Any]:
    return {
        "passed": report.passed,
        "gates": {
            str(number): {
                "name": name,
                "passed": not report.failed(number),
                "failures": [
                    {"case": f.case_id, "message": f.message} for f in report.failures if f.gate == number
                ],
            }
            for number, name in GATES.items()
        },
        "gated": report.gated,
        "not_gated": report.not_gated,
        "known_gaps": report.known_gaps,
        "notes": report.notes,
        "cases": [r.to_dict() for r in results],
    }

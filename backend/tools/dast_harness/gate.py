"""The regression gate (DAST-16-040).

Fails when, for any target with a recorded baseline, recall dropped at all or precision dropped by
more than `PRECISION_TOLERANCE`, when a result was scored against unverified ground truth, when it was
scored against a different image than its baseline, or when the offline suite or the layering test is
red. Baselines change only through `--update-baseline`, which needs a stated reason and a result
scored against verified ground truth, so a baseline moves in a reviewed commit.

`PRECISION_TOLERANCE` is deliberately strict and documented here, not tucked into a config: precision
is the noisier of the two numbers (a model can add a lucky false positive), so it gets two points of
slack; recall gets none, because a missed vulnerability is the regression this gate exists to catch.
Loosen it only with a justification in the commit that changes it.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

PRECISION_TOLERANCE = 0.02
EPSILON = 1e-9
BACKEND_DIR = Path(__file__).resolve().parents[2]


@dataclass
class Row:
    target: str
    status: str  # pass | fail | no-baseline
    recall: float | None = None
    recall_delta: float | None = None
    precision: float | None = None
    precision_delta: float | None = None
    reasons: list[str] = field(default_factory=list)


@dataclass
class GateReport:
    rows: list[Row] = field(default_factory=list)
    suite_ok: bool | None = None
    layering_ok: bool | None = None
    failures: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.failures


def compare_target(result: Mapping[str, Any], baseline: Mapping[str, Any] | None, *, tolerance: float = PRECISION_TOLERANCE) -> Row:
    row = Row(result["target"], "pass", float(result["recall"]), None, float(result["precision"]), None)
    if baseline is None:
        row.status = "no-baseline"
        row.reasons.append("no baseline is recorded for this target, so nothing to compare with")
        return row
    row.recall_delta = round(float(result["recall"]) - float(baseline["recall"]), 4)
    row.precision_delta = round(float(result["precision"]) - float(baseline["precision"]), 4)
    if not result.get("ground_truth_verified"):
        row.reasons.append("the result was scored against unverified ground truth")
    if result.get("image") != baseline.get("image"):
        row.reasons.append(f"the result was scored against a different image than the baseline ({result.get('image')!r} vs {baseline.get('image')!r}); record a new baseline deliberately")
    if row.recall_delta < -EPSILON:
        row.reasons.append(f"recall dropped by {-row.recall_delta:.2%}")
    if row.precision_delta < -(tolerance + EPSILON):
        row.reasons.append(f"precision dropped by {-row.precision_delta:.2%}, more than the {tolerance:.0%} tolerance")
    if row.reasons:
        row.status = "fail"
    return row


def evaluate(
    results: Mapping[str, Mapping[str, Any]],
    baselines: Mapping[str, Mapping[str, Any]],
    *,
    suite_ok: bool | None = None,
    layering_ok: bool | None = None,
    require_baseline: bool = False,
    tolerance: float = PRECISION_TOLERANCE,
) -> GateReport:
    report = GateReport(suite_ok=suite_ok, layering_ok=layering_ok)
    for target in sorted(results):
        row = compare_target(results[target], baselines.get(target), tolerance=tolerance)
        report.rows.append(row)
        if row.status == "fail":
            report.failures.append(f"{target}: " + "; ".join(row.reasons))
        elif row.status == "no-baseline" and require_baseline:
            report.failures.append(f"{target}: no baseline recorded (--require-baseline)")
    if suite_ok is False:
        report.failures.append("the offline test suite is red")
    if layering_ok is False:
        report.failures.append("the layering test is red")
    return report


def render_markdown(report: GateReport) -> str:
    def pct(v: float | None) -> str:
        return "—" if v is None else f"{v:.1%}"

    def delta(v: float | None) -> str:
        return "—" if v is None else f"{v:+.1%}"

    lines = ["## DAST quality gate: " + ("PASS" if report.passed else "FAIL"), ""]
    lines.append(f"Offline suite: {'—' if report.suite_ok is None else 'green' if report.suite_ok else 'RED'}; layering test: {'—' if report.layering_ok is None else 'green' if report.layering_ok else 'RED'}")
    lines += ["", "| Target | Status | Recall | Δ recall | Precision | Δ precision |", "|---|---|---|---|---|---|"]
    for r in report.rows:
        lines.append(f"| {r.target} | {r.status} | {pct(r.recall)} | {delta(r.recall_delta)} | {pct(r.precision)} | {delta(r.precision_delta)} |")
    if not report.rows:
        lines.append("| (no harness results supplied) | — | — | — | — | — |")
    for failure in report.failures:
        lines.append(f"- FAIL: {failure}")
    for r in report.rows:
        if r.status == "no-baseline":
            lines.append(f"- note: {r.target}: {r.reasons[0]}")
    return "\n".join(lines) + "\n"


def load_json_dir(directory: str | Path, *, suffix: str = ".json", skip_prefix: str = "") -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    path = Path(directory)
    if not path.is_dir():
        return out
    for file in sorted(path.glob(f"*{suffix}")):
        if file.name.startswith("README"):
            continue
        data = json.loads(file.read_text(encoding="utf-8"))
        if isinstance(data, dict) and data.get("target"):
            out[data["target"]] = data
    return out


def latest_results(directory: str | Path) -> dict[str, dict[str, Any]]:
    """The `<target>-latest.json` result for each target."""
    out: dict[str, dict[str, Any]] = {}
    for file in sorted(Path(directory).glob("*-latest.json")) if Path(directory).is_dir() else []:
        data = json.loads(file.read_text(encoding="utf-8"))
        out[data["target"]] = data
    return out


def record_baseline(result: Mapping[str, Any], baselines_dir: str | Path, *, reason: str, update: bool) -> Path:
    """Write a baseline from `result`. Needs the explicit flag, a reason, and verified ground truth."""
    if not update:
        raise PermissionError("baselines are only updated with --update-baseline (an explicit, reviewed change)")
    if not reason.strip():
        raise ValueError("--reason is required: say why this result is the new reference")
    if not result.get("ground_truth_verified"):
        raise ValueError("refusing to record a baseline from a result scored against unverified ground truth")
    target = result["target"]
    baseline = {
        "target": target, "image": result["image"], "precision": result["precision"], "recall": result["recall"], "counts": result.get("counts", {}),
        "rule_packs": result.get("rule_packs", []), "reason": reason.strip(), "recorded_at": datetime.now(timezone.utc).strftime("%Y-%m-%d"), "from_scan": result.get("scan_id", ""),
    }
    path = Path(baselines_dir) / f"{target}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(baseline, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def run_suites(backend_dir: str | Path = BACKEND_DIR) -> tuple[bool, bool]:
    """`(offline suite green, layering test green)`. The layering test is also part of the suite; it is
    run on its own so a failure there is named."""
    def ok(*args: str) -> bool:
        return subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *args], cwd=backend_dir).returncode == 0

    layering = ok("tests/test_dast_layering.py")
    suite = ok("-m", "not live")
    return suite, layering

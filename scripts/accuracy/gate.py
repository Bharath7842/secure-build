#!/usr/bin/env python3
"""The accuracy release gate. One command that fails when a scanner change loses a
known positive, misclassifies a known negative, resolves an uncertainty, or makes
the reports contradict each other.

    python scripts/accuracy/gate.py --baseline backend/tests/accuracy_corpus/accuracy_baseline.json

Runs the corpus (backend/tests/accuracy_corpus) offline against its recorded LLM
responses, checks every corpus scan's reports for consistency, and compares with
the committed baseline. Writes `accuracy_gate.md` (gate by gate, then the cases)
and `accuracy_gate.json` to `--out`, and exits non-zero when any gate fails.
`--update-baseline` rewrites the baseline from this run, and refuses when gate 1
or gate 5 fails. No live LLM call is ever made; see `backend/accuracy/gate.py`.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
BACKEND = REPO / "backend"
DEFAULT_CORPUS = BACKEND / "tests" / "accuracy_corpus"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--baseline", type=Path, required=True, help="accuracy_baseline.json")
    parser.add_argument("--update-baseline", action="store_true",
                        help="rewrite the baseline from this run (refused if gate 1 or 5 fails)")
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS, help="the corpus directory")
    parser.add_argument("--out", type=Path, default=Path("."), help="where accuracy_gate.md/.json go")
    args = parser.parse_args(argv)

    if str(BACKEND) not in sys.path:
        sys.path.insert(0, str(BACKEND))
    from accuracy import gate
    from accuracy.case import discover_cases
    from accuracy.runner import run_case

    cases = discover_cases(args.corpus)
    if not cases:
        print(f"no cases under {args.corpus}", file=sys.stderr)
        return 2
    results = [run_case(case, check_consistency=True) for case in cases]
    baseline = gate.load_baseline(args.baseline)
    report = gate.evaluate(cases, results, baseline)

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "accuracy_gate.md").write_text(gate.render_markdown(report, results, cases), encoding="utf-8")
    (args.out / "accuracy_gate.json").write_text(
        json.dumps(gate.render_json(report, results, cases), indent=2, default=str) + "\n", encoding="utf-8"
    )

    print(f"accuracy gate: {'PASSED' if report.passed else 'FAILED'} "
          f"({len(report.gated)} gated, {len(report.known_gaps)} known gap(s), {len(report.not_gated)} not gated)")
    for failure in report.failures:
        print(f"  gate {failure.gate} [{gate.GATES[failure.gate]}] {failure.case_id}: {failure.message}")

    if args.update_baseline:
        blocking = [n for n in (1, 5) if report.failed(n)]
        if blocking:
            print(f"refusing to update the baseline: gate(s) {blocking} failed", file=sys.stderr)
            return 1
        gate.write_baseline(args.baseline, gate.baseline_from_results(results))
        print(f"baseline updated: {args.baseline}")
        return 0 if report.passed else 1
    return 0 if report.passed else 1


if __name__ == "__main__":
    sys.exit(main())

"""`python -m tools.dast_harness {run,score,validate,gate}`."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import gate as gate_module
from . import ground_truth
from .scoring import build_result, findings_from_api, score, summary_text

HERE = Path(__file__).resolve().parent


def _truth_path(arg: str) -> Path:
    path = Path(arg)
    return path if path.exists() else HERE / "ground_truth" / f"{arg}.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m tools.dast_harness", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="scan a practice target through the backend and score it (live)")
    run.add_argument("--target", required=True)
    run.add_argument("--backend", default=os.environ.get("SAST_API_URL", "http://127.0.0.1:8000"))
    run.add_argument("--token", default=os.environ.get("SAST_API_TOKEN", ""))
    run.add_argument("--project-id")
    run.add_argument("--identity", action="append", default=[], help="label:role:username:password (form login), repeatable")
    run.add_argument("--timeout", type=float, default=3600)
    run.add_argument("--out", default=str(HERE / "results"))

    sc = sub.add_parser("score", help="score a saved GET /scans/{id}/findings response against a ground-truth file")
    sc.add_argument("--findings", required=True)
    sc.add_argument("--truth", required=True)
    sc.add_argument("--have", default="", help="comma separated: state_changing,second_identity,oast,schema")

    val = sub.add_parser("validate", help="validate ground-truth files")
    val.add_argument("files", nargs="*")

    gate = sub.add_parser("gate", help="compare results with the baselines; fail on a regression")
    gate.add_argument("--results", default=str(HERE / "results"))
    gate.add_argument("--baselines", default=str(HERE / "baselines"))
    gate.add_argument("--run-suite", action="store_true", help="also run the offline suite and the layering test")
    gate.add_argument("--require-baseline", action="store_true")
    gate.add_argument("--update-baseline", action="store_true")
    gate.add_argument("--target")
    gate.add_argument("--result")
    gate.add_argument("--reason", default="")

    args = parser.parse_args(argv)

    if args.command == "run":
        from . import runner

        if not args.token:
            parser.error("--token (or SAST_API_TOKEN) is required")
        result = runner.run(args.target, backend=args.backend, token=args.token, project_id=args.project_id, identities=[runner.parse_identity(i) for i in args.identity], timeout_s=args.timeout)
        stamped, summary = runner.write_result(result, args.out)
        print(summary_text(result))
        print(f"\nwrote {stamped} and {summary}")
        return 0

    if args.command == "score":
        truth = ground_truth.load(_truth_path(args.truth))
        payload = json.loads(Path(args.findings).read_text(encoding="utf-8"))
        have = [x for x in args.have.split(",") if x]
        result = build_result(score(findings_from_api(payload), truth, available=have or ground_truth.NEEDS), truth)
        print(summary_text(result))
        return 0

    if args.command == "validate":
        from app.services.dast_catalog import default_catalog

        known = {c.check_id for c in default_catalog().checks}
        files = [Path(f) for f in args.files] or sorted((HERE / "ground_truth").glob("*.json"))
        failed = False
        for file in files:
            report = ground_truth.validate_document(json.loads(file.read_text(encoding="utf-8")), known_check_ids=known)
            print(f"{file.name}: {'ok' if report.ok else 'INVALID'}")
            for item in report.errors:
                print(f"  error: {item}")
            for item in report.warnings:
                print(f"  warning: {item}")
            failed = failed or not report.ok
        return 1 if failed else 0

    if args.command == "gate":
        if args.update_baseline:
            if not args.result:
                parser.error("--update-baseline needs --result")
            path = gate_module.record_baseline(json.loads(Path(args.result).read_text(encoding="utf-8")), args.baselines, reason=args.reason, update=True)
            print(f"wrote {path}")
            return 0
        suite_ok = layering_ok = None
        if args.run_suite:
            suite_ok, layering_ok = gate_module.run_suites()
        results = gate_module.latest_results(args.results)
        report = gate_module.evaluate(results, gate_module.load_json_dir(args.baselines), suite_ok=suite_ok, layering_ok=layering_ok, require_baseline=args.require_baseline)
        text = gate_module.render_markdown(report)
        print(text)
        summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary_file:
            with open(summary_file, "a", encoding="utf-8") as handle:
                handle.write(text)
        return 0 if report.passed else 1
    return 2


if __name__ == "__main__":
    sys.exit(main())

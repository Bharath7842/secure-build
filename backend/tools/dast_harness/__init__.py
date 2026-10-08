"""The DAST measurement harness (DAST-16-010): run a scan against a practice target, score its
findings against a fixed ground-truth list, and gate releases on the result (DAST-16-040).

Usage (see `python -m tools.dast_harness --help`):

    python -m tools.dast_harness run   --target dvwa --backend http://127.0.0.1:8000 --token $TOKEN
    python -m tools.dast_harness score --findings scan-findings.json --truth tools/dast_harness/ground_truth/dvwa.json
    python -m tools.dast_harness gate  --result results/dvwa-latest.json

Only the scoring and the gate are tested offline; `run` needs the practice targets, a model and a
running backend (`live`).
"""

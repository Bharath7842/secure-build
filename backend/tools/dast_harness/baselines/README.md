# Harness baselines

One JSON file per target (`dvwa.json`, `juice-shop.json`): the precision and recall the regression
gate compares every later result against (`python -m tools.dast_harness gate`).

**No baseline is recorded yet.** A baseline may only be recorded from a result scored against a
*verified* ground-truth file, and the two files in `../ground_truth/` are still drafts (see their
`verified` flag and DAST-16-020). Until a maintainer has run the harness against the pinned practice
targets, reviewed the expectations by hand and flipped `verified`, the gate reports "no baseline" for
that target and passes (or fails with `--require-baseline`).

Baselines change only through an explicit, reviewed commit:

    python -m tools.dast_harness gate --update-baseline --target dvwa --result results/dvwa-<run>.json --reason "why this is the new reference"

writes `baselines/dvwa.json` (it refuses an unverified result and a missing reason); the diff is what a
reviewer approves.

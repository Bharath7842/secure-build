# Repository CI pipeline

The repository had no pipeline of its own (the other files in this folder are examples for
*consumers* of the scanner). DAST-00-070 chose **GitHub Actions**, because `origin` is
`github.com/TechtezLLP/augmented-secure-build`. The workflow is [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml).

## Jobs

| Job | Runs on | Command | Blocks merge |
|---|---|---|---|
| `backend` | pull requests, pushes to `main` | `pip install -r requirements.txt`, then `pytest -m "not live"` (includes the layering check, `tests/test_dast_layering.py`) | yes (once marked required) |
| `frontend` | pull requests, pushes to `main` | `npm ci`, `npm run lint`, `npm run build` | yes (once marked required) |
| `live` | manual only (`workflow_dispatch` with `run_live` ticked) | `pytest -m live` after a placeholder setup step for EPIC-16 | no (`continue-on-error`, nothing depends on it) |

The frontend has no test runner, so none is added.

## One-time repository setting (cannot be set from a file)

A workflow file cannot make a check *required*. In **Settings → Branches → branch protection for
`main`**, enable *Require status checks to pass before merging* and select **Backend (pytest,
layering check)** and **Frontend (lint, build)**. Until that is done, a red job is visible but does not
block the merge button.

## Runtime baseline

GitHub-hosted runtime has not been recorded yet: the workflow has not run on GitHub. After the first
green run on `main`, write the per-job durations here. Local timings, measured on a developer
machine (Apple silicon, warm caches, so expect GitHub runners to be slower):

| Step | Local time (2026-10-07) |
|---|---|
| `pip install -r requirements.txt` into a fresh Python 3.12 venv | ~29 s (warm pip cache) |
| `pytest -m "not live"` (626 tests, includes the layering check) | ~13 s |
| `npm run lint` | ~8 s |
| `npm run build` | ~22 s |

## Verifying that red means red

Locally: add a failing assertion to any test and run `pytest -m "not live"`; the layering check
fails the same way when a domain module imports `fastapi` (try it in a scratch branch). On GitHub,
open a draft PR containing a deliberately failing test and confirm the `backend` job goes red, then
close the PR.

## DAST quality gate (DAST-16-040)

`backend/tools/dast_harness/` measures the scanner against the pinned practice targets and gates
releases on the result. The `backend` job runs two extra steps after the suite:

- `python -m tools.dast_harness validate`: the ground-truth files must be well formed, name real
  catalog checks and the pinned images.
- `python -m tools.dast_harness gate`: compares the latest harness result per target with the stored
  baseline and fails on **any recall drop** or a **precision drop beyond 2 points**
  (`PRECISION_TOLERANCE` in `gate.py`, documented there; start strict, loosen only with a stated
  reason). It also fails when a result was scored against unverified ground truth or a different
  image than its baseline. `--run-suite` additionally runs the offline suite and the layering test and
  fails if either is red. The result, with per-target deltas, is written to the job summary
  (`GITHUB_STEP_SUMMARY`).

Baselines (`tools/dast_harness/baselines/<target>.json`) change only through
`gate --update-baseline --result ... --reason "..."`, which refuses an unverified result and a missing
reason: the change is a reviewed commit.

**Current state:** no baseline is recorded yet, because the ground-truth files are drafts that have
not been checked against the running pinned images (DAST-16-020). The gate therefore reports "no
baseline" and passes; once a maintainer has run `python -m tools.dast_harness run --target dvwa` (and
`juice-shop`), verified the expectations by hand and set `verified: true`, record the baselines and
the gate starts enforcing.

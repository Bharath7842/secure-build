# Sprint 2 status

Written for: the maintainers who will review, verify and merge Sprint 2.

Sprint 2 is EPIC-08 to EPIC-16 (41 stories). Everything is in the working tree, **uncommitted**, on top of the uncommitted Sprint 1 work.

## What was verified, and what was not

| Check | Result |
|---|---|
| Backend suite (`pytest -m "not live"`) | 1887 passed, 7 deselected (live tests) |
| Frontend `tsc --noEmit` | clean |
| Frontend `eslint .` | 0 errors, 13 warnings (the same pre-existing warnings; none in new files) |
| Frontend `next build` | **Not run.** This machine's `node` is x86 and fails to start, and the installed Next SWC binary is x86 too. I used an arm64 Node from a scratch virtualenv for `tsc` and `eslint`; `next build` then tries to download a wasm SWC through a broken `npm`. Run `npm run build` on a working toolchain |
| Any screen opened in a browser | **No.** No screen was looked at or clicked; the UI is verified by types, lint and reading only |
| Live tests (real browser, model, network, practice targets) | **Not run** |

## Stories

Status: **Done** = implemented and covered by the tests above. **Done, UI unviewed** = frontend story with no browser check. **Needs a person** = something only a human can finish.

| Epic | Stories | Status |
|---|---|---|
| 08 Passive analysis | 010 headers, cookies, CSP; 020 CORS, disclosure; 030 errors, sensitive data | Done (`domain/passive.py`, `passive.py`, `data/passive_patterns.json`) |
| 09 Active testing | 010 loop contract; 020 select and construct; 030 baseline, test, rule; 040 forms and parameters; 050 opt-in and assist-only; 060 SSRF with out-of-band | Done. 060 uses an HTTP callback service you must provide (see decisions) |
| 10 Authorization | 010 anonymous replay and degraded mode; 020 cross-role replay; 030 BOLA and BFLA; 040 matrix and API | Done |
| 11 Reporting | 010 roll-up and report data; 020 diff; 030 PDF; 040 XLSX | Done |
| 12 Narration | 010 progress; 020 narration for new stages with template fallback; 030 live counters | Done |
| 13 Scan flow UI | 010..040 form (target, safety, identities and roles, packs and model); 050 detail, counters, cancel; 060 discovery and analysis panels | Done, UI unviewed |
| 14 Findings UI | 010 findings panel; 020 matrix component; 030 report view and exports; 040 accessibility and states | Done, UI unviewed. 040 needs the manual pass in `a11y-checklist-DAST-14-040.md` |
| 15 Settings UI | 010 model routing and test; 020 credential entry with masking; 030 rule-set management; 040 custom rule authoring; 050 persistence | Done, UI unviewed (`/dast/settings`, project settings page) |
| 16 Quality | 010 harness; 020 ground truth; 030 determinism; 040 regression gate; 050 training capture; 060 security review | 010, 030, 040, 050 done. **020 and 060 need a person** (below) |

## Decisions I made (reverse any you disagree with)

- **Provider keys stay in the environment.** DAST-15-020 asked for credential entry with masking; the page shows set / not set only and cannot write a key. The OAST callback address is the one write-only field. Settings edits are stored as overrides in `dast_global_config` (key `settings`) and apply to new scans only (15-050).
- **OAST is HTTP, v1.** The scanner builds `<callback>/c/<token>` and polls `/poll?token=`. The poll uses its own client and is audited as `check_id = oast-poll`. The signal is named `oast_callback_received` (the story wrote `oast_callback`). Without a configured address the SSRF checks are skipped and reported as skipped.
- **Training capture is off by default,** per project, and needs `DAST_TRAINING_ADMIN_TOKEN` plus `X-Training-Admin-Token` and `X-Training-Reader` headers on every read; reads are audited.
- **A `true_positive` always needs a detector signal,** however the model answers.
- **The model-driven loop excludes** authorization, OAST, passive, opt-in and assist-only checks; each has its own stage.

## Deviations from the stories

- The baseline response is reused for identical requests within a target (saves requests; timing checks keep their own samples).
- The mock engine's `authorization` result carries both `matrix` and `replays`.
- Pre-auth session upload is read in the browser and sent in the JSON body, not as multipart.
- Global rules have no "clear this override" call, so resetting a check at the global level means setting it back to its base values; project level has a real reset.
- The confirm dialog (`ConfirmDialog.tsx`) does not manage focus. It predates this work and was left alone (noted in the accessibility checklist).

## Needs a person

1. **DAST-16-060 sign-off.** `security-review-DAST-16-060.md` lists 11 defects found and fixed and 7 accepted risks (R1..R7: DNS rebinding, the login-window POST, a deny-list validator, split inputs, pattern-based scrubbing, one shared training token, public-versus-protected pages). Accepting them is your call; the sign-off block is unsigned. R1 and R6 need an owner named.
2. **DAST-16-020 ground truth.** `tools/dast_harness/ground_truth/{dvwa,juice-shop}.json` are drafts marked `verified: false`, with no recorded baseline. Verify them against the pinned target images before trusting any precision or recall number, then record the baseline.
3. **Live runs.** The 7 live tests, a scan against each practice target, a live check of each provider key, and a real OAST service.
4. **Frontend pass in a browser** for EPIC-13 to 15: each screen's states, the keyboard and screen-reader checks, contrast and zoom (`a11y-checklist-DAST-14-040.md`).
5. **`npm run build`** on a working Node toolchain.
6. **Commit.** Nothing has been committed.

## Config added

`.env.example` documents `DAST_OAST_POLL_URL`, `DAST_OAST_WAIT_S`, `DAST_OPT_IN_REQUEST_CEILING` and `DAST_TRAINING_ADMIN_TOKEN`. CI is in `.github/workflows/ci.yml` and `docs/ci/pipeline.md`. The engine guide `backend/app/dast/CLAUDE.md` describes the new graph and modules.

# SAST accuracy stories

Source: `output/secure-build-npg-pakistan-accuracy-review.md`. Epics, in order:

| Epic | Subject |
|---|---|
| EPIC-00 | Verdict model and accuracy regression tests (foundational) |
| EPIC-01 | Per-occurrence decisions, grouping and publish filters |
| EPIC-02 | SQL injection: bound parameters and method identity |
| EPIC-03 | Log and output sinks: call boundaries and render context |

EPIC-00 builds the decision model, the corpus and the release gate that EPIC-01 to
EPIC-03 add their cases to, so it lands first.

## Epic template note: the gate

**Every story in EPIC-01 to EPIC-03 that changes a rule, a prompt or a publish filter lists
"gate green" in its Definition of Done:**

> **Definition of Done:** code merged + tests green (dev + test) + builds/deploys clean (devops)
> **+ accuracy gate green**

"Gate green" means `python scripts/accuracy/gate.py --baseline backend/tests/accuracy_corpus/accuracy_baseline.json`
exits 0 (`accuracy_gate.md` shows the five gates passing) and the story's own corpus cases are in
`backend/tests/accuracy_corpus/`:

* a **preservation positive** and its **paired negative** for every rule or filter the story touches
  (the review's §9.2 pairs), recorded and, once a second reviewer agrees, marked `adjudicated`;
* an **uncertainty** case where the story decides what stays undecided;
* an `xfail: EPIC-nn` marker on any case the story knowingly leaves for a later epic, removed in
  the story that fixes it (the corpus run fails the day it starts passing).

A prompt, catalog or filter change makes the gate fail with *unrecorded LLM call* until the author
re-records the affected cases (`ACCURACY_RECORD=scripted` or, deliberately, `live`; see
`backend/tests/accuracy_corpus/README.md`) and a reviewer accepts the new outputs. That is intended.
When the gate is green and a baseline moved for a good reason, update it with
`--update-baseline` (refused while a confirmed finding was lost) and put the diff in the PR.

Cases a developer labelled but nobody adjudicated stay `dev_label_only`: they are reported in the
gate's "not gated" section so their drift is visible, and never block a release by themselves.

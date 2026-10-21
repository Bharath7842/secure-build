# Accuracy corpus

Small, **synthetic** repositories paired as positive / negative cases, scanned with
the real scan graph **offline** against recorded LLM responses. Every rule, prompt
or filter change is measured against cases where we know the right answer.

```bash
cd backend
pytest -m accuracy                # every case + the harness meta-tests (~15 s)
pytest -m accuracy -k sql-soap    # a few cases
```

Needs the full engine dependencies (`langgraph`, `tree-sitter*`); without them the
accuracy tests skip and plain `pytest` stays green. The run writes
`backend/accuracy_report.json` (per-case results plus totals by area and polarity).

No client source is ever committed here. Re-create the minimal construct and put the
review's `#` number in `seed_findings` for traceability only.

## A case

```
<id>/case.yaml        metadata and expectations
<id>/repo/            the synthetic repository that is scanned
<id>/llm_responses/   one <key>.json per LLM call, keyed by result_cache_key
```

`case.yaml`:

| field | meaning |
|---|---|
| `id` | the directory name |
| `area` | e.g. `sql-binding`, `log-boundary`, `aggregation` |
| `polarity` | `positive` (a real issue that must stay found), `negative` (a look-alike that must be dismissed) or `uncertain` (the right answer is "undecided") |
| `seed_findings` | review `#` numbers, traceability only |
| `adjudication` | `adjudicated` once a **second reviewer** agrees with the expectation, else `dev_label_only`. Release gates count only `adjudicated` cases (SAST-00-100) |
| `xfail` | a known gap: the epic that will fix it. Reported, never failing; the run fails the day the case starts passing, so the marker goes with the fix |
| `allow_absent` | a negative may also pass by the rule not firing at all |
| `limitations`, `state_overrides` | engine knobs on top of the corpus defaults (sequential, no Joern, no derived rules, no call graph, no backfill into the deep scan) |
| `expected` | list of `{rule_id and/or cwe, file, sink_line (±2), verdict, issue_class?, unresolved_reason?, reason_tag?}`. `reason_tag` is a word that must appear in the finding's `verdict_reason` |
| `scripted` | what the scripted recorder answers (below) |

A case passes when its persisted findings are **exactly** its `expected` list: nothing
missing, nothing unexpected, every verdict (and optional field) as stated.

## Replay, and why it cannot go live

The scan runs through `agent_bridge.run_real_scan` with the real writers on a
throwaway SQLite DB. Every LLM call is looked up in `llm_responses/` by
`result_cache_key`, which hashes the provider, model, parameters and the **full
prompt**. So:

* a prompt, catalog or file change shows up as **"unrecorded LLM call"** — that is the
  intended signal: re-record and have a reviewer accept the new outputs;
* the provider functions are stubbed to refuse, cloud credentials are removed from the
  environment for the run, and the engine loader is pinned (it reloads `llm_client`
  on every call, which would otherwise undo the stubs). `tests/test_accuracy_harness.py`
  proves a run opens no socket.

## Recording

```bash
ACCURACY_RECORD=scripted pytest -m accuracy      # rewrite every case's recordings, no network
ACCURACY_RECORD=live pytest -m accuracy -k <id>  # a real provider; spends money
```

* `scripted` — a fake provider answers from each case's `scripted:` entries (the first
  entry whose `step` matches and whose `when_user_contains` strings all appear in the
  prompt; anything unscripted gets an empty but valid answer). No network, no cost.
  The seed responses were produced this way, so they say what a case's author
  *expects* a model to answer, not what a model did.
* `live` — the real provider answers (`bedrock`, the model pinned in
  `accuracy/case.py`). **This spends money**; it must be chosen explicitly, run by hand,
  and the diff of the new recordings reviewed before commit.

## Adding a case

1. Create `<id>/repo/` with the smallest repository that shows the construct (a `pom.xml`
   plus the Java file; put it under a `dao/`, `service/` or `controller/` package so it
   is a CRITICAL/HIGH file and goes through the deep scan).
2. Write `case.yaml`: expectations first, then `scripted:` answers.
3. Record it (`scripted`, or `live` for a real model), run `pytest -m accuracy -k <id>`.
4. Commit `repo/`, `case.yaml` and `llm_responses/`. Start as `dev_label_only`; flip to
   `adjudicated` only after a second reviewer agrees.
5. If the current engine gets it wrong, say so honestly with `xfail: EPIC-nn` rather than
   weakening the expectation.

EPIC-01 to EPIC-03 add their §9.2 pairs here.

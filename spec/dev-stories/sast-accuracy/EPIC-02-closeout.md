# EPIC-02 close-out — SAST-02-080 (rescan, diff, adjudicate the 38 SQL findings)

Fill this in after the rescan. SAST-02-010 to 02-070 are merged; this is the only story left, and it needs a real scan.

## Before you scan

- [ ] **Do not scan with the Claude/Haiku (Bedrock) model.** Use the local Ollama provider (project settings: provider `ollama`, your local model). The "after" scan from SAST-01-100 was made with a different model, so some differences in the diff come from the model, not from EPIC-02; note the model on every row you adjudicate.
- [ ] The app checkout is at `ae38067c239e`.
- [ ] Accuracy gate is green on the merge commit: `cd backend && python ../scripts/accuracy/gate.py --baseline tests/accuracy_corpus/accuracy_baseline.json --corpus tests/accuracy_corpus --out /tmp/gate`.
- [ ] Expect **one cache-missing scan**: the deep-scan system prompt changed twice in this epic (the PreparedStatement sentence; the derived wrapper rule ids).

## Run

1. `POST /scans` with `force: true` and `metadata.bypass_llm_cache: true`, branch/commit as above.
2. `GET /scans/{id}/decision-diff?base=<SAST-01-100 "after" scan id>` — save the JSON.
3. Export XLSX and PDF for the new scan; archive the exports, the diff and this table.
4. Join old and new rows with the SAST-00-080 labels file. Rule ids of `runtime-sink-sql-*` findings changed (they carry an owner/signature hash now), so expect `fuzzy` joins for those; resolve them by hand.
5. Check `usage_summary`: `validators` (by `reason_tag`), `sql_summaries` (methods summarised, cache hits, `unknown.*` by reason, `summary_depth_exceeded`), and the call-graph log lines (entry points by source, parse coverage, wrapper rules `N of M`). Summary time should stay under 5% of the scan's wall time.

## Acceptance (all must hold)

- [ ] Every **supported** finding is `false_positive` with a SQL proof tag.
- [ ] Every **conditional** finding is either `false_positive` with a proof, or `unverified` with a *named* gap. None is a bare true positive or an unexplained false positive.
- [ ] A **reachability** finding is `issue_class=inactive` only when its method is a proven-unreferenced **private** method; otherwise unchanged. (Note: public methods are never labelled inactive by design — most of #29/#30/#31/#55/#57/#60/#76 are expected to stay `security` unless private.)
- [ ] **Preservation positives still true positive:** #1, #2, the unsafe #78 members, #53's string member.
- [ ] Every `true_positive → false_positive` transition **outside** these 38 is listed below and reviewed by a second person.
- [ ] Every finding still `unverified` has its §10 evidence package named below.
- [ ] Accuracy gate green; `adjudication` flipped to `adjudicated` only for corpus cases a second reviewer agreed with.

## The 38 findings

Outcome codes: **FP** = `false_positive` with the proof tag shown; **FP/GAP** = FP with proof, or `unverified` with a named gap; **TP** = unchanged true positive; **TP+inactive** = true positive, `issue_class=inactive`, only for a proven-unreferenced private method.

| # | Group | Expected | Likely proof / mechanism | Old verdict | New verdict | `reason_tag` / gap | Reviewer |
|---|---|---|---|---|---|---|---|
| 15 | supported | FP | `sql_fixed_template_bound` (setObject is data) | | | | |
| 26 | supported | FP | `sql_fixed_template_bound` (`TO_CHAR(?)` is fixed grammar) | | | | |
| 28 | supported | FP | `sql_fixed_template_bound` | | | | |
| 34 | supported | FP | `sql_fixed_template_bound` (commented-out concat is not code) | | | | |
| 36 | supported | FP | `sql_fixed_template_bound` (numeric bound) | | | | |
| 47 | supported | FP | `sql_fixed_template_bound` (constant query) | | | | |
| 66 | supported | FP | `sql_fixed_template_bound` | | | | |
| 75 | supported | FP | `sql_fixed_template_bound` | | | | |
| 209 | supported | FP | `sql_fixed_template_bound` (`TO_CHAR` over a bound value) | | | | |
| 33 | conditional | FP/GAP | commented-out concatenation | | | | |
| 35 | conditional | FP/GAP | commented-out concatenation | | | | |
| 37 | conditional | FP/GAP | `match_is_declaration` | | | | |
| 38 | conditional | FP/GAP | facade, overloads by signature | | | | |
| 39 | conditional | FP/GAP | `stub_no_sink` | | | | |
| 40 | conditional | FP/GAP | commented-out concatenation | | | | |
| 45 | conditional | FP/GAP | field batch statement joined across the class | | | | |
| 46 | conditional | FP/GAP | field batch + default-WHERE helper | | | | |
| 49 | conditional | FP/GAP | zero-argument wrapper derives no rule | | | | |
| 50 | conditional | FP/GAP | zero-argument wrapper derives no rule | | | | |
| 51 | conditional | FP/GAP | helper / DAO summary | | | | |
| 54 | conditional | FP/GAP | `sql_api_misuse_constant` (`quality`) or facade summary | | | | |
| 59 | conditional | FP/GAP | commented-out concatenation | | | | |
| 61 | conditional | FP/GAP | getter derives no rule / `wrapper_identity_mismatch` | | | | |
| 62 | conditional | FP/GAP | `wrapper_identity_mismatch` (DAO `getPortID(long)` vs the message getter) | | | | |
| 63 | conditional | FP/GAP | evidence gap named, or proof | | | | |
| 65 | conditional | FP/GAP | helper / DAO summary | | | | |
| 67 | conditional | FP/GAP | placeholder-list helper, bound in a loop | | | | |
| 68 | conditional | FP/GAP | facade summary | | | | |
| 72 | conditional | FP/GAP | facade summary | | | | |
| 73 | conditional | FP/GAP | generated DAO with a parameter bag | | | | |
| 74 | conditional | FP/GAP | facade, two implementations | | | | |
| 29 | reachability | TP (+inactive if private & unreferenced) | | | | | |
| 30 | reachability | TP (+inactive if private & unreferenced) | | | | | |
| 31 | reachability | TP (+inactive if private & unreferenced) | | | | | |
| 55 | reachability | TP (+inactive if private & unreferenced) | | | | | |
| 57 | reachability | TP (+inactive if private & unreferenced) | cycle: `unknown/cycle` unless every non-cyclic path decides | | | | |
| 60 | reachability | TP (+inactive if private & unreferenced) | | | | | |
| 76 | reachability | TP (+inactive if private & unreferenced) | | | | | |

### Preservation positives

| Finding | Must stay | Old | New | OK? |
|---|---|---|---|---|
| #1 (SOAP string into `prepareStatement`) | TP | | | |
| #2 | TP | | | |
| unsafe #78 members (string concatenation) | TP | | | |
| #53 (stored string into a DELETE) | TP (`sql_second_order`) | | | |

### `true_positive → false_positive` outside the 38 (second reviewer required)

| Finding (rule, file:line) | Proof tag | Why it is right | Reviewer | Label updated |
|---|---|---|---|---|
| | | | | |

Already known: in the corpus, `group-split-same-name-different-owner` (#62 shape) moved the *message getter* call (`xmlPortMsg.getPortID()`) from true positive to false positive (`wrapper_identity_mismatch`) because that getter is a different method from the SQL wrapper. That label change needs a second reviewer too.

### Still `unverified`

| Finding | Named gap | §10 evidence that would resolve it |
|---|---|---|
| | | |

## Sign-off

- [ ] Close-out table reviewed by: ______  on: ______
- [ ] Labels file updated: ______
- [ ] Accuracy gate green on the final commit: ______

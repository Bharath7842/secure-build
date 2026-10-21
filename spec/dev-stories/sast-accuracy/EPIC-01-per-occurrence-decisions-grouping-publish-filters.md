# SAST Accuracy — EPIC-01 Per-Occurrence Decisions, Grouping and Publish Filters

Source: `output/secure-build-npg-pakistan-accuracy-review.md` (§5.8, §6, §7 P0 "Publication filters and group propagation", §9.2 "Aggregation/export"). Template: `spec/chain-templates/scaffolding-sprint-story-generation-prompt-simple.md`.

## [EPIC-01] Per-Occurrence Decisions, Grouping and Publish Filters

**Goal:** Every decision is made for one concrete occurrence before findings are grouped, so a group never applies one sampled verdict to members that differ. Publish filters and de-duplication never discard a real vulnerability because of how a line is spelled or how confident the model says it is. EPIC-02 and EPIC-03 build on two shared pieces from this epic: per-occurrence facts and a validator hook.
**Depends On:** EPIC-00 (SAST-00-010, 00-020, 00-040, 00-050, 00-060, 00-070). Stories that change rules or filters also need the SAST-00-100 gate.
**Blocks:** EPIC-02, EPIC-03
**Teams:** Dev / Test / DevOps

**Scope note.** The review found four ways the pipeline loses or blurs a decision after the model or a rule has produced it:

1. **Groups apply one verdict to unlike members.**
   - #62 merges a safe DAO `getPortID(long)` with the unsafe SOAP `xmlPortMsg.getPortID()` path behind #1.
   - #78 has a numeric representative, but some of its 156 occurrences concatenate strings.
   - #39 groups a `return false` stub with real implementations.
   - #284 lets one Calendar representative speak for 122 Throwable/object occurrences.
   - `build_group_confirm_prompt` (`llm_file_scan.py:2594`) sends only the representative's window plus a list of other file names, and the result is copied to every member.
2. **`should_publish_finding` drops any finding whose anchored line matches `_LOGGING_CALL_RE`, whatever its CWE** (`llm_file_scan.py:1237`). A credential written to `logger.error(...)`, as in #257/#258/#270, is a log line by definition.
3. **Model confidence alone can publish a noisy SQL rule.** A noisy SQL rule's finding is published as a true positive when `confidence >= UNEVIDENCED_CONFIDENCE_FLOOR`, even with no source and no query construction.
4. **`merge_dedupe` keeps the true positive in any conflict.** On a TP/FP conflict it prefers the TP. Within its line window it merges different AST nodes: #98's count log at 1135 and the `getMessage` call at 1139 are two sinks, not one.

**What this epic does not do.** It changes no SQL or logging rule semantics; that is EPIC-02 and EPIC-03. The validator hook ships with only two generic validators, to prove it works.

---

### SAST-01-010 Occurrence facts extractor (Java and TypeScript)

**Epic:** EPIC-01 Per-Occurrence Decisions, Grouping and Publish Filters        **Parent:** EPIC-01
**Parallelism:** Serial/Blocking    **Sprint:** 3

**Story**
As a scanner engineer, I want each finding's exact AST facts (the enclosing method, the call at the anchor, the receiver type and each argument's kind) worked out once and attached to the finding, so that grouping, validators and prompts all reason from the same resolved facts instead of from nearby text.

**Acceptance Criteria**
- `pipeline/occurrence_facts.py` exposes `facts_for(file_path, source_text, line, match_span) -> OccurrenceFacts | None` for Java and TypeScript. The result holds:
  - `enclosing`: owner FQN, method name, parameter types, arity, and the start/end lines of the enclosing method.
  - `is_declaration`: true when the anchor is a method *declaration*, not a call (#37).
  - `is_stub`: true when the method body is only `return <literal>;`, an empty body, or `throw new UnsupportedOperationException(...)` (#39).
  - `call`: the call node at the anchor. For multi-line calls, this is the outermost invocation that starts on the anchor line. It records the callee name, the receiver expression, the resolved receiver FQN (or `null`) and the argument count.
  - `args`: one entry per argument, with `kind` (`string_literal`, `constant`, `numeric`, `boolean`, `enum`, `string_var`, `call_result`, `throwable`, `object`, `unknown`) and the source expression text.
  - `in_comment`: true when the match lies inside a comment token.
- How the argument kind is decided:
  - **Constants** are folded across string literals, `static final` fields of the same class, local `final` variables assigned once, and `+` chains of those.
  - **Numeric** covers primitive and boxed numeric types, `BigInteger`, the result of `Integer/Long/...parseX`, and `size()`/`length` of collections and arrays. It applies only to the value actually used: if `s` is parsed into `n` but `s` is the argument, the kind is `string_var`.
  - **Receiver types** resolve from local declarations, fields, method parameters and the file's import map, reusing `call_graph`'s `_WELL_KNOWN_TYPES` and import handling.
- Facts are computed once per file (one parse, cached for the scan) and stored on the finding dict as `facts`. They are persisted as `Finding.facts` (JSON, nullable), added through `db._run_light_migrations`.
- If tree-sitter is unavailable or parsing fails, the result is `None`. Every consumer must then behave exactly as it does today.

**Dev Notes**
- Reuse `ast_struct.parser_for_lang` and `call_graph`'s receiver and type resolution; don't write a second resolver. Keep the module pure (source text in, facts out) so tests need no repository.
- `BigDecimal` is not final, so it counts as `numeric` only when the value comes from `new BigDecimal(..)`, `BigDecimal.valueOf(..)` or `ResultSet.getBigDecimal`. Otherwise it is `object` (review §5.5).
- Fact size per finding should stay under 2 KB. Cut argument text to 200 characters.
- These facts are inputs to decisions, not decisions; nothing in this story changes a verdict.

**Test Notes**
- Test level(s): unit (table-driven over code snippets).
- What to assert:
  - `log.info("rows " + count)` with `int count` gives args `[string_literal + numeric]`. The folded kind is `constant+numeric`.
  - `log.error("failed", ex)` gives `[string_literal, throwable]`.
  - A three-line `log.warn("{} {}",\n req.getRequestURI(),\n ex.getMessage())` gives one call node spanning three lines.
  - With `Long n = Long.parseLong(s); sql + s`, the argument kind is `string_var`, not `numeric`.
  - A method declaration line gives `is_declaration=true`; `boolean f(){ return false; }` gives `is_stub=true`.
  - A match inside `/* ... */` gives `in_comment=true`.
  - `System.out.println(x)` resolves the receiver to `java.io.PrintStream`.
  - TS: `this.translate.instant(key)` gives receiver `TranslateService` when it is constructor-injected.
  - A parse failure returns `None`.
- Test data / fixtures needed: `backend/tests/fixtures/occurrence_facts/` holding small Java and TS files, one construct each.
- Entry point to exercise: `occurrence_facts.facts_for`.

**DevOps Notes**
- Build/CI impact: none; tree-sitter is already in `requirements.txt`. The mock-engine suite must skip these tests cleanly when tree-sitter is absent.
- Deploy impact: one nullable JSON column on `findings`.
- Observability: log the fact-coverage share per scan (findings with facts ÷ all findings), split by language.

**Dependencies:** SAST-00-040 (enclosing-method resolution is shared with `occurrence_id`)
**Blocks:** SAST-01-020, SAST-01-030, SAST-01-050, SAST-01-060, SAST-01-090; EPIC-02, EPIC-03

**Definition of Done:** code merged + tests green (dev + test) + builds/deploys clean (devops)

---

### SAST-01-020 Occurrence validator hook and evidence precedence

**Epic:** EPIC-01 Per-Occurrence Decisions, Grouping and Publish Filters        **Parent:** EPIC-01
**Parallelism:** Serial/Blocking    **Sprint:** 3

**Story**
As a scanner engineer, I want one place to plug deterministic per-occurrence checks into the pipeline, with a fixed rule for how their proofs rank against an LLM verdict, so that a binding or constant proof is never overruled by a model hypothesis, and a model dismissal never overrules a proven unsafe construct.

**Acceptance Criteria**
- `pipeline/validators/` holds a registry. Validators register by `rule_id` (exact or prefix, e.g. `runtime-sink-sql-`) and/or CWE.
- The signature is `validate(finding, facts, ctx) -> ValidatorResult`. The result is one of:
  - `negative_proof(reason_tag, proof)`
  - `positive_fact(reason_tag, proof)`
  - `evidence_gap(missing)`
  - `no_opinion`
- `ctx` gives read access to the repo file text and the call graph.
- The hook runs on each occurrence:
  - for regex hits, after triage creates them;
  - for deep-scan findings, after `normalize_finding`;
  - for flow-verify findings, before `finalize_findings`/publish.

  It always runs before grouping and before group confirmation.
- Precedence is fixed and covered by tests:

  | Validator | LLM verdict | Result |
  |---|---|---|
  | negative proof | any | `false_positive`, `verdict_reason` = proof, `reason_tag` set |
  | positive fact | `false_positive` | `unverified`, `unresolved_reason=conflict`, both reasons kept |
  | positive fact | `true_positive` or none | unchanged; proof added to evidence |
  | evidence gap | any | `unverified`, `unresolved_reason=evidence_missing`, `missing` named (e.g. "callee `RequestsMgr.getCommMethod(String)` body not resolved") |
  | no opinion | any | unchanged |

- A regex hit with a negative proof is still written as a row (`kind=regex`, verdict FP). It is never dropped, so the report shows the scanner looked at it.
- Every validator outcome appends a `finding_decisions` row with `stage=validator` and the validator's name and version (SAST-00-050).
- `Finding.reason_tag` (`String(60)`, nullable) is added, and `conflict` is added to `UNRESOLVED_REASONS`.
- Validator proofs and facts are rendered into the deep-scan, group-confirm and flow-verify user prompts as a `Deterministic facts:` block, only when a validator or the facts have something to say. A finding with nothing to add keeps byte-identical prompts, so its cache entries stay valid.
- Two generic validators ship with the hook:
  - `declaration_not_call`: a call-site rule matched on a method declaration gives a negative proof `match_is_declaration` (#37).
  - `stub_method`: a sink rule on a stub body gives a negative proof `stub_no_sink` (#39). This applies to the stub occurrence only; its group siblings are untouched.
- A new scan limitation, `occurrence-validators` (default **on**, a real toggle), is read by `agent_bridge.run_real_scan` into `state["occurrence_validators"]`. Off means the hook is skipped entirely.

**Dev Notes**
- Follow the existing real-toggle pattern: `project.limitations_config.get(id, default)` → `initial_state` → `state.get(key, default)`. Add the entry to `scan_limitations.py` and update `tests/test_scan_limitations.py`.
- Validators must be pure and fast: no LLM calls and no network. Any lookup beyond the current file goes through `ctx`, which caches file reads.
- A validator must never return a negative proof based on a rule name, file path, logger spelling or severity (review §9.4 gate 2). Put that in the registry docstring and the validator template.
- The result cache key covers the full prompt, so adding the facts block changes keys only where it appears. No `RESULT_CACHE_VERSION` bump is needed for the prompt, but the response-handling precedence is new, so bump it once in this story.

**Test Notes**
- Test level(s): unit (precedence table), integration (deep-scan, triage and confirm paths with a stub validator).
- What to assert:
  - Each row of the precedence table, using a fake validator and a fake LLM verdict.
  - A regex hit with a negative proof is persisted with `verdict=false_positive`, `reason_tag`, and a `validator` decision row.
  - With `occurrence-validators` off, results equal the pre-change output for the same fixture.
  - The prompt for a finding with no facts is byte-identical to the pre-change prompt (compare against a snapshot).
  - `declaration_not_call` fires for `public int deleteJob(int id) {` matched by a `runtime-sink-sql-deleteJob` rule.
  - `stub_method` fires on the stub but not on the real implementation in the same group.
- Test data / fixtures needed:
  - a `validators/` fixture directory with a stub interface implementation and a declaration line;
  - corpus cases `aggregation-stub-vs-impl` (from #39) and `declaration-not-call` (from #37) added to `tests/accuracy_corpus/`.
- Entry point to exercise: `validators.run_validators`, `scan_deep_files`, `scan_triage_files`, `group_confirm_unverified_findings` (patched `call_llm`).

**DevOps Notes**
- Build/CI impact: run the accuracy gate (SAST-00-100). New corpus cases need recorded responses.
- Deploy impact: one nullable column; one new scan limitation, shown automatically by `ScanLimitationsPanel`.
- Observability: `usage_summary` gains a `validators` block with counts per validator and outcome.

**Dependencies:** SAST-01-010, SAST-00-010, SAST-00-050
**Blocks:** SAST-01-040, SAST-01-050, SAST-01-090; every validator story in EPIC-02 and EPIC-03

**Definition of Done:** code merged + tests green (dev + test) + accuracy gate green + builds/deploys clean (devops)

---

### SAST-01-030 Logging-line publish suppression decided by CWE, not spelling

**Epic:** EPIC-01 Per-Occurrence Decisions, Grouping and Publish Filters        **Parent:** EPIC-01
**Parallelism:** Parallel    **Sprint:** 4

**Story**
As a security reviewer, I want a finding about a secret or forged content in a log line to be published like any other, so that credential logging such as #257/#258/#270 is never deleted just because the flagged line is a logger call.

**Acceptance Criteria**
- In `should_publish_finding`, the logging-line check (snippet or anchored line is a log call) drops a finding **only** when its CWE belongs to a sink class a log call cannot be: SQL injection, XSS, command injection, path traversal, XXE, SSRF, deserialization and LDAP (CWE-89/79/78/22/611/918/502/90). The CWE set lives in one named constant.
- These are never dropped by the logging check: CWE-117, CWE-532, CWE-312/313/359, CWE-200/209/497 and CWE-798. Neither are findings with no CWE; those are still handled by `suppress_no_cwe`.
- "Is a log call" is decided from `facts.call` receiver resolution: any `org.slf4j`, `org.apache.logging.log4j`, `org.apache.log4j`, `java.util.logging`, `org.apache.commons.logging`, `org.jboss.logging` logger, whatever the variable is called, plus `console.*` and `NGXLogger` in TS. `_LOGGING_CALL_RE` is the fallback only when facts are `None`.
- Each logging-line drop is counted (`usage_summary.publish_filter.logging_line_dropped`, by CWE) and recorded as a `finding_decisions` row (`stage=publish_filter`) before the finding is discarded.
- Corpus cases added:
  - `secret-in-logger` (positive): a password value passed to `logger.error`;
  - `secret-in-renamed-logger` (positive): the same with `private static final Logger AUDIT = ...` and `AUDIT.info(pwd)`;
  - `sqli-blamed-on-log-line` (negative): a deep-scan CWE-89 finding anchored on a `log.debug("select ..." + id)` line.

**Dev Notes**
- The decision row needs a `finding_id`, but dropped findings are never written. Record these in a `publish_filter_drops` list on the scan's `usage_summary` (rule, file, line, CWE, reason) rather than in `finding_decisions`. Use the same shape so the SAST-00-090 diff can show them as `removed (publish_filter)`.
- Do not widen any other filter in this story.

**Test Notes**
- Test level(s): unit (`should_publish_finding` table), corpus.
- What to assert:
  - CWE-532 on `logger.error("pwd=" + pwd)` → published.
  - Same with logger variable `AUDIT` → published.
  - CWE-89 on a log line → dropped, and counted under `logging_line_dropped["CWE-89"]`.
  - CWE-117 on a log line → published.
  - With facts `None` and the old regex matching, a CWE-532 finding is still published.
  - The three corpus cases pass the gate.
- Test data / fixtures needed: the three corpus cases above.
- Entry point to exercise: `llm_file_scan.should_publish_finding`, `finalize_findings`.

**DevOps Notes**
- Build/CI impact: accuracy gate.
- Deploy impact: none. Expect slightly more published CWE-532/117 findings on rescans; brief whoever reads scan reports.
- Observability: the `logging_line_dropped` counter by CWE.

**Dependencies:** SAST-01-010
**Blocks:** EPIC-03 (SAST-03-060 relies on CWE-532 surviving publication)

**Definition of Done:** code merged + tests green (dev + test) + accuracy gate green + builds/deploys clean (devops)

---

### SAST-01-040 Noisy-rule publication requires evidence, not confidence

**Epic:** EPIC-01 Per-Occurrence Decisions, Grouping and Publish Filters        **Parent:** EPIC-01
**Parallelism:** Parallel    **Sprint:** 4

**Story**
As a developer acting on findings, I want a SQL-concatenation true positive to be published only when its own statement shows query construction or a named source, so that a confident guess with no evidence shows up as unresolved instead of as a confirmed injection.

**Acceptance Criteria**
- In `should_publish_finding`'s noisy-rule branch (`_is_noisy_rule`), the `confident` shortcut is removed.
- `builds_sql` is evaluated on the finding's own statement (the `facts.call` span, or the enclosing statement when there is no call), not on the whole ±context window. When facts are missing it falls back to the current window check.
- `has_source` is true only when the model's `source` expression text appears in the enclosing method's body, or on the flow path for flow findings.
- A noisy-rule true positive with neither `builds_sql` nor `has_source` is **published as `unverified`** with `unresolved_reason=evidence_missing` and a note naming what was missing. It is not dropped and not published as TP.
- A noisy-rule false positive keeps today's behaviour (dropped as a generic catalog echo), now counted in `usage_summary.publish_filter.noisy_fp_dropped`.
- `UNEVIDENCED_CONFIDENCE_FLOOR` is deleted if nothing else reads it. Otherwise its docstring states it no longer publishes anything.

**Dev Notes**
- This is a publish-time change only. The deep-scan prompt is unchanged.
- `_RESULTSET_READ_RE` (a bare ResultSet read is dropped) is out of scope; leave it.

**Test Notes**
- Test level(s): unit, corpus.
- What to assert:
  - A noisy-rule TP with confidence 0.95, no `source` and no concatenation in its statement is published as `unverified/evidence_missing`.
  - The same with `"SELECT ... " + id` in its statement → published TP.
  - The same with `source="request.getParameter(\"id\")"` present in the method → published TP.
  - The same with that `source` text absent from the method → `unverified`.
  - A concatenation 15 lines above, in a different statement, no longer counts as `builds_sql` when facts are available.
- Test data / fixtures needed: corpus case `noisy-sql-confident-no-evidence` (uncertain → expected `unverified`).
- Entry point to exercise: `should_publish_finding`.

**DevOps Notes**
- Build/CI impact: accuracy gate.
- Deploy impact: none.
- Observability: counters `noisy_tp_demoted_unverified` and `noisy_fp_dropped`.

**Dependencies:** SAST-01-010, SAST-01-020
**Blocks:** SAST-02-030

**Definition of Done:** code merged + tests green (dev + test) + accuracy gate green + builds/deploys clean (devops)

---

### SAST-01-050 De-duplication keeps distinct sinks and records conflicts

**Epic:** EPIC-01 Per-Occurrence Decisions, Grouping and Publish Filters        **Parent:** EPIC-01
**Parallelism:** Parallel    **Sprint:** 4

**Story**
As a security reviewer, I want two different calls on nearby lines to stay two findings, and two conflicting verdicts on the same call to be visible as a conflict, so that de-duplication can neither merge a safe log with an unsafe one nor quietly pick the more alarming answer.

**Acceptance Criteria**
- `merge_dedupe` merges two findings only when they refer to the **same AST node**: same `facts.call` start position, or the same `occurrence_id` when facts are missing. Two calls within `DEDUPE_LINE_WINDOW` stay separate, e.g. #98's count log at 1135 and the `getMessage` log at 1139.
- When findings on the same node disagree:
  - a validator negative proof or positive fact wins, following the SAST-01-020 precedence;
  - otherwise, the finding with more evidence fields (`source`, `sink`, `data_flow` all non-empty, and the sink present on the anchored line) wins;
  - when evidence is equal, the output is `unverified` with `unresolved_reason=conflict`, and both verdict reasons are appended to `verdict_reason`.
- `_is_better` no longer prefers `true_positive` as such. Severity and confidence only break ties between findings with the **same** verdict.
- Each merge that discards a finding appends a `finding_decisions` row on the survivor (`stage=dedupe`) naming the discarded verdict.

**Dev Notes**
- Multi-chunk files can produce the same node twice, once per chunk; this is the main source of same-node conflicts.
- Keep the sort order of the output identical to today for findings with no conflicts, so report diffs stay small.

**Test Notes**
- Test level(s): unit.
- What to assert:
  - Two findings at lines 1135 and 1139 with different call nodes → two findings out.
  - Two findings on the same node, TP (no evidence fields) vs FP (with a validator negative proof) → FP.
  - TP vs FP with equal evidence → `unverified/conflict`, and `verdict_reason` contains both reasons.
  - The same verdict at different severities → the higher severity survives (unchanged behaviour).
  - With facts `None`, merging falls back to `occurrence_id` equality.
- Test data / fixtures needed: corpus case `adjacent-log-calls` (from #98: count log is negative, `getMessage` log is evaluated separately).
- Entry point to exercise: `llm_file_scan.merge_dedupe`.

**DevOps Notes**
- Build/CI impact: accuracy gate.
- Deploy impact: none. Expect a few more findings per file where adjacent sinks were previously merged.
- Observability: counter `dedupe_conflicts` per scan.

**Dependencies:** SAST-01-010, SAST-01-020
**Blocks:** EPIC-03 (SAST-03-020)

**Definition of Done:** code merged + tests green (dev + test) + accuracy gate green + builds/deploys clean (devops)

---

### SAST-01-060 Semantic group keys: split groups whose members differ

**Epic:** EPIC-01 Per-Occurrence Decisions, Grouping and Publish Filters        **Parent:** EPIC-01
**Parallelism:** Serial/Blocking    **Sprint:** 4

**Story**
As a security reviewer, I want a group to contain only occurrences that share the same resolved facts, so that a safe DAO method and an unsafe DTO path that happen to share a name are never confirmed or dismissed together.

**Acceptance Criteria**
- `llm_file_scan.group_key_for_finding` and `scan_export._finding_group_key` both append a **semantic signature** from `facts`:
  - the resolved callee identity: owner FQN + name + arity, for calls;
  - the resolved receiver type;
  - the argument-kind vector, e.g. `(string_literal, numeric)`.

  With `group_by_rule: true`, the rule still collapses varying `matched_text`, but members are still split by semantic signature.
- Members whose facts are `None` get the signature `unresolved`. They group with each other but never with resolved members.
- The two key functions produce identical keys for identical input; a shared test enforces it.
- Required splits, each a corpus case:
  - #62: DAO `getPortID(long)` vs DTO `xmlPortMsg.getPortID()` → 2 groups;
  - #78: numeric-argument members vs string-concatenation members → 2 groups;
  - #284: `Calendar` receiver vs `Throwable` argument → 2 groups;
  - #39: stub vs implementations → 2 groups.
- `group_unverified_findings` summaries report the semantic signature so the grouping log shows why groups split.

**Dev Notes**
- The report key still leads with the verdict (`_finding_group_key`), so verdict splits are unchanged. This story adds the semantic split after the verdict.
- Expect more, smaller groups. The confirm stage's cost grows with group count, so measure the group count and confirm-call count on the corpus and on one real scan, and record both in the PR.
- `feedback._fingerprint` hashes `_finding_group_key`, so existing `FindingReview` rows will not match the new keys for rescans. That is acceptable (reviews are per scan), but document it in the PR, and make sure `find_review` for an old scan still uses the stored `member_finding_ids`.

**Test Notes**
- Test level(s): unit (key functions), integration (grouping over a mixed file set), corpus.
- What to assert:
  - The four required splits.
  - Identical construct and facts in 100 files → 1 group.
  - The same construct with facts `None` in some files → 2 groups (resolved, unresolved).
  - `group_key_for_finding(x) == _finding_group_key(x)[1:]` for a table of inputs. Adapt the slice to the actual key layout; the point is the shared portion is equal.
  - An existing review on an old scan is still found.
- Test data / fixtures needed: corpus cases `group-split-same-name-different-owner` (#62), `group-split-numeric-vs-concat` (#78), `group-split-receiver-type` (#284), `aggregation-stub-vs-impl` (#39).
- Entry point to exercise: `group_key_for_finding`, `scan_export._finding_group_key`, `group_unverified_findings`, `GET /scans/{id}/findings`.

**DevOps Notes**
- Build/CI impact: accuracy gate.
- Deploy impact: none. Report row counts rise for repos with heterogeneous groups; brief report readers.
- Observability: log the group count before and after the semantic split per scan.

**Dependencies:** SAST-01-010
**Blocks:** SAST-01-070, SAST-01-080; EPIC-02 (SAST-02-060)

**Definition of Done:** code merged + tests green (dev + test) + accuracy gate green + builds/deploys clean (devops)

---

### SAST-01-070 Per-member confirmation with coverage accounting

**Epic:** EPIC-01 Per-Occurrence Decisions, Grouping and Publish Filters        **Parent:** EPIC-01
**Parallelism:** Serial/Blocking    **Sprint:** 5

**Story**
As a security reviewer, I want grouped confirmation to decide each member it actually looked at, and to leave unseen members unresolved, so that "confirmed via grouped review" never means "one sample was read and the verdict copied to 150 others".

**Acceptance Criteria**
- `build_group_confirm_prompt` and `build_group_confirm_batch_prompt` send a numbered excerpt per member (`m1..mn`) up to `GROUP_CONFIRM_MEMBER_CHAR_BUDGET`, instead of one representative window plus a file list. Overlapping windows in one file are merged as triage already does (`merged_context_windows`).
- The response schema asks for one decision per member id. One group-level verdict is accepted **only** when every member has the same semantic signature *and* the same normalized excerpt.
- Members not shown because of the budget, or missing from the response, are handled like triage's missing ids:
  - they get one follow-up call with just their excerpts;
  - anything still undecided is `unverified` with `unresolved_reason=not_in_sample` or `llm_missing_verdict`;
  - no member ever inherits a sibling's verdict.
- Each group records `reviewed_members` and `total_members`. These are stored in each member's decision row and shown in `verdict_reason`, e.g. "Reviewed 3 of 156 occurrences", replacing "confirmed via grouped review of N occurrence(s)".
- `TRIAGE_GROUP_WINDOWS` in `llm_triage` mode follows the same rule: members beyond the windows shown are `not_in_sample`, never assigned.
- `RESULT_CACHE_VERSION` is bumped (the response schema changed).
- On the corpus, the confirm-stage token cost and call count are reported before and after in the PR. `groups_per_call` batching stays.

**Dev Notes**
- The reachability-strongest representative logic (CLAUDE.md, `node_corroborate_flows`) still picks which member's path evidence goes in the prompt, but every member now gets its own excerpt and decision.
- The `$2` cutoff and `reserve_stage_budgets` shares are unchanged. When the confirm share runs out, the remaining members are `unverified/llm_budget_exhausted` (SAST-00-010), not silently inherited.
- `verdict_updates_writer` keys on `(scan_id, file_path, rule_id, line)`. Per-member updates use that key as they do today, so no writer change is needed.

**Test Notes**
- Test level(s): unit (prompt and parsing), integration (patched `call_llm`), corpus.
- What to assert:
  - A group of 5 members within budget → the prompt contains `m1..m5` excerpts, and the response decides each.
  - A response omitting `m4` → one follow-up call for `m4` only. If that also omits it → `m4` is `unverified/llm_missing_verdict`.
  - A group of 200 members over budget → the members not sent are `unverified/not_in_sample`, and `reviewed_members < total_members` appears in `verdict_reason`.
  - A uniform group (identical signature and excerpt) accepts one group verdict.
  - The #78 corpus case: the unsafe members are TP and the numeric members get their own decisions.
- Test data / fixtures needed: corpus case `group-mixed-members` (#78); recorded responses for each case.
- Entry point to exercise: `group_confirm_unverified_findings`, `confirm_finding_group_batch`.

**DevOps Notes**
- Build/CI impact: accuracy gate; re-record the confirm responses for affected corpus cases.
- Deploy impact: higher confirm-stage input tokens per scan. Check the cost on one real scan before release and adjust `GROUP_CONFIRM_MEMBER_CHAR_BUDGET` if the stage share runs out early.
- Observability: `usage_summary` per step gains `members_reviewed`, `members_total` and `members_not_in_sample`.

**Dependencies:** SAST-01-060, SAST-00-020
**Blocks:** SAST-01-080

**Definition of Done:** code merged + tests green (dev + test) + accuracy gate green + builds/deploys clean (devops)

---

### SAST-01-080 Mixed constructs and review coverage in the UI and exports

**Epic:** EPIC-01 Per-Occurrence Decisions, Grouping and Publish Filters        **Parent:** EPIC-01
**Parallelism:** Parallel (with SAST-01-090)    **Sprint:** 5

**Story**
As a developer reading a report, I want to see when one construct has members with different verdicts, and how many members were actually reviewed, so that a mixed construct is visible as mixed rather than split into rows that look unrelated.

**Acceptance Criteria**
- Each grouped row carries a `construct_key`: the group key without its leading verdict. The findings API returns, per row, `construct_mix`: counts of TP / FP / unresolved across all rows sharing that `construct_key`.
- The UI findings panel shows a "Mixed: 3 confirmed · 150 false positive · 3 unresolved" chip on each row of a mixed construct. Clicking it filters to that construct.
- The XLSX findings sheet adds "Construct Mix" and "Reviewed / Total" columns. The PDF shows the same two facts under each finding heading.
- `count_findings` (SAST-00-060) counts **per member**. A mixed construct adds to each verdict bucket only the members with that verdict. `check_report_consistency` covers the new columns.
- The feedback API refuses a whole-group reviewer verdict on a row whose construct is mixed, unless the request names the member IDs it applies to or sets `apply_to: "all"` explicitly. The UI asks the reviewer which one they mean.

**Dev Notes**
- `group_findings_by_issue` mutates ORM instances. Compute `construct_mix` from the same grouped list in the same request; don't re-query.
- Next.js: check `node_modules/next/dist/docs/` before touching route handlers. The proxy route for findings already exists and should not need to change.
- The new feedback-API parameter needs no new route. Keep the same `require(...)` key.

**Test Notes**
- Test level(s): integration (API, exports), frontend lint/build, manual UI check.
- What to assert:
  - A scan with a construct split 2 TP / 3 FP shows `construct_mix={tp:2, fp:3, unresolved:0}` on both rows.
  - The XLSX columns are present and agree with the API.
  - `check_report_consistency` returns `[]`.
  - A whole-group override on a mixed construct without `apply_to` → 409 with a clear message. With `apply_to:"all"` → accepted, and a review event is recorded per member.
  - UI: the chip renders and filters.
- Test data / fixtures needed: mock-engine scan seeded with a mixed construct and one uniform construct.
- Entry point to exercise: `GET /scans/{id}/findings`, `export.xlsx`, `export.pdf`, the feedback API, `/scans/[id]`.

**DevOps Notes**
- Build/CI impact: `npm run lint`, `npm run build`, accuracy gate (consistency check).
- Deploy impact: two new XLSX columns. Tell consumers who parse by position.
- Observability: none beyond existing.

**Dependencies:** SAST-01-060, SAST-01-070, SAST-00-060
**Blocks:** —

**Definition of Done:** code merged + tests green (dev + test) + builds/deploys clean (devops)

---

### SAST-01-090 Pre-publication explanation consistency check

**Epic:** EPIC-01 Per-Occurrence Decisions, Grouping and Publish Filters        **Parent:** EPIC-01
**Parallelism:** Parallel    **Sprint:** 5

**Story**
As a security reviewer, I want each finding checked, before it is published, for an explanation that contradicts its own code or verdict, so that a finding describing a different line, a defence already in place, or a "safe" verdict reason under a TP never reaches the report as a settled answer.

**Acceptance Criteria**
- A deterministic `check_explanation(finding, facts, source_text) -> list[contradiction]` runs on deep-scan, flow-verify and group-confirm results before publishing. It detects:
  1. **Sink not on line:** the `sink` expression (or its callee name) is not in the anchored call node, or on the anchored line when facts are missing. Example: #98 discusses line 1139 while anchored at 1135.
  2. **Source not in scope:** the `source` expression is not in the enclosing method or on the flow path.
  3. **Verdict/reason mismatch:** a TP whose `verdict_reason` states the construct is safe ("parameterized", "bound", "no injection risk", "constant", "not exploitable"), or an FP whose reason asserts exploitation. Example: #93, where the scanner's own reason says no risk.
  4. **Fix already present:** `ai_fix` recommends a construct that already appears in the anchored call. Example: #81, which recommends `logger.error(msg, ex)` when that is the code.
  5. **Unproven "no callers" claim:** `verdict_reason` claims "no callers", "unused" or "dead code" while the call graph shows callers or is incomplete.
- When a contradiction is found and the stage still has budget, there is **one** targeted retry. It uses the same prompt plus a `Deterministic facts:` block (SAST-01-020) stating the contradiction.
- If the retry still contradicts, or there is no budget, the finding is `unverified` with `unresolved_reason=explanation_contradiction` and the contradictions are listed. **It is never turned into FP.** A wording check must not dismiss a vulnerability (review §5.8).
- `explanation_contradiction` is added to `UNRESOLVED_REASONS`.

**Dev Notes**
- Keep the phrase lists short, explicit and in one constant. They are only a trigger for a retry or for unresolved status, never a reason to dismiss.
- Check 5 depends on call-graph completeness. Until SAST-02-070 delivers the entry-point model, treat the graph as incomplete for every Java repo, so check 5 always fires on a "no callers" claim.

**Test Notes**
- Test level(s): unit (each check), integration (retry path with patched `call_llm`), corpus.
- What to assert:
  - One test per check above using a minimal finding plus source.
  - A first response contradicting and a retry consistent → the retry's verdict is published, and both decisions are in the history.
  - The retry still contradicting → `unverified/explanation_contradiction`.
  - No budget → no retry, `unverified`.
  - A consistent finding → no retry and no extra cost.
- Test data / fixtures needed: corpus cases `explanation-wrong-line` (#98), `explanation-tp-says-safe` (#93), `explanation-fix-already-present` (#81).
- Entry point to exercise: `check_explanation`, `scan_deep_files`, `confirm_finding_group_batch`, `flow_verify` (patched `call_llm`).

**DevOps Notes**
- Build/CI impact: accuracy gate.
- Deploy impact: a small increase in LLM calls (retries only).
- Observability: `usage_summary` gets `explanation_contradictions` by check type, plus `retries` and `retry_resolved`.

**Dependencies:** SAST-01-010, SAST-01-020
**Blocks:** SAST-02-070

**Definition of Done:** code merged + tests green (dev + test) + accuracy gate green + builds/deploys clean (devops)

---

### SAST-01-100 Rescan, diff and adjudicate the grouping and filter cases

**Epic:** EPIC-01 Per-Occurrence Decisions, Grouping and Publish Filters        **Parent:** EPIC-01
**Parallelism:** Serial/Blocking    **Sprint:** 5

**Story**
As the release owner, I want the npg-pakistan application rescanned with this epic's changes and every changed decision reviewed, so that the grouping and filter changes are judged by occurrence-level outcomes, not by a smaller report.

**Acceptance Criteria**
- The application at commit `ae38067c239e` is scanned twice:
  - once before this epic, with the engine at its pre-EPIC-01 tag;
  - once after, with `force: true`.

  The SAST-00-090 decision diff is exported.
- Every `true_positive → false_positive|removed` transition is reviewed by a second person, and its outcome is recorded in the corpus labels (`backend/tests/accuracy_corpus/_labels/`).
- #62, #78 and #284 are each confirmed split into homogeneous groups. #251's 41 file occurrences each carry their own decision, and coverage is shown for all four.
- #257/#258/#270 remain published.
- Findings the diff shows as newly mixed or newly unresolved are listed in the epic close-out note with their next action (an EPIC-02/03 story, or evidence needed).
- The accuracy gate is green on the corpus.

**Dev Notes**
- The scan needs a checkout of the application at `ae38067c239e` (review §10). It is not committed to this repo; run against a local clone.
- Turn off the cross-scan cache for the "after" scan (`metadata.bypass_llm_cache=true`) so it reflects the new prompts.

**Test Notes**
- Test level(s): exploratory/acceptance (real scan), corpus.
- What to assert: the acceptance criteria above. Record the diff summary (transition counts by rule) in the close-out note.
- Test data / fixtures needed: the application checkout; the R/S labels imported by SAST-00-080.
- Entry point to exercise: `POST /scans` (force), `GET /scans/{id}/decision-diff?base=`.

**DevOps Notes**
- Build/CI impact: none.
- Deploy impact: two real scans with LLM spend (about $2 cutoff each, up to $4 total). Schedule them and confirm the provider credentials.
- Observability: archive both scans' exports and the diff XLSX with the close-out note.

**Dependencies:** SAST-01-030 to SAST-01-090, SAST-00-080, SAST-00-090
**Blocks:** —

**Definition of Done:** diff reviewed + labels updated + accuracy gate green

---

## Story order and parallelism

| Story | Title | Parallelism | Sprint | Depends On |
|---|---|---|---|---|
| SAST-01-010 | Occurrence facts extractor | Serial/Blocking | 3 | SAST-00-040 |
| SAST-01-020 | Validator hook and evidence precedence | Serial/Blocking | 3 | 010, SAST-00-010, 00-050 |
| SAST-01-030 | Logging-line suppression by CWE | Parallel | 4 | 010 |
| SAST-01-040 | Noisy-rule publication requires evidence | Parallel | 4 | 010, 020 |
| SAST-01-050 | De-duplication keeps distinct sinks | Parallel | 4 | 010, 020 |
| SAST-01-060 | Semantic group keys | Serial/Blocking | 4 | 010 |
| SAST-01-070 | Per-member confirmation and coverage | Serial/Blocking | 5 | 060, SAST-00-020 |
| SAST-01-080 | Mixed constructs in UI and exports | Parallel | 5 | 060, 070, SAST-00-060 |
| SAST-01-090 | Explanation consistency check | Parallel | 5 | 010, 020 |
| SAST-01-100 | Rescan, diff and adjudicate | Serial/Blocking | 5 | 030–090, SAST-00-080, 00-090 |

Sprint numbers are provisional until the Sprint Plan is agreed.

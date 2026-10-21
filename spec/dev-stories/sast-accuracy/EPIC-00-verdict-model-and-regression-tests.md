# SAST Accuracy — EPIC-00 Verdict Model and Accuracy Regression Tests

Source: `output/secure-build-npg-pakistan-accuracy-review.md` (§5.1, §6, §7 P0, §9). Template: `spec/chain-templates/scaffolding-sprint-story-generation-prompt-simple.md`.

## [EPIC-00] Verdict Model and Accuracy Regression Tests

**Goal:** Every finding has one clear decision, one stable identity and an audit trail, and every rendering (UI, JSON, XLSX, PDF) reports it the same way. A regression corpus and release gate catch accuracy changes before they ship.
**Depends On:** — (foundational)
**Blocks:** EPIC-01 (per-occurrence decisions, grouping and publish filters), EPIC-02 (SQL injection: bound parameters and method identity), EPIC-03 (log and output sinks: exact call boundaries and render context)
**Teams:** Dev / Test / DevOps

**Scope note.** In the npg-pakistan review, 141 findings were marked false positive by developers. Before any rule is tuned to fix them, the platform has to report what it decided, and that is not reliable today. The evidence:

- **FP is shown as Needs Review, but counted as dismissed.** `scan_export._display_verdict` labels `false_positive` as "Needs Review", while `_is_dismissed` drops it from the actionable totals. The same scan therefore showed 64 "Needs Review" in the developer workbook and 152 in the scanner's own Excel export.
- **Unknown model answers become FP.** `llm_file_scan._normalize_verdict` returns `false_positive` for any text it does not recognise.
- **The PDF and the Excel export disagree.** The PDF has 295 findings and the Excel export 291. Four extra findings in the PDF shift the numbering, so the two cannot be matched by position.

This epic fixes the decision model and builds the test harness that EPIC-01 to EPIC-03 add their cases to. It changes no rule, prompt wording or publish filter: those belong to the later epics.

**Decision model used throughout** (review §5.1):

| Outcome | Stored as |
|---|---|
| Confirmed security issue | `verdict=true_positive`, `issue_class=security` |
| False positive for this rule | `verdict=false_positive` (+ `verdict_reason`) |
| Needs evidence / review | `verdict=unverified` + `unresolved_reason` |
| Code quality / hardening | `issue_class=quality` (any verdict) |
| Inactive code | `issue_class=inactive` (any verdict) |

The review workflow is a separate state, taken from `FindingReview`. It is never encoded in `verdict`.

---

### SAST-00-010 Verdict, issue-class and unresolved-reason contract

**Epic:** EPIC-00 Verdict Model and Accuracy Regression Tests        **Parent:** EPIC-00
**Parallelism:** Serial/Blocking    **Sprint:** 1

**Story**
As a security reviewer, I want each finding to carry its verdict, its issue class and, when undecided, the reason it is undecided, as separate fields, so that "the scanner dismissed this" and "nobody has decided this" can never be confused.

**Acceptance Criteria**
- `app/models.py` defines one shared contract next to `UNVERIFIED_VERDICT`:
  - `VERDICTS = {true_positive, false_positive, unverified}`
  - `ISSUE_CLASSES = {security, quality, inactive}`
  - `UNRESOLVED_REASONS`, which contains at least `not_reviewed_regex`, `llm_missing_verdict`, `llm_unrecognised_verdict`, `llm_call_failed`, `llm_budget_exhausted`, `cap_reached` and `evidence_missing`.
- `Finding` gains two columns, added through `db._run_light_migrations` with idempotent `ALTER TABLE`:
  - `issue_class` (`String(20)`, nullable)
  - `unresolved_reason` (`String(40)`, nullable)
- A rule in the catalog can declare an optional `issue_class`; the default is `security`. `serializable-missing-svuid` and `logger-exception-tostring` declare `quality`.
  - `findings_from_hits` copies the field onto the finding dict.
  - `scan_runner._make_findings_writer` persists it, the same way `group_by_rule` is handled.
- Every write path that stores `verdict=unverified` also stores a non-null `unresolved_reason`:
  - regex triage → `not_reviewed_regex`
  - `LlmBudgetExhausted` → `llm_budget_exhausted`
  - a group whose batch call and fallback call both failed → `llm_call_failed`
- `GET /scans/{id}/findings` returns `issue_class` and `unresolved_reason` on each item, and `frontend/lib/api.ts` types include both.
- Existing databases migrate cleanly. Old rows keep `NULL` in both columns, and the API reports them as `issue_class: null`, never as a guessed value.

**Dev Notes**
- No Alembic exists. Follow the existing `_run_light_migrations` pattern, and make each `ALTER` safe to run twice.
- The engine cannot import `app` (the bridge loads it with `importlib`), so the enum values are mirrored in `sast_engine` (`llm_file_scan.VERDICT_UNVERIFIED` style). Add a test that the two copies match.
- Add `issue_class` to `rules/README.md`'s field reference. `tests/test_rule_catalog.py` must reject unknown `issue_class` values.
- This story changes no display labels or counts; those are SAST-00-030 and SAST-00-060.

**Test Notes**
- Test level(s): unit, integration (API), migration.
- What to assert:
  - The migration adds both columns to an existing SQLite file that predates them, and a second run is a no-op.
  - A regex-triage finding is written with `verdict=unverified, unresolved_reason=not_reviewed_regex`.
  - A finding from `serializable-missing-svuid` has `issue_class=quality`; any other regex rule has `issue_class=security`.
  - Simulating `LlmBudgetExhausted` in the deep scan leaves the remaining work as `unverified` with `unresolved_reason=llm_budget_exhausted`.
  - The `GET /scans/{id}/findings` payload contains both new keys.
  - The engine-side and app-side enum sets are equal.
- Test data / fixtures needed:
  - a pre-migration SQLite file (create it from the current schema in the test);
  - a two-rule mini catalog with one `quality` rule.
- Entry point to exercise: `db._run_light_migrations`, `scan_runner._make_findings_writer`, `GET /scans/{id}/findings` (mock engine).

**DevOps Notes**
- Build/CI impact: none beyond the existing `pytest` run.
- Deploy impact: a schema migration on startup (two nullable columns). Back up the SQLite file before deploying; the change is additive and needs no data backfill.
- Observability: log one line per scan with the count of `unverified` findings by `unresolved_reason`.

**Dependencies:** —
**Blocks:** SAST-00-020, SAST-00-030, SAST-00-050, SAST-00-060

**Definition of Done:** code merged + tests green (dev + test) + builds/deploys clean (devops)

---

### SAST-00-020 Strict verdict parsing: unknown answers stay unresolved

**Epic:** EPIC-00 Verdict Model and Accuracy Regression Tests        **Parent:** EPIC-00
**Parallelism:** Serial/Blocking    **Sprint:** 1

**Story**
As a security reviewer, I want a malformed, missing or unrecognised LLM verdict to be recorded as unresolved with its reason, so that a model or parsing failure can never silently dismiss a real vulnerability.

**Acceptance Criteria**
- `llm_file_scan._normalize_verdict` is removed. Every verdict-parsing site uses one strict parser, `parse_verdict(raw) -> (verdict | None, reason | None)`. That covers:
  - deep scan `normalize_finding` (currently `llm_file_scan.py:1119`)
  - group confirm `_confirm_result_from_item` (`:2645`)
  - triage `_strict_verdict` callers (`:2123`, `:2186`)
  - flow verify
- The strict parser:
  - accepts the exact enums (case-insensitive, `-`→`_`) and a fixed alias table: `tp`, `fp`, `true positive`, `false positive`, `confirmed`, `dismissed`;
  - returns `None` for everything else, which is written as `verdict=unverified`, `unresolved_reason=llm_unrecognised_verdict`, plus the raw text, cut to 200 characters, in `verdict_reason`;
  - drops the substring and negation heuristics. Today "not sure", "no decision" and "cannot determine" all match `_NEGATION_RE` and become `false_positive`; after this change they become unresolved.
- An empty or absent verdict is written as `unverified` with `unresolved_reason=llm_missing_verdict` (the current group-confirm behaviour, now applied everywhere).
- `_normalize_confidence` no longer invents 0.7/0.5 for an unresolved verdict: confidence is `None`.
- `llm_client.RESULT_CACHE_VERSION` goes from `"1"` to `"2"`. Response handling changes while the prompt bytes stay the same, so cached decisions made under the old parser must not be reused.
- The deep-scan, triage, confirm and flow-verify response schemas in the system prompts are unchanged (this story is about parsing only).

**Dev Notes**
- One parser in `llm_file_scan.py`, imported by `flow_verify.py`. Keep it pure (no I/O) so the table-driven test covers it fully.
- `should_publish_finding` sees `unverified` deep-scan findings for the first time on this path. Check that `suppress_low_confidence_false_positives` and `suppress_no_cwe` do not drop them. They check `false_positive` or the CWE, so an unverified finding with a catalog `rule_id` must pass. Add a test either way.
- `build_report_from_file_results` and `scan_runner._build_report_from_db_findings` already have three-way tallies; confirm that nothing falls back to an `else: false_positive` branch.

**Test Notes**
- Test level(s): unit (table-driven), integration (replayed LLM responses).
- What to assert:
  - A table of at least 25 raw inputs → expected `(verdict, reason)`. It must include:
    - `"TRUE_POSITIVE"`, `"true-positive"`, `"tp"`, `"False Positive"`, `"fp"`
    - `"not sure"`, `"no decision"`, `"unknown"`, `"maybe"`, `""`, `None`, `42`, `["true_positive"]`
    - `"not a true positive"` → unresolved. This is deliberate: it is ambiguous, and an ambiguous answer must not dismiss.
  - A deep-scan response with one finding whose verdict is `"possibly"` persists a finding with `verdict=unverified, unresolved_reason=llm_unrecognised_verdict, confidence=None`.
  - A group-confirm batch with one group carrying `"verdict": "n/a"` leaves that group `unverified` and confirms the others normally.
  - Grepping the engine for `_normalize_verdict` finds nothing.
  - The cache key changes when `RESULT_CACHE_VERSION` changes.
- Test data / fixtures needed: canned LLM JSON responses in `backend/tests/fixtures/llm_responses/verdicts/`.
- Entry point to exercise: `llm_file_scan.parse_verdict`, `normalize_finding`, `confirm_finding_group_batch`, `flow_verify` result handling (patched `call_llm`).

**DevOps Notes**
- Build/CI impact: none.
- Deploy impact: the cache version bump means the first scan of each project after release misses the cross-scan result cache, so expect one full-cost scan per project. The `$2` cutoff still applies. Tell the scan operators before rollout.
- Observability: add `unrecognised_verdicts` and `missing_verdicts` counters to `usage_summary` per step, so a prompt or model change that degrades output format is visible.

**Dependencies:** SAST-00-010
**Blocks:** SAST-00-070, SAST-00-100

**Definition of Done:** code merged + tests green (dev + test) + builds/deploys clean (devops)

---

### SAST-00-030 Show FP as FP: separate the verdict from the review state in UI and exports

**Epic:** EPIC-00 Verdict Model and Accuracy Regression Tests        **Parent:** EPIC-00
**Parallelism:** Parallel (with SAST-00-040, SAST-00-050)    **Sprint:** 2

**Story**
As a developer reading a scan report, I want the scanner's verdict and the human review state shown side by side with their real names, so that a finding the scanner dismissed is never presented as one still waiting for review.

**Acceptance Criteria**
- `scan_export._display_verdict` maps each verdict to its own label:
  - `true_positive` → "True Positive"
  - `false_positive` → "False Positive"
  - `unverified` → "Unresolved", with the reason as a suffix, e.g. "Unresolved (regex, not reviewed)"
  - anything else → "Unknown (<raw>)" and a logged warning.
  - "Needs Review" is no longer a verdict label anywhere.
- A new `review_state` is derived from `FindingReview`:
  - `pending`: no review row
  - `agreed`: reviewer verdict equals the scanner's
  - `overridden`: `is_override`
  - `resolved`: `issue_status`/`is_closed`

  It is returned by `GET /scans/{id}/findings` and shown next to the verdict, e.g. "Scanner: False Positive · Review: pending".
- The XLSX findings sheet replaces the single "Verdict" column with four: "Scanner Verdict", "Review State", "Issue Class" and "Unresolved Reason". It adds a "Verdict (raw)" column holding the stored enum value.
- The PDF pill colour and text use the same three labels. The cover strip names the buckets "Confirmed", "Unresolved" and "False Positive" (not "Dismissed").
- Frontend `lib/verdict.ts` `verdictKind`:
  - returns a fourth kind, `"unknown"`, for `null`/unrecognised values instead of `"dismissed"`;
  - `ScanFindingsPanel.tsx` renders that kind with a distinct badge.
- The JSON API keeps the raw enum in `verdict`, so existing CI consumers of `gates.build_gate_summary` see no change in field values.

**Dev Notes**
- Update `test_display_verdict_labels_unverified_distinctly`. Its "Unverified (regex)" expectation becomes "Unresolved (regex, not reviewed)".
- `ScanFindingsPanel.tsx:177` duplicates `_is_dismissed` to compute chips. Leave the counting itself to SAST-00-060, but switch the label text here.
- `dastVerdictKind` delegates to `verdictKind`. Check the DAST findings UI still renders, and don't change DAST semantics.
- Check `node_modules/next/dist/docs/` before touching any Next-specific API (per `frontend/AGENTS.md`); this story should need none.

**Test Notes**
- Test level(s): unit (backend label mapping), integration (export bytes), frontend lint and build, manual UI check.
- What to assert:
  - `_display_verdict` for all three enums, plus `None`, `""` and `"weird"`.
  - The XLSX header row contains the five new columns. For a scan with one finding of each verdict, each row's "Verdict (raw)" equals the DB value.
  - The PDF text (extract with `pypdf` in the test) contains no "Needs Review" for a `false_positive` finding.
  - `review_state` equals `pending` without a review row and `overridden` after an override via the feedback API.
  - Frontend: `verdictKind(null) === "unknown"`, `verdictKind("false_positive") === "dismissed"`.
  - UI check on `/scans/<id>`: an FP finding shows "Scanner: False Positive · Review: pending".
- Test data / fixtures needed: a mock-engine scan seeded with one TP, one FP, one unverified (regex) and one unverified (LLM missing verdict) finding, plus one FindingReview override.
- Entry point to exercise: `scan_export._display_verdict`, `GET /scans/{id}/export.xlsx`, `GET /scans/{id}/export.pdf`, `GET /scans/{id}/findings`, `/scans/[id]` page.

**DevOps Notes**
- Build/CI impact: `npm run lint` and `npm run build` must pass.
- Deploy impact: the XLSX column layout changes. Tell anyone who parses the Excel export by column position, and point them to "Verdict (raw)".
- Observability: the `Unknown (<raw>)` warning log line is the signal that a non-enum verdict reached the export layer; it should be zero after SAST-00-020.

**Dependencies:** SAST-00-010
**Blocks:** SAST-00-060

**Definition of Done:** code merged + tests green (dev + test) + builds/deploys clean (devops)

---

### SAST-00-040 Stable occurrence identity and scan version stamp

**Epic:** EPIC-00 Verdict Model and Accuracy Regression Tests        **Parent:** EPIC-00
**Parallelism:** Parallel (with SAST-00-030)    **Sprint:** 1

**Story**
As a reviewer comparing two scans, I want every finding occurrence to carry an ID that survives a rescan and unrelated line shifts, and every scan to record exactly which engine, rules, prompts and model produced it, so that decisions can be joined across scans and exports without relying on report numbering.

**Acceptance Criteria**
- `Finding` gains two fields:
  - `occurrence_id` (`String(64)`, indexed): sha256 of `project_id | file_path | rule_id | cwe | normalized sink expression | enclosing method signature | ordinal of this sink within that method`.
  - `identity_quality` (`exact` | `file_level`): `file_level` when no enclosing method could be resolved.
- Line numbers are **not** part of `occurrence_id`. Inserting a blank line above a finding leaves its ID unchanged. Changing the sink expression or moving it into a different method changes it.
- The sink expression is computed in one place:
  - regex findings use `matched_text`;
  - LLM findings use `sink`, or the flagged line's `snippet` when `sink` is empty.
  - Normalization is shared with `scan_export._finding_group_key` (whitespace collapse).
- The enclosing method comes from the tree-sitter parse already used by `call_graph` (Java/TS/Python); other languages get `identity_quality=file_level`.
- `Scan.metadata_json["versions"]` records:
  - `engine_commit`: git SHA of the backend checkout, or `"unknown"`
  - `rule_catalog_sha256`: hash of the loaded catalog files
  - `result_cache_version`
  - `system_prompt_sha256` per LLM step
  - `llm_provider` and `llm_model`
- `occurrence_id` appears in the JSON findings response, as a new XLSX column "Occurrence ID", and in small text under each PDF finding. Grouped rows list the member occurrence IDs in `affected_files` order.

**Dev Notes**
- This is per-occurrence and differs from `feedback._fingerprint`, which hashes the *group* key and backs `FindingReview`. Keep both and do not repurpose the review fingerprint. EPIC-01 builds per-member decisions on `occurrence_id`.
- Compute it at write time in `scan_runner._make_findings_writer`. The verdict and reachability update writers keep keying on `(scan_id, file_path, rule_id, line)`; do not change those keys in this story.
- If the same sink appears twice in one method, the ordinal is counted by position within the method (first, second, ...), so two identical calls remain two occurrences.
- Version stamping belongs in `agent_bridge.run_real_scan` (real engine) and the mock engine path (fixed values) so tests can assert it.

**Test Notes**
- Test level(s): unit, integration.
- What to assert:
  - The same Java fixture scanned twice gives identical `occurrence_id` sets.
  - Adding 5 blank lines and a comment above the method gives the same IDs with different `line` values.
  - Renaming the enclosing method changes only that method's IDs.
  - Two identical `log.info(x)` calls in one method get two distinct IDs.
  - A finding in a `.yaml` file has `identity_quality=file_level`.
  - Mock scan metadata contains all five `versions` keys.
  - The XLSX "Occurrence ID" column equals the API value for each row.
- Test data / fixtures needed: a small Java class with two methods and a duplicated sink, plus a variant of it with shifted lines (`backend/tests/fixtures/identity/`).
- Entry point to exercise: the `occurrence_id` helper, `scan_runner._make_findings_writer`, `GET /scans/{id}/findings`, `export.xlsx`.

**DevOps Notes**
- Build/CI impact: none.
- Deploy impact: two nullable columns plus an index, added through `_run_light_migrations`. Old scans have `NULL` IDs and are excluded from decision diffs (SAST-00-090).
- Observability: log the share of `file_level` identities per scan. A high share means the diff's join quality is weak for that repo.

**Dependencies:** —
**Blocks:** SAST-00-050, SAST-00-080, SAST-00-090

**Definition of Done:** code merged + tests green (dev + test) + builds/deploys clean (devops)

---

### SAST-00-050 Immutable decision history per occurrence

**Epic:** EPIC-00 Verdict Model and Accuracy Regression Tests        **Parent:** EPIC-00
**Parallelism:** Parallel (with SAST-00-030)    **Sprint:** 2

**Story**
As an auditor, I want every machine and human decision on a finding kept as an append-only record, with what decided it and when, so that the original verdict is never lost when a later stage or a reviewer changes it.

**Acceptance Criteria**
- A new table, `finding_decisions` (append-only), records machine decisions:
  - `finding_id` and `occurrence_id`
  - `stage`: `deep_scan`, `triage_regex`, `triage_llm`, `group_confirm`, `flow_verify`, `reachability_floor`, `joern_confirm` or `reconcile`
  - `verdict`, `confidence`, `unresolved_reason`, `verdict_reason`
  - `evidence_version`: the `versions` block from SAST-00-040, plus `result_cache_hit` (bool)
  - `at`
- Rows are written in three places:
  - the initial insert, by `_make_findings_writer`;
  - every verdict change, by `_make_verdict_updates_writer`, by `reconcile_unverified_findings`, and by the reachability confidence floor (when it raises confidence);
  - not at all when an update leaves the verdict and confidence unchanged.
- Rows are never updated or deleted, except by cascade when the scan is deleted.
- `Finding.verdict` stays the current value and always equals the latest `finding_decisions` row for that finding (an invariant test).
- Human decisions stay in `FindingReviewEvent`. `GET /scans/{id}/findings/{finding_id}/history` returns both streams merged in time order. Each entry carries `source: machine|human`, `actor` (stage name or user), from→to verdict and `evidence_version`.
- The findings panel's detail view shows a "History" list for the selected finding.

**Dev Notes**
- Do not move `FindingReview` state onto `Finding`: its docstring explains why. The history endpoint is a read-side merge only.
- Group confirmation updates many occurrences at once. Write one decision row per updated finding in the same transaction under `scan_runner`'s DB write lock, and batch the inserts.
- The new route needs `Depends(require(...))` with the same key as `GET /scans/{id}/findings` and must go through `authorize_scan`. `tests/test_authz_routes.py` fails otherwise.
- Size: a 1,000-finding scan with grouped confirmation produces about 2,000 rows. That is fine for SQLite; add an index on `(finding_id, at)`.

**Test Notes**
- Test level(s): unit, integration, authz.
- What to assert:
  - A regex finding later confirmed by group confirm has exactly two decision rows (`triage_regex`/unverified → `group_confirm`/true_positive), and `Finding.verdict` equals the latest one.
  - A reconcile pass that resolves an unverified finding appends a `reconcile` row.
  - A no-op verdict update appends nothing.
  - An attempted UPDATE of a decision row via the ORM helper raises an error, or no update path exists at all (assert the helper module exposes insert only).
  - The history endpoint merges a human override after the machine rows, in time order.
  - An anonymous call gets 401. A user without scope gets 404 for another user's scan.
- Test data / fixtures needed: a mock-engine scan with a scripted verdict sequence. Patch the confirm stage to return a fixed decision.
- Entry point to exercise: `_make_findings_writer`, `_make_verdict_updates_writer`, `reconcile_unverified_findings`, `GET /scans/{id}/findings/{finding_id}/history`.

**DevOps Notes**
- Build/CI impact: none.
- Deploy impact: a new table, created by `Base.metadata.create_all` plus the light migration. Database growth is roughly 2× the findings row count per scan.
- Observability: emit the decision-row count per stage in the scan's `usage_summary`, so a stage that silently stops writing decisions is visible.

**Dependencies:** SAST-00-010, SAST-00-040
**Blocks:** SAST-00-090

**Definition of Done:** code merged + tests green (dev + test) + builds/deploys clean (devops)

---

### SAST-00-060 One count source: summary totals equal row data in every rendering

**Epic:** EPIC-00 Verdict Model and Accuracy Regression Tests        **Parent:** EPIC-00
**Parallelism:** Serial/Blocking    **Sprint:** 2

**Story**
As a developer acting on a scan, I want the headline numbers in the UI, JSON, Excel and PDF to be computed once and to match the rows listed beneath them, so that no two views of the same scan contradict each other.

**Acceptance Criteria**
- `scan_export.count_groups_by_severity` becomes `count_findings(grouped)`, the single counting function. It returns per-severity group and occurrence counts for each verdict bucket (`true_positive`, `unverified`, `false_positive`), plus per-`issue_class` totals.
- Every consumer uses it:
  - `GET /scans/{id}/findings` (`severity_group_counts`)
  - the PDF cover strip and OWASP table
  - the Excel summary sheet
  - `gates.build_gate_summary`
  - the frontend chips: `ScanFindingsPanel.tsx` reads the counts from the API response and no longer recomputes them (it does today at line 177).
- A new `scan_export.check_report_consistency(scan) -> list[str]` returns contradictions between:
  - the API counts;
  - the counts recomputed from the API rows;
  - the XLSX summary versus the XLSX findings rows;
  - the PDF cover numbers versus the number of PDF finding headings.

  An empty list means consistent.
- For a scan with the four-way verdict mix, `check_report_consistency` returns `[]`.
- Any extra section in the PDF (e.g. SCA or Joern findings) is counted in the cover totals or explicitly labelled as outside them. This was the source of the 295-vs-291 split.

**Dev Notes**
- Grouping and counting must keep using the same `group_findings_by_issue` output. Remember that it mutates ORM instances (`affected_files`, `occurrence_count`), so call it once per request and pass the result around.
- To make the PDF checkable, emit a hidden marker with the finding count (PDF metadata `/FindingCount`, or a final "Totals" table) rather than parsing headings.
- Mixed-verdict groups do not exist yet: the group key leads with the verdict. EPIC-01 introduces them and must extend `count_findings`; leave a clear seam.

**Test Notes**
- Test level(s): unit, integration (all four renderings from one seeded scan), frontend build.
- What to assert:
  - `check_report_consistency` returns `[]` for the seeded scan.
  - Tampering test: patch the PDF builder to drop one finding; `check_report_consistency` reports a PDF-count contradiction naming the bucket.
  - Patch the Excel summary to count FP as actionable; a contradiction is reported.
  - `gate_summary` counts equal `severity_group_counts`.
  - The frontend chips show the API values: in a manual check, the chips match the PDF cover for the same scan.
- Test data / fixtures needed: the SAST-00-030 seeded scan, plus a grouped regex finding with 5 occurrences and an SCA finding.
- Entry point to exercise: `scan_export.count_findings`, `check_report_consistency`, `GET /scans/{id}/findings`, `export.pdf`, `export.xlsx` (the only consumer of `gates.build_gate_summary`; no API route serves it).

**DevOps Notes**
- Build/CI impact: `check_report_consistency` is reused as a release-gate check in SAST-00-100.
- Deploy impact: none.
- Observability: run `check_report_consistency` at the end of each real scan and log any contradictions as a warning with the scan ID, without failing the scan.

**Dependencies:** SAST-00-010, SAST-00-030
**Blocks:** SAST-00-100

**Definition of Done:** code merged + tests green (dev + test) + builds/deploys clean (devops)

---

### SAST-00-070 Accuracy regression corpus harness with preservation positives

**Epic:** EPIC-00 Verdict Model and Accuracy Regression Tests        **Parent:** EPIC-00
**Parallelism:** Parallel    **Sprint:** 1

**Story**
As a scanner engineer, I want a versioned corpus of small paired positive and negative cases that runs offline under pytest, so that every rule or prompt change is measured against cases where we know the right answer.

**Acceptance Criteria**
- `backend/tests/accuracy_corpus/` holds one directory per case. Each case has:
  - its source files;
  - `case.yaml` with these fields:
    - `id`, `area` (e.g. `sql-binding`, `log-boundary`, `aggregation`)
    - `polarity`: `positive`, `negative` or `uncertain`
    - `seed_findings`: the review's `#` numbers, for traceability only
    - `expected`: a list of `{rule_id or cwe, file, sink_line, verdict, issue_class, reason_tag}`
    - `adjudication`: `adjudicated`, or `dev_label_only`
  - `llm_responses/`: recorded LLM responses keyed by `result_cache_key`, replayed so no network call is made.
- A runner, `pytest -m accuracy` (new marker in `pytest.ini`), scans each case with the real `sast_scan_agent` graph against a replaying result cache.
  - It reports per case: pass/fail, missing expected findings, unexpected findings and verdict mismatches.
  - A missing recorded response fails the case with "unrecorded LLM call", never a live call.
- A recording mode (`ACCURACY_RECORD=1`, live provider, run manually) writes new responses for a case.
- Seeded with **synthetic re-creations** (not copied client code) of the review's preservation positives and their paired negatives:
  1. SOAP string concatenated into `prepareStatement` (#1/#2) — positive.
  2. The same query fully bound with `?` and `setString` — negative.
  3. Credential logged via a `logger.*` call (#257/#258/#270) — positive.
  4. The same call with a renamed logger variable — positive.
  5. JMS message text into an unhardened `DOMParser`/`DocumentBuilder` (#274) — positive.
  6. The same with features set on *that* factory — negative.
  7. A group whose representative is numeric but one member concatenates a string (#78) — the unsafe member is positive.
  8. An LLM response with verdict `"not sure"` — uncertain; expected `unverified`.
- Cases whose current result is a known gap are marked `xfail` with the epic that will fix them (e.g. case 7 → EPIC-01). They report but do not fail the run.
- `backend/tests/accuracy_corpus/README.md` documents how to add a case. EPIC-01 to EPIC-03 add their §9.2 pairs here.

**Dev Notes**
- The agent graph needs `langgraph`/`tree-sitter`, which the default mock-engine suite deliberately avoids. Skip the `accuracy` marker cleanly when those imports fail, so `pytest` alone stays green without them.
- Replay through the existing `usage[RESULT_CACHE_USAGE_KEY]` `get`/`put` interface with a file-backed implementation. This exercises the real prompt-building code, and a prompt change shows up as an unrecorded call, which is the desired signal.
- Joern is off in the corpus (`conftest.py` already points `JOERN_HOME` at an empty dir).
- Follow §9.1: label each case `adjudicated` only after a second reviewer agrees. `dev_label_only` cases are reported but excluded from gates (SAST-00-100).
- No npg-pakistan source may be committed. Re-create the minimal construct, and reference the review's `#` number only in `seed_findings`.

**Test Notes**
- Test level(s): integration (full graph, offline), meta-tests for the harness itself.
- What to assert:
  - Each seeded case produces exactly its `expected` findings with the expected verdict.
  - Meta: a case with a deleted recorded response fails with "unrecorded LLM call".
  - Meta: a case expecting a finding that never appears fails and names it.
  - Meta: `xfail` cases do not fail the run.
  - Meta: the runner never opens a network socket (patch `socket.socket` to raise).
- Test data / fixtures needed: the eight seed cases above and their recorded responses (record once against Bedrock, then commit).
- Entry point to exercise: `pytest -m accuracy` from `backend/`.

**DevOps Notes**
- Build/CI impact: a new pytest marker. The full engine dependencies (`requirements.txt` incl. `langgraph`, `tree-sitter*`) are needed for the job that runs it. Expected runtime is under 2 minutes offline.
- Deploy impact: none (test-only).
- Observability: the runner writes `accuracy_report.json` (per-case results plus totals by area and polarity) as a build artifact.

**Dependencies:** SAST-00-020 (for case 8; other cases can be built before it lands)
**Blocks:** SAST-00-080, SAST-00-100; and every corpus-case story in EPIC-01 to EPIC-03

**Definition of Done:** code merged + tests green (dev + test) + builds/deploys clean (devops)

---

### SAST-00-080 Import and reconcile the npg-pakistan review labels

**Epic:** EPIC-00 Verdict Model and Accuracy Regression Tests        **Parent:** EPIC-00
**Parallelism:** Parallel    **Sprint:** 2

**Story**
As a scanner engineer, I want the developer review workbook, the scanner Excel export and the scanner PDF joined by finding identity rather than by row number, so that the 141 developer-FP labels can be traced to concrete occurrences and adjudicated.

**Acceptance Criteria**
- A script, `scripts/accuracy/import_review_labels.py`, takes:
  - the developer workbook (R);
  - the scanner XLSX (S);
  - optionally the scanner PDF (P), via its text extraction.

  It writes `backend/tests/accuracy_corpus/_labels/npg-pakistan.jsonl`, one row per finding.
- Rows are joined on `(file_path, rule_id or CWE, normalized matched text or sink, title)`, never on row ordinal. The script reports:
  - rows that joined across all sources;
  - rows present in only one source (e.g. the four PDF-only findings #80, #81, #257, #277 must appear here, not shift the join);
  - the count of verdict differences between R and S (expected: 88).
- Each row keeps `scanner_verdict_S`, `scanner_label_P` and `dev_label_R` as separate fields. `adjudication` is `dev_label_only` for every imported row; nothing is written as adjudicated by the import.
- Grouped rows are expanded to one record per affected file listed, with `group_ref` linking back to the source row.
- The labels file contains no source code: file paths, rule IDs, titles and labels only.

**Dev Notes**
- The historical exports predate `occurrence_id`, so this join is necessarily heuristic. Emit a `join_confidence` (`exact`, `fuzzy`, `none`) per row and do not auto-resolve `fuzzy` rows.
- Use `openpyxl` (already in the stack for exports) and `pypdf` for P.
- Keep the script out of the app package; it is tooling.

**Test Notes**
- Test level(s): unit (join logic), integration (small synthetic R/S/P triplet).
- What to assert:
  - A synthetic triplet where P has one extra finding inserted in the middle: all other rows still join `exact`, and the extra row is listed as P-only.
  - A swapped row order in S has no effect on the joins.
  - A grouped S row with 3 files expands to 3 records sharing a `group_ref`.
  - Every row has `adjudication=dev_label_only`.
  - On the real files (manual run): R=291 rows, S=291, P=295, 88 R/S verdict differences.
- Test data / fixtures needed: a hand-built 6-row synthetic R/S/P set. **The real R and S workbooks and the original scan JSON must be supplied by the project owner** (not committed).
- Entry point to exercise: `python scripts/accuracy/import_review_labels.py --review R.xlsx --scanner S.xlsx --pdf P.pdf --out ...`.

**DevOps Notes**
- Build/CI impact: unit tests run in the default suite; the real-file import is a manual step.
- Deploy impact: none.
- Observability: the script prints the join summary table; keep it in the PR description when labels are refreshed.

**Dependencies:** SAST-00-040, SAST-00-070
**Blocks:** — (feeds adjudication for EPIC-01 to EPIC-03 cases)

**Definition of Done:** code merged + tests green (dev + test) + builds/deploys clean (devops)

---

### SAST-00-090 Rescan decision diff

**Epic:** EPIC-00 Verdict Model and Accuracy Regression Tests        **Parent:** EPIC-00
**Parallelism:** Serial/Blocking    **Sprint:** 3

**Story**
As a reviewer approving a scanner change, I want a per-occurrence diff between two scans of the same commit, showing every verdict that changed, in both directions, and why, so that a fix is judged by what it changed rather than by how many rows it removed.

**Acceptance Criteria**
- `GET /scans/{id}/decision-diff?base=<scan_id>` returns one entry per `occurrence_id` present in either scan:
  - `change`: `added`, `removed`, `verdict_changed`, `issue_class_changed` or `unchanged` (unchanged entries are omitted unless `include_unchanged=true`)
  - old and new `verdict`, `issue_class`, `unresolved_reason` and `confidence`
  - the new decision's `stage` and `verdict_reason`
  - the `evidence_version` of both scans
- A summary block counts transitions by `(old_verdict → new_verdict)` and by `rule_id`, and leads with `true_positive → false_positive` and `true_positive → removed`.
- Both scans must belong to the same project. Different `commit_sha` values are allowed but flagged with `commit_differs: true`. A base scan without `occurrence_id`s returns `422` with a clear message.
- `GET /scans/{id}/decision-diff.xlsx?base=` exports the same data. The scan detail page gets a "Compare with…" control that renders the summary and a filterable table.

**Dev Notes**
- Join only on `occurrence_id`. Rows with `identity_quality=file_level` are joined but marked as such in the output.
- The diff is computed from current `Finding` rows plus their latest `finding_decisions` row. It does not recompute grouping, so mixed groups (EPIC-01) need no special handling here.
- Declare auth on both routes with `authorize_scan` on *both* scan IDs. A base scan outside the caller's scope returns 404, not 403.
- To get a same-commit rescan, `POST /scans` with `force: true` already bypasses scan reuse.

**Test Notes**
- Test level(s): unit (diff logic), integration (two mock scans), authz, frontend build.
- What to assert:
  - Two scans of the identity fixture, where scan B flips one TP to FP, drops one occurrence and adds one, give exactly one `verdict_changed`, one `removed` and one `added`, with the TP→FP transition first in the summary.
  - Identical scans give an empty diff.
  - A base scan from another project → 422.
  - A base scan the caller cannot see → 404.
  - The XLSX row count equals the JSON entry count.
- Test data / fixtures needed: two mock-engine scans built from the SAST-00-040 identity fixture with scripted verdicts.
- Entry point to exercise: `GET /scans/{id}/decision-diff`, `.xlsx` export, `/scans/[id]` "Compare with…" UI.

**DevOps Notes**
- Build/CI impact: the frontend build must pass. The diff function is reused by the release gate.
- Deploy impact: new API routes and a new Next proxy route under `app/api/scans/[id]/decision-diff/`.
- Observability: log the transition summary counts when a diff is requested.

**Dependencies:** SAST-00-040, SAST-00-050
**Blocks:** SAST-00-100

**Definition of Done:** code merged + tests green (dev + test) + builds/deploys clean (devops)

---

### SAST-00-100 Accuracy release gate

**Epic:** EPIC-00 Verdict Model and Accuracy Regression Tests        **Parent:** EPIC-00
**Parallelism:** Serial/Blocking    **Sprint:** 3

**Story**
As the release owner, I want a single command that fails when a scanner change loses a known positive, misclassifies a known negative, resolves an uncertainty case, or makes the reports contradict each other, so that accuracy regressions are blocked before release rather than found by customers.

**Acceptance Criteria**
- `python scripts/accuracy/gate.py --baseline accuracy_baseline.json` runs the corpus (SAST-00-070) and the consistency check (SAST-00-060). It exits non-zero when any of the review's §9.4 gates fails, counting only `adjudicated` cases:
  1. **Preservation:** any `positive` case's expected finding is missing or not `true_positive`.
  2. **Negatives:** any `negative` case is not `false_positive`, or its `reason_tag` does not match. A negative that disappears because the rule stopped firing entirely also fails unless the case allows `absent`.
  3. **Uncertainty:** any `uncertain` case resolves to TP or FP instead of `unverified` with the expected `unresolved_reason`.
  4. **Consistency:** `check_report_consistency` returns anything for the corpus scans.
  5. **No positive→FP regression:** compared with the committed baseline, any case moving `true_positive → false_positive|absent` fails, even when the case is `xfail`.
- Output: `accuracy_gate.md` (human summary: gate-by-gate pass/fail, then case detail) and `accuracy_gate.json`.
- `--update-baseline` rewrites `accuracy_baseline.json` and refuses if gate 1 or gate 5 fails.
- Every EPIC-01 to EPIC-03 story that changes a rule, prompt or filter must list "gate green" in its Definition of Done. This epic adds that line to the epic template note in `spec/dev-stories/sast-accuracy/README.md`.

**Dev Notes**
- Reuse the SAST-00-090 diff function to compare against the baseline per case. The gate is a thin orchestrator; do not duplicate logic.
- `dev_label_only` cases are reported in a separate "not gated" section, so their drift stays visible without blocking.
- The gate makes no live LLM calls (replay only). A prompt change therefore fails with "unrecorded LLM call" until the author records responses and a reviewer accepts the new outputs. That is intended.

**Test Notes**
- Test level(s): integration (the gate against a mini corpus), meta-tests per gate.
- What to assert: a mini corpus of 5 cases (2 positive, 2 negative, 1 uncertain), one test per gate.
  - Flip a positive's recorded response to FP: gate 1 and gate 5 fail, exit code ≠ 0, and the case is named in `accuracy_gate.md`.
  - Give a negative the wrong `reason_tag`: gate 2 fails.
  - Make the uncertain case's response `"true_positive"`: gate 3 fails.
  - Patch the XLSX summary: gate 4 fails.
  - All clean: exit 0.
  - `--update-baseline` with gate 1 failing: refused.
- Test data / fixtures needed: the mini corpus under `backend/tests/fixtures/accuracy_gate/`.
- Entry point to exercise: `scripts/accuracy/gate.py`.

**DevOps Notes**
- Build/CI impact: the repo has no CI pipeline definition today (`docs/ci/` documents integrating the *scanner* into others' CI). Add a job that installs the full backend requirements, runs `scripts/accuracy/gate.py` on every change under `backend/sast_engine/**` and `backend/app/services/scan_export.py`, and publishes `accuracy_gate.md`/`.json` as artifacts. Until a pipeline exists, run it as a required pre-merge step.
- Deploy impact: none.
- Observability: keep the gate JSON from each release, so the trend of passing cases by area is visible over time.

**Dependencies:** SAST-00-020, SAST-00-060, SAST-00-070, SAST-00-090
**Blocks:** EPIC-01, EPIC-02, EPIC-03 (their rule-changing stories)

**Definition of Done:** code merged + tests green (dev + test) + builds/deploys clean (devops)

---

## Story order and parallelism

| Story | Title | Parallelism | Sprint | Depends On |
|---|---|---|---|---|
| SAST-00-010 | Verdict / issue-class / unresolved-reason contract | Serial/Blocking | 1 | — |
| SAST-00-040 | Stable occurrence identity and version stamp | Parallel | 1 | — |
| SAST-00-020 | Strict verdict parsing | Serial/Blocking | 1 | 010 |
| SAST-00-070 | Regression corpus harness | Parallel | 1 | 020 (case 8 only) |
| SAST-00-030 | Show FP as FP; verdict vs review state | Parallel | 2 | 010 |
| SAST-00-050 | Immutable decision history | Parallel | 2 | 010, 040 |
| SAST-00-080 | Import and reconcile review labels | Parallel | 2 | 040, 070 |
| SAST-00-060 | One count source; summary equals rows | Serial/Blocking | 2 | 010, 030 |
| SAST-00-090 | Rescan decision diff | Serial/Blocking | 3 | 040, 050 |
| SAST-00-100 | Accuracy release gate | Serial/Blocking | 3 | 020, 060, 070, 090 |

Sprint numbers are provisional until the Sprint Plan is agreed.

## Evidence the team still needs (review §10)

- The scanner's own Excel export (S) and the developer review workbook (R) for SAST-00-080.
- The original scan's machine-readable findings (JSON), if it still exists, for SAST-00-080.
- The scanner revision, rule catalog and model/prompt configuration used for that scan, to stamp the historical baseline.
- The application checkout at `ae38067c239e` is **not** needed for EPIC-00, since corpus cases are synthetic. EPIC-02 and EPIC-03 need it to confirm their negatives.

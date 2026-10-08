## [EPIC-09] Active Testing Engine

**Goal:** For each discovered target, run the construct → validate → baseline → test → detect → rule → roll-up loop, bounded by budgets, safe by construction, and confirmed only by detector evidence.
**Depends On:** EPIC-01, EPIC-02, EPIC-03, EPIC-04, EPIC-07
**Blocks:** EPIC-10, EPIC-11, EPIC-16
**Teams:** Dev

Requirements: REQ-FR-ACT-1 to -9, REQ-FR-MDL-1, -7, REQ-FR-SAFE-7, -8. The existing `nodes/analyze_apis.py` and `api_analysis.py` (REST-only analysis of observed endpoints) are migrated onto this loop.

---

### DAST-09-010 Active stage and per-target loop

**Epic:** EPIC-09 Active Testing Engine        **Parent:** EPIC-09
**Parallelism:** Serial/Blocking    **Sprint:** 2

**Story**
As a security engineer, I want an active stage that tests every inventory target against the applicable checks within defined caps so that testing is thorough but bounded.

**Acceptance Criteria**
- The stage iterates the inventory; for each target it runs the loop steps in order: construct, validate, baseline, test, detect, rule, roll-up (steps implemented in later stories behind interfaces; this story wires them with fakes).
- Caps enforced from the effective settings: maximum targets and maximum tests per target; reaching a cap is logged, not silent.
- Cancellation is checked between individual tests.
- Only checks enabled in the effective rule set, and not skipped for a missing dependency, run.
- One target's failure (timeout, error) does not stop the stage; it is recorded and the loop continues.
- Banner `### DAST: testing apis` is kept so progress markers continue to work; sub-step lines are added beneath it.

**Dev Notes**
- Migrate `analyze_apis` incrementally: the stage shell first, then move its existing logic into the steps.
- Deterministic ordering of targets (sorted) so runs are reproducible.

**Dev Testing**
- Test level: unit (fake steps) + integration.
- Assert: caps stop the loop and log it; cancel mid-loop stops within one test; one failing target does not stop others; disabled and skipped checks never run; ordering deterministic across runs.

**Dependencies:** DAST-03-040, DAST-04-040, DAST-05-020, DAST-06-050, DAST-07-010, DAST-07-060, DAST-01-030, DAST-03-020, DAST-07-040
**Blocks:** DAST-09-020, DAST-09-060

**Definition of Done:** code merged + developer tests green

---

### DAST-09-020 Select and construct

**Epic:** EPIC-09 Active Testing Engine        **Parent:** EPIC-09
**Parallelism:** Serial/Blocking    **Sprint:** 2

**Story**
As a security engineer, I want the model to choose applicable checks and propose test inputs for each target so that testing adapts to what each endpoint is.

**Acceptance Criteria**
- Uses the `construct` gateway task with one target per call and truncated bodies.
- Reply shape per test: `{check_id, parameter, location, input, expected_signal}`.
- Check ids not in the effective rule set are dropped and counted (REQ-FR-MDL-7).
- Every proposed input passes the non-destructive validator (DAST-01-060); rejected ones are dropped and counted, never sent.
- Tests per target are limited to the configured cap, highest-priority first.
- If the model fails or returns nothing valid, a deterministic fallback produces a conservative baseline-only set for catalog checks that have a template, so the scan degrades rather than stalls.
- A test asserts that no code path sends a test input that has not passed the validator.

**Dev Notes**
- Prompt is the `construct` file plus few-shot examples (DAST-02-060).
- Payload strings come from the model under the catalog template; none are hard-coded in the engine.
- Enforce "validator was called" structurally: the executor wrapper for tests accepts only a `ValidatedTest` type that only the validator can create.

**Dev Testing**
- Test level: unit (scripted gateway).
- Assert: unknown check id dropped; destructive input dropped; cap respected; fallback on model failure; type-level guarantee (constructing a `ValidatedTest` any other way fails).
- Test data: scripted model replies including hostile ones (`DROP TABLE`, shell chains).

**Dependencies:** DAST-09-010, DAST-02-060, DAST-01-060, DAST-02-010
**Blocks:** DAST-09-030

**Definition of Done:** code merged + developer tests green

---

### DAST-09-030 Baseline, test execution and rule

**Epic:** EPIC-09 Active Testing Engine        **Parent:** EPIC-09
**Parallelism:** Serial/Blocking    **Sprint:** 2

**Story**
As a security engineer, I want each test compared against a baseline and judged by detectors, with the model only advising, so that findings are evidence-backed.

**Acceptance Criteria**
- For each validated test: send a baseline request, then the test request, both through the guarded executor with the target's recorded body shape (DAST-07-030) where available.
- Run the detectors named by the check on the pair.
- Ask the `rule` gateway task for a proposed verdict and reasoning (truncated bodies); its reply is advisory.
- Roll up and apply the guardrail (DAST-04-040); write the finding with evidence through the writer (DAST-04-050) including the audit reference.
- A model failure uses a deterministic verdict from the detectors alone.
- Time-based checks take the minimum number of samples defined by the detector.

**Dev Notes**
- This replaces the model-verdict-only path in `api_analysis.py`; known gap in the completion spec was "no independent validation of a model PASS".
- Evidence excerpts size-capped and redacted.

**Dev Testing**
- Test level: integration (fake target with scripted vulnerable and safe endpoints).
- Assert: vulnerable endpoint → `true_positive` with signals and evidence; safe endpoint → no finding; model says FAIL with no signal → `unverified`; model says PASS with signal → finding; model down → same results from detectors alone.

**Dependencies:** DAST-09-020, DAST-04-040, DAST-04-050, DAST-07-030, DAST-04-020
**Blocks:** DAST-09-040, DAST-09-050, DAST-09-060, DAST-10-010, DAST-16-010, DAST-16-030, DAST-16-050, DAST-16-060

**Definition of Done:** code merged + developer tests green

---

### DAST-09-040 Form and parameter testing

**Epic:** EPIC-09 Active Testing Engine        **Parent:** EPIC-09
**Parallelism:** Parallel    **Sprint:** 2

**Story**
As a security engineer, I want form fields and request parameters tested through the same pipeline so that injection and reflection flaws in forms are found.

**Acceptance Criteria**
- Forms and parameters from the inventory (including captured request bodies) become test targets with their field names and locations.
- Query, path, header and body locations are all supported.
- Form submissions that would change state are tested only when state-changing methods were opted in; otherwise the form is listed as "not tested: safe mode".
- Hidden and CSRF-token fields are preserved from the baseline so a test does not fail only because of a missing token.

**Dev Notes**
- Reuse the loop from DAST-09-010; this story only adds target kinds.

**Dev Testing**
- Test level: integration (fake target with a reflective form and a safe form).
- Assert: reflective field → finding with `input_reflected_unescaped`; safe-mode skip message; token field preserved.

**Dependencies:** DAST-09-030, DAST-07-030
**Blocks:** DAST-16-020

**Definition of Done:** code merged + developer tests green

---

### DAST-09-050 Opt-in and assist-only checks

**Epic:** EPIC-09 Active Testing Engine        **Parent:** EPIC-09
**Parallelism:** Parallel    **Sprint:** 2

**Story**
As an operator, I want load-generating checks to stay off until I enable them, and business-logic items surfaced for human review, so that scans stay safe and honest about their limits.

**Acceptance Criteria**
- Resource-consumption checks (API4) run only when the effective rule set explicitly enables them, and then respect an explicit request-count ceiling and the rate limit.
- Assist-only checks (API6 sensitive business flows, API10 unsafe consumption) do not run tests; they emit review items listing the relevant endpoints and why.
- Review items are findings with verdict `unverified`, a distinct source, and text that says human review is required; they are never labelled confirmed.
- Both categories appear in the report.

**Dev Notes**
- Heuristics for listing sensitive flows (login, checkout, password reset, transfer) are a data file.

**Dev Testing**
- Test level: unit + integration.
- Assert: API4 sends zero requests when disabled; when enabled it stops at the ceiling; assist-only items appear as `unverified` with review text; none become `true_positive`.

**Dependencies:** DAST-09-030, DAST-03-060
**Blocks:** DAST-11-010

**Definition of Done:** code merged + developer tests green

---

### DAST-09-060 SSRF with out-of-band confirmation

**Epic:** EPIC-09 Active Testing Engine        **Parent:** EPIC-09
**Parallelism:** Parallel    **Sprint:** 2

**Story**
As a security engineer, I want server-side request forgery confirmed by an out-of-band callback so that a received callback is unambiguous proof.

**Acceptance Criteria**
- When an OAST URL is configured, URL-accepting parameters are tested with a unique per-test callback address; a received callback yields signal `oast_callback` and a `true_positive` finding.
- With no OAST URL configured, the check is `assist-only`, runs no tests, and the report states why (DAST-03-060).
- Each callback address is unique and tied to its test so one callback cannot confirm another test.
- Polling for callbacks has a bounded wait.
- The OAST service is not the target and is never part of the in-scope hosts. Polling it uses a separate, explicitly configured client that is not subject to the target scope check; this exception is documented, and every poll is still written to the audit record under its own category so it stays reviewable.

**Dev Notes**
- Interface for the OAST collaborator lives in the domain; one implementation is enough for v1; choice of service (self-hosted or managed) is an open decision recorded in `core-requirements.md`.
- Add the `oast_callback` signal to the detector registry.

**Dev Testing**
- Test level: unit + integration (fake OAST collaborator).
- Assert: callback received → TP; none received → no finding; unique ids; bounded wait; disabled-without-config behavior.

**Dependencies:** DAST-09-030, DAST-03-060, DAST-09-010
**Blocks:** —

**Definition of Done:** code merged + developer tests green

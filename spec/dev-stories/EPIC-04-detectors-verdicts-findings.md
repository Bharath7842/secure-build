## [EPIC-04] Detectors, Verdicts & Findings

**Goal:** The pure domain core that makes the scan deterministic: findings with evidence, detector signals, verdict roll-up with the guardrail, dedupe, persistence and the findings query API.
**Depends On:** EPIC-00
**Blocks:** EPIC-08, EPIC-09, EPIC-10, EPIC-11, EPIC-14
**Teams:** Dev

Requirements: REQ-FR-ACT-2 to -4, REQ-FR-FIND-1 to -9. This is the heart of the "code decides, model advises" principle: nothing here may import a model, a browser or the network.

---

### DAST-04-010 Domain entities and finding mapping

**Epic:** EPIC-04 Detectors, Verdicts & Findings        **Parent:** EPIC-04
**Parallelism:** Serial/Blocking    **Sprint:** 1

**Story**
As a developer, I want typed domain entities for findings, evidence, verdicts and endpoints so that every stage speaks one vocabulary and findings persist in the platform's shared `Finding` shape.

**Acceptance Criteria**
- Entities defined: Endpoint, Identity, Role, Finding, Evidence, Signal, Verdict (`true_positive|unverified|false_positive`), Confidence (`HIGH|MEDIUM|LOW`).
- A mapper converts a domain Finding to a `Finding` row with `kind="dast"` using the columns from DAST-00-040 and the existing columns (`rule_id`, `severity`, `title`, `verdict`, `verdict_reason`, `source`, `sink`, `owasp_ref`, `cwe`).
- `UNVERIFIED_VERDICT` from `app.models` is reused, not redefined.
- Existing DAST findings written by `api_analysis` still map to valid rows.
- Domain module has no forbidden imports (layering test).

**Dev Notes**
- `source` = detector that surfaced it; `sink` = API URL or form action (per `DAST_tech_stack.md` §2.4).
- `title` is derived from the catalog check title.

**Dev Testing**
- Test level: unit.
- Assert: round-trip domain → row → domain; invalid enum values rejected; legacy `api_analysis` output maps.

**Dependencies:** DAST-00-020, DAST-00-040
**Blocks:** DAST-04-020, DAST-04-030, DAST-04-050, DAST-04-060, DAST-07-010

**Definition of Done:** code merged + developer tests green

---

### DAST-04-020 Detector library: injection and leakage signals

**Epic:** EPIC-04 Detectors, Verdicts & Findings        **Parent:** EPIC-04
**Parallelism:** Parallel    **Sprint:** 1

**Story**
As a security engineer, I want pure detectors that compare a baseline and a test response so that confirmed findings rest on observed signals, not model opinion.

**Acceptance Criteria**
- Detectors implemented as pure functions with the signature baseline response + test response → list of signals: `db_error_surfaced`, `input_reflected_unescaped`, `command_output_marker`, `stack_trace_leaked`.
- Each detector is deterministic, has no side effects and never produces a verdict.
- A registry exposes the set of valid signal names (used by the catalog loader, DAST-03-010).
- Detectors tolerate truncated bodies, non-text content and missing fields without raising.

**Dev Notes**
- Signals fire only on a difference between baseline and test where applicable (a DB error string present in both is not a signal).
- Keep pattern lists in data, not inline, so they can be extended.

**Dev Testing**
- Test level: unit.
- Assert: positive and negative cases per detector, including the "same string already in baseline" negative; HTML-escaped reflection is not `unescaped`; binary body handled.
- Test data: fixture response pairs per detector; at least 5 true and 5 false cases each.

**Dependencies:** DAST-04-010
**Blocks:** DAST-04-040, DAST-08-030, DAST-09-030

**Definition of Done:** code merged + developer tests green

---

### DAST-04-030 Detector library: divergence, timing and authorization boundary

**Epic:** EPIC-04 Detectors, Verdicts & Findings        **Parent:** EPIC-04
**Parallelism:** Parallel    **Sprint:** 1

**Story**
As a security engineer, I want detectors for response divergence, timing and authorization-boundary crossing so that blind injection and access-control flaws can be proven.

**Acceptance Criteria**
- Signals added: `boolean_divergence`, `time_delta`, `status_length_divergence`, `auth_boundary_crossed`.
- `time_delta` requires a configurable threshold and at least two samples to avoid single-request noise.
- `auth_boundary_crossed` fires when a lower-privilege or anonymous identity receives a successful, materially equivalent response to what a higher-privilege identity received.
- Detectors share the same signature and registry as DAST-04-020.

**Dev Notes**
- "Materially equivalent" = same status class and similar body shape/length within a tolerance; tolerance is a documented constant.
- Timing uses supplied durations only; the detector never measures time itself.

**Dev Testing**
- Test level: unit.
- Assert: timing noise below threshold is not a signal; equivalent vs. different bodies; 401/403 responses are never `auth_boundary_crossed`; empty-body 200 edge case documented and tested.

**Dependencies:** DAST-04-010
**Blocks:** DAST-04-040, DAST-10-010, DAST-10-030

**Definition of Done:** code merged + developer tests green

---

### DAST-04-040 Verdict roll-up and guardrail

**Epic:** EPIC-04 Detectors, Verdicts & Findings        **Parent:** EPIC-04
**Parallelism:** Serial/Blocking    **Sprint:** 1

**Story**
As a security engineer, I want a guardrail that downgrades any failure lacking a supporting signal so that no finding is confirmed on model opinion alone.

**Acceptance Criteria**
- Per-check result: FAIL only if at least one proving signal named by the check is present; a model-proposed FAIL with no signal becomes INCONCLUSIVE.
- Per-target roll-up: any FAIL → FAIL; all INCONCLUSIVE → INCONCLUSIVE; otherwise PASS.
- Mapping to stored verdict: FAIL → `true_positive`; INCONCLUSIVE → `unverified`; PASS → no finding.
- The guardrail has the final word: no code path produces `true_positive` without a signal (property test).
- A model-proposed PASS in the presence of a proving signal is overridden to FAIL.
- Every downgrade or override is recorded with its reason for the report.

**Dev Notes**
- Pure functions in `domain/verdict.py` and `domain/guardrail.py`.
- Track guardrail-override rate; EPIC-16 uses it as a model-quality metric.

**Dev Testing**
- Test level: unit + property.
- Assert: truth table for roll-up; downgrade without signal; override with signal; property test: for any random combination of model verdict and signal set, `true_positive` implies signal present.

**Dependencies:** DAST-04-020, DAST-04-030
**Blocks:** DAST-09-010, DAST-09-030, DAST-10-030, DAST-16-030

**Definition of Done:** code merged + developer tests green

---

### DAST-04-050 Findings writer with evidence and dedupe

**Epic:** EPIC-04 Detectors, Verdicts & Findings        **Parent:** EPIC-04
**Parallelism:** Parallel    **Sprint:** 1

**Story**
As an operator, I want findings and their evidence stored as they are produced, without duplicates, so that results appear mid-scan and stay readable.

**Acceptance Criteria**
- A writer persists a finding plus its evidence row as each stage emits it, through the existing incremental findings-writer mechanism in `scan_runner`.
- Dedupe on `(rule_id, path_template, param)` within a scan before insert; the duplicate's location is appended to the existing finding's affected locations.
- Evidence stores baseline and test excerpts (size-capped), signals, and the audit reference.
- Unverified findings are stored exactly like confirmed ones.
- Writing is idempotent per `(scan_id, rule_id, path_template, param)` so a retried stage does not duplicate.

**Dev Notes**
- Path template: replace numeric/UUID segments with placeholders (reuse `url_utils.get_url_pattern` logic).
- Use `affected_files` (existing JSON column) for the list of additional endpoints.
- Dedupe key function is pure and in the domain package.

**Dev Testing**
- Test level: unit + integration.
- Assert: two identical issues on `/users/1` and `/users/2` become one finding with two locations; different parameter stays separate; retry does not duplicate; evidence present; unverified stored with `verdict="unverified"`.

**Dependencies:** DAST-04-010, DAST-00-040
**Blocks:** DAST-04-060, DAST-07-060, DAST-08-010, DAST-09-030, DAST-11-010, DAST-12-030

**Definition of Done:** code merged + developer tests green

---

### DAST-04-060 Findings query API

**Epic:** EPIC-04 Detectors, Verdicts & Findings        **Parent:** EPIC-04
**Parallelism:** Parallel    **Sprint:** 1

**Story**
As an operator, I want to filter a DAST scan's findings by severity, verdict, role and check, and always see unverified ones, so that I can triage quickly without losing anything.

**Acceptance Criteria**
- `GET /scans/{id}/findings` for DAST scans returns grouped findings with target, parameter, location, severity, confidence label, verdict, standards, remediation reference, and evidence.
- Filters: severity, verdict, role (or role pair), check id.
- `unverified` findings are returned unless explicitly filtered out by the caller; no default hides them.
- Each finding includes remediation guidance text, not only a reference.
- SAST/SCA/SBOM responses are unchanged.

**Dev Notes**
- Extend `scan_export.group_findings_by_issue` with a DAST branch keyed on `(verdict, "dast", rule_id, path_template, param)`; remember the existing code mutates ORM instances, so do not flush afterwards.
- Remediation text read from catalog files by `remediation_ref`.

**Dev Testing**
- Test level: integration.
- Assert: each filter alone and combined; unverified present by default; grouping count; SAST endpoint regression; evidence block shape.
- Entry point: `GET /scans/{id}/findings?severity=&verdict=&role=&check=`.

**Dependencies:** DAST-04-050, DAST-03-020, DAST-04-010
**Blocks:** DAST-10-040, DAST-14-010

**Definition of Done:** code merged + developer tests green

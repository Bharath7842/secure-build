## [EPIC-16] Quality, Measurement & Hardening

**Goal:** The scanner is measured, repeatable, safe and offline-testable: a precision/recall harness against practice targets, a determinism check, a regression gate, controlled training-data capture, and a security review of the safety controls.
**Depends On:** EPIC-09, EPIC-10, and the stories named below
**Blocks:** — (release gate)
**Teams:** Dev

Requirements: REQ-NFR-1 to -5, REQ-SEC-4 to -6, REQ-FR-SAFE-7 to -9.

---

### DAST-16-010 Measurement harness

**Epic:** EPIC-16 Quality, Measurement & Hardening        **Parent:** EPIC-16
**Parallelism:** Serial/Blocking    **Sprint:** 2

**Story**
As a maintainer, I want a harness that runs a scan against a practice target and scores it against a fixed expected-findings list so that precision and recall are numbers, not impressions.

**Acceptance Criteria**
- A ground-truth file format lists expected findings per target: check id, endpoint template, parameter.
- A runner starts a scan against a named practice target, waits for completion, and compares findings to the ground truth.
- Output: true positives, false positives, false negatives, precision, recall, guardrail-override rate, scan duration, model cost; written as a JSON result and a readable summary.
- Unverified findings are scored separately and never counted as true positives.
- The harness is usable from the command line and from CI.

**Dev Notes**
- Lives under `backend/tools/dast_harness/` (or similar); marked `live`; not part of the default test run.
- Matching is on `(check, path template, parameter)`, the same key as the diff.

**Dev Testing**
- Test level: unit (scoring logic, using synthetic findings and ground truth) + `live`.
- Assert: scoring math on known inputs (including empty sets); unverified excluded from TP; result file schema.

**Dependencies:** DAST-09-030, DAST-00-080
**Blocks:** DAST-16-020, DAST-16-030, DAST-16-040

**Definition of Done:** code merged + developer tests green

---

### DAST-16-020 Practice-target ground truth

**Epic:** EPIC-16 Quality, Measurement & Hardening        **Parent:** EPIC-16
**Parallelism:** Parallel    **Sprint:** 2

**Story**
As a maintainer, I want curated expected-findings lists for DVWA and Juice Shop so that every change is scored against known vulnerabilities.

**Acceptance Criteria**
- One ground-truth file per practice target, tied to the pinned image version, listing the vulnerabilities in scope for the enabled rule packs.
- Each entry names the source of the claim (documentation or manual verification).
- Includes at least one multi-role authorization case where the target supports it.
- A first baseline run is recorded (precision, recall) as the starting reference, even if low.
- Known out-of-scope items (business logic, MFA) are listed as excluded, not as misses.

**Dev Notes**
- Do not tune detectors to the ground truth to inflate the score; the point is to see real behavior.

**Dev Testing**
- Test level: live.
- Assert: harness runs end-to-end on both targets; ground-truth files validate against the format.

**Dependencies:** DAST-16-010, DAST-09-040, DAST-10-030, DAST-00-080
**Blocks:** DAST-16-040

**Definition of Done:** code merged + developer tests green

---

### DAST-16-030 Determinism and offline guarantees

**Epic:** EPIC-16 Quality, Measurement & Hardening        **Parent:** EPIC-16
**Parallelism:** Parallel    **Sprint:** 2

**Story**
As a maintainer, I want proof that the same target scanned twice gives the same verdicts and that the default suite never touches a browser, model or network.

**Acceptance Criteria**
- A determinism test runs the pipeline twice against the fake target with a scripted gateway and compares findings and verdicts: identical.
- A live variant runs twice against a practice target and reports the verdict differences, with an allowed variance threshold recorded.
- An offline test imports and runs the full mock/fake-target pipeline with sockets, subprocesses, Playwright and provider SDK imports blocked; it passes.
- A property test covers the invariant "`true_positive` implies at least one detector signal" across the full pipeline output.

**Dev Notes**
- Sources of nondeterminism to remove: ordering of sets/dicts, timestamps in evidence, model temperature (use low temperature and fixed few-shot ordering).

**Dev Testing**
- Test level: unit + integration + `live`.
- Assert: as above.

**Dependencies:** DAST-16-010, DAST-04-040, DAST-09-030
**Blocks:** DAST-16-040

**Definition of Done:** code merged + developer tests green

---

### DAST-16-040 Regression gate

**Epic:** EPIC-16 Quality, Measurement & Hardening        **Parent:** EPIC-16
**Parallelism:** Serial/Blocking    **Sprint:** 2

**Story**
As a maintainer, I want a release gate that fails if the mock suite is red, recall drops, or precision regresses so that quality only moves forward.

**Acceptance Criteria**
- The gate compares the latest harness result to the stored baseline per target and fails on any recall drop or a precision drop beyond a configured tolerance.
- The gate also fails if the mock suite or layering test is red.
- Baselines are updated only by an explicit, reviewed change.
- The result is visible in the pipeline summary with the per-target deltas.

**Dev Notes**
- Tolerance is a documented constant; start strict, loosen only with justification.

**Dev Testing**
- Test level: integration.
- Assert: a doctored lower-recall result fails the gate; an equal or better result passes; baseline update requires the explicit flag.

**Dependencies:** DAST-16-010, DAST-16-020, DAST-16-030, DAST-00-070
**Blocks:** —

**Definition of Done:** code merged + developer tests green

---

### DAST-16-050 Training-data capture with controls

**Epic:** EPIC-16 Quality, Measurement & Hardening        **Parent:** EPIC-16
**Parallelism:** Parallel    **Sprint:** 2

**Story**
As a maintainer, I want confirmed test inputs captured as training examples only from authorized scans, with target identifiers removed and access restricted, so that the improvement flywheel does not become a leak.

**Acceptance Criteria**
- Capture is off by default and enabled per project by an authorized operator.
- Only records where the detector signal and the final verdict agree are kept, balanced across fail, pass and inconclusive.
- Hostnames, IPs, credentials, tokens and identifiers are stripped or replaced before storage.
- Inputs rejected by the non-destructive validator are never stored.
- Stored examples are readable only through an authenticated, role-restricted interface and every read is audit-logged.
- Export to the JSONL format in `spec/dast_training_samples.jsonl` is supported; a dataset version is recorded.

**Dev Notes**
- Provider-neutral `{task, input, output}` records per `DAST_complete_design.md` §8.3.
- Fine-tuning itself is out of scope; this story only produces the dataset.

**Dev Testing**
- Test level: unit + integration.
- Assert: seeded host/IP/token removed from stored examples; rejected input not stored; disagreement case excluded; unauthorized read denied and audit entry created; capture off by default.

**Dependencies:** DAST-09-030, DAST-01-060, DAST-06-010
**Blocks:** DAST-16-060

**Definition of Done:** code merged + developer tests green

---

### DAST-16-060 Security review of safety controls

**Epic:** EPIC-16 Quality, Measurement & Hardening        **Parent:** EPIC-16
**Parallelism:** Serial/Blocking    **Sprint:** 2

**Story**
As a security reviewer, I want the guard, validator, credential handling and audit trail attacked adversarially before release so that the controls hold when the model or the target misbehaves.

**Acceptance Criteria**
- Review covers: scope bypass attempts (redirects, DNS rebinding, look-alike hosts, IPv6 and encoded forms), method-gate bypass, validator evasion by encoding and splitting, prompt injection from target content steering the model into destructive or off-scope tests, credential leakage through logs/narration/exports/evidence, audit completeness, and formula injection in exports.
- A hostile fixture target is used: its pages and responses contain instructions aimed at the model, off-host links, and large or malformed bodies.
- Each finding is fixed or recorded as an accepted risk with an owner.
- The prompt-injection test proves that content from the target cannot cause a request outside scope or a destructive input to be sent.
- A written summary is saved with the story.

**Dev Notes**
- Use the project's security-review skill/process for the report format.
- Treat all target content as untrusted input to the model (architecture: security cross-cutting concern).

**Dev Testing**
- Test level: integration + adversarial.
- Assert: every bypass attempt is denied and audited; hostile-target scan finishes within scope with zero off-scope requests and zero rejected-unsafe inputs reaching the transport.

**Dependencies:** DAST-01-050, DAST-01-060, DAST-06-010, DAST-09-030, DAST-11-040, DAST-16-050
**Blocks:** —

**Definition of Done:** code merged + developer tests green

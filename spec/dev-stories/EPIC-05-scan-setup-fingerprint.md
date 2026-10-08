## [EPIC-05] Scan Setup, Fingerprint & Preflight

**Goal:** Operators can start, configure, cancel and track a DAST scan; the engine confirms reachability, detects the target's shape, and routes the pipeline accordingly.
**Depends On:** EPIC-00, EPIC-01, EPIC-02, EPIC-03
**Blocks:** EPIC-06, EPIC-07, EPIC-09, EPIC-13
**Teams:** Dev

Requirements: REQ-FR-SCAN-1 to -10, REQ-INT-1, -2. Much of scan creation already exists (`routers/scans.py`, `dast_input`, authorization check, inline project creation); stories here extend it.

---

### DAST-05-010 DAST scan creation contract

**Epic:** EPIC-05 Scan Setup, Fingerprint & Preflight        **Parent:** EPIC-05
**Parallelism:** Serial/Blocking    **Sprint:** 1

**Story**
As an operator, I want to create a DAST scan with its full configuration so that identities, safety settings, rule packs and model choice are captured in one request.

**Acceptance Criteria**
- `POST /scans` with `scan_type=dast` accepts: target address, authorization confirmation, project, identities (each with role and auth method), intensity preset, method policy (safe/opt-in mutating), rate limit, disposable-target flag, rule packs and per-scan overrides, model selection.
- A request without the authorization confirmation is rejected with a clear message (existing behavior preserved).
- Existing request shape (`target_url`, `login_url`, `username`, `password`, budgets, `headless`) keeps working as a single-identity form login.
- Passwords, tokens and uploaded session material are never written to `metadata_json`; only `has_*` flags and labels are.
- Scan appears alongside other scan types in project history with a sequential `version`.

**Dev Notes**
- Extend the `dast` Pydantic input in `schemas.py`; keep backward compatibility with the current single-credential fields.
- Credentials go to the credential holder (DAST-06-010) via the existing in-memory secrets path (`scan_runner._dast_secrets_lock`).

**Dev Testing**
- Test level: integration (mock engine).
- Assert: valid multi-identity request accepted; missing authorization rejected; legacy payload accepted; no credential string in the stored scan JSON (seed and search); version increments per project.
- Entry point: `POST /scans`.

**Dependencies:** DAST-00-030, DAST-03-040
**Blocks:** DAST-05-020, DAST-06-020, DAST-13-020

**Definition of Done:** code merged + developer tests green

---

### DAST-05-020 Effective settings snapshot and intensity presets

**Epic:** EPIC-05 Scan Setup, Fingerprint & Preflight        **Parent:** EPIC-05
**Parallelism:** Parallel    **Sprint:** 1

**Story**
As an operator, I want light, standard and deep presets and a frozen record of what each scan ran with so that scans are comparable over time.

**Acceptance Criteria**
- Presets map to concrete budgets: max targets, max tests per target, crawl depth, pages, runtime; values are documented and configurable.
- Explicit per-scan values override the preset.
- At scan start the effective settings (preset, budgets, safety, rule set, model routing, rate) are stored on the scan under a documented key and never modified afterwards.
- The scan API returns the snapshot.

**Dev Notes**
- Snapshot goes in `metadata_json["dast_effective"]`; do not store secrets.
- Pure function: inputs (request, settings, rule set) → effective settings.

**Dev Testing**
- Test level: unit + integration.
- Assert: preset mapping; override precedence; snapshot unchanged after changing global settings; snapshot contains no secret values.

**Dependencies:** DAST-05-010, DAST-00-030, DAST-03-040
**Blocks:** DAST-05-040, DAST-07-020, DAST-09-010

**Definition of Done:** code merged + developer tests green

---

### DAST-05-030 Preflight stage

**Epic:** EPIC-05 Scan Setup, Fingerprint & Preflight        **Parent:** EPIC-05
**Parallelism:** Parallel    **Sprint:** 1

**Story**
As an operator, I want the scan to confirm the target is reachable and in scope before doing anything else so that a mistyped address fails fast with a clear reason.

**Acceptance Criteria**
- The stage (extends `check_connection`) establishes the scope from the target, then requests the target through the guarded executor.
- Outcomes: reachable; unreachable (DNS, refused, timeout, TLS error) each with a distinct, human-readable reason; redirect to out-of-scope host flagged.
- On failure the scan ends `failed` with the reason and sends no further requests.
- The stage prints the banner `### DAST: checking connection`.

**Dev Notes**
- Replace the direct request in `nodes/check_connection.py` with the executor from DAST-01-030.
- Keep the node signature and banner so `scan_progress.PROGRESS_MARKERS` keeps working.

**Dev Testing**
- Test level: unit (fake target) + integration.
- Assert: each failure type's message; success path continues; no request sent after failure; banner present.

**Dependencies:** DAST-01-030, DAST-02-010, DAST-02-060
**Blocks:** DAST-05-040

**Definition of Done:** code merged + developer tests green

---

### DAST-05-040 Fingerprint stage and pipeline routing

**Epic:** EPIC-05 Scan Setup, Fingerprint & Preflight        **Parent:** EPIC-05
**Parallelism:** Serial/Blocking    **Sprint:** 1

**Story**
As an operator, I want the engine to detect whether the target is a classic site, a single-page app or an API-only service so that it runs only the stages that fit.

**Acceptance Criteria**
- Output: `{shape: mpa|spa|api, auth: none|form|token|preauth, schema: none|openapi|graphql}`.
- Uses the `fingerprint` model task with a deterministic fallback (heuristics over headers, content type, root document, well-known schema paths).
- Routing: `api` shape skips the browser crawl and goes to schema ingestion; a supplied token or stored session skips form login; others follow the existing path.
- The fingerprint result is stored in the scan's discovery summary and shown in the log.
- Banner: `### DAST: fingerprinting`.

**Dev Notes**
- Extend `graph.py`: new node plus conditional edges; keep `route_entry` behavior for storage-state scans.
- The `route_after_crawl` bounded re-login logic stays.

**Dev Testing**
- Test level: unit + integration.
- Assert: fake targets for each shape classify correctly with the model failing (fallback) and with a scripted gateway; routing decisions per shape; API-only scan makes zero browser calls (assert driver not constructed).

**Dependencies:** DAST-05-030, DAST-05-020, DAST-02-060
**Blocks:** DAST-06-030, DAST-07-020, DAST-07-040

**Definition of Done:** code merged + developer tests green

---

### DAST-05-050 End-to-end cancellation

**Epic:** EPIC-05 Scan Setup, Fingerprint & Preflight        **Parent:** EPIC-05
**Parallelism:** Parallel    **Sprint:** 1

**Story**
As an operator, I want to cancel a running scan and have it stop promptly so that I can abort a mistaken or harmful scan.

**Acceptance Criteria**
- `PATCH`/cancel endpoint sets the scan to `cancelled`; the guard stops sending requests immediately; stages exit at their next check point.
- The check point exists between individual tests in the active stage and between pages in the crawl.
- Findings and audit rows written before cancel are kept.
- A cancelled scan never transitions to `success`.
- Cancel on a finished scan returns a clear no-op response.

**Dev Notes**
- The status vocabulary in `Scan.status` comment lists `queued|running|success|failed`; add `cancelled` to the code paths that branch on status (including `scan_progress` and the frontend `ScanStatusBadge`).
- Engine reads cancellation through the callback supplied by the application.

**Dev Testing**
- Test level: integration.
- Assert: cancel mid-run on a fake slow target stops within one test interval; audit shows no requests after cancel timestamp; status stays `cancelled`; second cancel is a no-op.

**Dependencies:** DAST-01-020
**Blocks:** DAST-13-050

**Definition of Done:** code merged + developer tests green

## [EPIC-10] Multi-Role Authorization Testing

**Goal:** Cross-test every role against every other, plus an anonymous baseline, to find broken object-level and function-level authorization, and expose the result as a role-by-role matrix.
**Depends On:** EPIC-04, EPIC-06, EPIC-09
**Blocks:** EPIC-14 (matrix UI)
**Teams:** Dev

Requirements: REQ-FR-ROLE-2 to -8. This is the signature feature; it depends on isolated per-identity sessions (DAST-06-020).

---

### DAST-10-010 Anonymous replay and degraded mode

**Epic:** EPIC-10 Multi-Role Authorization Testing        **Parent:** EPIC-10
**Parallelism:** Serial/Blocking    **Sprint:** 2

**Story**
As a security engineer, I want every authenticated request replayed with no session so that unauthenticated access to protected resources is found even with a single identity.

**Acceptance Criteria**
- For each endpoint reached by an authenticated identity, the request is replayed as Anonymous through the guarded executor (read-only methods unless state-changing methods were opted in).
- A successful, materially equivalent response triggers `auth_boundary_crossed` and a finding via the guardrail path.
- With only one authenticated identity, cross-role checks are marked `degraded: no second identity` (DAST-03-060) and only this replay runs.
- The matrix notes which cells are untested and why.

**Dev Notes**
- Matrix cell for Anonymous is always populated; user-to-user cells are `untested` when a second identity is absent.

**Dev Testing**
- Test level: integration (fake target with one protected and one public endpoint).
- Assert: protected endpoint reachable anonymously is a finding; correctly protected is not; degraded status recorded with one identity.

**Dependencies:** DAST-09-030, DAST-06-020, DAST-04-030, DAST-03-060
**Blocks:** DAST-10-020, DAST-10-040

**Definition of Done:** code merged + developer tests green

---

### DAST-10-020 Cross-role replay engine

**Epic:** EPIC-10 Multi-Role Authorization Testing        **Parent:** EPIC-10
**Parallelism:** Serial/Blocking    **Sprint:** 2

**Story**
As a security engineer, I want each role's requests replayed as every other role so that access control is tested across all role pairs automatically.

**Acceptance Criteria**
- For N roles (including Anonymous) all ordered pairs are generated; each pair's requests are those the "owner" role reached, replayed as the "other" role.
- Replays respect the safe-mode method gate and rate limit; state-changing replays run only when opted in.
- Each result records owner role, acting role, request, response, and signals.
- Role pairs run in deterministic order; the engine supports cancel between replays.
- Identical requests are not replayed twice.

**Dev Notes**
- Replays use the identity's own session via the executor's identity label.
- Cap total replays through the existing max-tests settings; log when the cap truncates a pair.

**Dev Testing**
- Test level: integration (fake target, three roles).
- Assert: N×(N−1) pairs plus anonymous; deterministic order; no duplicate replay; safe mode blocks state-changing replays; cap logged.

**Dependencies:** DAST-10-010
**Blocks:** DAST-10-030, DAST-10-040

**Definition of Done:** code merged + developer tests green

---

### DAST-10-030 BOLA and BFLA checks

**Epic:** EPIC-10 Multi-Role Authorization Testing        **Parent:** EPIC-10
**Parallelism:** Parallel    **Sprint:** 2

**Story**
As a security engineer, I want broken object-level and function-level authorization detected so that users cannot reach other users' data or privileged functions.

**Acceptance Criteria**
- BOLA (API1): a request carrying an object identifier owned by one identity, replayed as another identity of equal or lower privilege, with `auth_boundary_crossed` → finding.
- BFLA (API5): a privileged function (reached by the higher role only) replayed as a lower role, with `auth_boundary_crossed` → finding.
- Role privilege order is derived from the identity roles and is overridable per scan (Custom roles have no implicit order until set).
- Findings record the role pair, the identifier or function, evidence from both responses, and are `true_positive` only with the signal.
- A 403/401 or equivalent denial is a PASS for that cell.

**Dev Notes**
- Findings use rule ids from the API pack (DAST-03-020); the role pair is stored in the finding's location/target fields and in evidence.
- Identifier detection reuses path templating from the inventory.

**Dev Testing**
- Test level: integration.
- Assert: seeded BOLA and BFLA flaws found; correctly protected endpoints produce none; custom role without order produces `unverified` with the reason, not a guess.
- Test data: fake target with three roles and seeded flaws.

**Dependencies:** DAST-10-020, DAST-04-040, DAST-03-020, DAST-04-030
**Blocks:** DAST-16-020

**Definition of Done:** code merged + developer tests green

---

### DAST-10-040 Authorization matrix and API

**Epic:** EPIC-10 Multi-Role Authorization Testing        **Parent:** EPIC-10
**Parallelism:** Parallel    **Sprint:** 2

**Story**
As an operator, I want a role-by-role matrix of results so that I can see at a glance which role pairs are exposed.

**Acceptance Criteria**
- A pure domain function derives the matrix from replay results: each cell is `ok`, `n failing`, or `untested` with a reason.
- `GET /scans/{id}/authz-matrix` returns roles, cells, and the finding ids behind each failing cell.
- Findings accept a role-pair filter matching a matrix cell (DAST-04-060).
- The matrix is available for finished and in-progress scans.

**Dev Notes**
- Matrix is derived, not stored; recomputed from findings and replay summaries so it cannot drift.

**Dev Testing**
- Test level: unit + integration.
- Assert: cell states for ok/fail/untested; counts equal the number of findings; role-pair filter returns the same findings listed in the cell.
- Entry point: `GET /scans/{id}/authz-matrix`.

**Dependencies:** DAST-10-020, DAST-04-060, DAST-10-010
**Blocks:** DAST-14-020

**Definition of Done:** code merged + developer tests green

## [EPIC-07] Discovery

**Goal:** Build a deduplicated inventory of the target's endpoints from a guarded browser crawl, recorded network traffic and ingested API schemas, and report where observed and documented surface differ.
**Depends On:** EPIC-01, EPIC-05, EPIC-06
**Blocks:** EPIC-08, EPIC-09
**Teams:** Dev

Requirements: REQ-FR-DISC-1 to -7. Existing: `nodes/crawl.py` (Playwright crawl with budgets, same-domain modes, noise params, planner).

---

### DAST-07-010 Endpoint inventory model

**Epic:** EPIC-07 Discovery        **Parent:** EPIC-07
**Parallelism:** Serial/Blocking    **Sprint:** 1

**Story**
As a developer, I want one inventory model that merges observed and schema-derived endpoints so that later stages test each endpoint once.

**Acceptance Criteria**
- An Endpoint holds: method, URL, path template, parameters (name, location, observed values), body schema or sample, source (`observed|schema|both`), identities that reached it.
- Merge key `(method, path_template)`; merging combines parameters and records both sources.
- Path templating normalizes numeric, UUID and slug-like segments.
- The inventory is pure domain code with no I/O.

**Dev Notes**
- Reuse `url_utils.get_url_pattern` semantics; extend for path-segment templating.
- Keep the structure compatible with the existing `discovery` summary shown by `ScanDiscoveryPanel`.

**Dev Testing**
- Test level: unit.
- Assert: `/users/1` and `/users/2` merge to `/users/{id}`; same path different method stays separate; observed+schema merges to `both`; parameter union.

**Dependencies:** DAST-00-020, DAST-04-010
**Blocks:** DAST-07-020, DAST-07-040, DAST-07-050, DAST-07-060, DAST-09-010

**Definition of Done:** code merged + developer tests green

---

### DAST-07-020 Crawl stage on the browser driver

**Epic:** EPIC-07 Discovery        **Parent:** EPIC-07
**Parallelism:** Serial/Blocking    **Sprint:** 1

**Story**
As an operator, I want the crawl to run through the guarded browser driver with configurable budgets so that it is bounded, in scope and audited.

**Acceptance Criteria**
- `nodes/crawl.py` obtains its browser context from the driver interface, inheriting guard interception (DAST-01-040) and the per-identity session (DAST-06-020).
- Budgets from the effective settings are enforced: runtime, depth, pages, per-pattern cap, same-domain mode.
- Discovered pages, forms and links feed the inventory (DAST-07-010).
- The crawl stops promptly on cancel.
- API-only targets skip this stage entirely (DAST-05-040).
- Banner `### DAST: crawling` and existing progress markers keep working.

**Dev Notes**
- Playwright stays lazy-imported; the mock engine never constructs a driver.
- Keep the existing session-lost signalling (`crawl_stop_reason`).

**Dev Testing**
- Test level: integration (`live`, local fixture site) + unit for budget logic.
- Assert: each budget stops the crawl at the limit; off-host links not followed; cancel stops it; inventory populated; existing crawl tests still pass.

**Dependencies:** DAST-01-040, DAST-06-030, DAST-06-040, DAST-05-040, DAST-07-010, DAST-05-020
**Blocks:** DAST-07-030

**Definition of Done:** code merged + developer tests green

---

### DAST-07-030 Network recorder with request bodies

**Epic:** EPIC-07 Discovery        **Parent:** EPIC-07
**Parallelism:** Serial/Blocking    **Sprint:** 1

**Story**
As a security engineer, I want the actual requests the application makes, including bodies, so that active tests use real request shapes instead of guesses.

**Acceptance Criteria**
- During the crawl, each XHR/fetch request and response is recorded: method, URL, headers (secrets redacted), request body (size-capped), response status, headers, body excerpt.
- Recorded traffic feeds both the inventory and the passive stage's input.
- Request bodies are stored only for the scan's lifetime in the run state and in evidence excerpts; credential-bearing fields are redacted.
- Static assets are recorded by URL and status only.

**Dev Notes**
- Replaces the current "request bodies inferred rather than captured" gap noted in `DAST_completion_spec.md`.
- Recorder is part of the browser driver adapter; output is plain data.

**Dev Testing**
- Test level: integration (`live`) + unit on the recording structures.
- Assert: a form POST and a JSON fetch are captured with bodies; password field value redacted; static assets body-less; size caps enforced.

**Dependencies:** DAST-07-020
**Blocks:** DAST-08-010, DAST-09-030, DAST-09-040

**Definition of Done:** code merged + developer tests green

---

### DAST-07-040 OpenAPI and Swagger ingestion

**Epic:** EPIC-07 Discovery        **Parent:** EPIC-07
**Parallelism:** Parallel    **Sprint:** 1

**Story**
As a security engineer, I want published API descriptions ingested so that endpoints and body shapes the UI never exposes are still tested.

**Acceptance Criteria**
- Probes well-known locations (OpenAPI/Swagger JSON and YAML) through the guarded executor; locations are configurable.
- A found document yields endpoints, parameters and body schemas merged into the inventory as `schema` sources.
- Both OpenAPI 3.x and Swagger 2.0 are supported; unparseable documents are logged and skipped without failing the scan.
- Large documents are size-capped.
- Skipped when the fingerprint reports no schema, unless the operator supplies a schema URL.

**Dev Notes**
- Use the already-pinned YAML library and Pydantic; no new dependency.
- `$ref` resolution must be bounded (depth and size) to avoid expansion attacks from a hostile document.

**Dev Testing**
- Test level: unit (fixture documents) + integration (fake target).
- Assert: endpoints and body schema extracted; Swagger 2 and OpenAPI 3 fixtures; recursive `$ref` bounded; malformed document skipped; probe requests appear in the audit.

**Dependencies:** DAST-07-010, DAST-01-030, DAST-05-040
**Blocks:** DAST-07-060, DAST-09-010

**Definition of Done:** code merged + developer tests green

---

### DAST-07-050 GraphQL introspection ingestion

**Epic:** EPIC-07 Discovery        **Parent:** EPIC-07
**Parallelism:** Parallel    **Sprint:** 1

**Story**
As a security engineer, I want GraphQL schemas introspected so that queries and mutations become part of the inventory.

**Acceptance Criteria**
- Probes `/graphql` and common variants with a standard introspection query (read-only), through the guarded executor.
- Queries and mutations become inventory entries with argument shapes; mutations are marked state-changing so the method gate applies.
- Introspection disabled by the target is recorded as a finding-free note, not an error.
- Response size is capped.

**Dev Notes**
- Introspection is a POST; it is allowed in safe mode as a read-only exception through an explicit, documented allow-list entry in the method policy, not a general POST allowance.

**Dev Testing**
- Test level: unit + integration (fake GraphQL target).
- Assert: introspection result parsed; mutations flagged; disabled introspection handled; the safe-mode exception permits only the introspection request.

**Dependencies:** DAST-07-010, DAST-01-010
**Blocks:** DAST-07-060

**Definition of Done:** code merged + developer tests green

---

### DAST-07-060 Observed vs documented inventory diff

**Epic:** EPIC-07 Discovery        **Parent:** EPIC-07
**Parallelism:** Parallel    **Sprint:** 1

**Story**
As a security engineer, I want endpoints that exist but are undocumented (and the reverse) reported so that improper-inventory risk is visible.

**Acceptance Criteria**
- Endpoints with source `observed` but absent from a found schema are listed as undocumented; `schema` endpoints never observed are listed as unexercised.
- Undocumented endpoints produce an API9 finding (`unverified` unless a stronger signal exists); unexercised ones are informational only.
- With no schema, the diff is skipped and noted as such.
- Results appear in the discovery summary.

**Dev Notes**
- Pure comparison on the inventory; the finding is created through the normal findings writer.

**Dev Testing**
- Test level: unit.
- Assert: both directions; no-schema case; finding fields and verdict.

**Dependencies:** DAST-07-040, DAST-07-050, DAST-04-050, DAST-07-010
**Blocks:** DAST-09-010, DAST-13-060

**Definition of Done:** code merged + developer tests green

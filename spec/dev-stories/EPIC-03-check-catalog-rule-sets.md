## [EPIC-03] Check Catalog & Rule Sets

**Goal:** Coverage is declarative data: a validated catalog of checks, grouped into rule packs, configurable globally, per project and per scan, extendable with custom rules, and snapshotted on each scan.
**Depends On:** EPIC-00 (and DAST-04-020/-030 for the signal names a check may reference)
**Blocks:** EPIC-09, EPIC-10, EPIC-15
**Teams:** Dev

Requirements: REQ-FR-RULE-1 to -12.

---

### DAST-03-010 Check schema and catalog loader

**Epic:** EPIC-03 Check Catalog & Rule Sets        **Parent:** EPIC-03
**Parallelism:** Serial/Blocking    **Sprint:** 1

**Story**
As a developer, I want a validated check schema and a loader so that every check is declared as data with identity, applicability, injection location, proving signals and severity.

**Acceptance Criteria**
- Check fields: id, title, standard tags (`owasp`, `apisec`, `wstg`, `cwe`), `applies_to`, injection location (`query|path|header|body`), `signal[]`, base severity, mode (`automated|opt-in|assist-only`), remediation reference, dependencies (`second_identity`, `oast`).
- Checks contain no fixed payload string; a field attempting to carry one is rejected by the schema.
- A check must name at least one signal that exists in the detector library; otherwise it loads as `assist-only` and is flagged.
- Duplicate ids and unknown fields fail the load with a file and line.
- Remediation references resolve to existing files.

**Dev Notes**
- Pydantic models in `domain/entities.py`; the YAML reader lives in infrastructure.
- Catalog directory: `backend/app/data/dast/` (`check_catalog.yaml`, `remediation/`).
- Detector signal names come from the detector library registry (DAST-04-020/030); until they land, use a registry stub listing the names in the design doc.

**Dev Testing**
- Test level: unit.
- Assert: valid catalog loads; each failure mode (duplicate id, unknown signal downgrade, payload field, missing remediation file, bad enum) produces a specific error.
- Test data: small fixture catalogs, valid and invalid.

**Dependencies:** DAST-00-020
**Blocks:** DAST-03-020, DAST-03-030, DAST-03-060

**Definition of Done:** code merged + developer tests green

---

### DAST-03-020 Default pack: OWASP API Security Top 10 (2023)

**Epic:** EPIC-03 Check Catalog & Rule Sets        **Parent:** EPIC-03
**Parallelism:** Parallel    **Sprint:** 1

**Story**
As a security engineer, I want the default API pack so that a scan covers the OWASP API Top 10 out of the box.

**Acceptance Criteria**
- Pack `owasp-api-top10-2023` contains checks for API1 to API10 with the modes in `project-concept.md` §5: API1, API2, API3, API5, API8, API9 automated; API4 opt-in and off by default; API6 and API10 assist-only; API7 automated only with an OAST dependency.
- Every check carries OWASP, API Top 10 and CWE tags and a remediation reference.
- A remediation Markdown file exists for every check in the pack.
- The pack validates against the schema from DAST-03-010.

**Dev Notes**
- Check ids use the `dast-` prefix; keep `dast-sqli`, `dast-xss`, `dast-misconfig` as aliases so existing mock output and tests still match.
- Remediation text should be actionable and non-exploit.

**Dev Testing**
- Test level: unit.
- Assert: ten risks represented; modes as specified; API4 disabled by default; every check has a resolvable remediation; aliases resolve.

**Dependencies:** DAST-03-010
**Blocks:** DAST-03-040, DAST-04-060, DAST-09-010, DAST-10-030

**Definition of Done:** code merged + developer tests green

---

### DAST-03-030 Default packs: Web Top 10, WSTG and passive-only

**Epic:** EPIC-03 Check Catalog & Rule Sets        **Parent:** EPIC-03
**Parallelism:** Parallel    **Sprint:** 1

**Story**
As a security engineer, I want the web-application packs so that a scan can test against the OWASP Web Top 10 and the Web Security Testing Guide, or run passive-only.

**Acceptance Criteria**
- Packs `owasp-web-top10`, `wstg-full` and `passive-only` exist; a check may belong to several packs.
- `passive-only` contains only checks that need no extra requests.
- A finding reports against every standard its check is tagged with.
- Each added check has remediation text.

**Dev Notes**
- Packs are selections over tags, not copies of checks; implement as a pack definition file referencing check ids or tag queries.
- Cover the passive checks in EPIC-08 and the active checks in EPIC-09; do not add a check with no planned detector.

**Dev Testing**
- Test level: unit.
- Assert: passive-only has no active check; overlap across packs resolves to one check instance; tag-based selection returns the expected ids.

**Dependencies:** DAST-03-010
**Blocks:** DAST-03-040, DAST-08-010

**Definition of Done:** code merged + developer tests green

---

### DAST-03-040 Packs, per-check overrides and effective rule set

**Epic:** EPIC-03 Check Catalog & Rule Sets        **Parent:** EPIC-03
**Parallelism:** Serial/Blocking    **Sprint:** 1

**Story**
As an operator, I want packs enabled globally, defaulted per project and overridden per scan, with per-check enable, severity and mode overrides, so that I control exactly what a scan tests.

**Acceptance Criteria**
- Resolution order: global defaults → project defaults → per-scan selection; later levels override earlier ones.
- Per check: enable/disable, severity override, mode override (automated/opt-in/assist-only).
- Load-generating checks (API4) stay disabled until explicitly enabled, regardless of pack.
- The effective rule set (pack ids, resolved check list, overrides, custom rule versions) is computed at scan start and stored on the scan under a documented key; later configuration changes do not alter it.
- Global and project configuration are persisted; the per-scan selection arrives in the create-scan request.

**Dev Notes**
- Project level follows the existing `Project.limitations_config` precedent: a JSON column with idempotent migration in `db.py`; global level can use a small settings table or file.
- Resolution is pure (domain); persistence is infrastructure.
- API routes for reading/updating global and project rule configuration are added here for EPIC-15 to consume.

**Dev Testing**
- Test level: unit + integration.
- Assert: override precedence at every combination; API4 stays off until enabled; snapshot unchanged after config edit; scan created with an unknown pack id rejected; existing projects without config resolve to defaults.
- Entry point: `GET/PATCH` rule-set endpoints; `POST /scans`.

**Dependencies:** DAST-03-020, DAST-03-030, DAST-00-040
**Blocks:** DAST-03-050, DAST-03-060, DAST-05-010, DAST-05-020, DAST-09-010, DAST-13-040, DAST-15-030

**Definition of Done:** code merged + developer tests green

---

### DAST-03-050 Custom rules

**Epic:** EPIC-03 Check Catalog & Rule Sets        **Parent:** EPIC-03
**Parallelism:** Parallel    **Sprint:** 1

**Story**
As a security engineer, I want to add my own checks without changing product code so that a client-specific test can be added in minutes.

**Acceptance Criteria**
- A custom check is supplied as YAML using the same schema as catalog checks and is stored with a version.
- Validation rejects: duplicate id, unknown detector signal, any fixed payload string, missing standard tags, invalid mode.
- A custom check with no resolvable signal is accepted only as `assist-only` or `unverified`-only and says so.
- Custom checks join the effective rule set and are snapshotted with their version.
- An API accepts, lists, updates and deletes custom checks.

**Dev Notes**
- Reuse the loader from DAST-03-010; custom rules are stored in the database, validated on save and on load.
- Guardrails apply identically: scope, method gate, validator, rate.

**Dev Testing**
- Test level: unit + integration.
- Assert: each rejection path; accepted rule runs against the fake target and produces an evidenced finding; version recorded in the snapshot; deletion does not alter past scans' snapshots.
- Entry point: custom-rule endpoints.

**Dependencies:** DAST-03-040
**Blocks:** DAST-15-040

**Definition of Done:** code merged + developer tests green

---

### DAST-03-060 Dependency-aware skip and degrade

**Epic:** EPIC-03 Check Catalog & Rule Sets        **Parent:** EPIC-03
**Parallelism:** Parallel    **Sprint:** 1

**Story**
As an operator, I want checks that cannot run to be reported as skipped or degraded, with the reason, so that missing coverage is never silent.

**Acceptance Criteria**
- At scan start, each selected check's dependencies are evaluated against the scan: second identity present, OAST URL configured, schema present.
- A check missing a dependency is marked `skipped` or `degraded` with a stated reason (for example "BOLA ran no-session replay only: no second identity").
- The skipped/degraded list is stored on the scan and returned by the scan API.
- API7 (SSRF) without an OAST URL becomes assist-only; API4 stays off unless enabled.

**Dev Notes**
- Pure function over the effective rule set and scan inputs; result stored alongside the snapshot.
- The report and UI read the list; do not hide any entry.

**Dev Testing**
- Test level: unit.
- Assert: each dependency combination yields the expected status and reason text; the list appears in the scan response.

**Dependencies:** DAST-03-040, DAST-03-010
**Blocks:** DAST-09-050, DAST-09-060, DAST-10-010, DAST-11-010

**Definition of Done:** code merged + developer tests green

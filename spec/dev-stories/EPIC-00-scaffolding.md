## [EPIC-00] Scaffolding & Project Setup

**Goal:** The DAST foundations every other epic builds on: pinned dependencies, the layered package structure with enforced import rules, the settings surface, the schema additions, the mock engine and test harness, CI, a local practice-target environment, and frontend type/API stubs.
**Depends On:** — (foundational)
**Blocks:** EPIC-01 to EPIC-16
**Teams:** Dev

Scope note: the repo already has a working five-stage DAST pipeline (`backend/app/dast/`), a `dast` scan type, an authorization check and narration. This epic does not rebuild those. It adds the structure and baseline they will be extended on, and keeps the existing test suite green throughout.

---

### DAST-00-010 Adopt the pinned dependency set

**Epic:** EPIC-00 Scaffolding & Project Setup        **Parent:** EPIC-00
**Parallelism:** Serial/Blocking    **Sprint:** 1

**Story**
As a developer, I want the backend dependencies locked to the versions in the tech-stack document so that every environment builds the same DAST engine.

**Acceptance Criteria**
- `backend/requirements.txt` carries the exact versions from `spec/dast-requirements.lock.txt` for every package DAST uses; SAST-only packages (tree-sitter\*, semgrep, networkx) are unchanged.
- A fresh Python 3.12 virtual environment installs from the file with no resolver conflicts.
- `pytest` from `backend/` passes with no new failures against the pre-change baseline.
- `langchain-core` is 1.6.6, and `langchain-anthropic`, `langchain-openai` and `psycopg[binary]` are present.
- `python -m playwright install chromium` is documented as a one-time step and is not required to run the mock suite.

**Dev Notes**
- Record the pre-change `pytest` result first so any regression is attributable.
- Heavy packages (Playwright, provider SDKs) must stay lazy-imported; do not add top-level imports in `app/`.
- The `tech-stack.md` "What has not been verified" list closes with this story: record the actual install and test result back into it.

**Dev Testing**
- Test level: smoke.
- Assert: clean install in a new venv; `pytest` green; `python -c "import app.main"` works without Playwright or provider SDKs importable (simulate by running the suite in an env without them).
- Entry point: `pip install -r backend/requirements.txt && pytest`.

**Dependencies:** — (scaffolding start)
**Blocks:** DAST-00-020, DAST-00-030, DAST-00-070, DAST-00-080

**Definition of Done:** code merged + developer tests green

---

### DAST-00-020 Layered package skeleton and import-rule check

**Epic:** EPIC-00 Scaffolding & Project Setup        **Parent:** EPIC-00
**Parallelism:** Serial/Blocking    **Sprint:** 1

**Story**
As a developer, I want the DAST code split into domain, engine and infrastructure packages with enforced dependency rules so that the verdict logic stays pure and the layers cannot erode.

**Acceptance Criteria**
- `backend/app/dast/domain/` exists with `entities.py`, `interfaces.py`, `verdict.py`, `guardrail.py`, `dedupe.py`, `diff.py`, `detectors.py`, `validation.py`, each importable and initially containing only the contracts and type definitions from the architecture document.
- `interfaces.py` declares the domain contracts: request executor, browser driver, model gateway, check catalog, finding store, credential holder.
- A test fails the build if any module under `app/dast/domain/` imports FastAPI, SQLAlchemy, Playwright, httpx, any LangChain/LLM SDK, or any module outside `app/dast/domain/`.
- A second rule fails the build if `app/dast/nodes/` imports from `app/routers/` or concrete infrastructure modules.
- Existing DAST modules keep working unchanged; nothing is moved yet.

**Dev Notes**
- Implement the check as an AST walk over imports in a pytest test, not a new dependency.
- Follow the dependency-rules table in `architecture.md`.
- Update `backend/app/dast/CLAUDE.md` with the new layout and the rule.

**Dev Testing**
- Test level: unit.
- Assert: the check passes on the skeleton; it fails when a deliberately bad import is added in a temporary fixture module; domain modules import with only the standard library available.
- Entry point: `pytest tests/test_dast_layering.py`.

**Dependencies:** DAST-00-010
**Blocks:** DAST-00-040, DAST-00-050, DAST-00-060, DAST-01-010, DAST-01-060, DAST-02-010, DAST-03-010, DAST-04-010, DAST-06-010, DAST-07-010

**Definition of Done:** code merged + developer tests green

---

### DAST-00-030 DAST settings surface

**Epic:** EPIC-00 Scaffolding & Project Setup        **Parent:** EPIC-00
**Parallelism:** Parallel    **Sprint:** 1

**Story**
As an operator, I want crawl budgets, rate limits, safe-mode default, model routing and the OAST address in configuration so that nothing the scan depends on is hard-coded.

**Acceptance Criteria**
- `backend/app/config.py` exposes: max runtime, depth, pages, per-pattern cap, same-domain mode (`exact` | `root-domain`), safe-mode default (default true), request rate per second (default 5), max targets, max tests per target, OAST callback URL (optional), per-task provider and model for `fingerprint`, `crawl_plan`, `login_selectors`, `construct`, `rule`, `narrate`.
- Every value is overridable by environment variable; defaults match `DAST_tech_stack.md` §5; the Ollama base URL is configurable (it is hard-coded in `app/dast/app.py` and `server.py` today).
- `.env.example` documents each new variable.
- Existing settings (`dast_ollama_model`, `run_dast`, `bedrock_model_id`) keep working unchanged.

**Dev Notes**
- Extend the existing `Settings` class; do not introduce a second settings object.
- Remove the hard-coded Ollama URL from the engine entry points by reading it from settings.
- Per-task routing is a mapping task name → (provider, model); keep it a plain structure so EPIC-15 can persist overrides.

**Dev Testing**
- Test level: unit.
- Assert: defaults; env override of each value; invalid same-domain mode rejected; routing mapping covers all six tasks.
- Test data: monkeypatched environment.
- Entry point: `Settings()` construction.

**Dependencies:** DAST-00-010
**Blocks:** DAST-01-010, DAST-01-020, DAST-02-010, DAST-05-010, DAST-05-020, DAST-15-050

**Definition of Done:** code merged + developer tests green

---

### DAST-00-040 Schema additions for DAST evidence and audit

**Epic:** EPIC-00 Scaffolding & Project Setup        **Parent:** EPIC-00
**Parallelism:** Parallel    **Sprint:** 1

**Story**
As a developer, I want the data tables DAST needs so that findings carry target, parameter, location and evidence, and every request sent is auditable.

**Acceptance Criteria**
- `Finding` gains nullable columns: `target` (`METHOD path`), `param`, `location` (query|path|header|body|response), `confidence_label` (HIGH|MEDIUM|LOW), `remediation_ref`, `standards` (JSON list), `first_seen_scan_id`, `last_seen_scan_id`. The existing float `confidence` column is untouched.
- A new evidence table stores, per finding: baseline excerpt, test excerpt, detector signals, and an audit reference.
- A new request-audit table stores, per scan: sequence, method, URL, identity label, allowed/denied, deny reason, response status, timestamp, check id (nullable).
- `Scan` needs no new column; the effective-settings snapshot goes in `metadata_json` under a documented key.
- Migrations are hand-written, idempotent and added to `db.py`'s light-migration routine; running them twice changes nothing; existing SAST/SCA/SBOM rows are unaffected.

**Dev Notes**
- Keep `confidence_label` separate from the float `confidence` because the SAST path already uses the float.
- Index the audit table on `(scan_id, seq)` and the evidence table on `finding_id`.
- Follow the pattern in `db._run_light_migrations`; there is no Alembic chain.
- Add the models to `app/models.py`; add Pydantic response shapes in `schemas.py` only when a later story needs them.

**Dev Testing**
- Test level: integration (SQLite).
- Assert: migration on a database created by the previous schema adds the columns; second run is a no-op; inserting and reading a finding with evidence round-trips; deleting a scan does not orphan evidence or audit rows.
- Test data: fixture database file from the pre-change schema.
- Entry point: `db.init_db()` / migration routine.

**Dependencies:** DAST-00-020
**Blocks:** DAST-01-050, DAST-03-040, DAST-04-010, DAST-04-050, DAST-11-010

**Definition of Done:** code merged + developer tests green

---

### DAST-00-050 Mock engine contract extended

**Epic:** EPIC-00 Scaffolding & Project Setup        **Parent:** EPIC-00
**Parallelism:** Parallel    **Sprint:** 1

**Story**
As a developer, I want the mock DAST engine to emit the full result shape (evidence, roles, matrix, unverified findings) so that every API and UI story can be built and tested offline.

**Acceptance Criteria**
- `engine_adapter` mock path returns deterministic discovery, passive findings, active findings with evidence, an unverified finding, a two-role authorization result, and a usage summary.
- Identical input yields byte-identical output.
- The mock run needs no browser, model or network and runs inline.
- The mock output validates against the same domain entities the real engine will use.

**Dev Notes**
- Extend `_mock_dast_discovery` / `_write_mock_dast_findings`; keep the existing `dast-sqli`, `dast-xss`, `dast-misconfig` ids working.
- Mock rule ids should migrate to catalog ids once EPIC-03 lands; leave a TODO tied to DAST-03-020.

**Dev Testing**
- Test level: integration.
- Assert: determinism (run twice, compare); presence of each result kind; unverified finding stored with `verdict="unverified"`.
- Entry point: `POST /scans` with `scan_type=dast` under the mock engine.

**Dependencies:** DAST-00-020
**Blocks:** DAST-00-090, DAST-12-010, DAST-13-010, DAST-14-010

**Definition of Done:** code merged + developer tests green

---

### DAST-00-060 Test harness and offline target fixtures

**Epic:** EPIC-00 Scaffolding & Project Setup        **Parent:** EPIC-00
**Parallelism:** Parallel    **Sprint:** 1

**Story**
As a developer, I want shared fixtures and markers so that unit, integration and live tests are cleanly separated and the default run is fully offline.

**Acceptance Criteria**
- `pytest.ini` defines markers `unit`, `integration`, `live` (live = needs browser, model or a practice target); live tests are skipped unless explicitly selected.
- A fixture provides a fake HTTP target (in-process, transport-level) with configurable pages, headers, cookies, an OpenAPI document, and two users, so crawl-free engine logic can be tested without sockets.
- A fixture provides a fake model gateway returning scripted replies and recording calls.
- Documented in `backend/tests/README.md` with one example per level.

**Dev Notes**
- Build the fake target on httpx's mock transport so it works with the guarded executor.
- Keep fixtures in `tests/conftest.py` or `tests/dast_fixtures/`.

**Dev Testing**
- Test level: unit (fixtures themselves).
- Assert: fake target serves scripted responses; fake gateway records calls and can simulate failure and malformed output; `live` tests are skipped by default.

**Dependencies:** DAST-00-020
**Blocks:** DAST-01-030

**Definition of Done:** code merged + developer tests green

---

### DAST-00-070 CI pipeline skeleton

**Epic:** EPIC-00 Scaffolding & Project Setup        **Parent:** EPIC-00
**Parallelism:** Parallel    **Sprint:** 1

**Story**
As a developer, I want a pipeline that runs the backend suite, the layering check and the frontend lint and build so that every DAST change is verified automatically.

**Acceptance Criteria**
- Pipeline jobs: backend `pytest -m "not live"`; frontend `npm run lint` and `npm run build`; both required on pull requests.
- A manual, non-blocking job exists for `live` tests, with a placeholder step to be filled by EPIC-16.
- Failing layering or test jobs block merge.
- Pipeline runtime is recorded as a baseline.

**Dev Notes**
- Use the CI system the repo already uses; if none exists, document the chosen one in the story.
- Frontend has no test runner; do not add one here.

**Dev Testing**
- Test level: smoke.
- Assert: a deliberately failing test turns the pipeline red; a clean branch is green.

**Dependencies:** DAST-00-010
**Blocks:** DAST-16-040

**Definition of Done:** code merged + developer tests green

---

### DAST-00-080 Local practice-target environment

**Epic:** EPIC-00 Scaffolding & Project Setup        **Parent:** EPIC-00
**Parallelism:** Parallel    **Sprint:** 1

**Story**
As a developer, I want one command that starts the backend, frontend, a local model host and deliberately vulnerable practice targets so that live scans can be run and measured locally.

**Acceptance Criteria**
- A compose file starts DVWA and Juice Shop, bound to localhost only.
- A short README covers: starting Ollama, pulling `gpt-oss:20b`, `playwright install chromium`, starting the backend and frontend, and running one live scan against each practice target.
- A reset script restores the practice targets to a known state.
- The environment is clearly marked as for authorized local testing only.

**Dev Notes**
- Pin the practice-target image versions and record them.
- Do not expose the targets beyond localhost.

**Dev Testing**
- Test level: smoke (manual checklist run by the developer).
- Assert: both targets respond on their ports; a mock-off scan reaches `success` against one of them.

**Dependencies:** DAST-00-010
**Blocks:** DAST-16-010, DAST-16-020

**Definition of Done:** code merged + developer tests green

---

### DAST-00-090 Frontend scaffolding: types, API stubs and shared helpers

**Epic:** EPIC-00 Scaffolding & Project Setup        **Parent:** EPIC-00
**Parallelism:** Parallel    **Sprint:** 1

**Story**
As a frontend developer, I want the DAST types, API functions, proxy routes and shared role/severity helpers stubbed so that UI epics can proceed in parallel against a stable contract.

**Acceptance Criteria**
- `lib/types.ts` gains DAST types: identity, role, scan options, finding with evidence, authorization matrix, rule pack, check, model route.
- `lib/api.ts` gains typed functions for every endpoint in the architecture's platform-API table; corresponding `app/api/**/route.ts` proxies exist and attach the token through `sastFetch`.
- A single role-to-tone mapping (Admin purple, User blue, Viewer cyan, Anonymous slate, Custom amber) is exported once and used wherever a role renders.
- `verdictKind()` handling for `unverified` is confirmed present and reused.
- `npm run lint` and `npm run build` pass.

**Dev Notes**
- Read `node_modules/next/dist/docs/` before writing route handlers (this Next.js version has breaking changes; see `frontend/AGENTS.md`).
- Stub endpoints return the mock-engine shapes until the backend stories land.

**Dev Testing**
- Test level: build + lint (no frontend test runner exists).
- Assert: type-check passes; each proxy route returns 401/502 correctly when the backend token is wrong or the backend is down; the token never appears in a client bundle (search the build output).

**Dependencies:** DAST-00-050
**Blocks:** DAST-13-010, DAST-13-020, DAST-15-010, DAST-15-050

**Definition of Done:** code merged + developer tests green

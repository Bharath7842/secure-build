# Technology Stack Documentation — DAST Scan Type

Phase 3 of the scaffolding chain. Input: [core-requirements.md](core-requirements.md). Application type: **Web UI + REST API**, added to the existing Augmented Secure Build platform.

**How versions were locked.** Every version below is either (a) the version already installed and running in this repo's `backend/.venv` or `frontend/node_modules`, or (b) for packages not yet installed, the version `pip install --dry-run` resolved against that venv on 2026-10-06. Where nothing could be verified, the entry says so. Nothing is a guess from memory.

## Core Technology

- Python 3.12.12
- Node.js 22.22.1
- FastAPI 0.141.1 (backend API)
- Next.js 16.2.10 (frontend, App Router, `--webpack`)
- React 19.2.4
- SQLite (development) / PostgreSQL (production) via SQLAlchemy 2.0.54
- Ollama 0.34.2 with `gpt-oss:20b` (default local model)

This is the existing platform stack. DAST adds no new core technology.

## Required Dependencies

### Backend API (already in `backend/requirements.txt`)

- fastapi 0.141.1
  - Purpose: HTTP interface for scans, findings, exports (REQ-INT-3)
  - Chosen because: already the platform backend
- uvicorn 0.53.0
  - Purpose: ASGI server
  - Chosen because: already in use
- pydantic 2.13.5 and pydantic-settings 2.15.0
  - Purpose: request/response validation, validation of check-catalog and custom-rule files (REQ-FR-RULE-7, -10), environment-driven config
  - Chosen because: already in use; one validation library for API, config and catalog
- SQLAlchemy 2.0.54
  - Purpose: persistence of scans, findings, evidence, request audit log (REQ-FR-FIND-5, REQ-FR-SAFE-9)
  - Chosen because: already in use. Schema changes stay as hand-written idempotent statements in `db.py`; Alembic is not adopted, matching the platform
- httpx 0.28.1
  - Purpose: request execution, baseline and test requests, schema probing (REQ-FR-ACT-2, REQ-FR-DISC-3)
  - Chosen because: already installed; the safety guard wraps it so every request is scope-checked and logged

### Discovery

- playwright 1.63.0 (plus `python -m playwright install chromium`)
  - Purpose: real-browser crawl and network recording (REQ-FR-DISC-1, -2, -5)
  - Chosen because: already in the DAST engine. Lazy-imported, so mock mode and the test suite never need it (REQ-NFR-2). Chromium builds 1208, 1217 and 1243 are already cached locally; the build Playwright 1.63.0 expects was not checked, so the install command is still required on a fresh machine
- tldextract 5.3.2
  - Purpose: same-domain and root-domain scope decisions (REQ-FR-SAFE-1, REQ-FR-DISC-6)
  - Chosen because: already in the DAST engine
- PyYAML 6.0.3
  - Purpose: load check catalog and custom rule files (REQ-FR-RULE-1, -7)
  - Chosen because: already in the platform; the catalog is declarative data, not code

### Orchestration and model layer

- langgraph 1.2.12 (with langgraph-checkpoint 4.2.0, langgraph-prebuilt 1.1.0, langgraph-sdk 0.4.5)
  - Purpose: scan pipeline as a state graph with conditional stages (REQ-FR-SCAN-9)
  - Chosen because: already drives both the SAST and DAST engines
- langchain-core 1.6.6
  - Purpose: shared message and model base types
  - Chosen because: required by every provider package below. Installed today is 1.6.4; adding `langchain-anthropic` moves it to 1.6.6, so the lock uses 1.6.6
- langchain-ollama 1.1.0
  - Purpose: local model provider, the default (REQ-FR-MDL-3, -4)
  - Chosen because: already installed
- langchain-anthropic 1.7.5 (pulls anthropic 1.11.0)
  - Purpose: hosted Anthropic provider (REQ-FR-MDL-3)
  - Chosen because: resolves cleanly against the current venv. Lazy-imported; only needed when a task is routed to it
- langchain-openai 1.6.7 (pulls openai 3.24.0, tiktoken 0.14.0)
  - Purpose: hosted OpenAI provider (REQ-FR-MDL-3)
  - Chosen because: resolves cleanly against the current venv. Lazy-imported
- boto3 1.43.100
  - Purpose: AWS Bedrock provider, called directly through the Converse API (REQ-FR-MDL-3)
  - Chosen because: already installed and already used by the SAST engine's LLM client, so Bedrock needs no new dependency

### Reporting

- reportlab 5.0.1
  - Purpose: PDF export (REQ-FR-RPT-4)
  - Chosen because: already used by the existing export
- openpyxl 3.1.5
  - Purpose: XLSX export (REQ-FR-RPT-5)
  - Chosen because: already used by the existing export

### Production database

- psycopg 3.3.6 with psycopg-binary 3.3.6
  - Purpose: PostgreSQL driver for production (the platform currently ships no PostgreSQL driver)
  - Chosen because: the standard SQLAlchemy 2 PostgreSQL driver. It resolves cleanly against the current venv. Not needed for local development

### Testing

- pytest 9.1.1
  - Purpose: offline suite against the mock engine (REQ-NFR-2)
  - Chosen because: already in use
- pytest-asyncio 1.4.0
  - Purpose: async model-gateway and request-guard tests
  - Chosen because: already in use

### Frontend (no new packages)

- next 16.2.10, react 19.2.4, react-dom 19.2.4
- tailwindcss 4.3.2, @tailwindcss/postcss 4.3.2
- typescript 5.9.3, eslint 9.39.5, eslint-config-next 16.2.10
- @types/node 20.19.43, @types/react 19.2.17, @types/react-dom 19.2.3
  - Purpose: every DAST screen, including the authorization matrix, identity cards and rule-pack picker
  - Chosen because: REQ-CON-1 requires reusing the existing frontend with no new UI framework. New components are composed from existing Tailwind utilities. The frontend has no test runner, so only `lint` and `build` apply

## Dependencies deliberately not adopted

The earlier `DAST_tech_stack.md` listed these. Each is dropped, with the reason.

| Package | Decision | Reason |
|---|---|---|
| `alembic` | Not used | The platform uses hand-written idempotent migrations in `db.py`; the design doc itself says "not used" |
| `ratelimit`, `apscheduler` | Not used | Request-rate and concurrency limiting (REQ-FR-SAFE-5) is a small token bucket inside `safety_guard.py`, so the limit and the scope check live in one place. `ratelimit` also appears unmaintained. Scheduled cross-scan reporting is out of scope for the first release |
| `structlog` | Not used | The platform already captures engine output through `scan_log` and drives progress from it. A second logging system would split the record. Credential redaction (REQ-SEC-2) is applied in that existing capture path |
| `click` | Not used | `app/dast/server.py` already provides the CLI entry point |
| `python-dateutil` | Not used | Nothing in the requirements needs relative-time parsing |
| `black`, `isort`, `mypy` | Not added | The repo configures none of them; adopting them is a separate decision |
| `flask` | Kept out of the backend lock | Used only by the standalone dev UI (`app/dast/app.py`) and already listed in `app/dast/requirements.txt` |
| Server-sent events for narration | Not used | The platform's incremental log polling (`GET /scans/{id}/logs?after=<seq>`) already does this with no new dependency |

## Corrections to the earlier design doc

- **Bedrock model id.** `DAST_tech_stack.md` names `anthropic.claude-3-5-haiku-20241022-v1:0`. The repo's `config.py` already uses `us.anthropic.claude-haiku-4-5-20251001-v1:0`; keep that one.
- **Bedrock adapter.** The earlier sketch calls `ChatAnthropic` for Bedrock, which would call Anthropic's own API, not Bedrock. The Bedrock adapter should use `boto3` (Converse API).
- **PostgreSQL driver.** The earlier doc says "switchable to PostgreSQL" but lists no driver. `psycopg` is added above.

## Compatibility Matrix

| Layer | Component | Version | Verified how |
|---|---|---|---|
| Runtime | Python | 3.12.12 | Venv interpreter |
| Runtime | Node.js | 22.22.1 | `node --version`; satisfies Next.js 16 and the `@types/node` 20 typings |
| API | fastapi / uvicorn / pydantic | 0.141.1 / 0.53.0 / 2.13.5 | Installed together in the working venv |
| Data | SQLAlchemy + psycopg | 2.0.54 + 3.3.6 | psycopg dry-run resolved with no conflicts; SQLAlchemy 2 supports psycopg 3 |
| Orchestration | langgraph + langchain-core | 1.2.12 + 1.6.6 | Installed together; core bump from 1.6.4 to 1.6.6 forced by `langchain-anthropic` and accepted by the resolver |
| Providers | langchain-ollama / -anthropic / -openai | 1.1.0 / 1.7.5 / 1.6.7 | One combined dry-run resolved all three against the venv |
| Providers | boto3 | 1.43.100 | Installed |
| Discovery | playwright + Chromium | 1.63.0 | `import playwright` works; browser build must be installed per machine |
| Frontend | Next.js + React | 16.2.10 + 19.2.4 | Installed; pinned exactly in `package.json` already |
| Frontend | Tailwind 4 + PostCSS plugin | 4.3.2 + 4.3.2 | Installed |
| Model host | Ollama | 0.34.2 | `ollama --version` on this machine |

## What has not been verified

- ~~That the full combined lock installs cleanly in a fresh venv and the existing test suite passes on it.~~ **Verified 2026-10-07 (DAST-00-010).** `backend/requirements.txt` (the pinned DAST set plus the unchanged SAST-only packages) installed into a fresh Python 3.12.12 venv with no resolver conflicts, resolving every pin in the lock. Pre-change baseline in the existing venv: 532 passed, 3 failed — all three `test_scan_export.py` tests, `ModuleNotFoundError: pypdf` (a test-only dependency that was never declared). After the change, in the fresh venv: 626 passed, 0 failed, with `pypdf==6.19.0` added to `requirements.txt`; with Playwright, `langchain-ollama`, `langchain-anthropic`, `langchain-openai`, `anthropic` and `openai` uninstalled the suite still passes and `import app.main` works (this needed the top-level Playwright/`langchain_ollama` imports in `app/dast/` made lazy). The Python 3.12 pins are exactly those in `dast-requirements.lock.txt`; the three pins that were NEW to the venv (`langchain-anthropic`, `langchain-openai`, `psycopg[binary]`) and `langchain-core` 1.6.6 all installed together. Not covered: running a real DAST scan on the new versions (needs Chromium and a model; see `dev/practice-targets/README.md`).
- That `gpt-oss:20b` is currently pulled in this Ollama install (`ollama list` was not run).
- Which Chromium build Playwright 1.63.0 requires.
- The newest-release status of any pinned package beyond what the resolver reported. The doc pins to what resolves and runs today, not to a freshly checked "latest".

## Dependency files

- [dast-requirements.lock.txt](dast-requirements.lock.txt): exact-version backend set for the DAST scan type, including the SAST-shared packages DAST relies on. Not applied to `backend/requirements.txt`.
- Frontend: no change to `frontend/package.json`.

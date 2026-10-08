# DAST Implementation (current state)

Snapshot of how DAST works in this repo today, including the uncommitted `analyze_apis` stage on `feature/sbom-scan-type`.

## 1. Summary

DAST is a third scan type (`scan_type = "dast"`, next to `sast`, `sca` and `sbom`). It does **not** use git or a repository. It targets a running web app by URL:

1. A Playwright-driven Chromium browser logs in (if credentials were given) and crawls the app.
2. A local Ollama LLM (`gpt-oss:20b` by default) makes the judgment calls a pentester would make.
3. Observed REST APIs are then actively tested with LLM-constructed payloads.
4. Results are stored as `Finding` rows (`kind=dast`) plus a discovery dict on `Scan.metadata_json`.
5. A chat-style "narration" timeline is generated from the engine log.

It is meant for local practice apps (DVWA, Juice Shop, etc.) that the operator owns or is authorized to test. The trigger endpoint requires an explicit `authorized` confirmation.

## 2. Layout

| Layer | Location | Role |
|---|---|---|
| Engine (LangGraph) | `backend/app/dast/` | Browser, crawl and API testing pipeline |
| Engine entry point | `backend/app/dast/runner.py` | Called by FastAPI; owns Playwright lifecycle and builds the discovery dict |
| Engine bridge | `backend/app/services/engine_adapter.py` (`run_dast_scan`) | Mock vs. real gate |
| Lifecycle | `backend/app/services/scan_runner.py` (`_execute_dast_scan`) | Status, log capture, persistence, cancel |
| Narration | `backend/app/services/dast_narration.py` | Log to chat-style step timeline (LLM or template) |
| HTTP | `backend/app/routers/scans.py` | Create scan, `/narration`, `/narration/stream` |
| UI | `frontend/app/dast/page.tsx`, `frontend/components/Dast*.tsx` | Dashboard, form, detail, analysis panel, timeline |
| Standalone tools | `backend/app/dast/app.py`, `server.py`, `static/` | CLI and Flask UI that run the same graph (not used by FastAPI) |

## 3. Engine pipeline

Five nodes, defined in `backend/app/dast/graph.py`. Each is wrapped by `_with_banner`, which prints `### DAST: <label>`. The log parsers, progress tracking and narration all key off those banners.

```
check_connection -> classify_login_type -> login -> crawl -> analyze_apis -> END
                                                      ^         |
                                                      +- login -+  (one bounded session-recovery hop)
```

With `--storage-state` (CLI only), the graph skips straight to `crawl`.

### Nodes

- **`check_connection`**: reachability check only. If it fails, the graph ends.
- **`classify_login_type`**:
  - Deterministically extracts forms, iframes and keywords, then asks the LLM to classify the login as `simple_form | multi_step | oauth_sso | captcha | otp_2fa | unknown`.
  - Only `simple_form` continues. The others end the graph with a `stop_reason`. They are detected but intentionally not automated.
- **`login`**:
  - The LLM proposes CSS selectors from the form HTML, with a hardcoded selector fallback.
  - It fills and submits, then verifies success through a 4-tier chain: indicator selector, indicator text, URL change, then password field detached.
  - There is one LLM-driven retry.
  - `click_with_retry` and `dismiss_overlays` handle cookie/consent overlays that intercept the click.
- **`crawl`**:
  - A plain `while` loop inside one node, alternating `plan_next_url` and `visit_url`.
  - `plan_next_url` checks hard budgets first: max pages, max depth, max runtime, and 5 consecutive low-value visits. Otherwise the LLM picks the next queued URL, biased toward admin/account/checkout paths. It falls back to FIFO on a bad answer.
  - `visit_url` navigates with retry and backoff, waits for `networkidle`, extracts same-domain links and forms, and enqueues them. Dedup is `normalize_url` plus `get_url_pattern` with `max_per_pattern`.
  - A Playwright `response` listener captures API calls (JSON responses, xhr/fetch, `/api/` and `/graphql` URLs).
  - If the session is lost, it routes back to `login` once (`MAX_RELOGIN_ATTEMPTS = 1`).
- **`analyze_apis`** (new, uncommitted): the active-testing stage. See section 4.

### Supporting modules

- `state.py`: `GraphState` TypedDict. It is a plain TypedDict because it carries Playwright handles. It also carries `findings_writer` and `should_abort` hooks injected by FastAPI, which are `None` in the CLI.
- `llm_utils.py`: all LLM calls go through `call_llm_json` (strict JSON, retries, streams `[thinking]` tokens to stdout) or `call_llm_tool_choice` (crawl planner). Both use the same "ethical hacker, authorized DAST" system prompt.
- `url_utils.py`: pure string normalization and pattern dedup. No embeddings.

## 4. API security analysis (`nodes/analyze_apis.py` + `api_analysis.py`)

Runs after the crawl.

1. **Select APIs.** Discovered `api_calls` are deduped to one per `(method, path)` and capped at `DEFAULT_MAX_APIS = 15`. State can override with `dast_max_apis`.
2. **Build target.** `build_api_target` gives method, URL, query params, content type and status. It adds any crawled form whose action matches the path as a hint for the request body shape.
3. **Construct tests** (LLM call 1, `construct_test_cases`):
   - The model picks which checks from `CHECK_CATALOG` apply to this specific endpoint.
   - For each test it chooses the target parameter, `location` (`query|path|header|body`), payload and expected signal.
   - Maximum `DEFAULT_MAX_TESTS_PER_API = 12`.
   - Payload strings are entirely the model's output. None are hard-coded. Unknown `check_id`s are dropped.
4. **Execute** (`execute_test`): sent through `page.request`, so requests carry the crawl's authenticated session cookies. `fail_on_status_code=False`, 10s timeout, response body truncated to 1500 characters. It never raises. Transport errors are recorded as evidence.
5. **Rule** (LLM call 2, `rule_on_results`): the model returns PASS/FAIL/INCONCLUSIVE per test with a finding sentence, severity, confidence and evidence.
6. **Roll up.** `overall_verdict` is computed deterministically and ignores the model's own overall:
   - any FAIL gives FAIL
   - all INCONCLUSIVE gives INCONCLUSIVE
   - otherwise PASS
7. **Persist.** Per-API results are appended to `state["api_analysis"]`. FAIL and INCONCLUSIVE checks are converted to finding dicts (`finding_rows_from_analysis`) and written immediately via `findings_writer`, so results appear mid-scan.

### Check catalog (10 categories)

| id | CWE | OWASP |
|---|---|---|
| `dast-sqli` | CWE-89 | A03 Injection |
| `dast-xss` | CWE-79 | A03 Injection |
| `dast-cmdi` | CWE-78 | A03 Injection |
| `dast-misconfig` | CWE-16 | A05 Misconfiguration |
| `dast-authn` | CWE-287 | A07 Auth Failures |
| `dast-session` | CWE-384 | A07 Auth Failures |
| `dast-authz` | CWE-639 | A01 Broken Access Control |
| `dast-input-validation` | CWE-20 | A03 Injection |
| `dast-info-disclosure` | CWE-209 | A05 Misconfiguration |
| `dast-robustness` | CWE-248 | A05 Misconfiguration |

### Verdict mapping to `Finding`

| Check verdict | Finding verdict | Written as row? |
|---|---|---|
| FAIL | `true_positive` | yes |
| INCONCLUSIVE | `unverified` (`UNVERIFIED_VERDICT`) | yes |
| PASS | none | no (kept only in the `api_analysis` tree) |

Finding shape:

| Field | Value |
|---|---|
| `kind` | `dast` |
| `rule_id` | the check id |
| `file_path` | `"<METHOD> <path>"` |
| `snippet` | check, target, payload, HTTP status, evidence |
| `source` | tested parameter |
| `sink` | API URL |
| `verdict_reason` | model's finding sentence |
| `confidence` | HIGH 0.9, MEDIUM 0.6, LOW 0.3 |

Every LLM or transport failure degrades to a skipped or inconclusive check. A single API failure never aborts the run (it is recorded as an `api_analysis_failed` warning).

## 5. Backend integration

### Creating a scan (`routers/scans.py`)

- `POST /scans` with `scan_type: "dast"` requires `dast.target_url` and `dast.authorized`.
- If `login_url` is given, `username` and `password` are required.
- The target URL is stored in `Scan.git_url`. There is no commit and no reuse (the `reused` / `resolve_remote_head` logic is skipped for DAST). `use_llm` is forced off, because the DAST LLM is separate (Ollama).
- `metadata_json["dast_input"]` holds target, login URL, username, `max_depth`, `max_pages`, `headless` and `has_password`.
- **The password is never persisted.** It is held in an in-memory dict (`scan_runner.set_dast_password` / `_pop_dast_password`) and popped at run start. It is also registered with `scan_log.register_secrets` so it is redacted from logs. If the server restarts between trigger and start, the scan fails with "credentials were lost".

### Engine gate (`engine_adapter.run_dast_scan`)

- **Mock engine** (default in tests): returns deterministic fake discovery. This includes a mock `api_analysis` tree and mock findings written through the same writer. It prints the same `### DAST:` banners, so the narration and progress code are exercised.
- **Real engine** needs `USE_MOCK_ENGINE=false` and `RUN_DAST` (`settings.run_dast`, default true). Otherwise the scan fails with an explicit message.
- Model: `settings.dast_ollama_model` (`gpt-oss:20b`). The Ollama base URL defaults to `http://localhost:11434` and is hardcoded.
- `runner.run_dast_scan` imports Playwright and `langchain_ollama` lazily, so the mock test suite needs neither installed. It runs the graph, always closes the browser in `finally`, prints `### DAST: summarizing`, and returns `{"discovery": ...}`.
- Fixed crawl budgets: `MAX_RUNTIME_MINUTES = 10`, `MAX_PER_PATTERN = 3`, same-domain mode `exact`.

### Lifecycle (`scan_runner._execute_dast_scan`)

1. Status moves `queued -> running`, then log capture starts and a line hook updates `Scan.progress` from the banners.
2. It calls `engine_adapter.run_dast_scan` with three hooks:
   - `discovery_writer`
   - `findings_writer` (the same one SAST uses)
   - `should_abort` (reads a fresh DB session for cancel)
3. The discovery dict is saved to `metadata_json["discovery"]`.
4. Final status:
   - **failed** if the target was unreachable.
   - **failed** if no pages were crawled and there was a `stop_reason` or `login_error`. The message is "Crawl did not start: ...".
   - **cancelled** if the user aborted.
   - **success** otherwise.

### Discovery dict (`runner.build_discovery`)

```
target_url, connection_ok/error, login_type, login_success/error,
stop_reason, crawl_stop_reason,
pages[]        {url, depth, title, forms[], links_count, new_link_count}
api_calls[]
forms_count, skipped_duplicate_patterns, failed_urls, warnings,
api_analysis[] {method, url, path, label, checks[], overall_verdict, summary, counts}
analysis_summary {apis_tested, fail, pass, inconclusive, apis_failing}
```

### Narration (`services/dast_narration.py`)

- **Step splitting.** The engine log is split on `### DAST:` banners into five UI steps: Checking connection, Authenticating, Discovering application, Testing REST APIs, Analyzing attack surface.
- **Per-step output.** Each finished step gets a first-person narration and 2-4 reasoning bullets from the LLM. It is told to state only facts present in the evidence.
- **Caching.** Results are cached in memory, keyed by scan, step and an evidence fingerprint. They are persisted to `metadata_json["dast_narration"]` once the scan finishes.
- **Non-blocking.** `get_narration` returns what is cached and starts background threads for finished-but-unnarrated steps. `pending=True` tells the UI to keep polling.
- **Fallback.** If the LLM is unavailable (mock engine, Ollama down, bad JSON), it uses a deterministic template (`source="template"`). The page never depends on the model.
- **Parsing.** `parse_narration_response` strips raw model JSON, `[thinking]` text and log noise. The two most recent commits fixed these leaking into the prose.
- **Endpoints:**
  - `GET /scans/{id}/narration` returns the timeline payload.
  - `GET /scans/{id}/narration/stream?step=...` is an SSE stream of thinking, response and error events for one step.

## 6. Frontend

All requests go through the Next.js server-side proxy routes under `frontend/app/api/**`, which attach the bearer token.

- **`app/dast/page.tsx`**: dashboard listing DAST scans (`api.scans.list(undefined, "dast")`), with a project filter and delete.
- **`DastScanForm.tsx`**: new scan form (target URL, optional login URL, username and password, depth, pages, headless, authorization checkbox). It can create a project inline.
- **`DastScanDetail.tsx`**: the detail page. It polls every 2s until the scan is terminal. It shows click-to-open cards (Discovery, Analysis, Summary, same pattern as SAST Discovery). It contains `DastDiscoveryPanel` (pages, forms and API calls with method styling) and `DastSummaryPanel`.
- **`DastAnalysisPanel.tsx`** (new, uncommitted): drill-down API, then Check, then Payload, then Response, then Finding, then Verdict, driven by `discovery.api_analysis`.
- **`DastNarrationTimeline.tsx`**: the chat-style step timeline. It consumes `api.scans.narration` and `narrationStream`.
- **`AgentArtifactCard.tsx`**: shared card component, modified for DAST.
- **`lib/types.ts`**: `DastInput`, `DastPage`, `DastApiCall`, `DastApiCheck`, `DastApiAnalysis`, `DastAnalysisSummary`, `DastDiscovery`, `DastStepStatus`, `DastNarration`.
- Findings appear in the existing `ScanFindingsPanel` and in the PDF/XLSX exports, because DAST writes ordinary `Finding` rows.

## 7. Tests

`backend/tests/test_dast_scan.py`, `test_dast_narration.py` and `test_dast_api_analysis.py` all run on the mock engine. No browser, Ollama or network is needed. There is no frontend test runner.

## 8. Known limitations

- Active testing covers **observed REST APIs only**. Forms and DOM sinks are discovered but not fuzzed.
- The request body shape is inferred only from matching form inputs. The crawl listener sees responses, not request bodies.
- `path` location payloads are appended as an extra segment, with no real path-template fuzzing. `body` payloads are sent as a simple `{param: payload}` dict.
- Login automation covers `simple_form` only. Multi-step, OAuth/SSO, CAPTCHA and OTP/2FA are detected and reported, and the scan stops.
- A model-produced PASS cannot be independently validated. A weak model can produce false positives or negatives, so INCONCLUSIVE is surfaced as `unverified` rather than hidden.
- Ollama URL and crawl budgets (runtime, per-pattern, same-domain mode) are hardcoded. `dast_max_apis` and `dast_max_tests_per_api` are state-level only and not exposed in the API or UI.
- `DastAnalysisPanel`, `api_analysis.py` and `analyze_apis.py` are uncommitted. The root `CLAUDE.md` still calls `app/dast` a UI-only mockup, which is outdated; `backend/app/dast/CLAUDE.md` is current.
- A scan can fail partway if the server restarts, because the password is in memory only.

## 9. Tech stack

### Backend (`backend/`)

| Area | Technology |
|---|---|
| Language | Python 3.12 |
| API framework | FastAPI (>=0.115) served by Uvicorn (`uvicorn[standard]`) |
| Validation / settings | Pydantic v2, `pydantic-settings` (env-driven `app/config.py`) |
| Database | SQLAlchemy 2.x. Default is SQLite (`data/secure_build.db`), switchable via `DATABASE_URL`. No Alembic: schema changes are hand-written idempotent `ALTER TABLE` migrations in `db.py` |
| Auth | Static bearer token (`SAST_API_TOKEN`), checked by `verify_bearer` on every endpoint except `/health` |
| Background work | Daemon threads (real engine) or inline execution (mock engine). No Celery or queue |
| Live logs / narration | In-memory log buffer (`scan_log`) polled via `/scans/{id}/logs`. Server-Sent Events for narration streaming |
| HTTP client | `httpx`, `requests` |
| Exports | `reportlab` (PDF), `openpyxl` (XLSX) |
| Tests | `pytest`, `pytest-asyncio`. Mock engine by default, so no network, git or AWS |

### DAST engine (`backend/app/dast/`)

| Area | Technology |
|---|---|
| Orchestration | LangGraph (`StateGraph`, conditional edges) with `langchain-core` |
| Browser automation | Playwright (Chromium). `page.request` is reused for authenticated API tests |
| LLM | Local Ollama via `langchain-ollama` (`ChatOllama`), model `gpt-oss:20b`, `temperature=0.1`, `reasoning=True` |
| URL handling | `tldextract` for same-domain / root-domain logic, plus custom `url_utils.py` |
| Standalone UI | Flask + a single vanilla-JS HTML page (CLI/dev use only, not part of the FastAPI app) |
| Loading | Playwright and `langchain-ollama` are imported lazily, so the mock test suite doesn't need them |

### Other engines in the same backend (for context)

- **SAST** (`backend/sast_engine/`): LangGraph, AWS Bedrock via `boto3` (Ollama fallback), tree-sitter parsers (Java, Python, TypeScript), Semgrep, NetworkX, PyYAML, BeautifulSoup.
- **DAST vs. SAST LLMs:** DAST uses only local Ollama. SAST uses Bedrock (Claude Haiku by default) with a $2 cutoff.

### Frontend (`frontend/`)

| Area | Technology |
|---|---|
| Framework | Next.js 16.2.10, App Router, run with `--webpack` (`next dev --webpack`, `next build --webpack`) |
| UI library | React 19.2.4 |
| Language | TypeScript 5 |
| Styling | Tailwind CSS 4 (`@tailwindcss/postcss`) |
| Lint | ESLint 9 with `eslint-config-next` |
| Tests | None configured (only `lint` and the Next build) |
| Data access | Client components call `lib/api.ts`, which hits server-only Next route handlers in `app/api/**/route.ts`. Those use `lib/server-sast.ts` (`sastFetch`) to attach the bearer token and proxy to FastAPI. The browser never sees the token or talks to FastAPI directly |
| Live updates | Polling every 2s (scan detail and logs), plus `fetch` stream reading for narration SSE |
| Note | This Next version has breaking changes versus common training data. Check `node_modules/next/dist/docs/` before writing Next-specific code (per `frontend/AGENTS.md`) |

### Runtime topology

```
Browser --> Next.js (React 19, App Router)
              |  app/api/** route handlers (adds Bearer token)
              v
         FastAPI (Uvicorn) --> SQLAlchemy --> SQLite
              |
              +-- thread: LangGraph DAST pipeline --> Playwright/Chromium --> target app
              |                                   \-> Ollama (localhost:11434, gpt-oss:20b)
              +-- thread: narration LLM calls    --> Ollama
```

### Local prerequisites for a real DAST run

- Python 3.12 with `pip install -r backend/requirements.txt`
- `python -m playwright install chromium`
- Ollama running locally, with `ollama pull gpt-oss:20b`
- Env: `USE_MOCK_ENGINE=false` (and `RUN_DAST=1`, the default)
- Node.js for the frontend (`npm install`, then `npm run dev`)

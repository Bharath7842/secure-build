# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A DAST (Dynamic Application Security Testing) tool built as a LangGraph pipeline. It drives a real
Chromium browser (Playwright) against a target web app, uses a local Ollama LLM (`gpt-oss:20b` by
default) to make judgment calls a human pentester would make (classify the login flow, guess form
selectors, prioritize crawl targets), and reports discovered pages/forms/API endpoints. It targets
local practice apps (DVWA, Juice Shop, etc.) the operator owns or is authorized to test.

There is also a minimal Flask + vanilla JS web UI (`server.py` + `static/index.html`) that runs the
same pipeline from a browser form instead of the CLI, streaming console output live.

## Setup and running

```bash
pip install -r requirements.txt
python3 -m playwright install chromium   # one-time, downloads the browser binary
ollama pull gpt-oss:20b                  # or whatever model you pass to --ollama-model
```

Ollama must be running and reachable. The address comes from `settings.dast_ollama_url`
(`DAST_OLLAMA_BASE_URL`, falling back to `OLLAMA_BASE_URL`, default `http://localhost:11434`); the CLI
overrides it with `--ollama-base-url`. Crawl budgets, rate limit, safe mode, the OAST address and
per-task model routing are all `DAST_*` settings in `app/config.py` (see `.env.example`) and the
CLI/Flask defaults read them.

CLI:
```bash
python3 app.py --url http://localhost:3000 --login-url http://localhost:3000/login \
    --username admin@example.com --password 'secret' --headless
```

Skip login entirely with a pre-authenticated session:
```bash
python3 app.py --url http://localhost:3000 --storage-state ./session.json --headless
```
(`--login-url`/`--username`/`--password` become optional only when `--storage-state` is given;
`parse_args()` enforces this manually since argparse can't express the conditional requirement.)

Useful crawl-tuning flags: `--max-depth`, `--max-pages`, `--max-runtime-minutes`,
`--max-per-pattern`, `--same-domain-mode {exact,root-domain}`, `--noise-params`,
`--verbose`/`--no-verbose` (verbose HTML/action tracing is on by default).

Web UI:
```bash
python3 server.py   # serves http://127.0.0.1:5001
```

The standalone tool itself has no build step. The backend test suite (`backend/tests/`, `pytest -m "not live"`)
covers it offline against the mock engine and fakes (`backend/tests/README.md`); live validation means
running a scan against a practice target (`dev/practice-targets/README.md`).

## Layout and layering rules

```
app/dast/
  domain/        pure vocabulary and rules: entities, interfaces (Protocols), verdict, guardrail,
                 dedupe, diff, detectors, validation. Stdlib only. Contracts/types today; logic lands
                 story by story (see spec/dev-stories).
  nodes/         the LangGraph stages (engine layer)
  contract.py    maps engine finding/identity dicts onto the domain entities and validates results
  mock_engine.py the deterministic mock result (what USE_MOCK_ENGINE returns), no browser/model/network
  api_analysis.py, runner.py, graph.py, state.py, llm_utils.py, url_utils.py, app.py, server.py  (existing)
```

Two import rules are enforced by `backend/tests/test_dast_layering.py` (an AST walk; it fails the build):

1. `domain/` imports only the standard library and itself. No FastAPI, SQLAlchemy, Playwright, httpx,
   LangChain/LLM SDKs, and nothing else from `app/` — not even under `TYPE_CHECKING`.
2. `nodes/` never imports `app.routers` or concrete infrastructure (`app.services`, `app.db`, Playwright,
   provider SDKs, httpx, SQLAlchemy, FastAPI). Imports under `if TYPE_CHECKING:` are allowed, which is how the
   nodes name Playwright types.

Heavy packages (Playwright, provider SDKs, `langchain_ollama`) stay lazy: imported inside the functions
that need them, or under `TYPE_CHECKING` for annotations. `GraphState` types `browser`/`page` as `Any`
because LangGraph resolves TypedDict hints at runtime. The whole mock suite runs without those packages
installed. Dependency direction (architecture.md): API -> application -> engine -> domain; infrastructure
implements domain interfaces.

## Architecture

The pipeline is a LangGraph state machine over a per-scan `ScanRuntime` (`runtime.py`):

```
check_connection -> fingerprint -> authenticate -> discover -> passive_analysis
                                  ^                 |              |
                                  +-- one re-login -+              +-- passive-only/cancelled -> END
                                                                   +-- agent mode -> plan_tests --+
                                                                   +-- otherwise ----------------+-> analyze_apis
                                                                                                     -> browser_probe
                                                                                                     -> check_authorization -> END
```

Every collaborator arrives through the runtime, built by `app/services/dast_runtime.py` (the composition
root): the **model gateway**, the **guarded executor** (the only HTTP client), a **browser factory** that
launches Chromium only when a stage asks (an API-only target launches none), and the in-memory
**credential holder**. Nodes never construct infrastructure; `tests/test_dast_layering.py` enforces it,
including "only `app/services/model_gateway/` imports a model SDK".

- **`nodes/check_connection.py`** — preflight: one guarded GET, with a distinct reason per failure
  (dns/refused/timeout/tls/off-scope redirect/5xx). A failure ends the scan; nothing else is sent.
- **`nodes/fingerprint.py`** + **`domain/fingerprint.py`** — shape (mpa/spa/api), auth (from the supplied
  identities) and schema (probed well-known paths). The `fingerprint` model task may refine only the shape.
- **`nodes/authenticate.py`** — one isolated session per identity (`sessions.py`): token header, saved
  session cookies, or form login in its own guarded browser context (login retried once; multi-step/SSO/
  CAPTCHA/OTP are "not automated, use a pre-authenticated session"). Any failure ends the scan naming the
  identity; lost credentials end it as "credentials lost". Form login runs inside the guard's *login
  window* (`SafetyGuard.login_window`), one of the two documented POST allowances in safe mode. The other is
  the marker window, used only by the browser probe.
- **`nodes/discover.py`** — crawl per identity (page/time budget split between them), fold pages, forms,
  XHR and recorded request bodies into `domain/inventory.py`, ingest OpenAPI/Swagger and GraphQL
  introspection (`nodes/ingest_schemas.py`, bounded `$ref` expansion, YAML alias cap), and diff observed vs
  documented (undocumented endpoints become `unverified` API9 findings via `inventory_findings.py`).
- **`nodes/crawl.py`** — the LLM-directed crawl loop, now asking the `crawl_plan` task and honouring a
  `session_lost_check` (a run of 401/403s) for identities with no login page to bounce back to.
- **`nodes/passive_analysis.py`** + **`passive.py`** + **`domain/passive.py`** — zero-request checks over the
  recorded exchanges (headers/CSP/HSTS, cookies, CORS with a two-origin rule, disclosure, errors and
  sensitive data). Patterns are data (`data/passive_patterns.json`); every stored text is redacted with the
  scan's secrets. `route_after_passive` skips the active stage when nothing is eligible.
- **`nodes/analyze_apis.py`** + **`active.py`** + **`domain/active.py`** — the model-driven loop per endpoint:
  construct (model proposes) -> validate (`ValidatedTest`; the only thing the executor will send) -> baseline
  -> test -> detect -> rule -> roll-up. A `true_positive` always needs a detector signal. `analyze_apis.py`
  also owns the `InputGate` (foreign-host and method-override refusals), the SSRF/OAST sub-stage
  (`ssrf.py`, `domain/oast.py`, `services/oast.py`), assist-only review items (`assist.py`) and the live
  counters. The loop excludes authorization, OAST, passive, opt-in, assist-only and browser-only checks
  (`dast-xss-dom`, `dast-xss-stored`): those signals are in the detector registry so a check may name them,
  and excluded from the HTTP loop because a response pair cannot raise them.
- **`nodes/plan_tests.py`** + **`domain/agent.py`** — optional `plan` task between passive and active
  analysis. Agent mode defaults off (`agent_mode`, `max_agent_turns=60`,
  `max_turns_per_hypothesis=4`, per scan and global settings). Only known endpoint keys and enabled
  loop check ids survive parsing; unknown, malformed and duplicate hypotheses are counted and dropped.
  Empty/failed plans use the ordinary loop. `run_target_agentic` keeps the first pass's ordinary check
  coverage and adds one guarded probe per follow-up turn. A thread-safe budget bounds planned turns;
  targets without a usable hypothesis/budget still receive their ordinary pass. Small or unsized Ollama
  construct models use at most 20 turns / 2 per hypothesis. History retains only status, byte delta,
  duration and signal names, never bodies or tokens. Proof, an empty model answer, cancellation and caps
  stop iteration. Planning has its own model route and usage bucket (`plan`); follow-ups use `construct`.
- **`jwt_probe.py`** + **`domain/jwt_check.py`** — deterministic JWT sub-stage after HTTP/OAST tests,
  with no model call. For each authenticated identity, chooses one observed successful GET and isolates
  its JWT header or cookie from all other credentials. Requires a successful real-token baseline and
  an anonymous 401/403 control. Sends at most one modified token per enabled weakness: `alg=none`,
  missing `exp`/`iss`/`aud`, and (explicit opt-in only) a signature matching one of five fixed public
  tutorial HMAC secrets. Only a matching accepted response raises a proving signal through the guardrail.
  Generated tokens are registered for redaction before sending; findings contain only response metadata.
  Without a known signing key, signature rejection may mask missing claim validation: the coverage
  matrix records this limitation. TLS remains the separate `tls_probe.py` sub-stage.
- **`nodes/browser_probe.py`** + **`browser_probe.py`** + **`domain/browser_probe.py`** — after the HTTP tests,
  types an inert marker into crawled query parameters and visible inputs (including a search box with no
  form) and reloads each reflected-XSS failure with the same marker. A finding is a true positive only when
  the page sets `window.__dast_<id>`. A sink hit or stored markup that does not run stays unverified. Stored
  XSS is a POST inside `SafetyGuard.marker_window`, and only when the scan opted in, the target is disposable,
  and the body is that marker (plus short markup-free companion fields). Progress banner
  `### DAST: probing browser inputs` (82).
- **`nodes/check_authorization.py`** + **`authorization.py`** + **`domain/authz.py`** — replays one identity's
  successful requests as lower-privileged and anonymous identities and classifies the boundary; the role-pair
  matrix is derived from the findings (`services/dast_authz.py`). Needs two identities; says so when it ran
  degraded.
  With a usable agent plan, A01 endpoints replay first across owners and observed-id substitution
  can try at most two adjacent numeric ids. No ids are generated without an observed numeric value.
  Unobserved neighbors remain unverified leads because schema authentication does not prove ownership.
  Without a plan the replay order and observed-only substitution stay unchanged.
- **Reporting**: `services/dast_report.py` (report data), `dast_diff.py` + `domain/diff.py` (new / unchanged /
  fixed against the previous scan, keyed by `item_key`), `dast_export.py` (PDF/XLSX, formula-guarded),
  `dast_summary.py` (live counters). Endpoints: `/scans/{id}/summary|report|diff|authz-matrix`.
- **Model providers** (`services/model_gateway/`): `ollama` (default), `bedrock`, `openai`, `anthropic` and `claude_cli`, routed per task. `claude_cli` (`ClaudeCliAdapter`) runs the local `claude -p` with the same login SAST's `claude_cli` uses (`CLAUDE_CLI_PATH`, `CLAUDE_CLI_REQUEST_TIMEOUT`), but **ephemeral per call**, not one session per scan: DAST tasks are independent and a session would carry one page's text into another task's prompt. No tools/settings/MCP, empty cwd (`<claude_cli_dir>/dast`); cost is notional (Sonnet/Haiku rates in `domain/usage.py`). Empty model = `DAST_CLAUDE_CLI_MODEL` (`claude-sonnet-5-5`).
- **Settings**: `services/dast_settings.py` + `routers/dast_settings.py`. Overrides live in `dast_global_config`
  (key `settings`) on top of env defaults and apply to *new* scans only. Provider keys are env-only (the API
  shows set/not-set). The OAST address is write-only.
- **Training capture** (`domain/training.py`, `services/dast_training.py`, `routers/dast_training.py`): off by
  default, per project, needs `DAST_TRAINING_ADMIN_TOKEN`; reads are audited.
- **Quality harness**: `backend/tools/dast_harness/` (ground truth, scoring, gate, determinism). The bundled
  ground-truth files are drafts (`verified: false`).
- **`llm_utils.py`** — only `ask_json` (one gateway call, `None` on fallback) and `print_snippet`. The shared
  ethical-testing persona is `app/data/dast/prompts/_preamble.md`.
- **Domain (pure)**: `detectors.py` (+`detector_patterns.py`), `verdict.py`, `guardrail.py` (a
  `true_positive` needs a proving signal; checked exhaustively), `dedupe.py`, `mapping.py`, `catalog.py`,
  `ruleset.py`, `identities.py`, `presets.py`, `session.py`, `openapi.py`, `graphql.py`/`introspection.py`,
  `traffic.py`, `usage.py`, `schema.py`, `model_errors.py`.
- **Checks are data**: `app/data/dast/check_catalog.yaml`, `rule_packs.yaml`, `remediation/*.md`, loaded by
  `services/dast_catalog.py`. Global/project/per-scan rule configuration resolves in `domain/ruleset.py`
  (`services/dast_rules.py`, `routers/dast_rules.py`); custom rules are versioned DB rows.
- **Scan setup**: `services/dast_scan_setup.py` validates the request and produces the stored,
  secret-free `dast_input`, the frozen `dast_effective` settings, the `dast_rule_set` snapshot and
  `dast_skipped_degraded`. Credentials go to `scan_runner`'s in-memory hand-over only.
- **`state.py`**, **`graph.py`**, **`runner.py`**, **`app.py`**, **`server.py`**, **`url_utils.py`** —
  as before; the CLI and Flask entry points build a standalone runtime.

## Safety guard (EPIC-01)

Every request to the target passes one guard. The preflight, schema probes, token/session probes and
the API tests send through the guarded executor; browser traffic goes through `browser_guard` contexts.

- **`domain/policy.py`** — pure scope + method decision (`evaluate_request`, `evaluate_redirect`). Deny
  reasons are `off_scope` / `method_not_permitted` / `cancelled`. URLs with userinfo, backslashes, control
  characters or a non-http(s) scheme are denied outright. `root-domain` mode widens only when the host
  has a public-suffix-aware registrable domain, so `.test`/`.corp`/IP/single-label targets stay exact.
- **`app/services/safety_guard.py`** — per-scan rate limiter (capacity-one bucket), concurrency cap and
  cancellation around the policy. `SafetyGuard.from_settings` reads the scan's snapshotted effective settings.
- **`app/services/guarded_executor.py`** — the only HTTP client engine code may use (`httpx` is forbidden
  in `nodes/` by `tests/test_dast_layering.py`). Follows redirects hop by hop through the guard, keeps no
  cookie jar, truncates bodies, audits every call.
- **`app/services/browser_guard.py`** — Playwright route interception for crawl contexts
  (`new_guarded_context`). Subject to the same method policy, so safe mode aborts browser POSTs too.
- **`app/services/request_audit.py`** + `GET /scans/{id}/requests` — batched `dast_request_audit` rows with
  redacted headers/URLs (`domain/redaction.py`); bodies are never stored.
- **`domain/validation.py`** + **`input_gate.py`** + `data/input_rules.json` — non-destructive input check
  for model-generated tests (deny-list over decoded views + method/shape gates). Residual risk is documented
  in the module docstring: it reduces, not eliminates, destructive output.

## Known constraints worth knowing before changing things

- No standalone report *file* is generated here — the FastAPI backend persists the discovery dict
  (pages/api_calls/`api_analysis`/summary) onto `Scan.metadata_json` and the findings as `Finding`
  rows, which the existing PDF/Excel export endpoints and findings panel consume.
- Active vulnerability testing is per endpoint in the inventory (`analyze_apis`), capped by `max_targets` and
  `max_tests_per_target`. The browser probe then types inert markers into crawled inputs and DOM sinks
  (`dast_browser_probe_enabled`, on by default). Stored-XSS marker POSTs stay off unless
  `dast_browser_marker_posts` is on and the target is disposable.
- Safety review (`spec/dev-stories/security-review-DAST-16-060.md`) lists the accepted risks (DNS rebinding,
  the login-window POST, the deny-list validator). Add a case to `tests/test_dast_security_review.py` whenever
  a bypass is found.
- Multi-step login (`multi_step`) is detected and reported but not implemented — the graph stops
  rather than attempting it.
- Every `print()` "Executing: ..." / `[thinking]` / HTML-snippet line is intentional operator-facing
  tracing (`llm_utils.print_snippet`, gated by `state["verbose"]`), not debug scaffolding to clean up.

## Model task registry and agent limits

The seven routed tasks are `fingerprint`, `crawl_plan`, `login_selectors`, `plan`, `construct`,
`rule` and `narrate`. Every task needs its prompt under `app/data/dast/prompts/`; the gateway loads
all seven on startup. `DAST_MODEL_PLAN_PROVIDER` / `DAST_MODEL_PLAN_MODEL` configure the planner.
`DAST_AGENT_MODE_DEFAULT`, `DAST_MAX_AGENT_TURNS` and `DAST_MAX_TURNS_PER_HYPOTHESIS` supply global
baselines; the settings API and scan request can override them for new scans.

The ordinary target/test caps and request guard still apply. Planned turns are model-call budgets,
not HTTP-request budgets: baseline and boolean/timing controls still use the existing guarded steps.
A first planned turn keeps the ordinary per-target test cap; subsequent turns select one probe.
Multi-step finding chains, independent self-verification and SAST endpoint linking are deferred.

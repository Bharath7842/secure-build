# Project Concept — DAST Scan Type for Augmented Secure Build

Distilled from the documents in `spec/`. For detail, follow the pointers in [Source documents](#12-source-documents).

---

## 1. One-paragraph summary

Augmented Secure Build is a platform for triggering and reviewing security scans (SAST today; SCA/SBOM alongside). This project adds **DAST — Dynamic Application Security Testing**: an engine that crawls and actively tests a *running* web target (server-rendered site, SPA, or API-only backend), authenticated or not, and reports **evidence-backed** findings in the same `Finding` row shape the other scan types use. A local LLM (`gpt-oss:20b` via Ollama by default) plans and narrates the scan, but **deterministic detectors decide every verdict** — the model advises, code rules. That is what makes a small local model sufficient.

## 2. Problem and goals

SAST finds issues in source; it cannot see runtime behaviour — broken authorization, misconfigured headers/cookies/CORS, injection that only manifests against a live stack, or API surface that the UI exposes only through XHR/fetch. Legacy DAST tools also struggle with SPAs (no static links to follow) and produce noisy, unevidenced findings.

**Goals**

- One engine, three target shapes (multi-page app, SPA, API-only); the engine fingerprints the target and adapts rather than being configured per target.
- Findings backed by observed evidence, not model opinion.
- A declarative, data-driven check catalog mapped to OWASP WSTG / Web Top 10 / API Top 10 and CWE — new coverage means a new entry, not new code.
- A client-readable report (PDF/XLSX) with evidence, severity, remediation, and scan-to-scan diff.
- Safe by construction: scope lock, mutation opt-in, rate control, responsive abort.

**Non-goals**

- Replacing a human pentester on business-logic flaws (flagged as assist-only).
- Defeating CAPTCHA, OTP/MFA, or full OAuth/SSO flows — handled by accepting pre-authenticated state instead.
- gRPC / custom protocols (REST and GraphQL are first-class; SOAP/others best-effort via schema).

## 3. Core principles

1. **Authorization is a precondition.** Every scan carries an explicit operator authorization; active testing is confined to the authorized host(s), enforced in the orchestration tier.
2. **Verdicts are deterministic; the model advises.** Every active FAIL needs a detector signal. A model FAIL with no supporting signal is downgraded to INCONCLUSIVE (`unverified`). Training can't manufacture evidence.
3. **Passive before active.** A passive analyzer finds issues from already-observed traffic with zero added requests and no model calls.
4. **Browser-first discovery plus schema ingestion.** A real headless Chromium drives the crawl and records network traffic; OpenAPI/GraphQL schemas, when present, give exact endpoints and body shapes.
5. **Checks are data, not code — and the rule set is configurable.** Nuclei-style catalog entries declare identity, applicability, injection location, proving signal and severity — but no hard-coded payload strings. Which standards and checks run (OWASP API Top 10, OWASP Web Top 10, WSTG, custom rules) is a configuration choice, not a fixed property of the engine (see [Configurable rule sets](#configurable-rule-sets)).
6. **Safety is a tier, not a checkbox.** Every request passes the scope guard, method gate and rate controller.
7. **LLM-agnostic.** All model calls go through one gateway; correctness never depends on which provider is behind it.

## 4. System architecture

Five tiers plus two cross-cutting concerns:

| Tier | Responsibility | Components |
|---|---|---|
| 1. Interfaces | How operators/CI drive it | REST API, Web UI, CLI/CI |
| 2. Orchestration & Safety | Lifecycle and guardrails | Scan lifecycle, scope/method guard, rate & budget controller |
| 3. Discovery | Build the target inventory | Browser crawler, network recorder, schema ingester, auth manager |
| 4. Analysis | Find and judge issues | Passive analyzer, active check engine, detector library, verdict roll-up |
| 5. Knowledge & Data | Persist and report | Check catalog, findings store, evidence store, reports/export |
| Cross-cutting | — | **Model Gateway** (the only component that calls an LLM); **Observability** (log, progress, narration) |

### Scan pipeline

A LangGraph-style state graph; each stage emits a `### DAST: <label>` banner that drives progress and narration.

```
Preflight + reach → Fingerprint shape → Authenticate / load state → Discover (crawl + schema)
  → Passive analysis → Active test (per target) → Verdict roll-up → Dedupe + persist → Report + diff
```

Fingerprinting outputs `{shape: mpa|spa|api, auth: none|form|token|preauth, schema: none|openapi|graphql}`, which decides which later stages run (e.g. an API-only target skips the browser crawl).

### Active check loop

`Select + construct (LLM) → Baseline request → Execute test → Detectors (deterministic) → Rule (LLM) → Roll-up + guardrail (code)`

- The model chooses applicable catalog checks and builds inputs; unknown check ids are dropped.
- Detectors are pure functions comparing baseline vs. test (DB error surfaced, input reflected unescaped, command-output marker, stack trace leaked, time delta, status/length divergence, auth boundary crossed). They observe; they do not opine.
- Roll-up: any FAIL → target FAIL; all INCONCLUSIVE → INCONCLUSIVE; else PASS. The guardrail has the final say.

## 5. Key capabilities

### Authentication (four modes)

| Mode | Notes |
|---|---|
| None | Public app or pre-scoped API |
| Form login | Model proposes selectors with a hard-coded fallback; multi-signal success check; one bounded retry |
| Token | Bearer/JWT/API key supplied or extracted at login and injected into every request |
| Pre-authenticated state | Uploaded browser `storage-state` — the escape hatch for SSO/MFA/CAPTCHA |

Credentials are held **in memory only**, registered with the log redactor, and dropped at scan end. A process restart mid-scan fails the scan ("credentials lost") rather than silently continuing unauthenticated.

### Multi-role authorization testing (the signature feature)

Identities are added **by role** (Admin / User / Viewer / Anonymous / Custom). Every role pair is cross-tested automatically, which makes OWASP API1 (BOLA) and API5 (BFLA) testable. An Anonymous no-session baseline is always implied. Results surface as a role × role **authorization matrix**.

### Configurable rule sets

The OWASP API Security Top 10 and the other web-security rules below are the **default rule packs**, not hard-wired behaviour. Operators choose what a scan tests.

- **Rule packs.** A pack is a named set of catalog checks. Shipped packs: `owasp-api-top10-2023`, `owasp-web-top10`, `wstg-full`, and a `passive-only` pack. Every catalog entry already carries `owasp`, `apisec`, `wstg` and `cwe` tags, so a pack is just a selection over those tags and new standards can be added without engine changes.
- **Selection levels.** Packs are enabled globally in Settings, defaulted per project, and overridden per scan on the New Scan form. A finding reports against whichever standard(s) its check is tagged with.
- **Per-check controls.** Within a pack, individual checks can be enabled/disabled, have their severity overridden, and have their mode set (automated / opt-in / assist-only). Load-generating checks such as API4 stay off until explicitly enabled.
- **Custom rules.** Operators can add their own catalog entries (YAML: id, CWE/standard tags, `applies_to`, proving `signal[]`, base severity, remediation ref) without code changes. Payload strings are still produced by the model under the entry's template; nothing is hard-coded.
- **Guardrails still apply.** A custom or reconfigured check must name detector signals from the detector library; a rule that can't produce deterministic evidence can only surface as `unverified` or assist-only. Scope lock, method gating and rate limits apply to every rule regardless of pack, and credentials/authorization requirements are unchanged.
- **Reproducibility.** The effective rule set (pack ids, per-check overrides, custom rule versions) is snapshotted onto the scan at start, so history and scan-to-scan diffs stay meaningful if configuration changes later.
- **Dependencies.** A check that needs something absent from the scan (e.g. BOLA/BFLA without a second identity, SSRF without an OAST collaborator) is reported as skipped or degraded, never silently dropped.

### Default rule pack: OWASP API Security Top 10 (2023)

| Risk | Approach | Mode |
|---|---|---|
| API1 BOLA | Replay with another object id / another user's session | Automated |
| API2 Broken Authentication | No-session replay, token/session weakness checks | Automated (partial) |
| API3 BOPLA | Mass-assignment and excessive data exposure | Automated where schema known |
| API4 Resource Consumption | Missing rate/size limits | Opt-in, off by default (generates load) |
| API5 BFLA | Privileged function as lower-privilege identity | Automated |
| API6 Sensitive Business Flows | Surface flows for review | Assist-only |
| API7 SSRF | Injection + out-of-band (OAST) callback | Automated only if an OAST collaborator is configured |
| API8 Security Misconfiguration | Passive analyzer (headers, CORS, verbose errors) | Automated |
| API9 Improper Inventory | Diff observed vs. documented endpoints | Automated |
| API10 Unsafe Consumption | Largely non-observable | Assist-only |

### Passive analyzer

Missing/misconfigured security headers, cookie flags (HttpOnly/Secure/SameSite), over-permissive CORS, server/framework/version disclosure, verbose errors/stack traces, sensitive data in responses. HIGH confidence because directly observed.

### Safety tier

Scope lock (off-host tests rejected before sending), safe mode (non-mutating methods by default; state-changing methods need per-scan opt-in), rate/concurrency cap, abort checked between individual tests, and safe mode defaulting on when the target isn't disposable.

## 6. Model layer

All calls go through a **Model Gateway** with a provider-neutral request `{task, system, prompt, schema, max_tokens, temperature}` returning schema-validated JSON, with retries, a repair pass, token/cost accounting and a deterministic fallback per task.

- **Decision: multi-provider.** The engine is LLM-agnostic by design; there is no single-model assumption anywhere in the pipeline.
- **Providers:** Ollama (`gpt-oss:20b`, default and primary), AWS Bedrock (Claude Haiku), OpenAI, Anthropic.
- **Per-task routing:** config maps each task to a provider — e.g. keep planning/narration local and send only the high-stakes `rule` call to a stronger hosted model.
- **Tasks:** `fingerprint`, `crawl_plan`, `login_selectors`, `construct`, `rule`, `narrate`. Each has a fallback so nothing is load-bearing on the model.
- **Discipline for small models:** strict JSON I/O, one target per call, truncated bodies, one shared ethical-testing system prompt, and the verdict guardrail.

### Training flywheel (optional)

Detectors act as a free labeling oracle: every active test yields `(target, constructed input, detector signals, deterministic verdict)`. The deterministic verdict is the gold label — the model never grades itself. Examples are stored as provider-neutral `{task, input, output}` records.

- **Default: few-shot, no training.** `dast_fewshot_examples.json` is pasted into prompts per task.
- **Optional: LoRA/QLoRA** on `gpt-oss:20b` using `dast_training_samples.jsonl` (OpenAI fine-tune API works with the same JSONL; Bedrock/Claude fall back to few-shot).
- **Hygiene:** keep only examples where signal and verdict agree, balance FAIL/PASS/INCONCLUSIVE, redact target identifiers, version the dataset, train only on authorized targets.
- **Accept/reject gate:** promote a tuned model only if harness precision/recall improve and the guardrail-override rate drops.

## 7. Data model and reporting

Findings reuse the platform's unified `Finding` row (`kind="dast"`) so SAST/SCA/SBOM/DAST export uniformly.

- **Fields:** `rule_id` (catalog check id), `severity`, `confidence` (HIGH/MEDIUM/LOW), `verdict` (`true_positive` | `unverified`; FAIL→TP, INCONCLUSIVE→unverified), `target` (`METHOD path`), `param`, `location` (query/path/header/body/response), evidence (baseline, test, signals, status), remediation, first/last seen scan.
- **Evidence store:** baseline/test pairs plus detector signals, kept for audit.
- **Dedupe** on `(rule_id, path_template, param)` before persist.
- **Report:** severity roll-up (unverified shown separately), per-finding evidence and remediation, and a **scan-to-scan diff** (New / Fixed / Still-open) keyed on `(check, endpoint, param)`; exports to PDF and XLSX.
- **Narration:** the engine log is split on stage banners into a first-person timeline, with a template fallback so the UI never blocks on the model.

## 8. User experience

**Decision: the DAST UI is built inside the existing frontend and uses its existing styles.** It is not a separate app and does not adopt the standalone design system from `DAST_ui_design.md` / `dast_new_scan_ui.html` (indigo accent, its own `DAST·Scanner` rail, light/dark tokens). Those two files are used only as a reference for *what* each screen contains and how the multi-role form behaves — never for colours, fonts or layout chrome.

### Existing frontend conventions to reuse

| Concern | Use the existing… |
|---|---|
| Navigation | The shared `Sidebar` and its DAST entry; no second rail. DAST pages live under the existing `/dast` route and `/scans/new?type=dast` |
| Page shell | `PageContainer` (`px-12 py-10`); page title as `font-display` (Georgia) `text-3xl`, with a muted `text-sm` description beneath |
| Tokens | `--ink`, `--muted`, `--accent` (`#2563eb`), `--canvas` / `--canvas-2` page gradient, `--sidebar` — referenced as `var(--…)` in Tailwind 4 utilities. No new colour tokens for chrome |
| Typography | Open Sans body from `globals.css`; section labels as `text-xs font-semibold uppercase tracking-wide text-[var(--muted)]`; monospace only for evidence/payloads |
| Forms | `inputClass` / `selectClass` from `lib/formStyles.ts`, extending `DastScanForm` rather than replacing it; checkboxes styled as on the DAST dashboard |
| Buttons and surfaces | Primary: `rounded-md bg-[var(--accent)] … text-white hover:opacity-90`. Cards/panels: `rounded-md border border-slate-200 bg-white`. Empty states: dashed or `bg-white/60` boxes with centered muted text; errors: `border-red-200 bg-red-50 text-red-700` |
| Status | `ScanStatusBadge` for queued/running/success/failed/cancelled |
| Scan artifacts | `AgentArtifactCard` (click-to-open summaries, with its tone variants), `DastNarrationTimeline`, `DastAnalysisPanel`, the `agent-*` progress/pulse primitives from `globals.css` |
| Findings | The `ScanFindingsPanel` treatment: severity chips, verdict rows (confirmed = red, false positive = emerald, **unverified = amber**), same wording and `verdictKind()` handling |
| Dialogs | `useConfirmDialog` / `ConfirmDialog` for destructive actions (delete, cancel scan) |
| Per-project settings | The `/projects/[id]/settings` pattern (`ScanLimitationsPanel`, which renders whatever the backend catalog returns generically) |
| Data access | `lib/api.ts` → server-only `app/api/**/route.ts` proxies; types in `lib/types.ts`. No client-side calls to FastAPI and no new UI dependency |

New components (authorization matrix, identity cards, rule-pack picker) are composed from these same Tailwind utilities and tokens. The frontend's own `AGENTS.md` applies: this Next.js version has breaking changes, so check `node_modules/next/dist/docs/` before writing Next-specific code.

### Screens, mapped onto existing pages

| Screen | Built on | Purpose |
|---|---|---|
| DAST dashboard | Existing `/dast` page | Recent-scans list with `ScanStatusBadge` and the project filter that already exist; add finding counts. Stat tiles are optional and use the same card style |
| New Scan | Extend `DastScanForm` | Target (+ authorization confirm, already present), **Identities & roles** (multi-identity; replaces the single login block), Scope & safety (intensity preset, method policy, rate limit, **rule packs to run**), Model (provider + base/fine-tuned profile) |
| Scan Detail | Extend `DastScanDetail` | Live narration timeline (Checking connection → Authenticating → Discovering → Testing → Analyzing) via `DastNarrationTimeline`; Discovery and Analysis via `AgentArtifactCard` → side panels; live counters, severity breakdown, Cancel |
| Findings | Reuse `ScanFindingsPanel` | Add role and check filters and a DAST evidence block (baseline vs. test, detector signals, HTTP status); unverified findings are always shown, never hidden |
| Authorization matrix | New `DastAuthzMatrix` | Role × role grid; OK / n FAIL / untested; clicking a failing cell filters findings to that role pair |
| Report & diff | Existing export buttons (`ScanExportButtons`) | Severity summary, New/Fixed/Still-open, PDF/XLSX |
| Settings | Project settings page + global model settings | Per-task model routing, credentials (write-only, masked), scan defaults, safety (OAST URL), **rule-set management** (enable packs, toggle checks, override severity/mode, add custom rules) |

### Colour and accessibility rules

- **Severity and verdict** reuse the red / amber / emerald Tailwind tones already used by `ScanFindingsPanel` — no new hex values.
- **Role badges** are new but drawn from the same Tailwind tone palette that `AgentArtifactCard` already exposes (Admin purple, User blue, Viewer cyan, Anonymous slate, Custom amber), with one mapping used wherever a role appears (form, findings filter, matrix).
- **Theme:** the existing frontend is light-only (no dark-mode tokens in `globals.css`), so DAST screens are light-only too. Dark mode is out of scope unless the whole app adopts it.
- Colour is never the only signal: severity and verdict always carry a text label; matrix cells are buttons with aria-labels naming the role pair and result; every control keeps the existing focus ring.
- Every data view handles empty, loading, running, failed and cancelled states, using the existing empty/error box styles above.

## 9. Technology stack

| Layer | Choice |
|---|---|
| Backend | FastAPI, Uvicorn, SQLAlchemy 2 (SQLite dev → PostgreSQL prod), Pydantic Settings, hand-written idempotent migrations in `db.py` (no Alembic), structlog |
| DAST engine | LangGraph orchestration, Playwright (Chromium) for crawl + network recording, httpx, PyYAML, tldextract; detectors as pure Python |
| Model layer | `langchain-ollama` (default), `langchain-anthropic`, `langchain-openai`, `boto3` for Bedrock |
| Safety | New `safety_guard.py` (scope lock, method gate, rate limit) |
| Export | reportlab (PDF), openpyxl (XLSX) |
| Frontend | The existing Next.js 16 App Router frontend (React 19, TypeScript, Tailwind 4, existing styles and components — no new UI framework); server-only `app/api/**/route.ts` proxy routes attach the bearer token via `sastFetch` — the token never reaches the browser |
| Deployment | Local-first (backend + UI + Playwright + Ollama on one host/compose stack); Docker compose, Kubernetes or managed services for production |

Heavy dependencies (Playwright, Ollama) are lazy-imported so the **mock engine** runs the full pipeline offline — the same pattern the SAST engine uses, keeping the pytest suite free of browser, model and network.

## 10. Delivery plan

Build order for the greenfield design: skeleton + mock engine + config → passive analyzer → browser crawler + network recorder → detectors + active engine + guardrail → authorization checks → schema ingester → auth modes (token, pre-auth) → safety hardening + reporting + diff. *Pull safety forward if scanning anyone else's app.*

For the existing implementation, `DAST_completion_spec.md` gives a phased plan (items tagged **[IMPLEMENTED]** / **[RECOMMENDED]**):

| Phase | Deliverable |
|---|---|
| 0 | Stabilize and make measurable: commit the pending work, fix docs, build the DVWA / Juice Shop precision-recall harness, move hardcoded settings to config, light/standard/deep preset |
| 2 | Passive analysis node (`passive.py`) — no model, zero risk |
| 1 | Detectors + baseline + guardrail downgrade + no-session / second-identity replay |
| 3 | Real request shapes: capture request bodies, probe OpenAPI/Swagger |
| 4 | Form and parameter fuzzing through the same pipeline |
| 5 | Auth fallback: storage-state upload or bearer token/cookie header, skipping `login` |
| 6 | Safety (scope lock, safe mode, rate limit, responsive cancel) and reporting (dedupe, remediation, diff, evidence in exports) |

Suggested order: 0 → 2 → 1 → 3 → 4 → 5 → 6, with Phase 6 safety first if client-owned apps are ever scanned.

**Current state (per the completion spec):** a five-node graph (`check_connection → classify_login_type → login → crawl → analyze_apis`) with only `simple_form` login automated, REST-only active testing against observed endpoints, narration timeline, and in-memory credentials. Known gaps: no forms/DOM-sink fuzzing, request bodies inferred rather than captured, no independent validation of a model PASS, hardcoded Ollama URL and crawl budgets.

## 11. Quality and success criteria

- **Definition of done** (real engine, not mock): a practice app scanned twice yields the same verdicts; each run is scored against a fixed expected-findings list with precision and recall; active FAILs always carry a deterministic signal; client-readable report with evidence and remediation; active testing confined to the target host with mutation behind explicit opt-in.
- **Unit tests (offline, mock engine):** detectors, passive analyzer, catalog loader, scope guard, dedupe, narration parsing.
- **Integration (manual gate):** measurement harness against deliberately vulnerable practice targets (DVWA, Juice Shop) with ground-truth files; run before and after every change.
- **Regression bar:** ship only if the mock suite is green, harness recall holds, and precision doesn't regress.

## 12. Source documents

| File | Contents |
|---|---|
| `README.md` | Package overview, how to use the files, key decisions, assumptions, scope |
| `DAST_complete_design.md` | Full system design: architecture, pipeline, discovery, analysis, OWASP API coverage, model layer, safety, evaluation |
| `DAST_ui_design.md` | Screen-by-screen UI spec and UI → engine mapping (its standalone design system/colours are superseded by the existing frontend styles) |
| `DAST_tech_stack.md` | Package-level stack, module layout, DB schema, config, deployment |
| `DAST_completion_spec.md` | Phased plan to finish the existing DAST implementation |
| `dast_fewshot_examples.json` | Few-shot demonstrations for `rule`, `construct`, `fingerprint`, `crawl_plan` |
| `dast_training_samples.jsonl` | Same style of records in JSONL for optional fine-tuning |
| `dast_new_scan_ui.html` | Interactive New Scan mockup — reference for multi-role identity behaviour, auth-method switching and the authz matrix preview only; its styling is not used |

## 13. Open questions and assumptions to confirm

1. **Audience:** local practice targets only, or client engagements? Client use pulls all safety work forward.
2. **Resolved decisions:** (a) multi-provider LLM with per-task routing, `gpt-oss:20b` as default — this supersedes the `gpt-oss:20b`-only assumption in `DAST_completion_spec.md`; (b) OWASP API Top 10 and other web-security rules are configurable rule packs, not fixed coverage.
3. **Rule-pack granularity:** are packs configured at global, per-project and per-scan levels as proposed, or is per-project enough for v1? Should custom rules be authored in YAML only, or also through the Settings UI?
4. **Second identity / multi-role:** assumed available for cross-role checks; without it BOLA/BFLA degrade to no-session replay only.
5. **Disposable targets:** if targets aren't reset between runs, safe mode should default on.
6. **OAST collaborator:** needed for automated SSRF; without one, SSRF is assist-only. API4 (resource consumption) stays off unless enabled.
7. **Determinism target:** how much run-to-run variance is acceptable — tighter means leaning more on detectors, less on model wording.
8. **Database / deployment:** SQLite for dev and PostgreSQL for production; Docker compose vs. Kubernetes vs. managed services is undecided.
9. **UI scope:** existing light-only frontend theme (no dark mode, no per-tenant theming), per-scan reports only (no cross-scan program dashboard) in v1.
10. **Fine-tuning:** treated as an optimization, not a dependency; training data only from authorized targets.

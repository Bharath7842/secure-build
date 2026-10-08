# Architecture Documentation — DAST Scan Type

Phase 4 of the scaffolding chain. Inputs: [core-requirements.md](core-requirements.md), [tech-stack.md](tech-stack.md). Scope is core structural decisions only: layers, boundaries, patterns and contracts. No implementation detail.

Markers: **[EXISTS]** already in the repo, **[EXTEND]** exists and grows, **[NEW]** to be built.

## Architecture Overview

DAST is a new scan type inside the existing Augmented Secure Build platform. It is not a separate product. It reuses the platform's scan lifecycle, `Scan` and `Finding` records, bearer-token API, server-side proxy pattern, exports and UI shell.

Three decisions shape everything else:

1. **Deterministic code decides; the model advises.** The model plans, builds test inputs and proposes verdicts. A verdict becomes confirmed only through an observable detector signal. This is why the model sits behind one gateway and the verdict logic lives in the domain layer, where no model can reach it. (REQ-FR-FIND-3, -4, REQ-FR-MDL-1)
2. **One choke point for every outbound request.** Every request to the target, from the browser crawl or from an active test, passes a single safety guard that enforces scope, method policy, rate and cancellation, and writes the audit record. Nothing reaches the target any other way. (REQ-FR-SAFE-1 to -9)
3. **Checks are data.** Coverage is a catalog of declarative entries grouped into rule packs. Adding coverage means adding an entry, not changing the engine. (REQ-FR-RULE-\*)

The system has six layers. Dependencies point inward: outer layers depend on inner ones, never the reverse. The domain layer depends on nothing.

```
┌───────────────────────────────────────────────────────────────────────┐
│ 1. PRESENTATION                                                       │
│    Browser UI (Next.js)  ──►  server-only proxy routes                │
│    [EXTEND]                   (attach bearer token) [EXISTS]          │
└────────────────────────────────┬──────────────────────────────────────┘
                                 │ REST + bearer token
┌────────────────────────────────▼──────────────────────────────────────┐
│ 2. API                                                                │
│    Scan, findings, rule-set, settings, export routers [EXTEND]        │
└────────────────────────────────┬──────────────────────────────────────┘
                                 │
┌────────────────────────────────▼──────────────────────────────────────┐
│ 3. APPLICATION  (use cases and policy)                                │
│    Scan lifecycle · Rule-set resolution · Safety guard [NEW]          │
│    Findings recording · Report and diff · Narration                   │
└──────────┬───────────────────────────────────────────────┬────────────┘
           │ starts / observes                             │ uses
┌──────────▼───────────────────────────┐   ┌───────────────▼────────────┐
│ 4. ENGINE  (scan pipeline stages)    │   │ 5. DOMAIN                  │
│    Preflight · Fingerprint ·         │──►│    Entities, verdict rules,│
│    Authenticate · Discover ·         │   │    guardrail, dedupe, diff,│
│    Passive · Active · Roll-up        │   │    detectors, interfaces   │
│    [EXTEND: 5 stages exist]          │   │    [NEW, pure, no I/O]     │
└──────────┬───────────────────────────┘   └───────────────▲────────────┘
           │ via interfaces defined in Domain              │ implements
┌──────────▼───────────────────────────────────────────────┴────────────┐
│ 6. INFRASTRUCTURE                                                     │
│    Browser driver · Request executor · Model providers · Persistence  │
│    Catalog and prompt files · Report exporters · Credential holder    │
└───────────────────────────────────────────────────────────────────────┘
```

## Core Layers

### 1. Presentation

Renders the operator's view and holds no business rules. Pages: DAST dashboard, New Scan, Scan Detail (timeline, discovery, analysis, findings, authorization matrix, report), Settings. It talks only to the server-side proxy routes, never to the backend directly, and never sees the platform token. (REQ-INT-4, REQ-CON-1)
**Owns:** presentation state, filtering, empty/loading/running/failed/cancelled states. **Does not own:** verdicts, severity rules, scope decisions.

### 2. API

HTTP surface of the backend. Validates input, authenticates the caller, hands off to the application layer, shapes responses. Every endpoint except health requires the bearer token. (REQ-INT-3)
**Owns:** request validation, auth, serialization. **Does not own:** scan logic.

### 3. Application

Use cases and policy. This is where "what happens when an operator does X" lives.

| Service | Responsibility | Status |
|---|---|---|
| Scan lifecycle | Create, queue, run, cancel and finish a scan; status transitions; run the engine inline (mock) or on a background thread (real); snapshot the model settings and effective rule set at start | [EXISTS], [EXTEND] |
| Rule-set resolution | Combine global, project and per-scan settings into one effective rule set; mark checks skipped or degraded when a dependency is missing | [NEW] |
| Safety guard | Scope lock, method policy, rate and concurrency limits, cancellation check, request audit record. Sole gateway to the target | [NEW] |
| Findings recording | Persist findings and evidence incrementally as stages produce them; dedupe | [EXTEND] |
| Report and diff | Severity roll-up, New/Fixed/Still-open comparison, PDF and XLSX export | [EXTEND] |
| Narration | Turn the engine log into a readable timeline, with a template fallback | [EXISTS] |

### 4. Engine

The scan pipeline: an ordered set of stages with conditional routing, sharing one in-memory run state. Each stage announces itself with a banner line that drives progress and narration.

```
Preflight ─► Fingerprint ─► Authenticate ─► Discover ─► Passive ─► Active ─► Roll-up
                                              ▲            │
                                              └─ one bounded re-login if the session is lost
```

Routing rules: an API-only target skips the browser crawl; a supplied token or stored session skips form login; an unreachable target or failed authentication ends the run with a reason.
Today the repo has: connection check, login classification, login, crawl, API analysis. Fingerprint, passive, active (full catalog), roll-up and multi-identity authentication are [NEW].
**Owns:** stage order and routing, run state. **Does not own:** how a request is sent, how a verdict is computed, or how a model is called. It reaches those only through domain interfaces.

### 5. Domain

Pure logic and vocabulary, with no I/O, no framework and no model calls. This is the layer that makes the scan deterministic and unit-testable offline. (REQ-NFR-1, -2)

- **Entities:** Scan, Target, Identity, Role, Endpoint (the inventory item), Check, Rule pack, Finding, Evidence, Verdict.
- **Rules:** verdict roll-up (any fail → fail; all inconclusive → inconclusive; else pass), the **guardrail** (a model-proposed fail with no detector signal becomes unverified), dedupe key, scan-to-scan diff keyed on check, endpoint and parameter, role-pair matrix derivation, non-destructive input validation.
- **Detectors:** pure comparisons of baseline against test response. They observe and never judge.
- **Interfaces** implemented elsewhere: Request executor, Browser driver, Model gateway, Check catalog, Finding store, Credential holder (see Interface Contracts).

### 6. Infrastructure

Everything that touches the outside world, each behind a domain interface so it can be swapped or replaced by a mock.

| Concern | Provided by |
|---|---|
| Browser crawl and network recording | Headless browser driver; its outgoing requests are routed through the safety guard |
| HTTP request execution | Request executor, wrapped by the safety guard |
| Model calls | One adapter per provider (local, Bedrock, OpenAI, Anthropic) behind the Model gateway |
| Persistence | Relational store (SQLite dev, PostgreSQL prod) |
| Catalog, remediation text, prompts | Versioned files loaded at startup and validated |
| Exports | PDF and XLSX writers |
| Credentials | In-memory holder, registered with the log redactor, cleared at scan end |

**Mock engine.** A complete alternate implementation of layers 4 and 6 returns deterministic output with no browser, model or network. The application and API layers cannot tell the difference. This is the existing engine-adapter pattern and it keeps the whole test suite offline. (REQ-NFR-2)

## Cross-cutting Concerns

| Concern | How it spans the layers |
|---|---|
| **Error handling** | Failures are contained at the stage that raised them and converted to one of three outcomes: *scan failed* with a human-readable reason (unreachable target, failed authentication, lost credentials); *stage degraded* (a model call failed, so a deterministic fallback ran); *check skipped* (a dependency such as a second identity or an OAST service is absent). Nothing is dropped silently, and skipped or degraded checks appear in the report. (REQ-FR-AUTH-7, -8, REQ-FR-MDL-6, REQ-FR-RULE-12) |
| **Logging and observability** | The engine writes banner and progress lines to a captured log. The application derives progress and narration from it, and the UI reads it incrementally. Credentials are registered with a redactor before any line is written. The safety guard's request audit record is separate from this log and is a durable record. (REQ-FR-NARR-\*, REQ-SEC-2, REQ-FR-SAFE-9) |
| **Security** | Four boundaries: bearer token on the API; token held server-side only; target scope enforced in the application layer, never trusted to the engine or the model; credentials in memory only. Model output is treated as untrusted input at every use: unknown check ids are dropped, test inputs are validated before sending, and a verdict is never accepted without a signal. (REQ-INT-3, -4, REQ-SEC-\*, REQ-FR-MDL-7, REQ-FR-SAFE-8) |
| **Configuration** | Environment-driven settings supply defaults (budgets, rate, model routing per task, safe-mode default). The operator can override per project and per scan. The effective values, including rule set and model, are snapshotted onto the scan when it starts, so history and diffs stay valid when configuration changes. (REQ-FR-RULE-11, REQ-FR-MDL-5) |

## Integration Patterns

### External service integration

| Service | Direction | Pattern |
|---|---|---|
| Target application | Outbound | Only through the safety guard; browser traffic by request interception, API traffic through the request executor |
| Model providers | Outbound | One gateway, one provider-neutral request shape, task-based routing, schema-validated replies, deterministic fallback per task |
| OAST callback service | Outbound and inbound | Optional. Absent means SSRF checks degrade to assist-only (REQ-FR-ACT-7) |
| Platform database | Internal | Findings are written incrementally while the scan runs, so results appear mid-scan |

### Communication methods

- Browser to Next.js route handler to FastAPI: request/response over REST. The route handler adds the token.
- Progress and narration: the UI polls an incremental log endpoint with a sequence cursor. No push channel is introduced.
- Application to engine: in-process call, inline for the mock engine and on a background thread for the real one. The engine reports back through callbacks supplied by the application: write findings, emit log lines, check for cancellation.
- Stage to stage: shared in-memory run state, never persisted.

### State management

| State | Lives in | Lifetime |
|---|---|---|
| Run state (inventory, identities, live browser handles, per-stage results) | Engine memory | One scan; discarded at the end. Not serializable by design |
| Credentials and session material | Credential holder, memory only | One scan; a process restart fails the scan rather than continuing unauthenticated |
| Scan record, summaries, narration, effective rule set | `Scan` row and its metadata | Permanent |
| Findings and evidence | `Finding` and evidence rows | Permanent; the same finding shape as other scan types, marked as DAST |
| Request audit record | Persistent store | Permanent, per scan |
| Check catalog, custom rules, remediation, prompts | Versioned files | Loaded at start; custom rules validated before use |

## Component Interactions

### Scan from request to results

```
Operator ─► UI ─► proxy route ─► Scan API ─► Scan lifecycle
                                                │ snapshot settings + effective rule set
                                                ▼
                                        Engine (background)
   Preflight ─► Fingerprint ─► Authenticate ─► Discover ─► Passive ─► Active ─► Roll-up
        │            │              │             │           │         │          │
        └────────────┴──────────────┴─────────────┴───────────┴─────────┘          │
                       every outbound request ─► Safety guard ─► Target            │
                                                                                   ▼
                        Findings recording ◄── deduped, evidence attached ◄── Verdicts
                                │
                                ▼
                  Findings store ◄── UI polls findings and log incrementally
                                │
                                ▼
                       Report and diff ─► PDF / XLSX
```

### Active check loop (per discovered target)

```
Select checks + build inputs   (model, via gateway; unknown checks dropped)
        ▼
Validate inputs                (domain: non-destructive rule; reject otherwise)
        ▼
Baseline request ──┐
Test request ──────┴─► Safety guard ─► Target
        ▼
Detectors                      (domain: observe baseline vs test)
        ▼
Propose verdict                (model, via gateway; advisory)
        ▼
Roll-up + guardrail            (domain: final verdict; no signal means unverified)
        ▼
Record finding + evidence
```

### Authorization matrix

The engine takes the identity set from the scan, always adds an Anonymous baseline, and replays each discovered request as every other role. The domain layer derives the role-by-role matrix from the verdicts. The UI renders it and filters findings by a selected cell. Without a second identity, cross-role checks are marked degraded rather than omitted. (REQ-FR-ROLE-\*)

### Dependency rules

| From | May depend on | Must not depend on |
|---|---|---|
| Presentation | API (via proxy only) | Anything in the backend directly |
| API | Application | Engine, infrastructure |
| Application | Domain, Engine (as a runner), domain interfaces | Concrete infrastructure classes |
| Engine | Domain, domain interfaces | API, application services other than supplied callbacks |
| Domain | Nothing | Everything else |
| Infrastructure | Domain (implements its interfaces) | Application, engine |

## Interface Contracts

Contracts describe behaviour and guarantees, not code.

### Platform API (scan type: DAST)

| Operation | Contract |
|---|---|
| Create scan | Input: target address, authorization confirmation (required), project, identities with roles, intensity preset, method policy, rate limit, rule packs, model selection. Output: scan id, status `queued`. Rejected without the authorization confirmation |
| Get scan | Status, progress, summaries, narration, effective rule set |
| Cancel scan | Takes effect between individual tests |
| Get log | Lines after a given sequence number |
| Get findings | Filterable by severity, verdict, role, check; returns confirmed and unverified, never hiding either |
| Get authorization matrix | Role pairs with result: OK, number of failures, or untested |
| Export | PDF or XLSX including evidence, remediation and the New/Fixed/Still-open diff |
| Rule sets and settings | List and update packs, per-check overrides, custom rules, per-task model routing. Credentials are write-only and returned masked |

### Safety guard

- **Input:** a request description plus the scan's authorization (permitted hosts, method policy, rate limit) and its cancellation state.
- **Output:** allow, with the response and an audit record; or deny, with a stated reason (off-scope, method not permitted, cancelled).
- **Guarantees:** denial happens before anything is sent; every sent request has an audit record; rate and concurrency never exceed the scan's limit; the guard cannot be bypassed because the executor and browser driver only accept requests through it.

### Model gateway

- **Input:** task name, system text, prompt, expected reply shape, size and temperature limits.
- **Output:** a reply validated against the expected shape, with token and cost accounting; or a task-specific deterministic fallback result.
- **Guarantees:** the gateway is the only component that calls a model; the provider is chosen per task from configuration; a malformed reply gets one repair attempt before the fallback; no verdict is final because of a model reply.
- **Tasks:** fingerprint, crawl plan, login selectors, construct, rule, narrate.

### Check (catalog entry)

- **Fields:** id, standard tags (OWASP, API Top 10, WSTG, CWE), applies-to conditions, injection location, one or more proving detector signals, base severity, mode (automated, opt-in, assist-only), remediation reference, dependencies (for example, second identity or OAST).
- **Guarantees:** no fixed payload string; at least one named detector signal, otherwise the check can only produce unverified or assist-only results; a custom check is validated against these rules before it can run.

### Detector

- **Input:** baseline response and test response (status, length, body excerpt, timing, headers).
- **Output:** zero or more named signals. It is deterministic and has no side effects. It does not produce a verdict.

### Finding and evidence

- **Finding:** check id, severity, confidence (high, medium, low), verdict (true positive or unverified), target as method plus path, parameter, location (query, path, header, body, response), standards reported against, remediation reference, first and last seen scan.
- **Evidence:** baseline and test exchange excerpts, triggering signals, and the audit-record reference.
- **Guarantees:** a true-positive verdict implies at least one signal; findings dedupe on check, path template and parameter; unverified findings are stored and returned the same way as confirmed ones.

### Engine and platform

- **Supplied to the engine:** the effective scan settings, the identity set, the safety guard, the model gateway, and callbacks to write a finding, emit a log line and check cancellation.
- **Returned by the engine:** discovery summary, analysis summary, usage summary; findings are written during the run rather than only at the end.
- **Stage contract:** each stage reads and extends the shared run state, prints its banner, and ends with success, a stop reason, or a degraded note. A stage never sends a request except through the safety guard.

### Credential holder

- **Operations:** store an identity's credentials or session material for a scan, read them for the engine, clear everything at scan end.
- **Guarantees:** values are registered with the log redactor on store; nothing is written to the database or logs; a process restart loses them, and the scan then fails.

## Requirement coverage

| Requirement group | Primary layer |
|---|---|
| SCAN, UI, NARR | Presentation, Application |
| AUTH, ROLE | Engine (stages), Domain (matrix), Infrastructure (credential holder) |
| DISC, PASS, ACT | Engine (stages), Domain (detectors), Infrastructure (browser, executor) |
| RULE | Application (resolution), Domain (check contract), Infrastructure (catalog files) |
| FIND, RPT | Domain (verdict, dedupe, diff), Application (recording, report), Infrastructure (exporters) |
| MDL | Infrastructure (adapters), Domain (interface and guardrail) |
| SAFE | Application (safety guard), Domain (input validation) |
| INT, SEC | API, Application, Infrastructure |
| NFR | Domain purity, mock engine, measurement harness |
| CON | Presentation |

## Open architecture decisions

These need an answer before Phase 5 turns them into sprint stories.

1. **Where the safety guard sits for browser traffic.** The browser driver can be intercepted at the request level, which keeps one choke point but means the crawl cannot bypass it. The alternative is guarding only the executor and trusting the crawl. The first is recommended and assumed above.
2. **Where the request audit record lives.** Its own table, or inside each finding's evidence. A separate table is assumed because the audit must cover requests that produced no finding (REQ-FR-SAFE-9).
3. **Whether the domain layer gets its own package.** The repo today mixes domain and engine logic inside `app/dast/`. Assumed: a distinct domain package inside `app/dast/`, so layer rules can be enforced by import checks.

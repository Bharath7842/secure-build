# DAST — Complete System Design

A greenfield, end-to-end design for a Dynamic Application Security Testing engine that works against **any** web target — server-rendered sites, single-page apps, and API-only backends — authenticated or not, REST or GraphQL. It is **LLM-agnostic**: `gpt-oss:20b` via Ollama is the primary/default model, with AWS Bedrock (Haiku), OpenAI and Claude as drop-in providers behind one gateway (§8). The engine can also **fine-tune its own model** on evidence-labeled data it generates as it runs (§8.3).

This is a design document, not exploit material: it specifies components, interfaces, data and control flow. Payload construction is delegated to the runtime (declarative templates plus the model), exactly as a production scanner does, so no attack strings are hard-coded here.

> **Authorization is a precondition, not a feature.** Every scan carries an explicit operator authorization for the target. Active testing is confined to the authorized host(s). This is enforced in the design (Tier 2, §7), not left to policy.

> **Reading guide.** Design decisions are marked **[DECISION]**. Open assumptions are marked **[ASSUMPTION]** so you can overrule them. Everything else is mechanism.

---

## 1. Goals and non-goals

**Goals**
- One engine, three target shapes: classic multi-page app, SPA, headless API. The engine *detects* the shape and adapts rather than being configured per target.
- Findings backed by **observed evidence**, not model opinion — so a small local model is enough.
- A declarative, data-driven check catalog mapped to OWASP WSTG / Top 10 and CWE, extensible without code changes.
- A client-readable report with evidence, severity and remediation, plus scan-to-scan diffing.
- Safe by construction: scope lock, mutation opt-in, rate control, abort responsiveness.

**Non-goals**
- Not a replacement for a human pentester on business-logic flaws. The engine assists; it flags and evidences.
- No automation of CAPTCHA / OTP / full OAuth dance. These are handled by *accepting pre-authenticated state* (§5), not by defeating them.
- No cloud model, no second model. The design is shaped by the `gpt-oss:20b` ceiling throughout (§8).

---

## 2. Design tenets (grounded in how real scanners are built)

1. **Browser-first discovery.** Link-following misses SPA and API surface. A real headless Chromium drives the crawl, executes JS, and simulates user interaction, while a network interceptor records every request/response — the UI's own XHR/fetch calls *are* the API surface.
2. **Schema-based discovery beats guessing.** When an OpenAPI / GraphQL / SOAP description exists, ingest it for exact endpoints, parameters and body shapes. Runtime observation and schema ingestion are complementary inputs to the same target model.
3. **Passive before active.** A passive analyzer draws findings purely from observed traffic (headers, cookies, leaks) with zero added requests and zero risk. An active tester then sends crafted inputs. This is the ZAP-style split and it lets most of the value ship with no attack traffic.
4. **Checks are data, not code.** A declarative check catalog (Nuclei-style: a check = where to inject, what to send, what signal proves it) keeps the engine small and the coverage extensible.
5. **Verdicts are deterministic; the model advises.** Every active finding must be backed by a deterministic *detector* signal. The model proposes and explains; code decides. This is the core move that makes `gpt-oss:20b` sufficient.
6. **Stateful and token-aware.** Auth tokens are extracted once and injected into every subsequent request; multi-step flows are replayed in sequence, not as isolated stateless hits.
7. **Safety is a tier, not a checkbox.** Scope enforcement, method gating and rate limiting sit in the orchestration path that every request passes through.

---

## 3. High-level architecture

Five tiers plus two cross-cutting concerns. Clean separation so each tier is independently testable and the model is isolated to one worker.

<svg viewBox="0 0 920 600" xmlns="http://www.w3.org/2000/svg" font-family="Segoe UI, Helvetica, Arial, sans-serif">
  <style>
    .band{stroke:#334155;stroke-width:1}
    .box{fill:#ffffff;stroke:#334155;stroke-width:1.2}
    .t{fill:#0f172a;font-size:13px}
    .tb{fill:#0f172a;font-size:14px;font-weight:700}
    .tw{fill:#ffffff;font-size:14px;font-weight:700}
    .cap{fill:#0f172a;font-size:11px}
  </style>
  <!-- Tier 1 -->
  <rect x="10" y="10" width="760" height="70" class="band" fill="#e2e8f0"/>
  <text x="20" y="30" class="tb">Tier 1 · Interfaces</text>
  <rect x="210" y="22" width="160" height="44" class="box"/><text x="236" y="49" class="t">REST API</text>
  <rect x="390" y="22" width="160" height="44" class="box"/><text x="430" y="49" class="t">Web UI</text>
  <rect x="570" y="22" width="180" height="44" class="box"/><text x="612" y="49" class="t">CLI / CI</text>
  <!-- Tier 2 -->
  <rect x="10" y="90" width="760" height="86" class="band" fill="#dbeafe"/>
  <text x="20" y="110" class="tb">Tier 2 · Orchestration &amp; Safety</text>
  <rect x="210" y="118" width="160" height="46" class="box"/><text x="224" y="146" class="t">Scan lifecycle</text>
  <rect x="390" y="118" width="160" height="46" class="box"/><text x="410" y="140" class="t">Scope / method</text><text x="430" y="156" class="t">guard</text>
  <rect x="570" y="118" width="180" height="46" class="box"/><text x="590" y="140" class="t">Rate &amp; budget</text><text x="600" y="156" class="t">controller</text>
  <!-- Tier 3 -->
  <rect x="10" y="186" width="760" height="86" class="band" fill="#dcfce7"/>
  <text x="20" y="206" class="tb">Tier 3 · Discovery</text>
  <rect x="150" y="214" width="140" height="46" class="box"/><text x="166" y="236" class="t">Browser</text><text x="166" y="252" class="t">crawler</text>
  <rect x="306" y="214" width="140" height="46" class="box"/><text x="322" y="236" class="t">Network</text><text x="322" y="252" class="t">recorder</text>
  <rect x="462" y="214" width="140" height="46" class="box"/><text x="478" y="236" class="t">Schema</text><text x="478" y="252" class="t">ingester</text>
  <rect x="618" y="214" width="140" height="46" class="box"/><text x="634" y="236" class="t">Auth</text><text x="634" y="252" class="t">manager</text>
  <!-- Tier 4 -->
  <rect x="10" y="282" width="760" height="86" class="band" fill="#fef9c3"/>
  <text x="20" y="302" class="tb">Tier 4 · Analysis</text>
  <rect x="150" y="310" width="150" height="46" class="box"/><text x="166" y="332" class="t">Passive</text><text x="166" y="348" class="t">analyzer</text>
  <rect x="316" y="310" width="150" height="46" class="box"/><text x="332" y="332" class="t">Active check</text><text x="332" y="348" class="t">engine</text>
  <rect x="482" y="310" width="150" height="46" class="box"/><text x="498" y="332" class="t">Detector</text><text x="498" y="348" class="t">library</text>
  <rect x="648" y="310" width="110" height="46" class="box"/><text x="664" y="332" class="t">Verdict</text><text x="664" y="348" class="t">roll-up</text>
  <!-- Tier 5 -->
  <rect x="10" y="378" width="760" height="86" class="band" fill="#ede9fe"/>
  <text x="20" y="398" class="tb">Tier 5 · Knowledge &amp; Data</text>
  <rect x="150" y="406" width="150" height="46" class="box"/><text x="166" y="428" class="t">Check</text><text x="166" y="444" class="t">catalog</text>
  <rect x="316" y="406" width="150" height="46" class="box"/><text x="332" y="428" class="t">Findings</text><text x="332" y="444" class="t">store</text>
  <rect x="482" y="406" width="150" height="46" class="box"/><text x="498" y="428" class="t">Evidence</text><text x="498" y="444" class="t">store</text>
  <rect x="648" y="406" width="110" height="46" class="box"/><text x="664" y="428" class="t">Reports</text><text x="664" y="444" class="t">/ export</text>
  <!-- Cross-cutting -->
  <rect x="790" y="90" width="120" height="180" class="band" fill="#1e293b"/>
  <text x="800" y="138" class="tw">Model</text><text x="800" y="156" class="tw">Gateway</text>
  <text x="800" y="184" class="cap" fill="#e2e8f0">Ollama ·</text>
  <text x="800" y="200" class="cap" fill="#e2e8f0">gpt-oss20b</text>
  <text x="800" y="220" class="cap" fill="#e2e8f0">Bedrock ·</text>
  <text x="800" y="236" class="cap" fill="#e2e8f0">OpenAI ·</text>
  <text x="800" y="252" class="cap" fill="#e2e8f0">Claude</text>
  <rect x="790" y="282" width="120" height="182" class="band" fill="#475569"/>
  <text x="800" y="360" class="tw">Observ-</text><text x="800" y="378" class="tw">ability</text>
  <text x="800" y="404" class="cap" fill="#e2e8f0">log,</text>
  <text x="800" y="420" class="cap" fill="#e2e8f0">progress,</text>
  <text x="800" y="436" class="cap" fill="#e2e8f0">narration</text>
  <!-- flow arrow -->
  <line x1="390" y1="80" x2="390" y2="90" stroke="#334155" stroke-width="1.4"/>
  <line x1="390" y1="176" x2="390" y2="186" stroke="#334155" stroke-width="1.4"/>
  <line x1="390" y1="272" x2="390" y2="282" stroke="#334155" stroke-width="1.4"/>
  <line x1="390" y1="368" x2="390" y2="378" stroke="#334155" stroke-width="1.4"/>
  <text x="20" y="500" class="cap">The Model Gateway is the ONLY component that calls an LLM. Tiers 2 and 4 call it through a provider-neutral</text>
  <text x="20" y="516" class="cap">JSON interface; the active provider is config-driven, and verdicts never depend on the model alone (§8).</text>
</svg>

---

## 4. Scan pipeline (control flow)

A staged pipeline orchestrated as a state graph (LangGraph-style). Each stage emits a banner for progress and narration. The graph adapts to the detected target shape: a pure-API target skips the browser crawl; an unauthenticated target skips auth.

<svg viewBox="0 0 920 360" xmlns="http://www.w3.org/2000/svg" font-family="Segoe UI, Helvetica, Arial, sans-serif">
  <style>
    .n{fill:#ffffff;stroke:#334155;stroke-width:1.3}
    .nf{fill:#dcfce7;stroke:#334155;stroke-width:1.3}
    .na{fill:#fef9c3;stroke:#334155;stroke-width:1.3}
    .ns{fill:#dbeafe;stroke:#334155;stroke-width:1.3}
    .lt{fill:#0f172a;font-size:12px}
    .ar{stroke:#334155;stroke-width:1.5;fill:none;marker-end:url(#a)}
  </style>
  <defs><marker id="a" markerWidth="9" markerHeight="9" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 z" fill="#334155"/></marker></defs>
  <rect x="15" y="30" width="110" height="50" class="ns"/><text x="30" y="52" class="lt">Preflight</text><text x="30" y="68" class="lt">+ reach</text>
  <rect x="150" y="30" width="120" height="50" class="ns"/><text x="165" y="52" class="lt">Fingerprint</text><text x="165" y="68" class="lt">target shape</text>
  <rect x="295" y="30" width="110" height="50" class="ns"/><text x="312" y="52" class="lt">Authenticate</text><text x="320" y="68" class="lt">/ load state</text>
  <rect x="430" y="30" width="120" height="50" class="nf"/><text x="452" y="52" class="lt">Discover:</text><text x="445" y="68" class="lt">crawl + schema</text>
  <rect x="575" y="30" width="120" height="50" class="na"/><text x="592" y="52" class="lt">Passive</text><text x="592" y="68" class="lt">analysis</text>
  <rect x="720" y="30" width="120" height="50" class="na"/><text x="740" y="52" class="lt">Active test</text><text x="740" y="68" class="lt">(per target)</text>
  <rect x="430" y="150" width="120" height="50" class="n"/><text x="452" y="172" class="lt">Verdict</text><text x="452" y="188" class="lt">roll-up</text>
  <rect x="575" y="150" width="120" height="50" class="n"/><text x="592" y="172" class="lt">Dedupe +</text><text x="592" y="188" class="lt">persist</text>
  <rect x="720" y="150" width="120" height="50" class="n"/><text x="748" y="172" class="lt">Report</text><text x="738" y="188" class="lt">+ diff</text>
  <!-- arrows row1 -->
  <path class="ar" d="M125,55 L150,55"/>
  <path class="ar" d="M270,55 L295,55"/>
  <path class="ar" d="M405,55 L430,55"/>
  <path class="ar" d="M550,55 L575,55"/>
  <path class="ar" d="M695,55 L720,55"/>
  <!-- active loops back to verdict -->
  <path class="ar" d="M780,80 L780,120 L490,120 L490,150"/>
  <path class="ar" d="M550,175 L575,175"/>
  <path class="ar" d="M695,175 L720,175"/>
  <!-- skip arrows -->
  <path class="ar" d="M210,80 L210,210 L430,210 L430,180" stroke-dasharray="5 4"/>
  <text x="215" y="230" class="lt">API-only target: skip browser crawl, go on schema + recorder</text>
  <text x="15" y="300" class="lt">Blue = setup · Green = discovery · Yellow = analysis · White = output. Every active request first passes</text>
  <text x="15" y="318" class="lt">the Tier-2 scope/method guard and rate controller before it leaves the engine.</text>
</svg>

**Stages**

1. **Preflight + reachability.** Validate authorization token for the target, resolve host(s), confirm reachability. Unreachable → fail fast.
2. **Fingerprint target shape** **[DECISION]**. Fetch the root, inspect for a JS app shell vs. server-rendered HTML, probe well-known schema locations, detect GraphQL. Output: `{shape: mpa|spa|api, auth: none|form|token|preauth, schema: none|openapi|graphql}`. This single classification drives which later stages run.
3. **Authenticate / load state** (§5). Skippable.
4. **Discover** (§6): browser crawl with network recording, plus schema ingestion. Produces the **target inventory**: pages, forms, endpoints, parameters, request shapes, observed responses.
5. **Passive analysis** (§7.1): findings from observed traffic only.
6. **Active test** (§7.2): for each target in the inventory, run applicable checks → detectors → model ruling → deterministic roll-up. Findings stream as they resolve.
7. **Verdict roll-up → dedupe → persist → report + diff** (§9).

---

## 5. Authentication subsystem

Target-agnostic auth must cover four cases without automating what shouldn't be automated.

| Mode | How it works | Notes |
|---|---|---|
| **None** | Skip. | Public app or pre-scoped API. |
| **Form login** | Browser fills the login form; the model proposes selectors from the form HTML with a hard-coded fallback; success verified by a multi-signal chain (post-login indicator, URL change, credential field gone). | One bounded retry. |
| **Token** | Operator supplies a bearer/JWT or API key, or the engine extracts a token observed at login and injects it into every subsequent request header. Refresh tokens honored during long scans. | Covers OAuth/JWT/API-key apps. |
| **Pre-authenticated state** **[DECISION]** | Operator uploads a browser `storage-state` (cookies + local storage) captured from a real session. The crawl starts already logged in. | This is the escape hatch for SSO / MFA / CAPTCHA — no need to defeat them. |

**Credential handling (non-negotiable):** credentials and tokens are held **in memory only**, never persisted, registered with the log redactor, and dropped at scan end. If the process restarts mid-scan, the scan fails with "credentials lost" rather than silently continuing unauthenticated.

**[ASSUMPTION]** A second identity (user B) can optionally be supplied to enable authorization/IDOR cross-user checks. If you'd rather keep single-identity only, that check degrades gracefully to "no-session replay" alone.

---

## 6. Discovery tier

The inventory is the heart of target-agnosticism. Three producers feed one merged model.

**6.1 Browser crawler.** Headless Chromium (Playwright). Executes JS, waits for network-idle, and *simulates interaction* — clicking, expanding, submitting benign forms — not just link-following, because SPA routes have no static links. A planner (the model) picks the next action/route, biased toward high-value areas (admin, account, checkout), with FIFO fallback and hard budgets: max pages, max depth, max runtime, consecutive-low-value cutoff. URL dedup via normalization + pattern caps so parameterized routes don't explode.

**6.2 Network recorder.** A request/response interceptor on the browser captures **method, URL, query, request headers, request body, content-type, status, and response body** for every call — including the XHR/fetch the SPA makes. This fixes the classic gap where only responses are seen: request bodies give real parameter shapes. Same-origin API calls are promoted straight into the endpoint inventory.

**6.3 Schema ingester.** Probe well-known locations (OpenAPI/Swagger JSON/YAML, `/graphql` introspection, SOAP WSDL). When found, derive exact endpoints, parameters, and body schemas. Schema-derived and observed endpoints are merged and de-duplicated by `(method, path-template)`.

**Target inventory (output):**

```
inventory = {
  pages[]      : {url, depth, title, forms[], links}
  endpoints[]  : {method, url, path_template, params[], body_schema,
                  content_type, observed_status, source: crawl|schema}
  forms[]      : {action, method, fields[]}
  shape, auth_state, schema_kind
}
```

---

## 7. Analysis tier

### 7.1 Passive analyzer (no added requests, no risk)

Pure functions over already-observed traffic. Highest-confidence, zero-risk findings — ship this first.

- Missing/misconfigured security headers (transport security, content-type/frame options, CSP).
- Cookie flags: HttpOnly, Secure, SameSite.
- Over-permissive CORS.
- Server/framework/version disclosure, verbose error/stack-trace leakage.
- Sensitive data in responses (tokens, keys echoed back).

Each maps to a catalog check id and writes a finding at **HIGH** confidence because it is directly observed.

### 7.2 Active check engine

For each target in the inventory, the engine runs the **construct → execute → detect → rule → roll-up** loop:

<svg viewBox="0 0 900 150" xmlns="http://www.w3.org/2000/svg" font-family="Segoe UI, Helvetica, Arial, sans-serif">
  <style>.b{fill:#ffffff;stroke:#334155;stroke-width:1.3}.m{fill:#1e293b}.d{fill:#dcfce7;stroke:#334155;stroke-width:1.3}.x{fill:#0f172a;font-size:12px}.xw{fill:#fff;font-size:12px}.ar{stroke:#334155;stroke-width:1.5;fill:none;marker-end:url(#b)}</style>
  <defs><marker id="b" markerWidth="9" markerHeight="9" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 z" fill="#334155"/></marker></defs>
  <rect x="10" y="45" width="120" height="54" class="m"/><text x="24" y="68" class="xw">1 Select +</text><text x="24" y="86" class="xw">construct (LLM)</text>
  <rect x="160" y="45" width="110" height="54" class="b"/><text x="176" y="68" class="x">2 Baseline</text><text x="176" y="86" class="x">request</text>
  <rect x="300" y="45" width="110" height="54" class="b"/><text x="320" y="68" class="x">3 Execute</text><text x="320" y="86" class="x">test</text>
  <rect x="440" y="45" width="120" height="54" class="d"/><text x="456" y="68" class="x">4 Detectors</text><text x="456" y="86" class="x">(deterministic)</text>
  <rect x="590" y="45" width="110" height="54" class="m"/><text x="606" y="68" class="xw">5 Rule</text><text x="606" y="86" class="xw">(LLM)</text>
  <rect x="730" y="45" width="150" height="54" class="b"/><text x="746" y="68" class="x">6 Roll-up +</text><text x="746" y="86" class="x">guardrail (code)</text>
  <path class="ar" d="M130,72 L160,72"/>
  <path class="ar" d="M270,72 L300,72"/>
  <path class="ar" d="M410,72 L440,72"/>
  <path class="ar" d="M560,72 L590,72"/>
  <path class="ar" d="M700,72 L730,72"/>
  <text x="10" y="125" class="x">Dark = model advises · Green = deterministic evidence · the guardrail (code) has the final say on every verdict.</text>
</svg>

1. **Select + construct (model).** The model reads one target and picks which catalog checks apply, then constructs test inputs for each: target parameter, injection location (query / path / header / body), the input to send, and the signal that would prove the issue. Bounded per target. Unknown check ids dropped. Payload *strings* come from the model constrained by the catalog template — never hard-coded in the engine.
2. **Baseline.** Send the unmodified request; record status, length, body, timing.
3. **Execute.** Send the test through the authenticated session (`page.request`-equivalent, so cookies/tokens ride along). Never raises; transport errors become evidence. Body truncated; timeout bounded.
4. **Detectors (deterministic, the decisive step).** Pure functions compare baseline vs. test and emit *signals*: data-layer error surfaced, input reflected unescaped, command-output marker present, stack trace leaked, meaningful time delta, status/length divergence, auth boundary crossed. Detectors observe; they do not opine.
5. **Rule (model).** The model rules PASS / FAIL / INCONCLUSIVE **on the detector signals plus the body**, with a finding sentence, severity and confidence.
6. **Roll-up + guardrail (code).** Deterministic: any FAIL → target FAIL; all INCONCLUSIVE → INCONCLUSIVE; else PASS. **Guardrail:** a model FAIL with *no* supporting detector signal is downgraded to INCONCLUSIVE. Nothing is hidden, but nothing is asserted without evidence.

**Authorization checks** (cheap, high-yield, mostly deterministic): replay each request with the session stripped (success where auth was expected = broken access) and, if a second identity exists, replay user B against user A's resource.

### 7.3 Check catalog (declarative, Nuclei-inspired)

Checks are **data**. A check entry declares identity, applicability, where to inject, what signal proves it, and how to score — but not a fixed payload string (the model fills that under the template's guidance). Adding coverage = adding an entry, not code.

```yaml
- id: dast-sqli
  cwe: CWE-89
  owasp: A03-Injection          # OWASP Web Top 10
  apisec: null                  # OWASP API Security Top 10 (set for API-surface checks)
  wstg: WSTG-INPV-05
  applies_to: {locations: [query, body, path], param_types: [string, number]}
  signal: [db_error_surfaced, boolean_divergence, time_delta]   # which detectors prove it
  severity_base: high
  remediation_ref: rem/sqli.md
```

Catalog spans the OWASP WSTG surface: configuration & deployment, identity & authentication, session management, authorization, input validation (injection/XSS/command), error handling, cryptography/transport, information disclosure, and API-specific tests. Every entry carries both an `owasp` (Web Top 10) and, where it targets an API endpoint, an `apisec` tag (§7.4), so a finding reports against whichever standard the client cares about. Business-logic checks are flagged as *assist-only* (surfaced for human review, not auto-ruled).

### 7.4 API security coverage — OWASP API Security Top 10 (2023)

API endpoints are tested against the **OWASP API Security Top 10**, not just the general Web Top 10, because the dominant API risks are authorization and inventory flaws that web-page checks miss. The inventory tier (§6) — browser-recorded API calls plus ingested OpenAPI/GraphQL schema — is what makes this tractable: object ids, function paths and parameter shapes are known, so the authorization replays have something concrete to mutate.

| API risk (2023) | How the engine addresses it | Mode |
|---|---|---|
| **API1 Broken Object Level Authorization (BOLA)** | Replay a request with another object id / another user's session; a success where denial was expected is the signal. Deterministic detector (`authz_boundary_crossed`). | **Automated** (strongest with a 2nd identity) |
| **API2 Broken Authentication** | No-session replay, token/JWT handling checks, weak-session signals, auth-required endpoint reached unauthenticated. | Automated (partial) |
| **API3 Broken Object Property Level Authorization (BOPLA)** | Mass-assignment: add unexpected properties from the schema and check if accepted; excessive-data-exposure: response carries more fields than the operation needs. | Automated where schema known; else assist |
| **API4 Unrestricted Resource Consumption** | Probe for missing rate/size limits — **gated by the Tier-2 rate controller and off by default**, since this generates load. | Opt-in / careful |
| **API5 Broken Function Level Authorization (BFLA)** | Access a privileged/admin function as a lower-privilege (or anonymous) identity; success is the signal. Same replay machinery as BOLA. | **Automated** (needs 2nd identity for full value) |
| **API6 Unrestricted Access to Sensitive Business Flows** | Surface sensitive flows (checkout, invite, password reset) for review; flow-abuse is business logic. | **Assist-only** |
| **API7 Server-Side Request Forgery (SSRF)** | Injection check on URL-accepting params with an **out-of-band (OAST) callback** detector; a received callback is unambiguous proof. | Automated **if** an OAST collaborator is configured; else assist |
| **API8 Security Misconfiguration** | Covered mostly by the passive analyzer (§7.1): headers, CORS, verbose errors, debug surfaces. | **Automated** |
| **API9 Improper Inventory Management** | Diff observed endpoints vs. schema; flag undocumented, old-version (`/v1` vs `/v2`), debug and shadow endpoints found during discovery. | Automated (discovery-driven) |
| **API10 Unsafe Consumption of APIs** | Trust of upstream third-party APIs is largely non-observable black-box; flag where detectable, otherwise note for review. | **Assist-only** |

New catalog check ids this adds: `dast-bola`, `dast-bfla`, `dast-mass-assignment`, `dast-excessive-data`, `dast-ssrf`, `dast-api-inventory` (plus the existing auth/session/misconfig checks, now also `apisec`-tagged).

> **[ASSUMPTION]** SSRF testing is only meaningful with an out-of-band callback endpoint (an OAST/collaborator service) the operator controls. Without one, SSRF degrades to assist-only. Resource-consumption (API4) stays off unless explicitly enabled, because it is inherently load-generating.

---

## 8. Model layer — provider-agnostic, with a single-call discipline

### 8.1 The engine is LLM-agnostic

No component talks to a model directly. They all call one **Model Gateway** with a provider-neutral request `{task, system, prompt, schema, max_tokens, temperature}` and get back schema-validated JSON. The active provider is config-driven and hot-swappable. `gpt-oss:20b` via Ollama is the default and primary; the others are drop-in.

| Provider | Model(s) | When to use | Fine-tunable by you? |
|---|---|---|---|
| **Ollama (local)** | **gpt-oss:20b (primary)**, any open GGUF | Default. Offline, zero per-call cost, data never leaves the host. | **Yes** — you own the weights (§8.3) |
| AWS Bedrock | Claude Haiku, others | Managed, scalable, no local GPU | Varies — Bedrock customization; verify current support |
| OpenAI API | gpt-4o-mini, etc. | Hosted quality / fallback | Yes — supervised fine-tune API |
| Anthropic API | Claude Haiku / Sonnet | Hosted quality | Limited — mostly few-shot / prompt |

**Gateway responsibilities:** one adapter per provider; uniform JSON-schema validation with a repair pass; retries with a per-task deterministic fallback; token/cost accounting; secret handling; and **per-task routing** — each call site names a *task*, and config maps tasks to providers. So you can run everything on gpt-oss:20b, or send only the high-stakes *ruling* call to a stronger hosted model while planning and narration stay local — no code change, just config.

**Where the model is used (and why any small model suffices):**

| Model call (task) | Role | Why a small model is enough |
|---|---|---|
| `fingerprint` | Classify target shape/auth | Deterministic probes do most of it; model only tie-breaks |
| `crawl_plan` | Pick next route/action | FIFO fallback on any bad/empty answer |
| `login_selectors` | Suggest form selectors | Hard-coded selector fallback always present |
| `construct` | Choose applicable checks, build inputs | Catalog constrains the space; unknown ids dropped |
| `rule` | PASS/FAIL/INCONCLUSIVE over **detector signals** | Judges observed facts, not raw guessing |
| `narrate` | Log → readable timeline | Deterministic template fallback; UI never blocks on model |

### 8.2 Discipline that makes any small model reliable

- **Strict JSON I/O** on every call, with retries and a deterministic fallback for each — nothing is load-bearing on the model.
- **Small context per call** — one target at a time, truncated bodies — so even a 20B local model stays within a prompt size it handles well.
- **Verdict guardrail** (§7.2 step 6): the model can never assert a finding the detectors don't support.
- **One ethical-testing system prompt**, scoped to the authorized target, shared across providers.
- **Correctness is provider-independent:** swap gpt-oss:20b for Haiku or GPT and quality may rise, but the detectors and guardrail hold the floor either way.

### 8.3 Training the model — fine-tune on your own scans (the data flywheel)

**The core idea: your detectors are a free labeling oracle.** Every active test already produces `(target descriptor, constructed input, detector signals, deterministic verdict)`. The deterministic roll-up verdict is the **gold label** — no human labeling, and critically, the model is *not* grading itself; the evidence grades it. So the scanner manufactures its own supervised dataset simply by running on authorized targets.

<svg viewBox="0 0 900 200" xmlns="http://www.w3.org/2000/svg" font-family="Segoe UI, Helvetica, Arial, sans-serif">
  <style>.c{fill:#ede9fe;stroke:#334155;stroke-width:1.3}.cg{fill:#dcfce7;stroke:#334155;stroke-width:1.3}.cd{fill:#1e293b}.z{fill:#0f172a;font-size:12px}.zw{fill:#fff;font-size:12px}.ar{stroke:#334155;stroke-width:1.6;fill:none;marker-end:url(#f)}</style>
  <defs><marker id="f" markerWidth="9" markerHeight="9" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 z" fill="#334155"/></marker></defs>
  <rect x="15" y="40" width="130" height="54" class="cg"/><text x="34" y="62" class="z">Authorized</text><text x="48" y="80" class="z">scan</text>
  <rect x="190" y="40" width="140" height="54" class="cg"/><text x="206" y="62" class="z">Detectors</text><text x="206" y="80" class="z">label (gold)</text>
  <rect x="375" y="40" width="140" height="54" class="c"/><text x="391" y="62" class="z">Dataset</text><text x="391" y="80" class="z">(JSONL)</text>
  <rect x="560" y="40" width="130" height="54" class="cd"/><text x="580" y="68" class="zw">Fine-tune</text>
  <rect x="735" y="40" width="150" height="54" class="c"/><text x="751" y="62" class="z">Improved</text><text x="751" y="80" class="z">model</text>
  <path class="ar" d="M145,67 L190,67"/>
  <path class="ar" d="M330,67 L375,67"/>
  <path class="ar" d="M515,67 L560,67"/>
  <path class="ar" d="M690,67 L735,67"/>
  <path class="ar" d="M810,94 L810,150 L80,150 L80,94"/>
  <text x="300" y="172" class="z">The model gets better the more you run it — and the labels are evidence, never the model's own opinion.</text>
</svg>

**What to fine-tune, and where each label comes from:**

| Task | Training input | Gold label source |
|---|---|---|
| **`rule`** (highest value) | detector signals + truncated body | the **deterministic roll-up verdict + severity** |
| `construct` | (check id, target descriptor, location) | the test inputs that detectors **confirmed** effective on authorized practice targets |
| `fingerprint` / `crawl_plan` | target / page descriptor | the shape later proven correct / routes that yielded surface |
| `narrate` (optional) | stage evidence | curated reference narrations (style tune only) |

**Dataset mechanics:**
- **Seed** from the §12 practice targets with known ground truth — clean positive *and* negative examples.
- **Grow** from every real authorized scan (the flywheel above).
- **Format:** provider-neutral JSONL, `{task, input, output}`. One asset serves every provider.
- **Hygiene:** keep only examples where the detector signal and the verdict agree; balance classes (FAIL / PASS / INCONCLUSIVE) so the model doesn't learn to always-FAIL; redact target-identifying data; version the dataset.

**"Training" = feeding labeled sample records.** There is no custom algorithm — the fine-tune simply adjusts the model's weights to reproduce the gold `output` given the `input`. A starter set ships as `dast_training_samples.jsonl`. One `rule` record (the highest-value task):

```json
{"task":"rule",
 "input":{"check":"dast-bola","target":"GET /api/orders/{id}",
          "signals":["authz_boundary_crossed"],
          "test":{"status":200,"as":"other_user","body_excerpt":"{\"owner\":\"userA\"}"}},
 "output":{"verdict":"FAIL","severity":"critical","confidence":"HIGH",
           "finding":"Object-level authorization missing: user B can read user A's order by id."}}
```

Note the two teaching cases the set deliberately includes: a record with **no signal → INCONCLUSIVE** (so the model learns never to FAIL without evidence) and a **PASS** (correct denial / encoded reflection), so it doesn't learn to flag everything. At train time, `{task, input, output}` maps to a chat triple: the task's system prompt, the `input` JSON as the user turn, the `output` JSON as the assistant turn.

**How you actually train, per provider:**
- **gpt-oss:20b (primary, fully under your control):** LoRA / QLoRA supervised fine-tune on a single GPU; keep the adapter or merge it; convert to GGUF; serve via Ollama with a `Modelfile`. Re-tune on a schedule as the dataset grows. This is the path that benefits most — it's the smallest model and the one you own outright.
- **OpenAI:** upload the same JSONL to the fine-tune API, then point the gateway's `rule` task at the tuned model id.
- **Bedrock / Claude:** direct supervised fine-tuning may be unavailable or preview-only — **verify current availability**. Where it isn't, reuse the *same* JSONL as **few-shot exemplars** and prompt optimization. The dataset is portable precisely because it is provider-neutral.

**Guardrail survives training.** Fine-tuning raises model–evidence agreement and cuts INCONCLUSIVE noise, but §7.2's no-signal-downgrade still holds: a fine-tuned model that hallucinates a finding with no detector signal is still downgraded. **Training can't manufacture evidence** — so a bad fine-tune degrades gracefully instead of producing false positives.

**Accept / reject gate.** Run the §12 harness before and after each fine-tune. Promote a new model only if precision/recall improve *and* the guardrail-override rate drops. Otherwise roll back to the previous adapter.

> **[ASSUMPTION]** Training examples come only from targets you are authorized to test; the dataset is operator-owned, and the `construct` examples are confirmed test inputs from those authorized runs — not sourced externally.

---

## 9. Data, findings, and reporting

**Finding (unified row, same shape as your other scan types):**

```
{ kind: "dast", rule_id, severity, confidence: HIGH|MEDIUM|LOW,
  verdict: true_positive|unverified,              # FAIL→TP, INCONCLUSIVE→unverified
  target: "<METHOD> <path>", param, location,
  evidence: {baseline, test, signals[], http_status},
  remediation, first_seen_scan, last_seen_scan }
```

- **Dedupe** on `(rule_id, path_template, param)` before persist.
- **Evidence store** keeps baseline/test pairs and detector signals for audit.
- **Report**: client-readable PDF/XLSX with severity rollup, evidence, and remediation per finding; plus a **scan-to-scan diff** (new / fixed / still-open) computed against prior findings on the same target.
- **Narration/observability**: engine log split on stage banners into a readable timeline (first-person step summary + reasoning bullets), cached and persisted; template fallback when the model is unavailable.

---

## 10. Safety and scope (Tier 2 — every request passes through it)

- **Scope lock.** Constructed tests resolving off the authorized host(s) are rejected *before* they are sent — deterministically.
- **Method gating / safe mode.** Non-mutating methods by default; sending anything that can change or delete data requires an explicit per-scan opt-in, because active testing can mutate a live app.
- **Rate + concurrency controller.** Configurable delay and parallelism cap, so a scan can't hammer the target.
- **Abort responsiveness.** `should_abort` checked between individual tests, not just between targets.
- **Disposable-target guidance.** If the target isn't reset between runs, safe mode defaults on.

---

## 11. Deployment and configuration

**[ASSUMPTION]** Local-first: FastAPI backend + Next.js UI + Playwright + Ollama (`gpt-oss:20b`) all on one host or compose stack, with Bedrock / OpenAI / Anthropic reachable when configured. The browser and the local model are the two heavy dependencies; both are lazy-imported so a mock engine (deterministic fake discovery + findings through the same writers) runs the full pipeline with neither installed — the whole code path stays unit-testable offline.

Config surface (all in settings, nothing hard-coded): **model provider per task** (`ollama | bedrock | openai | anthropic`) + model id + credentials, default `ollama / gpt-oss:20b`; crawl budgets (runtime, depth, pages, per-pattern); same-domain mode; max-targets and max-tests-per-target (exposed as a light / standard / deep preset); rate / concurrency; safe-mode default; and the active fine-tuned model/adapter id.

---

## 12. Test and evaluation strategy

- **Unit (offline, mock engine):** detectors (pure functions — high coverage), passive analyzer, catalog loader, scope guard, dedupe, narration parsing. No browser/model/network.
- **Integration (real engine, manual gate):** a measurement harness against a *set of deliberately vulnerable practice targets you control*, each with a fixed expected-findings list. Report **precision and recall** and a diff vs. ground truth. This is the only objective quality signal; run it before and after every change.
- **Regression bar:** a change ships only if the mock suite is green and harness recall holds while precision doesn't regress.

---

## 13. Build order (value-for-effort)

1. **Skeleton + mock engine + config surface** — full pipeline runs deterministically; measurement harness stands up.
2. **Passive analyzer** — real findings, zero risk, no model.
3. **Browser crawler + network recorder** — the inventory, incl. request bodies.
4. **Detector library + active engine + guardrail** — evidence-backed active findings.
5. **Authorization checks** (no-session + second-identity replay) — cheap, high-yield.
6. **Schema ingester** — exact API shapes; unlocks API-only targets.
7. **Auth modes** (token + pre-auth state) — makes SSO/MFA targets scannable.
8. **Safety hardening + reporting + diff** — client-ready. *Pull forward if scanning anyone else's app.*

---

## 14. Assumptions to confirm

1. **[ASSUMPTION]** LLM-agnostic: `gpt-oss:20b` via Ollama is primary/default; Bedrock Haiku, OpenAI and Claude are drop-in via the Model Gateway, selectable per task. (Stated requirement.)
2. **[ASSUMPTION]** Targets are operator-authorized; practice/disposable for the eval harness.
3. **[ASSUMPTION]** Second-identity credentials optionally available for cross-user authorization checks.
4. **[ASSUMPTION]** REST + GraphQL are first-class; SOAP/gRPC are best-effort via schema ingestion only.
5. **[ASSUMPTION]** Findings share the existing platform's `Finding` row so SAST/SCA/SBOM/DAST report uniformly.

---

### Sources (real-world grounding)

- [StackHawk — Why legacy DAST fails for modern applications](https://www.stackhawk.com/blog/why-legacy-dast-fails-for-modern-applications-and-how-to-fix-it/)
- [Astra — DAST for Single Page Applications](https://www.getastra.com/blog/dast/dast-for-single-page-applications)
- [OWASP Web Security Testing Guide](https://wstg.owasp.org/)
- [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
- [OWASP ZAP (passive/active scanner model)](https://www.zaproxy.org/)
- [Nuclei — template-based scanning](https://docs.projectdiscovery.io/templates/introduction)
- [PortSwigger Burp — scanning best practices](https://portswigger.net/burp/documentation/dast/user-guide/working-with-scans/best-scanning-practices)

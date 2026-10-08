## [EPIC-01] Safety Guard & Request Audit

**Goal:** Every request that reaches a target passes one guard that enforces scope, method policy, rate and cancellation, and is recorded in an audit trail; model-generated inputs are validated as non-destructive before sending.
**Depends On:** EPIC-00
**Blocks:** EPIC-05, EPIC-06, EPIC-07, EPIC-09, EPIC-10
**Teams:** Dev

Requirements: REQ-FR-SAFE-1 to -9, REQ-FR-SCAN-2. Design basis: architecture decisions 2 and open decision 1 (browser traffic is intercepted at request level).

---

### DAST-01-010 Scope and method policy

**Epic:** EPIC-01 Safety Guard & Request Audit        **Parent:** EPIC-01
**Parallelism:** Serial/Blocking    **Sprint:** 1

**Story**
As an operator, I want testing confined to the authorized hosts and to non-mutating methods by default so that a scan cannot touch anything I did not approve.

**Acceptance Criteria**
- A scope is built from the scan's target address and same-domain mode (`exact` or `root-domain`, using the root-domain library).
- A request to a host outside scope is denied before anything is sent, with reason `off_scope`.
- With safe mode on (the default), only GET, HEAD and OPTIONS are allowed; POST, PUT, PATCH and DELETE are denied with reason `method_not_permitted` unless the scan opted in to state-changing methods.
- Safe mode defaults on whenever the target is not marked disposable.
- Redirects to an out-of-scope host are denied, not followed.
- The decision function is pure: it takes a request description plus the scope/policy and returns allow or deny with a reason.

**Dev Notes**
- Policy function lives in `app/dast/domain/` (pure); the application-layer guard in `app/services/safety_guard.py` composes it with rate, cancel and audit.
- Compare hosts after normalization (case, default port, trailing dot, IDN, IP literal) so look-alike hosts and `host@evil` URL tricks do not pass.
- Reuse `url_utils.normalize_url`.

**Dev Testing**
- Test level: unit.
- Assert: in-scope allowed; sibling subdomain denied in `exact`, allowed in `root-domain`; look-alike host (`target.com.evil.com`) denied; userinfo trick denied; redirect off-host denied; POST denied in safe mode, allowed after opt-in; non-disposable target forces safe mode.
- Test data: table of URL/method pairs with expected decisions.

**Dependencies:** DAST-00-020, DAST-00-030
**Blocks:** DAST-01-020, DAST-01-030, DAST-01-040, DAST-07-050

**Definition of Done:** code merged + developer tests green

---

### DAST-01-020 Rate limit, concurrency cap and cancellation

**Epic:** EPIC-01 Safety Guard & Request Audit        **Parent:** EPIC-01
**Parallelism:** Parallel    **Sprint:** 1

**Story**
As an operator, I want a request-rate and concurrency limit and responsive cancellation so that a scan cannot overload the target and can be stopped immediately.

**Acceptance Criteria**
- The guard never exceeds the scan's configured requests per second or concurrent request count.
- Cancellation is checked before every request; a cancelled scan sends no further requests and the guard denies with reason `cancelled`.
- The limiter is per scan, not process-global.
- Limits are read from the scan's effective settings (DAST-00-030 defaults).

**Dev Notes**
- Small token-bucket plus semaphore inside `safety_guard.py`; no third-party rate-limit package (see tech-stack).
- Cancellation flag is the existing scan cancel signal read through the callback the application supplies to the engine.

**Dev Testing**
- Test level: unit.
- Assert: N requests at limit R take at least the expected time using a fake clock; concurrency never exceeds the cap under parallel callers; request issued after cancel is denied; two scans do not share budgets.

**Dependencies:** DAST-01-010, DAST-00-030
**Blocks:** DAST-01-030, DAST-05-050

**Definition of Done:** code merged + developer tests green

---

### DAST-01-030 Guarded request executor

**Epic:** EPIC-01 Safety Guard & Request Audit        **Parent:** EPIC-01
**Parallelism:** Serial/Blocking    **Sprint:** 1

**Story**
As a developer, I want a single request executor that always goes through the guard so that no engine code can reach the target any other way.

**Acceptance Criteria**
- An executor implements the domain request-executor interface and is the only HTTP client the engine receives.
- Each call: guard decision → send (if allowed) → audit record → response returned with status, headers, body excerpt, timing.
- A denied call returns a structured denial, never an exception that could be swallowed into a send.
- Response bodies are truncated to a configured size before being kept.
- The executor accepts a per-request identity label so audit rows and later role tests can attribute traffic.

**Dev Notes**
- Wrap httpx; accept a transport argument so tests inject the fake target.
- Add an import-rule check (DAST-00-020 style) forbidding `httpx` in `app/dast/nodes/` so stages cannot bypass the executor.

**Dev Testing**
- Test level: unit + integration (fake target).
- Assert: denied request never reaches the transport (assert zero transport calls); allowed request produces exactly one audit row; body truncation; identity label recorded; a stage module importing httpx fails the layering test.

**Dependencies:** DAST-01-010, DAST-01-020, DAST-00-060
**Blocks:** DAST-01-040, DAST-01-050, DAST-05-030, DAST-07-040, DAST-09-010

**Definition of Done:** code merged + developer tests green

---

### DAST-01-040 Browser traffic through the guard

**Epic:** EPIC-01 Safety Guard & Request Audit        **Parent:** EPIC-01
**Parallelism:** Parallel    **Sprint:** 1

**Story**
As an operator, I want the crawling browser's requests to be scope-checked and audited too so that the crawl cannot leave the authorized host.

**Acceptance Criteria**
- Every request the browser makes (navigation, XHR, fetch, sub-resources) is intercepted and decided by the guard before it is sent.
- Out-of-scope requests are aborted in the browser and audited as denied; the page continues loading.
- Allowed requests are audited with the identity label of the active browser context.
- Third-party resources (fonts, analytics) are denied by scope without failing the crawl.
- Navigation to a denied URL is reported in the scan log, not as a crawl failure.

**Dev Notes**
- Use the browser's route-interception hook on each context created by the browser-driver interface; do this in the infrastructure layer.
- Existing `nodes/crawl.py` creates its own context; route its context creation through the driver so it inherits interception (finished in DAST-07-020).

**Dev Testing**
- Test level: integration (`live` marker, uses a local fixture page that references an off-host script).
- Assert: off-host script request aborted and audited; same-host requests pass; page still reaches `load`.

**Dependencies:** DAST-01-030, DAST-01-010
**Blocks:** DAST-07-020

**Definition of Done:** code merged + developer tests green

---

### DAST-01-050 Request audit persistence and retrieval

**Epic:** EPIC-01 Safety Guard & Request Audit        **Parent:** EPIC-01
**Parallelism:** Parallel    **Sprint:** 1

**Story**
As a security reviewer, I want every request a scan sent or was denied recorded so that I can audit exactly what was done to the target.

**Acceptance Criteria**
- Audit rows are written incrementally during the scan using the table from DAST-00-040.
- A new endpoint returns a scan's audit rows, paginated by sequence, with allowed/denied filter.
- Request bodies and credential material are never stored; headers are stored with auth values redacted.
- Audit rows survive scan cancellation and failure.
- The audit endpoint requires the bearer token.

**Dev Notes**
- Batch inserts to avoid per-request commits.
- Reuse the redactor registered in DAST-06-010 for header values; until then redact `Authorization`, `Cookie`, `Set-Cookie`.
- Add proxy route and `api.ts` function.

**Dev Testing**
- Test level: integration.
- Assert: counts match requests issued; denied requests present; no secret strings in any column (seed a known password and search); unauthenticated call rejected; pagination stable.
- Entry point: `GET /scans/{id}/requests`.

**Dependencies:** DAST-01-030, DAST-00-040, DAST-06-010
**Blocks:** DAST-12-030, DAST-16-060

**Definition of Done:** code merged + developer tests green

---

### DAST-01-060 Non-destructive input validator

**Epic:** EPIC-01 Safety Guard & Request Audit        **Parent:** EPIC-01
**Parallelism:** Parallel    **Sprint:** 1

**Story**
As an operator, I want every model-generated test input checked before sending so that a scan never sends input designed to delete, modify or corrupt data.

**Acceptance Criteria**
- A pure domain function accepts a constructed test (method, location, input value) and returns accept or reject with a reason.
- Rejects destructive intent: data-definition or data-manipulation statements, stacked statements, shell command chains that write or delete, file-write or file-delete paths, and any state-changing method while safe mode is on.
- Accepts non-destructive probes (reflection markers, quote characters, boolean-condition probes, time-delay probes, benign path traversal reads).
- Rejected inputs are counted and logged, never sent, and never stored as training data.
- Rules are data-driven (a versioned rule list) so they can be extended without code changes.

**Dev Notes**
- This is a deny-list plus an allow-shape check; neither alone is sufficient. Document the residual risk: a validator reduces, not eliminates, destructive output.
- Keep it in `domain/validation.py`; the active-testing loop (DAST-09-020) must call it, enforced by a test.

**Dev Testing**
- Test level: unit.
- Assert: table of at least 40 payload strings classified correctly, including obfuscated casing and encoding variants of destructive statements; benign probes accepted; method gate interplay; rejection reason recorded.
- Test data: committed fixture file of accepted and rejected inputs.

**Dependencies:** DAST-00-020
**Blocks:** DAST-09-020, DAST-16-050, DAST-16-060

**Definition of Done:** code merged + developer tests green

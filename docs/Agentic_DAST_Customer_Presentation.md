---
marp: true
theme: default
paginate: true
size: 16:9
title: Agentic DAST
description: Customer presentation explaining how the SecureBuild Agentic DAST framework works
---

# Agentic DAST

## Evidence-driven security testing for running applications

**Customer briefing**

<!--
Speaker notes:
Today I will explain how our Agentic Dynamic Application Security Testing framework examines a running application. The key idea is simple: AI helps the scanner understand the application and choose useful tests, while deterministic controls decide what may be sent and what the evidence proves.
-->

---

# The challenge with modern application testing

Traditional scanners work best when every route, parameter, and login flow is already known.

Modern applications make that difficult:

- The browser discovers APIs only after JavaScript runs
- Important functionality sits behind authentication
- Different roles see different pages and data
- API behavior matters more than HTTP status alone
- Large fixed payload lists create noise and unnecessary traffic

**The scanner must understand context before it tests.**

<!--
Speaker notes:
Set the stage with the customer's reality. A modern single-page application may return the same HTML shell for many routes, then load protected data through XHR or fetch. A useful scanner must observe that behavior, maintain the authenticated identity, and distinguish a real security signal from ordinary application behavior.
-->

---

# What Agentic DAST means

Agentic DAST combines two kinds of capability:

| Adaptive reasoning | Deterministic enforcement |
| --- | --- |
| Classifies the application shape | Enforces target scope and allowed methods |
| Understands login pages | Validates every proposed test input |
| Prioritizes useful crawl targets | Sends controlled baseline and test requests |
| Selects relevant checks for each endpoint | Runs repeatable detectors over the responses |
| Explains the observed evidence | Applies the final evidence guardrail |

**The model advises. The security engine controls execution and verdicts.**

<!--
Speaker notes:
This separation is the core design principle. We use model reasoning where context matters, such as recognizing a login form or deciding which checks fit an endpoint. We do not let the model directly send arbitrary traffic or declare a vulnerability without an evidence rule.
-->

---

# End-to-end scan workflow

```text
Seed URL
   |
   v
Connect -> Fingerprint -> Authenticate
   |
   v
Discover pages, forms, APIs and schemas
   |
   v
Build one endpoint inventory
   |
   v
Passive analysis -> Active API tests -> Browser probes
   |
   v
Authorization replay across identities
   |
   v
Evidence guardrail -> Findings -> Report and scan diff
```

Each stage keeps an audit trail of what it observed, tested, skipped, or blocked.

<!--
Speaker notes:
This is the full current pipeline. The original flow continues beyond API testing: browser input probes cover client-side behavior, and authorization replay checks whether lower-privileged or anonymous identities can repeat successful requests.
-->

---

# Connection and fingerprinting

The scan begins with a guarded connection check.

It then determines:

- **Application shape:** server-rendered site, single-page application, or API
- **Authentication:** none, form login, bearer token, or saved session
- **API description:** OpenAPI, Swagger, GraphQL, or observed traffic only

The result controls the rest of the scan. An API-only target does not launch a browser crawl. A web application keeps browser coverage even if a model suggests otherwise.

<!--
Speaker notes:
Fingerprinting uses deterministic evidence first, including content type, HTML structure, known SPA mount points, supplied identities, and discovered schema locations. A model may refine whether HTML looks like a classic site or SPA, but it cannot invent authentication or a schema and cannot hide browser coverage by relabeling HTML as API-only.
-->

---

# Authentication and identity isolation

Each configured identity receives an isolated session.

Supported approaches:

- Form login through a guarded Chromium browser
- Bearer or custom token headers
- Saved browser session state
- Recorded login traffic for flows that cannot be automated safely

If an identity cannot authenticate, the scan reports the named identity and stops instead of silently continuing with reduced coverage.

Complex SSO, CAPTCHA, and one-time-code flows require a pre-authenticated session or recorded login.

<!--
Speaker notes:
Identity isolation matters because later authorization checks depend on knowing which requests belong to which user or role. Credentials stay in memory during the scan. The stored scan configuration contains identity labels and methods, not secrets.
-->

---

# Application discovery

Discovery combines browser and network evidence:

```text
Authenticated browser
        |
        +---- HTML links and forms
        |
        +---- XHR and fetch traffic
        |
        +---- OpenAPI or GraphQL operations
        |
        +---- Recorded request shapes and parameters
                         |
                         v
                Endpoint inventory
```

The crawl uses page, depth, time, and repeated-pattern budgets. The model prioritizes useful URLs, while the engine enforces those limits.

<!--
Speaker notes:
The latest crawler discovers navigation passively from real anchors and forms. It does not click generic buttons during discovery. This avoids accidentally triggering controls such as logout, delete, or language-switch actions. The browser still records the APIs that the application itself calls.
-->

---

# One inventory, built from several sources

The endpoint inventory merges:

- Browser-observed requests
- Form actions and input fields
- Request bodies and parameter names
- OpenAPI or Swagger operations
- GraphQL introspection when allowed

Observed and documented endpoints can then be compared.

This reveals:

- APIs the browser actually exercised
- Documented operations that were never reached
- Undocumented or legacy endpoints that need review
- The identity associated with each observation

<!--
Speaker notes:
The inventory is the handoff between discovery and testing. It preserves real request shapes, which makes later tests more relevant than sending generic payloads to guessed URLs. Schema ingestion adds documented operations that the browser may not reach in one journey.
-->

---

# Passive analysis comes first

Passive checks inspect traffic already recorded during discovery.

Examples include:

- Content Security Policy and security headers
- Cookie flags and session properties
- CORS behavior
- Technology or error disclosure
- Sensitive data exposure
- TLS configuration

**Passive analysis sends no additional application request.**

The configured model may improve severity and reproduction guidance, but deterministic detectors decide whether the condition exists.

<!--
Speaker notes:
Passive analysis is low risk and gives value before active testing starts. Customers can also select the passive-only rule pack, which ends the scan after this stage.
-->

---

# Rules are resolved for each scan

The current catalog contains **59 checks** and **5 rule packs**.

Rule selection can combine:

- OWASP API Security Top 10
- OWASP Web Application Top 10
- OWASP Web Security Testing Guide coverage
- Passive-only checks
- Thorough checks that require explicit opt-in
- Project and scan-level overrides
- Versioned custom rules

The scan stores the effective rule set and settings snapshot, so the report can explain exactly what ran.

<!--
Speaker notes:
Checks are data, not hard-coded prompt text. Each definition names its severity, standards, eligible locations, operating mode, detector signals, dependencies, and remediation reference. The effective rule set is frozen at scan start for repeatability.
-->

---

# Active API testing loop

For each eligible endpoint:

```text
Choose relevant checks and propose minimal inputs
                      |
                      v
Validate method, shape, scope and payload safety
                      |
                      v
Send a baseline request
                      |
                      v
Send the controlled test request
                      |
                      v
Compare responses with deterministic detectors
                      |
                      v
Interpret evidence and apply the guardrail
```

Target and per-endpoint caps bound how much traffic the stage can generate.

<!--
Speaker notes:
The baseline matters because many application responses are noisy by default. The engine compares the test with the endpoint's ordinary behavior. If the model is unavailable or returns unusable proposals, the stage can fall back to a conservative deterministic set rather than sending arbitrary inputs.
-->

---

# The LLM has a bounded role

The model helps with tasks that benefit from context:

- Application shape refinement
- Login-field and action selection
- Crawl prioritization
- Check and input construction
- Evidence explanation
- Operator-facing narration

Every model response must match a task-specific JSON schema. An invalid response receives one repair attempt, then the engine uses a deterministic fallback.

Provider, model, token usage, estimated cost, fallbacks, and repairs are recorded per scan.

<!--
Speaker notes:
Model routing is task-specific. Different tasks can use different configured providers or models. The gateway validates structured output and redacts errors. Most importantly, model output remains advice until the surrounding engine validates and applies it.
-->

---

# Safety controls around every request

The execution boundary enforces:

- Same-target scope, including redirect checks
- Allowed HTTP methods
- Rate and concurrency limits
- Cancellation before new work begins
- Maximum response-body size
- Input length and control-character limits
- Decoded payload inspection for destructive patterns
- Foreign-host rejection, except an approved OAST host
- Redacted request auditing

State-changing tests require explicit opt-in **and** a disposable target.

<!--
Speaker notes:
The model never owns the network client. Every HTTP request passes through the guarded executor, and browser traffic passes through equivalent interception. Safe mode blocks state-changing methods except tightly bounded login and inert marker windows.
-->

---

# Browser and authorization testing

## Browser probes

The scanner types inert markers into discovered inputs and checks whether the browser executes them. Execution confirms browser-side XSS. Reflection without execution remains a review item.

## Authorization replay

The scanner replays successful requests as lower-privileged identities and as an anonymous visitor. It looks for broken authentication, BOLA, and BFLA behavior.

One authenticated identity supports anonymous replay. Two or more identities provide meaningful cross-role coverage.

<!--
Speaker notes:
These stages cover evidence that a simple baseline and response pair cannot prove. Browser execution is required for confirmed browser XSS. Authorization replay uses the request inventory and isolated sessions to compare access across identities.
-->

---

# Evidence decides the finding status

```text
Model advice + baseline/test responses
                  |
                  v
        Deterministic detectors
                  |
                  v
             Guardrail
          /             \
         v               v
True positive       Needs review
Proving signal      Suspicion without proof
```

- A proving detector signal can confirm a finding even when the model proposed PASS
- A model FAIL without a proving signal remains unverified
- A PASS without a signal produces no finding
- False-positive decisions remain visible as dismissed results

This keeps model judgment from becoming unsupported vulnerability proof.

<!--
Speaker notes:
Examples of proving signals include a database error, a controlled timing change, browser marker execution, an out-of-band callback, or an authorization boundary crossing. Severity totals count confirmed findings only. Unverified results stay separate so customers can see where evidence was insufficient.
-->

---

# What the customer receives

Each completed scan provides:

- Confirmed, unverified, and dismissed findings
- Severity, OWASP, API Security, WSTG, and CWE mappings
- Baseline and test evidence
- Reproduction guidance and remediation references
- Pages, forms, endpoints, and identities discovered
- Tested, skipped, capped, and degraded coverage
- Authorization role-pair results
- Request audit references with secrets redacted
- Comparison with an earlier scan
- PDF and Excel exports

The report distinguishes a clean result from an incomplete scan.

<!--
Speaker notes:
Coverage honesty is important. If the scan loses a session, reaches a target cap, lacks a second identity, or runs without OAST, the report states that limitation. A completed pipeline does not automatically mean complete security coverage.
-->

---

# A practical scan story

```text
1. Sign in as an employee user
2. Discover /home, /employees and /employees/new
3. Observe GET /api/employees in browser traffic
4. Build the endpoint inventory
5. Check recorded responses for passive issues
6. Select relevant active checks for each API
7. Validate every proposed input
8. Compare baseline and test responses
9. Replay eligible requests as anonymous or another role
10. Report findings with evidence and coverage limits
```

The operator can follow the same sequence in the live timeline and request audit.

<!--
Speaker notes:
Use this as the demo talk track. Point out that discovery no longer clicks generic controls, so the crawler does not sign itself out while mapping the application. If the target itself expires a session, the scanner can perform one bounded re-login and report the coverage impact.
-->

---

# Deployment expectations and boundaries

Agentic DAST tests a **running application**. It does not replace source-code review, dependency scanning, or manual business-logic testing.

For useful coverage, provide:

- Written authorization to test the target
- Stable test data and a controlled environment
- Representative user identities and role labels
- A saved session for complex authentication
- An OAST callback service when confirming SSRF
- A disposable target before enabling mutating tests

Some risks remain assist-only when the scanner cannot prove them safely from outside the application.

<!--
Speaker notes:
Set expectations clearly. Business-flow abuse and trust in upstream APIs often require human context. CAPTCHA and MFA should not be bypassed. Load-generating and state-changing checks stay off until the operator explicitly enables them for a suitable environment.
-->

---

# The outcome

Agentic DAST provides a controlled path from an unknown running application to evidence-backed findings.

It combines:

- Browser and API discovery based on real application behavior
- Adaptive test selection for each endpoint
- Deterministic validation, detection, and verdict controls
- Multi-identity authorization testing
- Transparent evidence, coverage, and model usage

**The result is a scan that can adapt without giving up control or auditability.**

<!--
Speaker notes:
Close on the operating model. Adaptability helps the scanner find relevant paths and tests. Deterministic controls keep execution bounded and results defensible. The customer can see what happened, what evidence supports each result, and where coverage was limited.
-->

---

# Discussion

## Suggested next questions

- Which application and environment should we demonstrate?
- Which identities represent the customer's real authorization boundaries?
- Should the first scan use passive-only, light, standard, or deep intensity?
- Which state-changing checks can the test environment safely support?
- What evidence and export format does the customer need for their workflow?

<!--
Speaker notes:
Use these questions to move from explanation into scoping a pilot. The answers determine identities, intensity, rule packs, safe mode, and reporting expectations.
-->

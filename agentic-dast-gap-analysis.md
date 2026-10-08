# Agentic DAST — Gap Analysis vs Burp Suite & Commercial DAST

**Scope:** Feature gap analysis of the Agentic DAST engine against Burp Suite (Pro/DAST), OWASP ZAP,
Invicti, Acunetix, StackHawk and Nuclei — mapped stage-by-stage onto the existing LangGraph pipeline.

**Date:** 2026-10-08

---

## How to read this document

Two kinds of content are kept separate:

- **Gap tables** — a feature is listed as missing because it is **not present in the source
  walkthrough document** (`Agentic DAST — How It Works`). Some items may already exist in the
  codebase; verify before using any of this externally.
- **Priority column, Part B flow, and Part C phasing** — these are **recommendations**, not
  document-sourced facts.

**Priority key**

| Label | Meaning |
|---|---|
| **P0** | Blocks credibility in a head-to-head against Burp / Invicti |
| **P1** | Needed for real-world client use |
| **P2** | Depth, scale, or differentiation |

---

## Part A — Gaps mapped to the pipeline

### A.1 `check_connection`

**Present:** one preflight GET through the guard; failure classification (DNS / refused / timeout /
TLS / off-scope redirect / 5xx); failure ends the scan immediately.

| Missing | Why it matters | Priority |
|---|---|---|
| TLS/SSL configuration analysis — cert validity, chain, expiry, TLS version, weak ciphers | Free findings at zero request cost; reported by every competitor | P1 |
| WAF / CDN detection | A WAF silently blocking payloads turns the scan into a false-negative machine; it must be detected and reported | P0 |
| `robots.txt` / `sitemap.xml` / `security.txt` pickup | Cheap seed URLs for discovery | P1 |
| Proxy / internal-network target support | Client environments are rarely internet-facing | P1 |

---

### A.2 `fingerprint`

**Present:** MPA / SPA / API-only shape detection, auth style, OpenAPI/Swagger/GraphQL schema
probe, LLM `fingerprint` task with heuristic fallback.

| Missing | Why it matters | Priority |
|---|---|---|
| Technology + **version** fingerprinting (server, framework, CMS, JS libraries) | Prerequisite for CVE matching; also drives smarter check selection | P0 |
| **Known-CVE matching** from fingerprint (Nuclei-style template matching) | A large volume of real, high-severity findings that cannot currently be produced at all | P0 |
| Vulnerable JS library detection (Retire.js equivalent) | Standard expected output | P1 |
| Additional spec sources: SOAP/WSDL, gRPC reflection, **Postman collection import**, **HAR import** | How API teams actually hand over their surface; HAR/Postman import is the fastest coverage win available | P1 |
| WebSocket endpoint detection | Currently an unscanned protocol | P2 |
| GraphQL introspection dump as a discovery step (not just schema presence) | Yields the full GraphQL surface | P1 |

---

### A.3 `authenticate` / `classify_login_type`

**Present:** one isolated browser/session per identity; token header, saved cookies, or real form
login; LLM `login_selectors` task with hard-coded selector fallback; one re-login per identity on
401/403. The scan **stops** when the login type is multi-step, SSO, CAPTCHA or OTP.

| Missing | Why it matters | Priority |
|---|---|---|
| **Multi-step login** support (step sequence) | Documented hard stop; most enterprise apps are multi-step | P0 |
| **SSO / OAuth2 / OIDC** flow handling | Documented hard stop; most enterprise apps | P0 |
| **Recorded login sequence import** (Burp login-recorder equivalent) | The universal escape hatch — covers all four stop cases without per-flow code | P0 |
| **Session-handling rules / macros** — refresh token mid-scan, re-fetch CSRF token per request | One re-login per identity is insufficient for long scans; an expired session produces silent false negatives | P0 |
| **Anti-CSRF token handling** (extract and replay per request) | Without it, every state-changing test fails for the wrong reason | P0 |
| **OTP/TOTP** support (seed-based) and CAPTCHA manual-assist | Remaining documented hard stops | P1 |
| Active session-validity checking (not only reactive on 401/403) | Detect logout/expiry before wasting the remainder of the scan | P1 |

---

### A.4 `discover`

**Present:** per-identity crawl; pages, forms and XHR recorded; API schema ingestion; observed vs.
documented endpoint diff; LLM `crawl_plan` task with FIFO fallback.

| Missing | Why it matters | Priority |
|---|---|---|
| **JS bundle parsing for endpoints** | In SPAs most API routes exist only inside bundles and are never linked — the single biggest coverage gap for modern apps | P0 |
| **Forced browsing / content discovery** (wordlists: admin panels, backup files, `.git`, `.env`, source maps, swagger at common paths) | Crawling only finds what is linked; standard in every competing tool | P0 |
| Hidden / undocumented **parameter discovery** | Otherwise unreachable attack surface | P1 |
| URL normalization and pattern collapsing (`/user/1`, `/user/2` → one template) | Prevents the `max_targets` budget being spent on duplicates | P1 |
| Configurable crawl depth / scope / exclusions | Operational control | P1 |
| **Coverage reporting when `max_targets` truncates** | Today a capped scan is indistinguishable from a complete one | P1 |
| Sitemap / robots seeding into the crawl frontier | Cheap win | P1 |

---

### A.5 `passive_analysis`

**Present:** zero-request checks over recorded traffic — headers, CSP/HSTS, cookies, CORS, error
disclosure.

| Missing | Why it matters | Priority |
|---|---|---|
| **Secrets / API keys in JS and responses** | High severity, zero request cost, high client impact | P0 |
| **Source map exposure** (`.js.map`) | Leaks full application source; common and trivially detectable | P1 |
| Sensitive data exposure — PII, stack traces, internal IPs/hostnames, email harvesting | Standard reporting expectation | P1 |
| Vulnerable JS library versions (ties to A.2) | Standard expected output | P1 |
| Clickjacking, mixed content, cacheable sensitive responses, verbose server banners | Rounds out the passive set | P2 |

---

### A.6 `analyze_apis` — the active loop (largest gap area)

**Present:** `construct → validate → baseline → test → detect → rule → roll-up`; `input_gate.py`
validation of model-proposed inputs; guarded executor sends baseline and test; pure-code detectors;
advisory `rule` verdict; guardrail requires a non-model signal for `true_positive`. One request at a
time. State-changing methods **denied by default**.

#### A.6.1 Infrastructure gaps

| Missing | Why it matters | Priority |
|---|---|---|
| **OAST / out-of-band collaborator** (DNS + HTTP callback server) | The single biggest detection gap. Without it, blind SQLi, blind SSRF, blind XXE, blind command injection and blind XSS are all invisible. This is Burp Collaborator's entire value proposition | **P0 — top item** |
| **"Full mode" with controlled write methods** (POST / PUT / PATCH / DELETE) on scoped, disposable targets | Write methods are denied by default per the document. Most real API vulnerabilities — mass assignment, IDOR on writes, body injection — live behind write methods, so safe-mode-only caps the engine at a fraction of achievable findings | **P0** |
| Configurable **concurrency** (currently one request at a time) | A serial scanner cannot finish a real application inside a client engagement window | P0 |
| Per-check budget and coverage accounting | Needed to know what was *not* tested | P1 |

#### A.6.2 Vulnerability-class gaps

None of the following appear in the source document.

| Class | Notes | Priority |
|---|---|---|
| **SQL injection** — error-based, boolean-blind, time-based, out-of-band | The most expected check in any DAST tool | P0 |
| **Command injection** — direct and blind/time-based | Core injection class | P0 |
| **Path traversal / LFI / RFI** | Core injection class | P0 |
| **SSRF** (requires OAST) | High severity, cloud-metadata impact | P0 |
| **XXE** (including blind via OAST) | Core injection class | P0 |
| **SSTI** (server-side template injection) | Frequently leads to RCE | P0 |
| **Open redirect** | Easy to detect, universally expected | P0 |
| **JWT attacks** — `alg:none`, weak secret, `kid` manipulation, expired-accepted, signature stripping | Very common real finding in API-first applications | P0 |
| **NoSQL injection** | Modern stacks (Mongo, etc.) | P1 |
| **Mass assignment / excessive data exposure** (OWASP API3 / API6) | Requires write mode | P1 |
| **Missing rate limiting** (OWASP API4) | Standard API check | P1 |
| **CSRF** — token absence and validation weakness | Standard check | P1 |
| **Unrestricted file upload** — type, path, webshell | High severity when present | P1 |
| **CRLF / HTTP header injection** | Standard check | P1 |
| **GraphQL suite** — introspection enabled, batching abuse, depth/complexity DoS, field suggestion leakage | Schemas are already ingested; the checks are the missing half | P1 |
| **Insecure deserialization** | Hard to detect generically | P2 |
| **LDAP / XPath injection** | Lower frequency | P2 |
| **HTTP request smuggling** | Burp's flagship differentiator | P2 |
| **Web cache poisoning / cache deception** | Advanced class | P2 |
| **Prototype pollution** (server and client side) | Modern JS class | P2 |
| **Race conditions** | Requires concurrent request primitives | P2 |
| **Business-logic flaws** | Genuinely hard; the clearest place for the LLM layer to differentiate later | P2 |

---

### A.7 `browser_probe`

**Present:** inert marker typed into crawled query parameters and visible form inputs (including
search boxes with no `<form>`); reflected-XSS failures reloaded with the marker; promotion to
`true_positive` only if `window.__dast_<id>` is set; stored-XSS marker POST off by default and
gated on opt-in plus a disposable target.

| Missing | Why it matters | Priority |
|---|---|---|
| **DOM XSS source → sink taint analysis** | Marker-only testing misses DOM sinks that require specific source formats (hash, `postMessage`, `document.referrer`) | P1 |
| **Blind XSS** (requires OAST callback) | Admin-panel XSS triggered by user-submitted data is invisible without an out-of-band callback | P1 |
| Sensitive data in `localStorage` / `sessionStorage` | Easy win from the browser already being driven | P1 |
| `postMessage` handler testing | Common modern DOM bug class | P2 |
| Client-side prototype pollution, DOM clobbering | Advanced DOM classes | P2 |

---

### A.8 `check_authorization`

**Present:** replays one identity's already-successful requests as every other identity including
Anonymous; role-pair matrix derived mechanically from replay outcomes; covers OWASP API1/API5 with
no model involvement.

| Missing | Why it matters | Priority |
|---|---|---|
| **Object-level IDOR via ID mutation** — replay identity A's request carrying identity B's *object IDs*, not merely replaying the same request as identity B | The current design catches endpoint-level access control; this catches the far more common per-object IDOR | P0 |
| Authorization testing on **write methods** | Depends on full mode; read-only replay misses escalation-by-write | P0 |
| **Function-level access control** — probe admin-only paths as a low-privileged user (ties to forced browsing) | OWASP API5 proper | P1 |
| **Token / JWT tampering for privilege escalation** (role claim edit, `sub` swap) | Common real-world escalation path | P1 |
| Horizontal vs. vertical escalation classification in the matrix | Reporting clarity | P2 |

---

### A.9 Post-graph — reporting, triage and platform

**Present:** incremental `Finding` rows written during the active loop; `Scan.metadata_json`
discovery dict; live progress from `### DAST: <phase>` stdout banners; `narrate` task for UI
narration; PDF/XLSX reports; diff against the previous scan on the same target;
authorization-matrix view; mock vs. real engine split for CI.

| Missing | Why it matters | Priority |
|---|---|---|
| **CVSS v3.1/v4 vectors + CWE IDs + OWASP Top 10 2021 / API Top 10 2023 mapping** | Clients and auditors will not accept findings without these | P0 |
| **Full request/response evidence per finding, highlighted proof, cURL reproduction command** | Developers cannot fix what they cannot reproduce; the guardrail story is only *provable* when evidence is attached | P0 |
| **Finding triage lifecycle** — false positive, accepted risk, suppression rules, baseline, status, assignee, comments, audit trail | Without it every rescan re-reports everything; unusable past the second scan | P0 |
| **SARIF + JSON/JUnit output, exit-code gating by severity** | The entry ticket to CI/CD | P0 |
| **Published benchmark results** — Juice Shop / DVWA / WAVSEP / OWASP Benchmark, with detection rate and false-positive rate | The first question any technical buyer asks; also the regression safety net for all the new checks above | P0 |
| **Single-finding re-test** ("verify fix") | Core remediation loop | P1 |
| **CI/CD integrations** — GitHub Action, GitLab template, Jenkins, Azure DevOps, PR annotations | Where DAST is actually bought today (StackHawk's entire thesis) | P1 |
| **Jira / ServiceNow / Slack / Teams / generic webhook / DefectDojo** integration | Expected enterprise workflow | P1 |
| **Scheduling, scan profiles (quick / standard / deep), pause/resume/checkpoint, scan queue** | Operational basics | P1 |
| **RBAC, multi-tenancy, platform SSO, audit log, API keys** | Required for multi-client or enterprise deployment | P1 |
| Compliance views — PCI DSS, ISO 27001, SOC 2 | Sales enabler | P2 |
| Distributed scan agents / internal-network scanning | Scale and client-network reach | P2 |
| **Custom check definitions** (YAML / Nuclei-style templates) | Lets clients add their own checks without code changes | P2 |
| Manual replay / repeater UI, extension hooks | Pentester usability — Burp's real moat | P2 |

---

## Part B — Target flow after the gaps are closed

> **Recommendation.** New or changed stages are marked in **bold**.

```
check_connection ──→ **tls_scan** ──→ **waf_detect**
                                           │
                                           ▼
                            fingerprint  (+ **tech/version → CVE match**)
                                           │
                                           ▼
                     classify_login_type ──→ authenticate
                     (**multi-step / SSO / OTP / recorded-login import**,
                      **session rules + CSRF token macro**)
                                           │
                                           ▼
                                      discover
                     (crawl + **JS bundle endpoint extraction**
                      + **forced browsing** + sitemap/robots seed
                      + **param discovery** + **URL normalization**
                      + **HAR / Postman import**)
                                           │
                                           ▼
                                 passive_analysis
                     (+ **secrets**, **source maps**, **vuln JS libs**, PII)
                                           │
                                           ▼
                                    analyze_apis
                     (**safe | full mode**, **concurrent**,
                      **injection suite: SQLi / cmd / traversal / XXE /
                      SSTI / SSRF / redirect / JWT / NoSQL / upload**,
                      **OAST-backed blind variants**)
                                           │
                                           ▼
                              **oast_collect**  ◄── async DNS/HTTP callbacks
                              (correlates late blind hits back to findings)
                                           │
                                           ▼
                                   browser_probe
                     (+ **DOM source→sink taint**, **postMessage**,
                      **storage secrets**, **blind XSS via OAST**)
                                           │
                                           ▼
                                check_authorization
                     (+ **object-ID mutation IDOR**, **write-method escalation**,
                      **admin forced-browse as low-priv**, **token tampering**)
                                           │
                                           ▼
                        **score_and_map**  (CVSS · CWE · OWASP · compliance)
                                           │
                                           ▼
                        **persist_evidence**  (req/resp pair, proof, cURL)
                                           │
                                           ▼
                   report · diff · **SARIF/CI gate** · **triage queue** · **Jira push**
                                           │
                                          END
```

### Two structural notes on this flow

**1. `oast_collect` must be a real graph node, not a side effect.**
Out-of-band callbacks arrive *after* the request that triggered them — sometimes seconds or minutes
later. The graph needs a stage that waits briefly and correlates late callbacks back to the finding
that caused them. Without it, blind findings are discovered and then dropped.

**2. The existing guardrail principle survives unchanged — and gets stronger.**
An OAST callback is an ideal non-model proving signal, exactly like the existing browser marker.
The rule does not change, only the evidence types expand:

> `true_positive` requires a detector signal, an executed browser marker, **or** a correlated OAST hit.

---

## Part C — Suggested phasing

> **Recommendation.**

| Phase | Theme | Contents |
|---|---|---|
| **0** | Cannot demo credibly without these | OAST infrastructure · core injection suite (SQLi, command, traversal, XXE, SSTI, SSRF, open redirect, JWT) · full-mode write methods · concurrency · CVSS/CWE/OWASP mapping · request/response evidence · triage lifecycle · benchmark run |
| **1** | Real-world coverage | JS endpoint extraction · forced browsing · recorded-login import + session/CSRF rules · tech fingerprint + CVE matching · secrets + source maps · object-ID IDOR · WAF detection · SARIF + CI gating |
| **2** | Workflow and platform | CI/CD plugins · Jira/Slack/webhook · scheduling + scan profiles · single-finding re-test · RBAC / multi-tenancy / audit log · HAR + Postman import |
| **3** | Depth and scale | DOM taint analysis · GraphQL check suite · request smuggling / cache poisoning / prototype pollution / race conditions · distributed agents · compliance views |
| **4** | Differentiation | Custom YAML check templates · manual replay UI · LLM-assisted business-logic testing — the clearest moat, since no competitor has the model layer |

---

## Part D — Where the engine is already strong

From the source document, these are genuine architectural advantages over classic scanners:

- **Model advises, code decides.** A `true_positive` always requires a non-model signal — a detector
  hit or an executed browser marker. The model cannot manufacture a finding.
- **One safety guard for everything.** `domain/policy.py`, `guarded_executor.py`,
  `browser_guard.py` and `input_gate.py` cover HTTP and browser traffic alike, with every call
  audited and only two narrow, explicitly logged POST exceptions.
- **Per-task provider routing with deterministic fallbacks.** Six narrow tasks, each independently
  routable across Ollama / Anthropic / OpenAI / Bedrock, each with a fallback, plus unified cost
  accounting and a cost cutoff. A model outage degrades the scan rather than stopping it.
- **Fully local operation is possible** (Ollama default, no data leaves the machine) — a real
  differentiator for regulated and air-gapped clients.
- **Mechanically derived authorization matrix** across identities, with no model reasoning about
  roles.
- **LLM-assisted login selectors and crawl prioritization** — capabilities classic scanners do not
  have at all.

---

## Part E — Positioning caution

> **Recommendation / commercial judgment.**

The strengths in Part D are **architectural**, not **coverage** advantages. On raw vulnerability-class
detection, Burp Suite will out-detect this engine today. Buyers compare findings first and design
second, so Phase 0 is what makes the architecture argument land in a client conversation.

Until Phase 0 ships, position the engine as an **AI-augmented, safety-first DAST layer** — strong on
auditability, authorization testing, provable findings and local/air-gapped operation — rather than
as a Burp replacement.

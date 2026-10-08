## [EPIC-08] Passive Analysis

**Goal:** Find header, cookie, CORS, disclosure, error and data-exposure issues from already-observed traffic, with no extra requests and no model calls.
**Depends On:** EPIC-03, EPIC-04, EPIC-07 (recorded traffic)
**Blocks:** EPIC-11
**Teams:** Dev

Requirements: REQ-FR-PASS-1 to -7. Passive findings are high-confidence because they are directly observed.

---

### DAST-08-010 Passive stage and header/cookie checks

**Epic:** EPIC-08 Passive Analysis        **Parent:** EPIC-08
**Parallelism:** Serial/Blocking    **Sprint:** 2

**Story**
As a security engineer, I want missing or weak security headers and cookie flags reported from observed traffic so that I get quick, risk-free findings.

**Acceptance Criteria**
- A passive stage consumes the recorded traffic and sends no request and makes no model call (asserted in test).
- Reports: missing or weak security headers (content security policy, frame protections, content-type sniffing protection, transport security on HTTPS, referrer policy); cookies lacking HttpOnly, Secure or SameSite.
- Each finding names the response (URL, status) it was observed on, with the header or cookie evidence.
- Results are deduped by `(check, header/cookie name)` across the whole scan, not once per response.
- Only checks enabled in the effective rule set run; with the `passive-only` pack the scan stops after this stage.
- Banner `### DAST: passive analysis`.

**Dev Notes**
- New `app/dast/passive.py` and `nodes/passive_analysis.py`; checks are pure functions over a recorded response.
- Findings use verdict `true_positive`, confidence HIGH, via the standard writer.
- Transport-security header applies only to HTTPS responses.

**Dev Testing**
- Test level: unit.
- Assert: each header absent/present/weak; cookie flag combinations; HTTP vs HTTPS handling; dedupe across 50 identical responses; zero requests made (executor and gateway fakes assert no calls).
- Test data: recorded response fixtures.

**Dependencies:** DAST-07-030, DAST-04-050, DAST-03-030
**Blocks:** DAST-08-020, DAST-08-030

**Definition of Done:** code merged + developer tests green

---

### DAST-08-020 CORS and technology disclosure

**Epic:** EPIC-08 Passive Analysis        **Parent:** EPIC-08
**Parallelism:** Parallel    **Sprint:** 2

**Story**
As a security engineer, I want over-permissive cross-origin settings and server or version disclosure reported so that misconfiguration is visible.

**Acceptance Criteria**
- CORS: wildcard origin combined with credentials, reflected arbitrary origin, and `null` origin allowed are each reported with the observed header values.
- Disclosure: server, framework and version leaks in headers (server, powered-by) and common meta tags.
- Severity depends on credentials/sensitivity of the endpoint, per the catalog entry.
- No additional requests are sent: reflected-origin detection uses only requests already made with an `Origin` header; if none exist, the check reports "not assessable" rather than probing.

**Dev Notes**
- Active CORS probing (sending test origins) is a separate active check in EPIC-09, off by default.

**Dev Testing**
- Test level: unit.
- Assert: each CORS condition; no false positive for specific allowed origin; disclosure of version string; "not assessable" state.

**Dependencies:** DAST-08-010
**Blocks:** DAST-11-010

**Definition of Done:** code merged + developer tests green

---

### DAST-08-030 Verbose errors and sensitive data exposure

**Epic:** EPIC-08 Passive Analysis        **Parent:** EPIC-08
**Parallelism:** Parallel    **Sprint:** 2

**Story**
As a security engineer, I want verbose errors, stack traces and sensitive data in responses reported so that information disclosure is found without testing.

**Acceptance Criteria**
- Reports: stack traces and framework error pages, database error text, internal paths and addresses, and sensitive patterns in responses (keys, tokens, personal-data-like fields).
- Evidence excerpts are redacted for the sensitive match itself (only the pattern type and location are kept, not the full secret).
- Pattern lists are data files, extensible without code change.
- A finding is `true_positive` only when the pattern is directly observed; ambiguous matches are `unverified`.

**Dev Notes**
- Reuse the leakage detectors from DAST-04-020 where applicable so the same signal definition serves passive and active.
- Be conservative with personal-data patterns; document precision limits.

**Dev Testing**
- Test level: unit.
- Assert: each pattern family positive and negative; secret redaction in evidence; ambiguous match → unverified; base64/JWT-looking noise does not trip.

**Dependencies:** DAST-08-010, DAST-04-020
**Blocks:** DAST-11-010

**Definition of Done:** code merged + developer tests green

## [EPIC-06] Authentication & Identities

**Goal:** Scans can authenticate by form, token or stored session, as one or several role-labelled identities, with credentials held in memory only and redacted everywhere.
**Depends On:** EPIC-01, EPIC-05
**Blocks:** EPIC-07 (authenticated crawl), EPIC-10
**Teams:** Dev

Requirements: REQ-FR-AUTH-1 to -8, REQ-FR-ROLE-1, -2, REQ-SEC-1 to -3, REQ-CON-6. Existing: `nodes/classify_login_type.py`, `nodes/login.py`, `--storage-state` entry.

---

### DAST-06-010 Credential holder and log redaction

**Epic:** EPIC-06 Authentication & Identities        **Parent:** EPIC-06
**Parallelism:** Serial/Blocking    **Sprint:** 1

**Story**
As a security reviewer, I want credentials held only in memory and masked in every log so that a scan can never leak a password or token.

**Acceptance Criteria**
- A credential holder implements the domain interface: store per identity, read for the engine, clear all at scan end (success, failure and cancel).
- Every stored secret value is registered with the redactor before any log line can contain it; redaction covers the scan log, narration input, error messages and audit headers.
- Nothing from the holder is written to the database, `metadata_json`, narration cache or exports.
- A process restart mid-scan leaves no credentials; the scan fails with "credentials lost" (see DAST-06-050).
- Tokens and session cookies are treated as secrets, not just passwords.

**Dev Notes**
- Build on the existing in-memory secrets path in `scan_runner` and the `scan_log` capture so the redactor sits where lines are captured.
- Redact by exact value and by common encodings (URL-encoded, base64 of `user:pass`).

**Dev Testing**
- Test level: unit + integration.
- Assert: seed password/token/cookie then run a mock scan and search scan log, narration, metadata, findings, exports and audit rows for the values (none found); holder empty after success, failure and cancel.

**Dependencies:** DAST-00-020
**Blocks:** DAST-01-050, DAST-06-020, DAST-06-050, DAST-16-050, DAST-16-060

**Definition of Done:** code merged + developer tests green

---

### DAST-06-020 Identity model and per-identity sessions

**Epic:** EPIC-06 Authentication & Identities        **Parent:** EPIC-06
**Parallelism:** Serial/Blocking    **Sprint:** 1

**Story**
As an operator, I want to add several identities, each with a role, so that the engine can later test access across roles.

**Acceptance Criteria**
- An identity has: label, role (`Admin|User|Viewer|Anonymous|Custom`), custom role name when `Custom`, and one auth method (form, token, pre-auth state).
- An Anonymous identity is added implicitly if not supplied and cannot be removed.
- The engine's run state holds one authenticated session per identity, each isolated (separate browser context and separate HTTP client state).
- Labels are unique within a scan; duplicates are rejected at creation.
- A scan with a single identity behaves exactly as today.
- A scan with no authenticated identity runs unauthenticated as the Anonymous identity only (REQ-FR-AUTH-1); no login stage runs.

**Dev Notes**
- Run-state structure change in `state.py`; keep the existing single-credential keys working until all stages are migrated.
- Isolation matters: cookies from one identity must never be sent as another.

**Dev Testing**
- Test level: unit + integration (fake target with two users).
- Assert: sessions isolated (request as User never carries Admin cookie, checked via audit identity labels and fake target logs); implicit Anonymous present; duplicate label rejected; single-identity regression.

**Dependencies:** DAST-06-010, DAST-05-010
**Blocks:** DAST-06-030, DAST-06-040, DAST-10-010

**Definition of Done:** code merged + developer tests green

---

### DAST-06-030 Form login adaptation

**Epic:** EPIC-06 Authentication & Identities        **Parent:** EPIC-06
**Parallelism:** Parallel    **Sprint:** 1

**Story**
As an operator, I want form login to work per identity with reliable success detection and one retry so that authenticated areas are actually reached.

**Acceptance Criteria**
- The existing login node runs once per form-login identity through the guarded browser context.
- Success is decided by more than one signal (post-login indicator, URL change, credential field gone); a single weak signal is not enough.
- One bounded retry on failure; a second failure ends that identity's login with a clear reason.
- Selector proposals use the `login_selectors` gateway task with the existing hard-coded fallback list.
- Login types detected as multi-step, OAuth/SSO, CAPTCHA or OTP are reported as "not automated, use pre-authenticated state" (REQ-CON-6).
- If any required identity fails to authenticate, the scan fails with the identity label and reason rather than continuing partially.

**Dev Notes**
- `nodes/login.py` already has selector guessing, fallback and success verification; adapt it to take an identity rather than global credentials.
- Do not log the filled form values.

**Dev Testing**
- Test level: unit (scripted gateway) + `live` (practice target login).
- Assert: success only with multiple signals; retry once; unsupported login types message; failure text names identity; fallback selectors used when the gateway fails.

**Dependencies:** DAST-06-020, DAST-05-040
**Blocks:** DAST-06-050, DAST-07-020

**Definition of Done:** code merged + developer tests green

---

### DAST-06-040 Token and pre-authenticated state

**Epic:** EPIC-06 Authentication & Identities        **Parent:** EPIC-06
**Parallelism:** Parallel    **Sprint:** 1

**Story**
As an operator, I want to supply a bearer token, JWT, API key or a saved browser session so that I can scan targets with SSO, MFA or CAPTCHA.

**Acceptance Criteria**
- Token identities: the token is injected on every request for that identity (header name and scheme configurable, default `Authorization: Bearer`).
- Pre-auth identities: an uploaded browser storage-state file seeds that identity's browser context and cookies; login stages are skipped.
- Uploaded files are validated (size cap, JSON structure) and kept only in memory for the scan.
- Both methods are redacted (DAST-06-010) and never stored.
- An invalid or expired token/session is detected by a probe request and fails the scan with a clear message.

**Dev Notes**
- `python-multipart` is already available for upload parsing.
- The existing `--storage-state` entry in `graph.route_entry` becomes the per-identity behaviour.

**Dev Testing**
- Test level: unit + integration.
- Assert: header injected for that identity only; storage-state upload seeds cookies; oversized or malformed upload rejected; expired token detected; secrets absent from all stored output.

**Dependencies:** DAST-06-020
**Blocks:** DAST-06-050, DAST-07-020, DAST-13-030

**Definition of Done:** code merged + developer tests green

---

### DAST-06-050 Session loss and failure semantics

**Epic:** EPIC-06 Authentication & Identities        **Parent:** EPIC-06
**Parallelism:** Serial/Blocking    **Sprint:** 1

**Story**
As an operator, I want a lost session handled predictably so that a scan never silently continues unauthenticated.

**Acceptance Criteria**
- Session loss during discovery or testing triggers one bounded re-login for that identity (existing `session_lost` / `MAX_RELOGIN_ATTEMPTS` behavior generalized per identity).
- If re-login fails, or credentials are gone after a process restart, the scan fails with "credentials lost" or the specific reason, and results gathered so far are kept.
- A scan whose credentials were lost never reports `success`.
- Detection covers 401/403 patterns, redirects to the login page, and a missing post-login indicator.

**Dev Notes**
- Generalize `route_after_crawl` and the relogin counter to be per identity.
- On startup, scans left `running` by a previous process are failed with the credentials-lost reason (check existing recovery logic in `scan_runner` first).

**Dev Testing**
- Test level: integration.
- Assert: forced session expiry on the fake target triggers exactly one re-login; second expiry fails; restart simulation fails the scan and does not continue unauthenticated; partial findings retained.

**Dependencies:** DAST-06-030, DAST-06-040, DAST-06-010
**Blocks:** DAST-09-010

**Definition of Done:** code merged + developer tests green

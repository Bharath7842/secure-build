# DAST Session-Loss Verdict and Readable Reasoning Design

## Goal

Make a DAST session-loss result easy to understand and safe to act on. The scan page must show a compact **True positive**, **False positive**, or **Needs review** assessment, a short reason, concrete evidence, confidence when available, and the model used. The same exact verdict words must be used throughout the DAST findings UI.

The change must also prevent a login-shaped UI from stopping a scan when stronger evidence proves the authenticated session is still usable, preserve partial discovery data when a scan really does stop, and make the supplied historical scan `4206f141-4af0-4652-822a-a21217c2668c` assessable from its durable log.

## Observed Failure and Root Cause

The supplied scan authenticated `Employee Management demo user`, crawled `/home`, re-authenticated once, then crawled `/employees`. The crawler stopped because both pages looked like login pages.

The durable evidence conflicts with that conclusion:

- the login flow reported success twice;
- `GET /api/auth/current-user` returned HTTP 200;
- `GET /api/employees` returned HTTP 200;
- manual inspection of the `/employees` screenshot shows employee rows behind the login-shaped panel (this visual fact supports the diagnosis but is not treated as machine-readable historical evidence);
- the page title and visible password form still looked like a login screen.

The current heartbeat treats correlated presentation signals as proof of logout. In `nodes/login.py`, leaving the login URL and losing the password field are enough to declare login success. During crawling, the same page later containing a visible password field makes `looks_logged_in` false. `nodes/crawl.py` immediately converts that UI-only result into `session_lost`, even though the identity-scoped application traffic and protected content remain available.

The current failure path also returns from `nodes/discover.py` before the crawl sub-state is folded into the public discovery state. That is why the final stored result says zero pages and zero APIs even though the durable log records two pages and nine API observations.

For this scan, the expected assessment is **False positive**: after the suspected loss, the identity-scoped browser received a JSON HTTP 200 from the non-auth-control application-data endpoint `/api/employees`. That objective response is newer and stronger than the login-shaped presentation signal. This is an assessment of the scanner claim, not a claim that the application itself has no authentication or UI defect.

## Product Language and Compact UI

The scan status and the security assessment are separate facts:

- Status: `Scan stopped early` or the normal running/success status.
- Claim assessed: `The signed-in session was lost`.
- Verdict: `True positive`, `False positive`, or `Needs review`.
- Why: one plain-language sentence.
- Evidence: one compact line containing the strongest two or three facts.
- Provenance: confidence, when valid, plus provider/model or `rules`.

Placement depends on outcome:

- a false positive that lets a live scan continue appears directly under the discovery step as `Session warning checked` and is repeated in the final summary;
- a terminal true positive or needs-review assessment appears directly after the failed discovery step and in the final summary;
- a historical terminal assessment appears after the failed discovery step once the background assessment finishes;
- while an assessment is pending, the same position shows `Checking session warning…` without a verdict or confidence.

The card does not open a new side panel and does not hide the explanation in an accordion.

Example:

> **False positive**
>
> **Why:** Protected employee data still loaded. The scanner mistook a visible login panel for a signed-out session.
>
> **Evidence:** `GET /api/employees` returned 200 JSON during the suspect navigation · the contrary signal was a login-shaped page
>
> 91% confidence · Claude Haiku 4.5

DAST finding chips, filters, group headings, report rows, and counters use the same literal labels:

- `true_positive` → `True positive`
- `false_positive` → `False positive`
- `unverified` → `Needs review`

“Confirmed” and “Dismissed” are not used as substitutes in DAST verdict UI because they obscure the requested decision.

## Architecture

### 1. Session evidence collectors

Add a focused backend service with two typed adapters and one shared normalized output:

- `collect_live_session_evidence`: identity, current login epoch, navigation-start traffic index, current page facts, traffic recorded since navigation began, retry count, and screenshot reference;
- `collect_historical_session_evidence`: durable log lines, stored discovery/input metadata, and request-audit rows when present.

Both return canonical signals, not free-form conclusions. Every signal has `kind`, `polarity`, `strength`, `identity_id`, `login_epoch`, `sequence`, `event_order`, `observed_at`, `detail`, and `reference`. `sequence` is the source-local traffic/log/audit index. `event_order` is a scan-global monotonically increasing integer allocated when live evidence is observed; historical reconstruction uses the durable log `seq`, which is already scan-global. Cross-identity UI selection and retention use `event_order`, never source-local `sequence` or login epoch.

Canonical signal kinds are:

- `LOGIN_UI_VISIBLE` — weak lost signal: current URL is login-shaped or a visible password input exists;
- `POST_LOGIN_INDICATOR` — weak alive signal: a visible logout/sign-out control exists;
- `AUTH_REDIRECT` — strong lost signal: the document navigation's recorded HTTP redirect chain ends at the known login URL;
- `DENIAL_STREAK` — strong lost signal: since the last `APPLICATION_DATA_SUCCESS`, `AUTH_IDENTITY_SUCCESS`, or `SUCCESS_AFTER_DENIAL` in this login epoch, denial score is at least 3 (`401 = 2`, `403 = 1`); public/document-shell successes do not clear it;
- `APPLICATION_DATA_SUCCESS` — strong alive signal: after the suspected page navigation began, the same identity receives a `2xx` JSON XHR/fetch or `/api/` response whose path is not an auth-control path and whose captured response body is non-empty;
- `APPLICATION_DATA_SUCCESS_NO_BODY` — medium alive signal: the same method/status/content-type/path facts exist but no response body was captured or persisted; applies equally to live recorder read failures and historical reconstruction;
- `AUTH_IDENTITY_SUCCESS` — strong alive signal: a `2xx` JSON auth-control response has a non-empty body and proves identity. For form login, at least one non-empty `user`, `username`, `email`, or `name` value must equal the configured username after trim/case normalization. For token/pre-auth identities without a username, a non-empty `id`, `sub`, `username`, or `email` value is required. Null, empty, boolean, and role-only values do not qualify;
- `SUCCESS_AFTER_DENIAL` — clears a prior denial streak when a newer strong-alive response occurs in the same epoch.
- `REAUTH_REJECTED` — strong lost signal: the one allowed re-authentication request reached the target and the target deterministically rejected it (credential error, explicit login error, or completed attempt that remained on a verified login response) after the identity had authenticated in an earlier epoch;
- `REAUTH_INFRA_FAILURE` — informational signal: browser, gateway, timeout, cancellation, or internal tooling prevented the re-authentication attempt from reaching a deterministic target result.

Path classification percent-decodes the URL path, lowercases it, splits it on `/`, and compares whole segments only. An auth-control path contains an exact segment in `{login, logout, signin, signout, auth, session, current-user, me, token}`. Substrings do not match: the segment `employees` is not the segment `me`. An application-data path is an XHR/fetch or `/api/` path without an auth-control segment. Static assets and document-shell HTTP 200 responses never become alive signals.

Live evidence uses the in-memory redacted `RecordedExchange` values, including response bodies when captured. Historical evidence uses the durable log as its ordering authority when present:

- with a log, log `seq` becomes `event_order`; audit/metadata may enrich a signal with matching identity/method/normalized URL but inherit that log order and never introduce independently ordered facts;
- without a log, audit `seq` becomes `event_order`, the stored terminal session-loss message is a synthetic candidate at `max(audit seq) + 1`, and metadata-only facts use `event_order=0` and can produce only `needs_review`;
- request-audit response facts outrank log facts for matching fields, and log facts outrank stored discovery-summary fields.

Duplicate signals are keyed by `(kind, identity_id, login_epoch, sequence, reference)`; a higher-priority matching source replaces/enriches a lower-priority duplicate without changing its established `event_order`.

Audit-only history has no trustworthy login-epoch or navigation-start boundary. Its facts may be shown as context, but the collector assigns `login_epoch=-1`, scopes the synthetic candidate over the available audit page only, and the guardrail returns `needs_review`; audit-only evidence never produces a binary historical verdict.

Persisted assessments are cache entries, not evidence sources. Before normalization, the caller computes `source_fingerprint`:

- historical: `SHA-256(algorithm_version + relevant raw log lines + relevant audit-row scalar fields + relevant metadata fields + model route)`;
- live: `SHA-256(algorithm_version + identity_id + login_epoch + navigation-start traffic index + canonical scalar fields of traffic/page facts in the decision window + retry_count + model route)`.

It accepts a cached assessment only when this cheap raw-source fingerprint and algorithm version match. A missing or stale assessment is then collected/normalized, receives a separate `evidence_fingerprint`, and replaces the cache entry. The collector never reconstructs signals from an assessment.

The historical log parser accepts only existing stable emitted formats:

- `[session_lost] <details>` for the candidate claim;
- `GET|POST <url> (status <integer>, <content-type>)` under `Discovered API endpoints` for API response facts;
- `[N/M] Visiting <url>` and `[screenshot: <file>]` for display references;
- `Agentic login SUCCESS` and `authenticated by` for login-epoch boundaries.

It derives context deterministically:

1. `[4/4] Crawling as '<label>'` opens a crawl segment and resolves the label to the matching identity from `dast_input.identities`.
2. The first authenticated crawl is epoch `0`; `[3/4] Authenticating ... (re-login after a lost session)` increments that identity to epoch `1` immediately, whether the attempt later succeeds or fails.
3. The most recent `[planner] Chose <url>` or `[N/M] Visiting <url>` line is the segment's navigation start.
4. Endpoint summary lines printed before that segment's `Warnings:` block belong to the same identity, epoch, and navigation. Their log sequence is retained; a qualifying `2xx` JSON non-auth-control line becomes `APPLICATION_DATA_SUCCESS_NO_BODY`.
5. `[session_lost] <details>` closes the candidate. It becomes `LOGIN_UI_VISIBLE`, with the warning line's sequence and the most recent visited URL as its reference.
6. A target-authentication rejection in a re-login segment becomes `REAUTH_REJECTED` for epoch `1`; a browser/model/timeout/cancellation/tooling error becomes `REAUTH_INFRA_FAILURE`. The existing raw error is mapped through an explicit classifier and redacted before either signal is created.

The decision window starts at the segment's navigation-start sequence and ends at the candidate warning/failure sequence. Endpoint-summary facts within that window are considered even though they are printed as a batch immediately before the warning.

Screenshot existence is a reference for the operator only. The collector never claims what an image contains unless future persisted machine-readable DOM evidence explicitly says so.

The normalized `SessionEvidence` additionally includes:

- the identity and current login epoch;
- the exact session-warning sequence;
- canonical evidence signals ordered within that epoch;
- retry count and whether the warning occurred before or after the single re-login;
- source references safe to show in the UI.

Secrets, authorization headers, cookies, passwords, and full response bodies never enter the model prompt or UI result. Existing redaction utilities apply before fingerprinting, caching, logging, or prompting.

### 2. Deterministic verdict guardrail

The guardrail determines which verdicts the model is permitted to return.

The guardrail evaluates only signals at or after the candidate warning's navigation start in the same login epoch. Newer sequence wins when strong signals conflict.

| Evidence after navigation began | Allowed/fallback verdict |
| --- | --- |
| Newest strong signal is `APPLICATION_DATA_SUCCESS`, `AUTH_IDENTITY_SUCCESS`, or `SUCCESS_AFTER_DENIAL` | `false_positive` |
| Newest strong signal is `AUTH_REDIRECT` or `DENIAL_STREAK`, with no newer strong-alive signal | `true_positive` |
| `APPLICATION_DATA_SUCCESS_NO_BODY` (live or historical) plus a weak login-UI signal, with no denial/redirect signal | `false_positive` |
| `REAUTH_REJECTED` after a previously successful epoch | `true_positive` |
| `REAUTH_INFRA_FAILURE` | `needs_review` |
| Strong alive and strong lost share the same sequence or cannot be ordered | `needs_review` |
| Only weak signals, only a generic HTTP 200, missing status, or no evidence | `needs_review` |

Appearance-only evidence never permits `true_positive`. Absence of successful activity is not evidence of loss. `APPLICATION_DATA_SUCCESS_NO_BODY` requires the exact `2xx` JSON non-auth-control response facts even though the body is unavailable; it deterministically makes the supplied historical claim false positive and never permits true positive.

The LLM may phrase and rank evidence, but it cannot select a verdict outside the guardrail's allowed set. Invalid output is rejected and retried once. A second invalid response falls back to the deterministic result when decisive or `needs_review` when it is not.

### 3. Structured LLM assessment

The existing configured DAST gateway is reused with a small structured schema:

```json
{
  "verdict": "true_positive | false_positive | needs_review",
  "reason_code": "one code from the verdict-specific allowed list",
  "evidence_signal_ids": ["signal-id-1", "signal-id-2"],
  "confidence": 0.0 | null
}
```

Each normalized signal has a stable ID equal to the first 16 hexadecimal characters of SHA-256 over its canonical JSON fields. The prompt contains only normalized, redacted facts, their IDs, the single verdict selected by the guardrail, and verdict-specific reason codes:

- false positive: `application_data_succeeded`, `identity_response_confirmed`;
- true positive: `redirected_to_login`, `requests_rejected`, `reauth_rejected`;
- needs review: `signals_conflict`, `only_ui_evidence`, `evidence_missing`, `recovery_infrastructure_failed`.

The model explains by selecting a permitted reason code and up to three evidence IDs; it cannot emit free-form reasoning that contradicts the verdict. The server renders the visible one-sentence `why` from the accepted code plus trusted signal details. `confidence` is optional/nullable and clamped to `[0, 1]` when numeric.

Validation applies one consistent contract. A response is invalid if JSON/schema validation fails, its verdict differs from the guardrail verdict, its reason code is not allowed for that verdict/evidence class, any evidence ID is absent from the supplied signal-ID set, or its IDs fail the support rules below. Any invalid response is retried once with validation errors appended. A second invalid response uses the rules-only fallback. The server renders both `why` and evidence text from the accepted code/IDs; model prose is never displayed as reasoning or evidence. Rules-only results always have `confidence=null`.

Evidence support is mandatory:

- every binary assessment has one to three IDs and must include the decisive newest signal;
- `application_data_succeeded` requires `APPLICATION_DATA_SUCCESS`, `APPLICATION_DATA_SUCCESS_NO_BODY`, or `SUCCESS_AFTER_DENIAL`;
- `identity_response_confirmed` requires `AUTH_IDENTITY_SUCCESS`;
- `redirected_to_login` requires `AUTH_REDIRECT`;
- `requests_rejected` requires `DENIAL_STREAK`;
- `reauth_rejected` requires `REAUTH_REJECTED`;
- `signals_conflict` requires at least one strong alive and one strong lost signal;
- `only_ui_evidence` requires `LOGIN_UI_VISIBLE` and no strong signal;
- `recovery_infrastructure_failed` requires `REAUTH_INFRA_FAILURE`;
- `evidence_missing` is the only result allowed zero IDs and is valid only when no signals exist.

The rules-only fallback is a complete assessment:

- binary verdict: select the decisive newest signal, candidate `LOGIN_UI_VISIBLE`, then newest corroborating winning-polarity signal;
- needs review from tied/unorderable strong signals: select the newest strong alive signal, newest strong lost signal, then candidate UI signal;
- needs review from weak-only evidence: select the candidate UI signal, then other weak signals newest-first;
- needs review from `REAUTH_INFRA_FAILURE`: select that signal first, then the candidate UI signal if present;
- needs review with no evidence: select no evidence IDs and use `evidence_missing`.

All lists are deduplicated and capped at three IDs. The server-authored base explanations are:

- false positive: `Application data still succeeded after the page looked signed out.`
- true positive: `The session was rejected and no newer authenticated success was observed.`
- needs review: `The available evidence does not prove whether the session was still valid.`

The fallback reason code is derived without judgment: `APPLICATION_DATA_SUCCESS*` or `SUCCESS_AFTER_DENIAL` → `application_data_succeeded`; `AUTH_IDENTITY_SUCCESS` → `identity_response_confirmed`; `AUTH_REDIRECT` → `redirected_to_login`; `DENIAL_STREAK` → `requests_rejected`; `REAUTH_REJECTED` → `reauth_rejected`; tied strong signals → `signals_conflict`; weak-only → `only_ui_evidence`; no evidence → `evidence_missing`; `REAUTH_INFRA_FAILURE` → `recovery_infrastructure_failed`.

The stored assessment also records `source`, `provider`, and `model`. Raw chain-of-thought is neither requested nor exposed. The visible reasoning is the structured `why` plus evidence list.

### 4. Live crawl integration

`crawl.py` changes a UI-only failure into `suspected_session_loss`. Each identity has an explicit state machine:

```text
ACTIVE(epoch 0)
  -> SUSPECTED
     -> ACTIVE          false positive; same-epoch fingerprint is suppressed
     -> TERMINAL        needs review
     -> REAUTH_PENDING(epoch + 1)  first true positive; increment epoch when attempt begins
REAUTH_PENDING(epoch 1)
  -> ACTIVE(epoch 1)    login succeeds; retry_count remains 1 for the whole scan
  -> TERMINAL           login fails
ACTIVE(epoch 1)
  -> SUSPECTED
     -> ACTIVE          false positive
     -> TERMINAL        true positive (retry already used) or needs review
```

The discover node collects evidence and obtains an assessment before routing:

- `false_positive`: add a warning, persist the assessment, and continue the crawl without consuming the re-login allowance;
- `true_positive`: use the existing single bounded re-login; a second true positive in any later epoch stops the scan;
- `needs_review`: stop safely, keep partial results, and state that the evidence was inconclusive rather than claiming the session was lost.

Transport-level repeated denials remain an immediate strong signal, but still receive the same readable assessment for audit and UI consistency.

The epoch increments when re-authentication starts, before success or failure, so live and historical failed attempts both belong to epoch `1`. Re-login rejection emits `REAUTH_REJECTED`, creating a terminal true-positive assessment through the same collector, guardrail, fingerprint, and persistence path. Re-login infrastructure failure emits `REAUTH_INFRA_FAILURE`, creates a terminal needs-review assessment, and reports that recovery could not be checked; neither starts another attempt. `retry_count` never resets during a scan. A false-positive fingerprint is suppressed only within its login epoch; re-login increments the epoch, so the same page can be assessed again with new evidence. The terminal assessment is always retained even when its fingerprint matches an earlier epoch.

### 5. Partial-result preservation

Before any early return from discovery, fold the current crawl sub-state into the shared inventory and public discovery state. One helper owns this fold and records its stable keys:

- pages: `(identity_id, normalized_url)`; a later visit replaces title/forms/links and keeps the latest non-empty screenshot;
- forms: nested inside the page and replaced with that page snapshot, not appended independently;
- API observations: `(identity_id, method, normalized_url)`; a later observation replaces non-null status/content type;
- warnings: `(identity_id, login_epoch, warning_event_order, event, details)` so a repeated warning after re-authentication remains distinct;
- failed URLs: `(identity_id, normalized_url, error)`;
- inventory endpoints: the existing `Inventory.add` merge remains authoritative.

The helper may run after every crawl segment and before every return. Stable-key sets live in graph state for the run; historical/public output is derived from the merged lists. Traffic is already append-only in `runtime.traffic` and is not copied by this helper.

The final failed or needs-review scan therefore reports the pages, APIs, forms, warnings, screenshots, and traffic already collected. Coverage remains explicitly incomplete.

### 6. Historical scan compatibility

The narration endpoint builds an assessment for terminal DAST scans that contain a session-loss claim but do not already have one. It uses the historical collector and guardrail. If the durable log is absent, remaining metadata/audit sources are still evaluated; a claim with no usable evidence returns a rules-based `needs_review`, while a scan with no session-loss claim has no assessment.

The existing background/cached narration pattern is reused so the HTTP request is not blocked by an LLM call. The first response may contain `assessment_pending=true`. A later poll returns the completed in-memory result and attempts persistence. If persistence fails, later polls in the same server process still receive the memory-cached result; after restart it is recomputed. No already-returned HTTP response is amended.

Once complete, the compact assessment is stored under scan metadata and returned in the narration payload. A versioned assessment fingerprint includes the algorithm version, normalized evidence, and model routing so changes invalidate stale cached output predictably.

This path makes scan `4206f141-4af0-4652-822a-a21217c2668c` display the new assessment without rerunning the target.

## Interfaces

Backend domain values:

```text
SessionEvidence
  claim: string
  identity_id: string
  login_epoch: int
  warning_sequence: int
  signals: list[{kind, polarity, strength, identity_id, login_epoch, sequence, event_order, observed_at, detail, reference}]
  retry_count: int
  fingerprint: string

SessionAssessment
  verdict: true_positive | false_positive | needs_review
  why: string
  evidence: list[string]
  evidence_signal_ids: list[string]
  reason_code: string
  confidence: float | null
  source: llm | rules
  provider: string | null
  model: string | null
  identity_id: string
  login_epoch: int
  warning_sequence: int
  event_order: int  # the scan-global order of the warning/recovery event represented by this assessment
  created_at: string
  source_fingerprint: string
  evidence_fingerprint: string
  fingerprint: string
```

Scan metadata stores a bounded list at `dast_session_assessments` (maximum 10; discard the lowest `(event_order, created_at)` first) and `dast_terminal_session_assessment_fingerprint` when an assessment caused a terminal result. The graph/live writer owns updates while a scan runs; the narration endpoint owns historical backfill after a scan is terminal. Both use the same compare-and-replace helper keyed by fingerprint.

The narration response gains optional `assessment`, `assessment_pending`, and `assessments` fields. They remain optional for non-session scans and old clients. The frontend mirrors the backend types and continues polling while either narration or assessment is pending.

The UI selection rule is deterministic: show the assessment whose fingerprint equals `dast_terminal_session_assessment_fingerprint`; otherwise show the highest `(event_order, created_at)` assessment. Timeline placement uses the matching discovery-step `event_order`. The summary uses the same selected assessment.

## Error Handling

- LLM disabled/unavailable: return a decisive rules result with `source=rules`; otherwise return `Needs review`.
- Invalid/partial model JSON: retry once, then use the same fallback.
- Historical log missing: use metadata/audit sources; if a session-loss claim exists but no usable evidence remains, return rules-based `Needs review`; omit only when there is no session-loss claim.
- Missing screenshot: rely on traffic and DOM/log facts; do not claim visual evidence.
- Missing request response status: do not infer success from the request alone.
- Conflicting strong evidence: `Needs review`; never force a binary label.
- Persistence failure: keep the result in process memory for later polls, log the cache-write error, and recompute after restart if needed.
- Any schema-invalid, verdict-mismatched, disallowed-reason-code, or unknown-signal-ID model response follows the same one-retry validation contract, then falls back.

## Testing

### Backend unit tests

- Truth table for strong-alive, strong-lost, weak-only, conflicting, and missing evidence.
- Appearance-only login signals cannot produce a true positive.
- A live `APPLICATION_DATA_SUCCESS` recorded after the suspected navigation began and before the decision turns the session-loss claim into a false positive.
- Historical `APPLICATION_DATA_SUCCESS_NO_BODY` with no denial/redirect produces false positive even without an LLM.
- Live `APPLICATION_DATA_SUCCESS_NO_BODY` follows the same verdict/conflict rules as historical evidence.
- Repeated denials with no later success produce a true positive.
- Conflicting strong signals produce needs review.
- Secrets are redacted before prompt construction and persistence.
- Invalid model verdict/evidence is rejected; deterministic fallback is used.
- Binary model output without its decisive signal ID is rejected.
- Confidence is absent for rules-only results and clamped for model results.

### Regression and integration tests

- Reproduce the supplied historical log pattern: successful login epoch, login-shaped warning, and same-segment durable `GET /api/employees (status 200, application/json)`. Expected rules and model-backed verdict: false positive.
- Reproduce the live equivalent with a non-empty employee JSON body. Expected rules result is false positive and the crawl continues.
- Reproduce a live response-body read failure with the same `2xx` JSON application-data facts and no denial/redirect signal. Expected rules result is false positive. When any denial/redirect signal is present, the no-body signal does not override it; apply the decision table (`true_positive` for an orderable strong-lost signal, `needs_review` when unorderable).
- Verify a failed re-login attempt is epoch `1` for both target rejection and infrastructure failure; rejection is true positive, infrastructure failure needs review.
- Verify log-ordered evidence enrichment from audit rows and audit-only fallback ordering when the durable log is absent.
- Changing the algorithm version or a relevant raw source invalidates the cached source fingerprint and rebuilds the assessment.
- A genuine expiry pattern re-authenticates once and stops on the second true positive.
- False-positive assessment does not consume the re-login allowance.
- Partial crawl data is present after a real stop and is not duplicated after resume.
- Narration first returns pending, then returns and persists an assessment for a historical terminal scan without blocking the first request.
- Existing narration payloads remain valid when assessment is absent.

### Frontend verification

- Compact verdict renders after a failed timeline step, or as `Session warning checked` under a continued discovery step, and in the summary.
- `why` and evidence are visible without expanding anything.
- Provider/model and valid confidence are shown compactly; missing values are omitted cleanly.
- DAST findings, filters, headings, report, and counters display True positive / False positive / Needs review consistently.
- Run lint and production build.
- Inspect the supplied scan page in a real browser at desktop and narrow widths and capture screenshots for comparison with the approved compact mockup.

## Non-Goals

- Exposing raw model chain-of-thought or hidden scratchpad tokens.
- Treating a scan infrastructure failure as an application vulnerability.
- Replacing the existing per-finding guardrail.
- Adding a new side panel, workflow, or manual triage system.
- Reworking unrelated DAST checks or the global scan-result design.

## Explicit Tradeoff

A `2xx` JSON response from a non-auth-control application-data endpoint in the identity's browser context is treated as evidence that the application remains usable even when no anonymous-access baseline exists. That endpoint could be public, so this is not proof of authorization. It is used only to prevent an appearance-only session-loss stop; separate authorization replay checks remain responsible for deciding whether anonymous access is a vulnerability.

## Acceptance Criteria

1. The supplied scan displays a compact session-loss assessment reconstructed from existing evidence.
2. Its expected verdict is False positive when the authenticated employee API/content evidence is available.
3. The card visibly answers verdict, why, evidence, confidence when available, and model/source.
4. Future scans do not stop on login-shaped UI alone when stronger evidence proves the session is usable.
5. Genuine session loss still re-authenticates once and then stops safely if repeated.
6. Failed scans preserve the partial discovery facts collected before stopping.
7. DAST verdict wording is consistently True positive, False positive, or Needs review across the UI.
8. Raw chain-of-thought is not requested or displayed.
9. Focused backend tests, the relevant full backend suite, frontend lint, and frontend production build pass.

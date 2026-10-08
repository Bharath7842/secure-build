# DAST — Completion Specification

A design document for finishing the DAST scan type. It builds on the current-state snapshot you provided. It assumes the existing constraints: authorized targets only (operator owns or is permitted to test), the explicit `authorized` gate on the trigger endpoint, and a single local LLM, **`gpt-oss:20b`** via Ollama, for every model call.

Two labels are used throughout:
- **[IMPLEMENTED]** — already present in your snapshot.
- **[RECOMMENDED]** — my proposal for finishing, not yet in the code.

---

## 1. Definition of done

DAST is "finished" when all of the following hold on the **real** engine (not the mock):

1. A scan of a known practice app (DVWA, Juice Shop) run twice produces the same verdicts on the same findings — deterministic enough to trust.
2. Each run is scored against a fixed expected-findings list per app, and reports precision and recall.
3. False positives stay low because every active FAIL is backed by a deterministic signal, not the model's opinion alone.
4. A client-readable report comes out (PDF/XLSX) with evidence and remediation per finding.
5. All active testing is confined to the target host, and anything that mutates state requires an explicit opt-in.

Until there is a way to **measure** findings against ground truth, no later change can be judged. That measurement harness is therefore the first deliverable.

---

## 2. Current state (condensed)

The pipeline is a five-node LangGraph: `check_connection → classify_login_type → login → crawl → analyze_apis → END`, with one bounded re-login hop from `crawl`. Only `simple_form` login is automated; other login types are detected and the scan stops with a `stop_reason`. The crawl captures API responses through a Playwright `response` listener. `analyze_apis` selects observed REST endpoints, asks the model which checks apply and to construct test cases, executes them through the authenticated session, and asks the model to rule PASS/FAIL/INCONCLUSIVE. Results become `Finding` rows (`kind=dast`) plus a discovery dict. Narration turns the engine log into a five-step chat timeline. The password is in-memory only and redacted from logs.

Known gaps from the snapshot: active testing covers observed REST APIs only (forms and DOM sinks are discovered but not fuzzed); request bodies are inferred from matching forms, never captured; a model PASS can't be independently validated; Ollama URL and crawl budgets are hardcoded; `analyze_apis.py`, `api_analysis.py` and `DastAnalysisPanel` are uncommitted; the root `CLAUDE.md` is outdated.

---

## 3. Target architecture

```
check_connection
      │
classify_login_type ──(non-simple)──▶ END (stop_reason)
      │
    login ◀───────────┐
      │               │ (one re-login hop)
    crawl ────────────┘
      │  captures: responses, request bodies, API specs
      │
  ┌───┴───────────────┐
  │ passive_analysis  │  headers, cookies, CORS, leaks   [RECOMMENDED]
  └───┬───────────────┘  deterministic, no model
      │
  analyze_apis         LLM-constructed tests + deterministic detectors
      │
     END  ──▶ discovery dict + Finding rows + narration
```

Everything new reuses the existing contracts: the `findings_writer`, `should_abort` and `discovery_writer` hooks; the `Finding` row shape; and the `### DAST: <label>` banner convention that narration and progress depend on. A new node must emit a banner or it will be invisible to the timeline.

---

## 4. Phase plan

Ordered by value-for-effort. Each phase is independently shippable and leaves the tool working.

### Phase 0 — Stabilize and make it measurable  [RECOMMENDED]

The foundation. Nothing after this is trustworthy without it.

1. **Commit the uncommitted work.** `analyze_apis.py`, `nodes/analyze_apis.py`, `DastAnalysisPanel.tsx`, and the `lib/types.ts` additions. One commit, with the mock-engine tests green.
2. **Fix docs.** Root `CLAUDE.md` still calls `app/dast` a UI-only mockup. Correct it to point at `backend/app/dast/CLAUDE.md` as the current source of truth.
3. **Measurement harness.** A `docker-compose.dast-eval.yml` that brings up DVWA and Juice Shop locally, plus `backend/tests/eval/ground_truth/<app>.yaml` listing the findings each app is expected to produce (check id + endpoint/param, severity). A script `run_dast_eval.py` runs a real scan against each and prints precision, recall and a diff against ground truth. This is a manual regression gate, run before and after every later phase — not part of the mock unit suite.
4. **Config surface.** Move to `settings`: `dast_ollama_base_url`, `dast_ollama_model` (already there), `dast_max_runtime_minutes`, `dast_max_per_pattern`, `dast_same_domain_mode`, `dast_max_apis`, `dast_max_tests_per_api`. Expose `max_apis` and `max_tests_per_api` in the form as a single "thoroughness" preset (light / standard / deep) rather than raw numbers.

**Exit:** real scans of both apps run end to end and the harness reports a baseline precision/recall, however poor.

### Phase 1 — Evidence-backed verdicts  [RECOMMENDED]

The single biggest accuracy win. Today the model both writes the payload and judges the result. Keep the model writing payloads; stop it judging alone.

New module `backend/app/dast/detectors.py` — **pure functions**, no model, no I/O. Each takes `(baseline_response, test_response, payload_meta)` and returns a structured signal: did a database-layer error surface, did the input reflect unescaped, did a command-output marker appear, did a stack trace leak, was there a meaningful time delta on a timing test, did status or length diverge from baseline. These are observations, not verdicts.

Pipeline change in `analyze_apis`:
1. **Baseline first.** Send the unmodified request, record status/length/body.
2. **Execute test**, as today, through `page.request` (authenticated session, `fail_on_status_code=False`).
3. **Run detectors** on the pair. Attach the signals to the test evidence.
4. **Rule call (LLM):** the model now rules on *detector signals plus the truncated body*, not the body alone. Prompt it to rule FAIL only when a signal supports it.
5. **Guardrail:** deterministically downgrade a model FAIL with **no** supporting signal to INCONCLUSIVE (`unverified`). This caps false positives without hiding anything.

Authorization/IDOR coverage, cheap and high-yield:
- **Replay without session:** resend each selected request with cookies stripped. A success where auth was expected is a strong, deterministic broken-access signal.
- **Second-identity replay (optional):** if the form supplied a second credential set, replay as user B against user A's resource.

**Exit:** every active FAIL carries a named deterministic signal; harness precision rises; recall at least holds.

### Phase 2 — Passive analysis  [RECOMMENDED]

No model, no active payloads, no risk — pure inspection of responses already captured. Fast, reliable findings.

New node `passive_analysis` (emit `### DAST: inspecting responses`), between `crawl` and `analyze_apis`. New module `backend/app/dast/passive.py`:
- Security headers present/absent and misconfigured (transport security, content-type options, frame options, content security policy).
- Cookie flags: HttpOnly, Secure, SameSite.
- CORS policy over-permissiveness.
- Server/framework/version disclosure and verbose error leakage.

Each maps to an existing check id where one fits (`dast-misconfig`, `dast-info-disclosure`, `dast-session`) and writes through the same `findings_writer`. Confidence HIGH for header/cookie facts — they are directly observed.

**Exit:** passive findings appear on every scan with zero model dependence.

### Phase 3 — Real request shapes  [RECOMMENDED]

Fixes the snapshot's biggest gap: bodies are inferred from forms, never seen.

1. **Capture request bodies.** Extend the Playwright `response` listener to also record `request.post_data`, method and content-type on the matching request. Store alongside each `api_call`.
2. **Spec discovery.** After login, probe common spec locations (OpenAPI/Swagger JSON, API-docs). When a spec is found, derive real endpoints, parameters and body schemas from it and feed them into `build_api_target`. This gives accurate request shapes without guessing.

**Exit:** `build_api_target` prefers captured bodies and spec schemas over form inference.

### Phase 4 — Form and parameter fuzzing  [RECOMMENDED]

The biggest coverage gain, the most work. DVWA and most client apps exercise form-based reflected/stored injection, which observed-REST-only testing misses entirely.

Generalize `analyze_apis` into a target abstraction: an endpoint target (as today) or a **form target** (action URL, method, input fields from the crawl). The same construct → execute → detect → rule pipeline runs over both. Reuse detectors unchanged; reflected-input and error-signature detection already cover the form case. Respect `max_tests_per_api` as a per-target cap.

**Exit:** crawled forms are tested with the same evidence-backed pipeline; harness recall on DVWA/Juice Shop rises.

### Phase 5 — Auth fallback  [RECOMMENDED]

Today non-`simple_form` logins stop the scan. Rather than automate OAuth/SSO/CAPTCHA/OTP (fragile and out of scope), accept pre-authenticated state:
- Uploaded Playwright `storage-state` JSON (the CLI already supports `--storage-state`; expose it in the API/form).
- A bearer token or raw cookie header entered in the form.

When provided, the graph skips `login` and goes straight to `crawl`, as the CLI storage-state path already does. This makes MFA/SSO sites scannable without automating their login.

**Exit:** a scan can run against a site the operator is already signed into, via uploaded state or token.

### Phase 6 — Safety and reporting polish  [RECOMMENDED]

**Safety** (promote ahead of everything else if this will ever touch client apps):
- **Scope lock:** active tests only ever hit the target host. Reject any constructed test whose URL resolves off-host, deterministically, before sending.
- **Safe mode:** a scan option that restricts active tests to non-mutating methods. Sending anything that can change or delete data requires an explicit per-scan opt-in, because active testing against a live app can mutate state.
- **Rate limit:** a configurable delay/concurrency cap on active requests.
- **Responsive cancel:** check `should_abort` between individual tests, not only between APIs.

**Reporting:**
- **Dedupe** findings on `(rule_id, endpoint, param)` before persistence.
- **Remediation text** per check id, added to the finding or rendered in the report.
- **Scan-to-scan diff:** new / fixed / still-open, computed from prior findings on the same target.
- **Evidence in exports:** carry baseline-vs-test signal and HTTP status into the existing PDF/XLSX.

---

## 5. Module summary

| Module | Status | Role |
|---|---|---|
| `backend/app/dast/detectors.py` | [RECOMMENDED] | Pure signal detectors over (baseline, test) response pairs |
| `backend/app/dast/passive.py` | [RECOMMENDED] | Header/cookie/CORS/leak inspection, no model |
| `backend/app/dast/nodes/passive_analysis.py` | [RECOMMENDED] | Graph node wrapping `passive.py`, emits banner |
| `backend/app/dast/nodes/analyze_apis.py` | [IMPLEMENTED] | Active testing node; extend for baseline + detectors + form targets |
| `backend/app/dast/api_analysis.py` | [IMPLEMENTED] | Test construction/execution/ruling; add baseline, detector feed, guardrail downgrade |
| `backend/app/dast/graph.py` | [IMPLEMENTED] | Add `passive_analysis` edge; storage-state skip path to `crawl` |
| `backend/app/dast/runner.py` | [IMPLEMENTED] | Capture `request.post_data`; spec probe; pass new settings |
| `backend/app/core/settings` | [IMPLEMENTED] | Add Ollama URL + crawl budget + max-apis/tests config |
| `tests/eval/` + `run_dast_eval.py` | [RECOMMENDED] | Ground-truth harness against DVWA/Juice Shop |

---

## 6. Model usage (gpt-oss:20b only)

Every model call stays on `gpt-oss:20b` through the existing `call_llm_json` / `call_llm_tool_choice` path. The design deliberately reduces how much rides on model quality, because a 20B local model is the fixed constraint:

- **Classification** (login type, crawl planning): unchanged.
- **Test construction:** model still chooses applicable checks and constructs payloads per endpoint. No payloads are hard-coded; unknown check ids are dropped, as today.
- **Ruling:** model rules on detector signals + body, and a model FAIL with no supporting signal is deterministically downgraded. This is what lets a smaller model stay useful — it judges against observed facts rather than guessing.
- **Narration:** unchanged; template fallback remains so the UI never depends on the model.

No second model, no cloud model, no model swap is assumed anywhere.

---

## 7. Testing

- **Unit (mock engine, no browser/Ollama/network):** keep the existing `test_dast_scan`, `test_dast_narration`, `test_dast_api_analysis`. Add `test_dast_detectors` (pure functions — easy, high coverage) and `test_dast_passive`.
- **Integration (real engine, manual):** the Phase 0 harness against DVWA/Juice Shop, with precision/recall and a ground-truth diff. Run before and after each phase.
- **Regression gate:** a phase is not done until the mock suite is green and the harness shows recall held or improved and precision not regressed.

---

## 8. Suggested sequence

Phase 0 → Phase 2 (passive) → Phase 1 (detectors + authz) → Phase 3 (request shapes) → Phase 4 (form fuzzing) → Phase 5 (auth fallback) → Phase 6 (safety + reporting).

Passive checks and detectors give the largest accuracy gain for the least effort. Form fuzzing is the largest coverage gain but the most work. **If this will ever scan client-owned apps rather than local practice targets, move the Phase 6 safety items (scope lock, safe mode, rate limit) to the front, before any active testing is widened.**

---

## 9. Open questions that change the plan

1. **Audience:** local practice only, or client engagements? Client use pulls all safety work forward.
2. **Determinism target:** how much run-to-run variance is acceptable? Tighter targets mean leaning harder on detectors and less on the model's wording.
3. **State mutation:** are target apps disposable (reset between runs)? If not, safe mode should default on.

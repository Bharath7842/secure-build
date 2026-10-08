# Sprint Plan: DAST Scan Type

All 90 stories delivered in **2 sprints**, with the implementation done by AI. Every story's `Sprint` field matches this plan.

## Assumptions

- **AI implementation.** Developer throughput is not the limit, so the split is driven only by dependency order. Sprint length is not specified; two sprints is the scope boundary.
- **Dev only.** No Test or DevOps streams. Dev Testing is part of each story.
- **Scaffolding first.** Within Sprint 1, EPIC-00 completes before any other epic starts (template rule).
- **Dependencies are strict.** A story starts only when everything it depends on is done. Sprint 1 depends on nothing in Sprint 2 (verified).
- **Wave = execution order inside a sprint.** Stories in the same wave have no dependency on each other and can run in parallel; each wave waits for the previous one.

## Overview

| Sprint | Theme | Epics | Stories |
|---|---|---|---|
| 1 | Backend foundations through discovery | EPIC-00 to EPIC-07 | 49 |
| 2 | Analysis, authorization, reporting, UI and release gate | EPIC-08 to EPIC-16 | 41 |
| | **Total** | | **90** |

## Sprint 1: Backend foundations through discovery

**Scope:** Scaffolding, safety guard, model gateway, check catalog and rule sets, detectors and findings core, scan setup and fingerprint, authentication and identities, discovery.

**Exit criteria:** Layering test green and existing suite green on the new structure; guarded executor audits every request to the fake target; a full DAST scan can be created and routed by fingerprint; an authenticated multi-identity crawl produces an endpoint inventory.

**15 waves.**

| Wave | Part | Stories | Deliverable | Parallelism | Depends On |
|---|---|---|---|---|---|
| 1 | Dev: EPIC-00 | 00-010 | Adopt the pinned dependency set | Serial/Blocking | — |
| 2 | Dev: EPIC-00 | 00-020, 00-030, 00-070, 00-080 | Layered package skeleton and import-rule check; DAST settings surface; CI pipeline skeleton; Local practice-target environment | Parallel, Serial/Blocking | DAST-00-010 |
| 3 | Dev: EPIC-00 | 00-040, 00-050, 00-060 | Schema additions for DAST evidence and audit; Mock engine contract extended; Test harness and offline target fixtures | Parallel | DAST-00-020 |
| 4 | Dev: EPIC-00 | 00-090 | Frontend scaffolding: types, API stubs and shared helpers | Parallel | DAST-00-050 |
| 7 | Dev: EPIC-01 | 01-010, 01-060 | Scope and method policy; Non-destructive input validator | Parallel, Serial/Blocking | DAST-00-020, DAST-00-030 |
| 7 | Dev: EPIC-02 | 02-010 | Gateway core and request contract | Serial/Blocking | DAST-00-020, DAST-00-030 |
| 7 | Dev: EPIC-03 | 03-010 | Check schema and catalog loader | Serial/Blocking | DAST-00-020 |
| 7 | Dev: EPIC-06 | 06-010 | Credential holder and log redaction | Serial/Blocking | DAST-00-020 |
| 8 | Dev: EPIC-01 | 01-020 | Rate limit, concurrency cap and cancellation | Parallel | DAST-00-030, DAST-01-010 |
| 8 | Dev: EPIC-02 | 02-020, 02-030, 02-040, 02-060 | Local model adapter and migration of existing callers; Anthropic and OpenAI adapters; Bedrock adapter; Task prompts and few-shot loader | Parallel, Serial/Blocking | DAST-02-010 |
| 8 | Dev: EPIC-03 | 03-020, 03-030 | Default pack: OWASP API Security Top 10 (2023); Default packs: Web Top 10, WSTG and passive-only | Parallel | DAST-03-010 |
| 8 | Dev: EPIC-04 | 04-010 | Domain entities and finding mapping | Serial/Blocking | DAST-00-020, DAST-00-040 |
| 9 | Dev: EPIC-01 | 01-030 | Guarded request executor | Serial/Blocking | DAST-00-060, DAST-01-010, DAST-01-020 |
| 9 | Dev: EPIC-02 | 02-050 | Token and cost accounting | Parallel | DAST-02-020 |
| 9 | Dev: EPIC-03 | 03-040 | Packs, per-check overrides and effective rule set | Serial/Blocking | DAST-00-040, DAST-03-020, DAST-03-030 |
| 9 | Dev: EPIC-04 | 04-020, 04-030, 04-050 | Detector library: injection and leakage signals; Detector library: divergence, timing and authorization boundary; Findings writer with evidence and dedupe | Parallel | DAST-00-040, DAST-04-010 |
| 9 | Dev: EPIC-05 | 05-050 | End-to-end cancellation | Parallel | DAST-01-020 |
| 9 | Dev: EPIC-07 | 07-010 | Endpoint inventory model | Serial/Blocking | DAST-00-020, DAST-04-010 |
| 10 | Dev: EPIC-01 | 01-040, 01-050 | Browser traffic through the guard; Request audit persistence and retrieval | Parallel | DAST-00-040, DAST-01-010, DAST-01-030, DAST-06-010 |
| 10 | Dev: EPIC-03 | 03-050, 03-060 | Custom rules; Dependency-aware skip and degrade | Parallel | DAST-03-010, DAST-03-040 |
| 10 | Dev: EPIC-04 | 04-040, 04-060 | Verdict roll-up and guardrail; Findings query API | Parallel, Serial/Blocking | DAST-03-020, DAST-04-010, DAST-04-020, DAST-04-030, DAST-04-050 |
| 10 | Dev: EPIC-05 | 05-010, 05-030 | DAST scan creation contract; Preflight stage | Parallel, Serial/Blocking | DAST-00-030, DAST-01-030, DAST-02-010, DAST-02-060, DAST-03-040 |
| 10 | Dev: EPIC-07 | 07-050 | GraphQL introspection ingestion | Parallel | DAST-01-010, DAST-07-010 |
| 11 | Dev: EPIC-05 | 05-020 | Effective settings snapshot and intensity presets | Parallel | DAST-00-030, DAST-03-040, DAST-05-010 |
| 11 | Dev: EPIC-06 | 06-020 | Identity model and per-identity sessions | Serial/Blocking | DAST-05-010, DAST-06-010 |
| 12 | Dev: EPIC-05 | 05-040 | Fingerprint stage and pipeline routing | Serial/Blocking | DAST-02-060, DAST-05-020, DAST-05-030 |
| 12 | Dev: EPIC-06 | 06-040 | Token and pre-authenticated state | Parallel | DAST-06-020 |
| 13 | Dev: EPIC-06 | 06-030 | Form login adaptation | Parallel | DAST-05-040, DAST-06-020 |
| 13 | Dev: EPIC-07 | 07-040 | OpenAPI and Swagger ingestion | Parallel | DAST-01-030, DAST-05-040, DAST-07-010 |
| 14 | Dev: EPIC-06 | 06-050 | Session loss and failure semantics | Serial/Blocking | DAST-06-010, DAST-06-030, DAST-06-040 |
| 14 | Dev: EPIC-07 | 07-020, 07-060 | Crawl stage on the browser driver; Observed vs documented inventory diff | Parallel, Serial/Blocking | DAST-01-040, DAST-04-050, DAST-05-020, DAST-05-040, DAST-06-030, DAST-06-040, DAST-07-010, DAST-07-040, DAST-07-050 |
| 15 | Dev: EPIC-07 | 07-030 | Network recorder with request bodies | Serial/Blocking | DAST-07-020 |

## Sprint 2: Analysis, authorization, reporting, UI and release gate

**Scope:** Passive analysis, active testing, multi-role authorization, reporting and exports, narration, all UI screens, settings and rule management, measurement harness, determinism, regression gate and security review.

**Exit criteria:** Evidence-backed passive and active findings; authorization matrix with seeded flaws found; PDF and XLSX exports; all UI screens working against the real backend; harness baseline recorded; regression gate and security review complete.

**8 waves.**

| Wave | Part | Stories | Deliverable | Parallelism | Depends On |
|---|---|---|---|---|---|
| 1 | Dev: EPIC-08 | 08-010 | Passive stage and header/cookie checks | Serial/Blocking | DAST-03-030, DAST-04-050, DAST-07-030 |
| 1 | Dev: EPIC-09 | 09-010 | Active stage and per-target loop | Serial/Blocking | DAST-01-030, DAST-03-020, DAST-03-040, DAST-04-040, DAST-05-020, DAST-06-050, DAST-07-010, DAST-07-040, DAST-07-060 |
| 1 | Dev: EPIC-12 | 12-010, 12-030 | Banners and progress markers for new stages; Live counters and severity breakdown | Parallel | DAST-00-050, DAST-01-050, DAST-02-050, DAST-04-050 |
| 1 | Dev: EPIC-13 | 13-010, 13-020 | DAST dashboard; New Scan form: target, authorization and safety | Parallel, Serial/Blocking | DAST-00-050, DAST-00-090, DAST-05-010 |
| 1 | Dev: EPIC-15 | 15-010, 15-050 | Model routing settings; Scan defaults and OAST address | Parallel, Serial/Blocking | DAST-00-030, DAST-00-090, DAST-02-030, DAST-02-040 |
| 2 | Dev: EPIC-08 | 08-020, 08-030 | CORS and technology disclosure; Verbose errors and sensitive data exposure | Parallel | DAST-04-020, DAST-08-010 |
| 2 | Dev: EPIC-09 | 09-020 | Select and construct | Serial/Blocking | DAST-01-060, DAST-02-010, DAST-02-060, DAST-09-010 |
| 2 | Dev: EPIC-12 | 12-020 | Narration for new stages with template fallback | Parallel | DAST-02-020, DAST-12-010 |
| 2 | Dev: EPIC-13 | 13-030, 13-040 | New Scan form: identities and roles; New Scan form: rule packs and model | Parallel | DAST-03-040, DAST-06-040, DAST-13-020 |
| 2 | Dev: EPIC-15 | 15-020 | Credential entry with masking | Parallel | DAST-15-010 |
| 3 | Dev: EPIC-09 | 09-030 | Baseline, test execution and rule | Serial/Blocking | DAST-04-020, DAST-04-040, DAST-04-050, DAST-07-030, DAST-09-020 |
| 3 | Dev: EPIC-13 | 13-050 | Scan detail: timeline, counters and cancel | Serial/Blocking | DAST-05-050, DAST-12-010, DAST-12-020, DAST-12-030 |
| 3 | Dev: EPIC-15 | 15-030 | Rule-set management | Parallel | DAST-03-040, DAST-13-040 |
| 4 | Dev: EPIC-09 | 09-040, 09-050, 09-060 | Form and parameter testing; Opt-in and assist-only checks; SSRF with out-of-band confirmation | Parallel | DAST-03-060, DAST-07-030, DAST-09-010, DAST-09-030 |
| 4 | Dev: EPIC-10 | 10-010 | Anonymous replay and degraded mode | Serial/Blocking | DAST-03-060, DAST-04-030, DAST-06-020, DAST-09-030 |
| 4 | Dev: EPIC-13 | 13-060 | Scan detail: discovery and analysis panels | Parallel | DAST-07-060, DAST-13-050 |
| 4 | Dev: EPIC-14 | 14-010 | Findings panel: DAST evidence and filters | Serial/Blocking | DAST-00-050, DAST-04-060, DAST-13-050 |
| 4 | Dev: EPIC-15 | 15-040 | Custom rule authoring | Parallel | DAST-03-050, DAST-15-030 |
| 4 | Dev: EPIC-16 | 16-010, 16-050 | Measurement harness; Training-data capture with controls | Parallel, Serial/Blocking | DAST-00-080, DAST-01-060, DAST-06-010, DAST-09-030 |
| 5 | Dev: EPIC-10 | 10-020 | Cross-role replay engine | Serial/Blocking | DAST-10-010 |
| 5 | Dev: EPIC-11 | 11-010 | Severity roll-up and report data | Serial/Blocking | DAST-00-040, DAST-03-060, DAST-04-050, DAST-08-020, DAST-08-030, DAST-09-050 |
| 5 | Dev: EPIC-16 | 16-030 | Determinism and offline guarantees | Parallel | DAST-04-040, DAST-09-030, DAST-16-010 |
| 6 | Dev: EPIC-10 | 10-030, 10-040 | BOLA and BFLA checks; Authorization matrix and API | Parallel | DAST-03-020, DAST-04-030, DAST-04-040, DAST-04-060, DAST-10-010, DAST-10-020 |
| 6 | Dev: EPIC-11 | 11-020 | Scan-to-scan diff | Parallel | DAST-11-010 |
| 7 | Dev: EPIC-11 | 11-030, 11-040 | PDF export; XLSX export | Parallel | DAST-11-010, DAST-11-020 |
| 7 | Dev: EPIC-14 | 14-020 | Authorization matrix component | Parallel | DAST-10-040, DAST-13-030, DAST-14-010 |
| 7 | Dev: EPIC-16 | 16-020 | Practice-target ground truth | Parallel | DAST-00-080, DAST-09-040, DAST-10-030, DAST-16-010 |
| 8 | Dev: EPIC-14 | 14-030, 14-040 | Report view and exports; Accessibility and states pass | Parallel, Serial/Blocking | DAST-11-020, DAST-11-030, DAST-11-040, DAST-13-050, DAST-14-010, DAST-14-020 |
| 8 | Dev: EPIC-16 | 16-040, 16-060 | Regression gate; Security review of safety controls | Serial/Blocking | DAST-00-070, DAST-01-050, DAST-01-060, DAST-06-010, DAST-09-030, DAST-11-040, DAST-16-010, DAST-16-020, DAST-16-030, DAST-16-050 |

## What "complete" means here

AI can write the code, the Dev Testing for each story, and run everything that runs offline (the mock engine, fake-target tests, layering and lint/build checks). Some acceptance criteria cannot be closed by AI alone because they need an environment or a human judgment:

- **Live tests** (browser crawl, real model calls, practice targets): DAST-01-040, 02-020, 06-030, 07-020, 07-030, 16-010 to 16-040 need Chromium, Ollama and DVWA/Juice Shop running. AI can run them where that environment exists in the session; otherwise they stay open.
- **Practice-target ground truth** (DAST-16-020): expected-findings lists must be verified against the pinned target images. Unverified lists would produce a misleading precision/recall baseline.
- **Frontend manual checklists** (EPIC-13 to 15): the frontend has no test runner, so each screen's checklist needs a browser pass. The accessibility pass (DAST-14-040) needs a keyboard and screen-reader check.
- **Security review sign-off** (DAST-16-060): AI can run the adversarial fixtures and fix what they find, but accepting residual risk is a human decision.
- **Provider credentials** (DAST-02-030, 02-040): hosted-model live checks need real keys; otherwise only the stubbed tests run.
- **Open decisions** that block specific stories: OAST service (DAST-09-060), provider-key storage (DAST-15-020), settings persistence (DAST-15-050).

A story is Done when its code is merged and its Dev Testing passes. Stories whose Dev Testing is marked `live` or manual are Done only when that run has happened.

## Risks

- **Two sprints is a scope boundary, not an estimate.** The 18-story critical path (listed in the [README](README.md)) is unchanged and runs through DAST-03-040; it must finish inside Sprint 1 for Sprint 2 to start cleanly.
- **Sprint 2 depends on Sprint 1 being solid.** The active, authorization and reporting epics all build on the guard, gateway, catalog and findings core. Defects there propagate.
- **Frontend contract drift.** Sprint 2 builds the UI against the real backend. Contract changes late in Sprint 1 would force rework; DAST-00-090 fixes the contract early.
- **Existing code is modified, not replaced.** Several stories rework `crawl.py`, `login.py` and `api_analysis.py`. The existing DAST tests must stay green after each such story.

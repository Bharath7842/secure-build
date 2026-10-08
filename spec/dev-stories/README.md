# DAST Scan Type: Epics and Dev Stories

Phase 5 of the scaffolding chain (see [../chain-templates/project-scaffolding-workflow-chain.md](../chain-templates/project-scaffolding-workflow-chain.md)). Inputs:

| Phase | Document |
|---|---|
| 1 Vision | [../vision-statement.md](../vision-statement.md) |
| 2 Requirements | [../core-requirements.md](../core-requirements.md) |
| 3 Technology stack | [../tech-stack.md](../tech-stack.md), [../dast-requirements.lock.txt](../dast-requirements.lock.txt) |
| 4 Architecture | [../architecture.md](../architecture.md) |

Status: **epics, stories and a 2-sprint plan drafted** (AI implementation). See [sprint-plan.md](sprint-plan.md). Each story's `Sprint` field matches the plan.

## Conventions

- **Story ID:** `DAST-<EPIC number>-<NNN>`, for example `DAST-00-010`. Numbers step by 10 so stories can be inserted. This is the template's default format with `DAST` as the project key; change it with a find-and-replace if you prefer another.
- **Files:** one file per epic, plus this index.
- **Dependencies are the source of truth.** Each story's `Blocks` line is the inverse of the `Dependencies` lines, regenerated from them, and the graph was checked for missing IDs and cycles.
- **Parallelism:** `Parallel` or `Serial/Blocking`, generic `Dev` streams only; assignment to individuals happens in Jira.
- **Existing code:** the repo already has a working five-stage DAST pipeline, a `dast` scan type, an authorization check, narration and basic UI. Stories extend that code; none assumes a blank slate. Several Dev Notes name the existing file to extend.
- **Frontend testing:** the frontend has no test runner. Frontend stories verify through `npm run lint`, `npm run build` and a manual checklist in the story's Dev Testing section, run by the developer.
- **Dev only:** each story has Dev Notes and Dev Testing (tests the developer writes and runs). There are no separate Test/QA or DevOps sections.

## Epics

| Epic ID | Epic Name | Depends On | Stories | Goal |
|---|---|---|---|---|
| [EPIC-00](EPIC-00-scaffolding.md) | Scaffolding & Project Setup | — (foundational) | 9 | The DAST foundations every other epic builds on: pinned dependencies, the layered package structure with enforced import rules, the settings surface, the schema additions, the mock engine and test harness, CI, a local practice-target environment, and frontend type/API stubs. |
| [EPIC-01](EPIC-01-safety-guard.md) | Safety Guard & Request Audit | EPIC-00 | 6 | Every request that reaches a target passes one guard that enforces scope, method policy, rate and cancellation, and is recorded in an audit trail; model-generated inputs are validated as non-destructive before sending. |
| [EPIC-02](EPIC-02-model-gateway.md) | Model Gateway | EPIC-00 | 6 | One provider-neutral gateway is the only component that calls a model, routed per task, schema-validated, with fallbacks and cost accounting. |
| [EPIC-03](EPIC-03-check-catalog-rule-sets.md) | Check Catalog & Rule Sets | EPIC-00 (and DAST-04-020/-030 for the signal names a check may reference) | 6 | Coverage is declarative data: a validated catalog of checks, grouped into rule packs, configurable globally, per project and per scan, extendable with custom rules, and snapshotted on each scan. |
| [EPIC-04](EPIC-04-detectors-verdicts-findings.md) | Detectors, Verdicts & Findings | EPIC-00 | 6 | The pure domain core that makes the scan deterministic: findings with evidence, detector signals, verdict roll-up with the guardrail, dedupe, persistence and the findings query API. |
| [EPIC-05](EPIC-05-scan-setup-fingerprint.md) | Scan Setup, Fingerprint & Preflight | EPIC-00, EPIC-01, EPIC-02, EPIC-03 | 5 | Operators can start, configure, cancel and track a DAST scan; the engine confirms reachability, detects the target's shape, and routes the pipeline accordingly. |
| [EPIC-06](EPIC-06-authentication-identities.md) | Authentication & Identities | EPIC-01, EPIC-05 | 5 | Scans can authenticate by form, token or stored session, as one or several role-labelled identities, with credentials held in memory only and redacted everywhere. |
| [EPIC-07](EPIC-07-discovery.md) | Discovery | EPIC-01, EPIC-05, EPIC-06 | 6 | Build a deduplicated inventory of the target's endpoints from a guarded browser crawl, recorded network traffic and ingested API schemas, and report where observed and documented surface differ. |
| [EPIC-08](EPIC-08-passive-analysis.md) | Passive Analysis | EPIC-03, EPIC-04, EPIC-07 (recorded traffic) | 3 | Find header, cookie, CORS, disclosure, error and data-exposure issues from already-observed traffic, with no extra requests and no model calls. |
| [EPIC-09](EPIC-09-active-testing.md) | Active Testing Engine | EPIC-01, EPIC-02, EPIC-03, EPIC-04, EPIC-07 | 6 | For each discovered target, run the construct → validate → baseline → test → detect → rule → roll-up loop, bounded by budgets, safe by construction, and confirmed only by detector evidence. |
| [EPIC-10](EPIC-10-authorization-testing.md) | Multi-Role Authorization Testing | EPIC-04, EPIC-06, EPIC-09 | 4 | Cross-test every role against every other, plus an anonymous baseline, to find broken object-level and function-level authorization, and expose the result as a role-by-role matrix. |
| [EPIC-11](EPIC-11-reporting.md) | Reporting, Roll-up & Diff | EPIC-03, EPIC-04, EPIC-08, EPIC-09 | 4 | A client-readable report with severity roll-up, evidence, remediation, skipped/degraded checks and a scan-to-scan comparison, exported as PDF and XLSX. |
| [EPIC-12](EPIC-12-narration-progress.md) | Narration & Progress | EPIC-02, EPIC-05, and the stages that emit banners (EPIC-07 to EPIC-10) | 3 | Operators see live, readable progress through every stage, with counters and a severity breakdown, and the timeline still works when the model is down. |
| [EPIC-13](EPIC-13-ui-scan-flow.md) | UI: Dashboard, New Scan and Scan Detail | EPIC-00 (frontend stubs), EPIC-05, EPIC-12 (progress/narration data); each story names its backend dependency | 6 | Operators can list DAST scans, start one with identities, scope/safety, rule packs and model choice, and watch it run, all inside the existing frontend using its existing styles. |
| [EPIC-14](EPIC-14-ui-findings-matrix-report.md) | UI: Findings, Authorization Matrix and Report | EPIC-04, EPIC-10, EPIC-11, EPIC-13 | 4 | Operators review evidence-backed findings, see the role-by-role authorization matrix, and read and export the report with the scan-to-scan diff. |
| [EPIC-15](EPIC-15-ui-settings-rule-management.md) | UI: Settings and Rule-Set Management | EPIC-02, EPIC-03, EPIC-13 | 5 | Operators configure per-task model routing, provider credentials, scan defaults, the OAST address, and manage rule packs, per-check overrides and custom rules from the settings pages. |
| [EPIC-16](EPIC-16-quality-hardening.md) | Quality, Measurement & Hardening | EPIC-09, EPIC-10, and the stories named below | 6 | The scanner is measured, repeatable, safe and offline-testable: a precision/recall harness against practice targets, a determinism check, a regression gate, controlled training-data capture, and a security review of the safety controls. |

**Total: 90 stories across 17 epics.**

## Sequencing

EPIC-00 blocks everything else. After it, the backend foundations (safety guard, model gateway, catalog, detectors and findings) can run in parallel, and the frontend epics can start against the mock engine as soon as the EPIC-00 frontend stubs and mock-engine contract land.

```
EPIC-00 Scaffolding
   ├─► EPIC-01 Safety guard ───────┐
   ├─► EPIC-02 Model gateway ──────┼─► EPIC-05 Scan setup ─► EPIC-06 Auth ─► EPIC-07 Discovery ─┬─► EPIC-08 Passive
   ├─► EPIC-03 Catalog & rule sets ┘                                                             └─► EPIC-09 Active ─► EPIC-10 Authz
   ├─► EPIC-04 Detectors & findings ─────────────────────────────► (feeds 08, 09, 10, 11)                     │
   │                                                                  EPIC-11 Reporting ◄──────────────────────┤
   │                                                                  EPIC-12 Narration (needs banners 05–10)  │
   └─► EPIC-13/14/15 UI (against the mock engine first, then the real one)
                                                                        EPIC-16 Quality gate (last)
```

**Critical path (computed from the Dependencies lines, 18 stories):**
DAST-00-010 → 00-020 → 03-010 → 03-030 → 03-040 → 05-010 → 05-020 → 05-040 → 07-040 → 07-060 → 09-010 → 09-020 → 09-030 → 09-050 → 11-010 → 11-020 → 11-040 → 14-030.

It runs through the catalog and rule-set work (EPIC-03), not through the guard or the crawl. Anything that delays the rule-set resolution story (DAST-03-040) delays scan creation, and with it everything after. That story is worth starting early and staffing well.

Work off that path is where extra developers add the most parallelism: the safety guard, model gateway, detectors, passive checks, authentication, UI and settings.

## Known cross-epic wrinkles

- **Detector names vs. catalog (EPIC-03 and EPIC-04).** The catalog loader must validate signal names that the detector library defines. DAST-03-010 starts with a stub registry of the names in the design doc; DAST-04-020 and -030 replace it. Neither blocks the other.
- **Mock output uses old check ids.** `dast-sqli`, `dast-xss` and `dast-misconfig` stay as aliases in the catalog (DAST-03-020) so existing tests keep passing.
- **Confidence column.** The existing `Finding.confidence` is a float used by SAST. DAST adds a separate `confidence_label` (High/Medium/Low) instead of changing it (DAST-00-040).
- **Cancelled status.** The code currently documents `queued|running|success|failed`; adding `cancelled` touches status handling in the backend and in `ScanStatusBadge` (DAST-05-050).
- **Credentials.** Held in memory only, and a restart fails the scan (DAST-06-010, -050). That matches the existing in-memory secrets path.

## Open decisions that affect stories

1. **OAST service** (DAST-09-060): self-hosted or managed collaborator. Without one, SSRF stays assist-only.
2. **Secret storage for provider keys** (DAST-15-020): the platform has no secret store today, so v1 may be environment-only.
3. **Where settings persist** (DAST-15-050): database or environment-only.
4. **Request-audit retention** (DAST-01-050): rows per scan will be large; the retention policy is deferred.
5. **Practice-target ground truth** (DAST-16-020): expected-findings lists need manual verification against the pinned image versions.

## Story index


**EPIC-00**

| Story | Title | Parallelism | Depends on |
|---|---|---|---|
| DAST-00-010 | Adopt the pinned dependency set | Serial/Blocking | — |
| DAST-00-020 | Layered package skeleton and import-rule check | Serial/Blocking | DAST-00-010 |
| DAST-00-030 | DAST settings surface | Parallel | DAST-00-010 |
| DAST-00-040 | Schema additions for DAST evidence and audit | Parallel | DAST-00-020 |
| DAST-00-050 | Mock engine contract extended | Parallel | DAST-00-020 |
| DAST-00-060 | Test harness and offline target fixtures | Parallel | DAST-00-020 |
| DAST-00-070 | CI pipeline skeleton | Parallel | DAST-00-010 |
| DAST-00-080 | Local practice-target environment | Parallel | DAST-00-010 |
| DAST-00-090 | Frontend scaffolding: types, API stubs and shared helpers | Parallel | DAST-00-050 |

**EPIC-01**

| Story | Title | Parallelism | Depends on |
|---|---|---|---|
| DAST-01-010 | Scope and method policy | Serial/Blocking | DAST-00-020, DAST-00-030 |
| DAST-01-020 | Rate limit, concurrency cap and cancellation | Parallel | DAST-01-010, DAST-00-030 |
| DAST-01-030 | Guarded request executor | Serial/Blocking | DAST-01-010, DAST-01-020, DAST-00-060 |
| DAST-01-040 | Browser traffic through the guard | Parallel | DAST-01-030, DAST-01-010 |
| DAST-01-050 | Request audit persistence and retrieval | Parallel | DAST-01-030, DAST-00-040, DAST-06-010 |
| DAST-01-060 | Non-destructive input validator | Parallel | DAST-00-020 |

**EPIC-02**

| Story | Title | Parallelism | Depends on |
|---|---|---|---|
| DAST-02-010 | Gateway core and request contract | Serial/Blocking | DAST-00-020, DAST-00-030 |
| DAST-02-020 | Local model adapter and migration of existing callers | Serial/Blocking | DAST-02-010 |
| DAST-02-030 | Anthropic and OpenAI adapters | Parallel | DAST-02-010 |
| DAST-02-040 | Bedrock adapter | Parallel | DAST-02-010 |
| DAST-02-050 | Token and cost accounting | Parallel | DAST-02-020 |
| DAST-02-060 | Task prompts and few-shot loader | Parallel | DAST-02-010 |

**EPIC-03**

| Story | Title | Parallelism | Depends on |
|---|---|---|---|
| DAST-03-010 | Check schema and catalog loader | Serial/Blocking | DAST-00-020 |
| DAST-03-020 | Default pack: OWASP API Security Top 10 (2023) | Parallel | DAST-03-010 |
| DAST-03-030 | Default packs: Web Top 10, WSTG and passive-only | Parallel | DAST-03-010 |
| DAST-03-040 | Packs, per-check overrides and effective rule set | Serial/Blocking | DAST-03-020, DAST-03-030, DAST-00-040 |
| DAST-03-050 | Custom rules | Parallel | DAST-03-040 |
| DAST-03-060 | Dependency-aware skip and degrade | Parallel | DAST-03-040, DAST-03-010 |

**EPIC-04**

| Story | Title | Parallelism | Depends on |
|---|---|---|---|
| DAST-04-010 | Domain entities and finding mapping | Serial/Blocking | DAST-00-020, DAST-00-040 |
| DAST-04-020 | Detector library: injection and leakage signals | Parallel | DAST-04-010 |
| DAST-04-030 | Detector library: divergence, timing and authorization boundary | Parallel | DAST-04-010 |
| DAST-04-040 | Verdict roll-up and guardrail | Serial/Blocking | DAST-04-020, DAST-04-030 |
| DAST-04-050 | Findings writer with evidence and dedupe | Parallel | DAST-04-010, DAST-00-040 |
| DAST-04-060 | Findings query API | Parallel | DAST-04-050, DAST-03-020, DAST-04-010 |

**EPIC-05**

| Story | Title | Parallelism | Depends on |
|---|---|---|---|
| DAST-05-010 | DAST scan creation contract | Serial/Blocking | DAST-00-030, DAST-03-040 |
| DAST-05-020 | Effective settings snapshot and intensity presets | Parallel | DAST-05-010, DAST-00-030, DAST-03-040 |
| DAST-05-030 | Preflight stage | Parallel | DAST-01-030, DAST-02-010, DAST-02-060 |
| DAST-05-040 | Fingerprint stage and pipeline routing | Serial/Blocking | DAST-05-030, DAST-05-020, DAST-02-060 |
| DAST-05-050 | End-to-end cancellation | Parallel | DAST-01-020 |

**EPIC-06**

| Story | Title | Parallelism | Depends on |
|---|---|---|---|
| DAST-06-010 | Credential holder and log redaction | Serial/Blocking | DAST-00-020 |
| DAST-06-020 | Identity model and per-identity sessions | Serial/Blocking | DAST-06-010, DAST-05-010 |
| DAST-06-030 | Form login adaptation | Parallel | DAST-06-020, DAST-05-040 |
| DAST-06-040 | Token and pre-authenticated state | Parallel | DAST-06-020 |
| DAST-06-050 | Session loss and failure semantics | Serial/Blocking | DAST-06-030, DAST-06-040, DAST-06-010 |

**EPIC-07**

| Story | Title | Parallelism | Depends on |
|---|---|---|---|
| DAST-07-010 | Endpoint inventory model | Serial/Blocking | DAST-00-020, DAST-04-010 |
| DAST-07-020 | Crawl stage on the browser driver | Serial/Blocking | DAST-01-040, DAST-06-030, DAST-06-040, DAST-05-040, DAST-07-010, DAST-05-020 |
| DAST-07-030 | Network recorder with request bodies | Serial/Blocking | DAST-07-020 |
| DAST-07-040 | OpenAPI and Swagger ingestion | Parallel | DAST-07-010, DAST-01-030, DAST-05-040 |
| DAST-07-050 | GraphQL introspection ingestion | Parallel | DAST-07-010, DAST-01-010 |
| DAST-07-060 | Observed vs documented inventory diff | Parallel | DAST-07-040, DAST-07-050, DAST-04-050, DAST-07-010 |

**EPIC-08**

| Story | Title | Parallelism | Depends on |
|---|---|---|---|
| DAST-08-010 | Passive stage and header/cookie checks | Serial/Blocking | DAST-07-030, DAST-04-050, DAST-03-030 |
| DAST-08-020 | CORS and technology disclosure | Parallel | DAST-08-010 |
| DAST-08-030 | Verbose errors and sensitive data exposure | Parallel | DAST-08-010, DAST-04-020 |

**EPIC-09**

| Story | Title | Parallelism | Depends on |
|---|---|---|---|
| DAST-09-010 | Active stage and per-target loop | Serial/Blocking | DAST-03-040, DAST-04-040, DAST-05-020, DAST-06-050, DAST-07-010, DAST-07-060, DAST-01-030, DAST-03-020, DAST-07-040 |
| DAST-09-020 | Select and construct | Serial/Blocking | DAST-09-010, DAST-02-060, DAST-01-060, DAST-02-010 |
| DAST-09-030 | Baseline, test execution and rule | Serial/Blocking | DAST-09-020, DAST-04-040, DAST-04-050, DAST-07-030, DAST-04-020 |
| DAST-09-040 | Form and parameter testing | Parallel | DAST-09-030, DAST-07-030 |
| DAST-09-050 | Opt-in and assist-only checks | Parallel | DAST-09-030, DAST-03-060 |
| DAST-09-060 | SSRF with out-of-band confirmation | Parallel | DAST-09-030, DAST-03-060, DAST-09-010 |

**EPIC-10**

| Story | Title | Parallelism | Depends on |
|---|---|---|---|
| DAST-10-010 | Anonymous replay and degraded mode | Serial/Blocking | DAST-09-030, DAST-06-020, DAST-04-030, DAST-03-060 |
| DAST-10-020 | Cross-role replay engine | Serial/Blocking | DAST-10-010 |
| DAST-10-030 | BOLA and BFLA checks | Parallel | DAST-10-020, DAST-04-040, DAST-03-020, DAST-04-030 |
| DAST-10-040 | Authorization matrix and API | Parallel | DAST-10-020, DAST-04-060, DAST-10-010 |

**EPIC-11**

| Story | Title | Parallelism | Depends on |
|---|---|---|---|
| DAST-11-010 | Severity roll-up and report data | Serial/Blocking | DAST-04-050, DAST-03-060, DAST-08-020, DAST-08-030, DAST-09-050, DAST-00-040 |
| DAST-11-020 | Scan-to-scan diff | Parallel | DAST-11-010 |
| DAST-11-030 | PDF export | Parallel | DAST-11-010, DAST-11-020 |
| DAST-11-040 | XLSX export | Parallel | DAST-11-010, DAST-11-020 |

**EPIC-12**

| Story | Title | Parallelism | Depends on |
|---|---|---|---|
| DAST-12-010 | Banners and progress markers for new stages | Parallel | DAST-00-050 |
| DAST-12-020 | Narration for new stages with template fallback | Parallel | DAST-12-010, DAST-02-020 |
| DAST-12-030 | Live counters and severity breakdown | Parallel | DAST-04-050, DAST-01-050, DAST-02-050 |

**EPIC-13**

| Story | Title | Parallelism | Depends on |
|---|---|---|---|
| DAST-13-010 | DAST dashboard | Parallel | DAST-00-090, DAST-00-050 |
| DAST-13-020 | New Scan form: target, authorization and safety | Serial/Blocking | DAST-05-010, DAST-00-090 |
| DAST-13-030 | New Scan form: identities and roles | Parallel | DAST-13-020, DAST-06-040 |
| DAST-13-040 | New Scan form: rule packs and model | Parallel | DAST-13-020, DAST-03-040 |
| DAST-13-050 | Scan detail: timeline, counters and cancel | Serial/Blocking | DAST-12-010, DAST-12-020, DAST-12-030, DAST-05-050 |
| DAST-13-060 | Scan detail: discovery and analysis panels | Parallel | DAST-13-050, DAST-07-060 |

**EPIC-14**

| Story | Title | Parallelism | Depends on |
|---|---|---|---|
| DAST-14-010 | Findings panel: DAST evidence and filters | Serial/Blocking | DAST-04-060, DAST-13-050, DAST-00-050 |
| DAST-14-020 | Authorization matrix component | Parallel | DAST-10-040, DAST-14-010, DAST-13-030 |
| DAST-14-030 | Report view and exports | Parallel | DAST-11-020, DAST-11-030, DAST-11-040, DAST-13-050 |
| DAST-14-040 | Accessibility and states pass | Serial/Blocking | DAST-14-010, DAST-14-020, DAST-13-050 |

**EPIC-15**

| Story | Title | Parallelism | Depends on |
|---|---|---|---|
| DAST-15-010 | Model routing settings | Serial/Blocking | DAST-02-030, DAST-02-040, DAST-00-090 |
| DAST-15-020 | Credential entry with masking | Parallel | DAST-15-010 |
| DAST-15-030 | Rule-set management | Parallel | DAST-03-040, DAST-13-040 |
| DAST-15-040 | Custom rule authoring | Parallel | DAST-03-050, DAST-15-030 |
| DAST-15-050 | Scan defaults and OAST address | Parallel | DAST-00-030, DAST-00-090 |

**EPIC-16**

| Story | Title | Parallelism | Depends on |
|---|---|---|---|
| DAST-16-010 | Measurement harness | Serial/Blocking | DAST-09-030, DAST-00-080 |
| DAST-16-020 | Practice-target ground truth | Parallel | DAST-16-010, DAST-09-040, DAST-10-030, DAST-00-080 |
| DAST-16-030 | Determinism and offline guarantees | Parallel | DAST-16-010, DAST-04-040, DAST-09-030 |
| DAST-16-040 | Regression gate | Serial/Blocking | DAST-16-010, DAST-16-020, DAST-16-030, DAST-00-070 |
| DAST-16-050 | Training-data capture with controls | Parallel | DAST-09-030, DAST-01-060, DAST-06-010 |
| DAST-16-060 | Security review of safety controls | Serial/Blocking | DAST-01-050, DAST-01-060, DAST-06-010, DAST-09-030, DAST-11-040, DAST-16-050 |

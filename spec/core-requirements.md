# Core Requirements for Augmented Secure Build — DAST Scan Type

Derived from [vision-statement.md](vision-statement.md) (Phase 1) and the source documents in `spec/`. Technology choices are deliberately excluded; they belong to Phase 3.

## Functional Requirements

### Scan Setup (SCAN)

- REQ-FR-SCAN-1: The system shall let an operator start a DAST scan against a running web target by supplying its address.
- REQ-FR-SCAN-2: The system shall require the operator to confirm authorization to test the target before a scan starts.
- REQ-FR-SCAN-3: The system shall let an operator associate a DAST scan with an existing project.
- REQ-FR-SCAN-4: The system shall let an operator create a new project from the DAST scan form.
- REQ-FR-SCAN-5: The system shall provide a light, standard and deep scan intensity preset.
- REQ-FR-SCAN-6: The system shall let an operator cancel a running scan.
- REQ-FR-SCAN-7: The system shall record each scan with a status of queued, running, success, failed or cancelled.
- REQ-FR-SCAN-8: The system shall detect the target's type (multi-page site, single-page app, or API-only service) without per-target configuration.
- REQ-FR-SCAN-9: The system shall adapt which scan stages run according to the detected target type.
- REQ-FR-SCAN-10: The system shall detect the target's authentication style and whether it publishes an API schema.

### Authentication (AUTH)

- REQ-FR-AUTH-1: The system shall support scanning a target with no authentication.
- REQ-FR-AUTH-2: The system shall support authenticating through a web login form.
- REQ-FR-AUTH-3: The system shall support authenticating with a supplied bearer token, JWT or API key.
- REQ-FR-AUTH-4: The system shall support authenticating from an uploaded pre-authenticated browser session.
- REQ-FR-AUTH-5: The system shall verify that a form login succeeded using more than one signal.
- REQ-FR-AUTH-6: The system shall retry a failed form login once.
- REQ-FR-AUTH-7: The system shall fail the scan with a clear message when authentication fails.
- REQ-FR-AUTH-8: The system shall fail a scan whose credentials were lost mid-scan instead of continuing unauthenticated.

### Multi-Role Authorization Testing (ROLE)

- REQ-FR-ROLE-1: The system shall let an operator add multiple identities to a scan, each assigned a role (Admin, User, Viewer, Anonymous or Custom).
- REQ-FR-ROLE-2: The system shall always include an unauthenticated (Anonymous) baseline in authorization testing.
- REQ-FR-ROLE-3: The system shall test every pair of roles against each other automatically.
- REQ-FR-ROLE-4: The system shall test for broken object-level authorization.
- REQ-FR-ROLE-5: The system shall test for broken function-level authorization.
- REQ-FR-ROLE-6: The system shall present authorization results as a role-by-role matrix.
- REQ-FR-ROLE-7: The system shall let an operator select a failing matrix cell to filter findings to that role pair.
- REQ-FR-ROLE-8: The system shall report cross-role checks as skipped or degraded when a second identity is not supplied.

### Discovery (DISC)

- REQ-FR-DISC-1: The system shall build an inventory of the target's endpoints by exploring it as a real browser would.
- REQ-FR-DISC-2: The system shall record the network requests the target makes while it is explored.
- REQ-FR-DISC-3: The system shall ingest an OpenAPI or GraphQL schema when the target publishes one.
- REQ-FR-DISC-4: The system shall merge observed and schema-derived endpoints and remove duplicates.
- REQ-FR-DISC-5: The system shall capture the request bodies the target sends.
- REQ-FR-DISC-6: The system shall let an operator bound a crawl by runtime, depth and number of pages.
- REQ-FR-DISC-7: The system shall report endpoints that were observed but are absent from the published schema, and the reverse.

### Passive Analysis (PASS)

- REQ-FR-PASS-1: The system shall analyze already-observed traffic without sending additional requests.
- REQ-FR-PASS-2: The system shall report missing or misconfigured security headers.
- REQ-FR-PASS-3: The system shall report cookies lacking HttpOnly, Secure or SameSite protection.
- REQ-FR-PASS-4: The system shall report over-permissive cross-origin settings.
- REQ-FR-PASS-5: The system shall report server, framework or version disclosure.
- REQ-FR-PASS-6: The system shall report verbose errors and stack traces.
- REQ-FR-PASS-7: The system shall report sensitive data exposed in responses.

### Active Testing (ACT)

- REQ-FR-ACT-1: The system shall actively test each discovered target against the applicable checks.
- REQ-FR-ACT-2: The system shall compare each test result against a baseline request to the same target.
- REQ-FR-ACT-3: The system shall judge each test using observable signals, including database error disclosure, unescaped input reflection, command output, stack trace leakage, response timing and response status or length changes.
- REQ-FR-ACT-4: The system shall roll up per-target results as fail if any check fails, inconclusive if all are inconclusive, and pass otherwise.
- REQ-FR-ACT-5: The system shall let an operator cap the number of targets and the number of tests per target.
- REQ-FR-ACT-6: The system shall test form fields and request parameters.
- REQ-FR-ACT-7: The system shall detect server-side request forgery only when an out-of-band callback service is configured, and mark it assist-only otherwise.
- REQ-FR-ACT-8: The system shall keep resource-consumption checks disabled until an operator explicitly enables them.
- REQ-FR-ACT-9: The system shall flag sensitive business flows and unsafe consumption of third-party APIs for human review rather than reporting them as confirmed findings.

### Rule Sets (RULE)

- REQ-FR-RULE-1: The system shall organize checks into named rule packs.
- REQ-FR-RULE-2: The system shall ship rule packs for the OWASP API Security Top 10 (2023), the OWASP Web Top 10, the OWASP Web Security Testing Guide, and a passive-only pack.
- REQ-FR-RULE-3: The system shall let rule packs be enabled globally, defaulted per project and overridden per scan.
- REQ-FR-RULE-4: The system shall let an operator enable or disable individual checks.
- REQ-FR-RULE-5: The system shall let an operator override a check's severity.
- REQ-FR-RULE-6: The system shall let an operator set a check's mode to automated, opt-in or assist-only.
- REQ-FR-RULE-7: The system shall let an operator add custom checks without changing product code.
- REQ-FR-RULE-8: The system shall tag every check with its OWASP, WSTG and CWE references.
- REQ-FR-RULE-9: The system shall report a finding against each standard its check is tagged with.
- REQ-FR-RULE-10: The system shall reject or limit to unverified a custom check that cannot name an observable proving signal.
- REQ-FR-RULE-11: The system shall record the effective rule set on each scan at the moment it starts.
- REQ-FR-RULE-12: The system shall report a check as skipped or degraded when something it needs is absent from the scan.

### Findings and Evidence (FIND)

- REQ-FR-FIND-1: The system shall record each finding as the same type of finding record that other scan types use, marked as a DAST finding.
- REQ-FR-FIND-2: The system shall record, for each finding, its check id, severity, confidence, verdict, target, parameter and location.
- REQ-FR-FIND-3: The system shall mark a finding as confirmed only when an observable signal supports it.
- REQ-FR-FIND-4: The system shall mark any model-proposed failure that lacks a supporting signal as unverified.
- REQ-FR-FIND-5: The system shall store the baseline and test exchange and the triggering signals as evidence for each finding.
- REQ-FR-FIND-6: The system shall remove duplicate findings that share a check, endpoint pattern and parameter.
- REQ-FR-FIND-7: The system shall always show unverified findings and never hide them.
- REQ-FR-FIND-8: The system shall include remediation guidance with each finding.
- REQ-FR-FIND-9: The system shall let an operator filter findings by severity, verdict, role and check.

### Model Layer (MDL)

- REQ-FR-MDL-1: The system shall use an AI model only to plan scans, build test inputs, suggest login selectors, propose verdicts and narrate progress.
- REQ-FR-MDL-2: The system shall route every model call through a single gateway.
- REQ-FR-MDL-3: The system shall support a local model and hosted models from more than one provider.
- REQ-FR-MDL-4: The system shall default to a local model.
- REQ-FR-MDL-5: The system shall let an operator choose the provider and model separately for each task.
- REQ-FR-MDL-6: The system shall continue the scan with a deterministic fallback when a model call fails.
- REQ-FR-MDL-7: The system shall reject any model output that names a check not in the catalog.
- REQ-FR-MDL-8: The system shall record token usage and cost for each scan.

### Safety (SAFE)

- REQ-FR-SAFE-1: The system shall confine active testing to the authorized host or hosts.
- REQ-FR-SAFE-2: The system shall reject a test aimed at an unauthorized host before sending it.
- REQ-FR-SAFE-3: The system shall send only non-mutating requests unless the operator opts in to state-changing methods for that scan.
- REQ-FR-SAFE-4: The system shall default to the non-mutating setting when the target is not marked disposable.
- REQ-FR-SAFE-5: The system shall let an operator set a request-rate and concurrency limit.
- REQ-FR-SAFE-6: The system shall check for cancellation between individual tests.
- REQ-FR-SAFE-7: The system shall generate only non-destructive test inputs, and shall not produce inputs designed to delete, modify or corrupt data.
- REQ-FR-SAFE-8: The system shall validate every model-generated test input before sending it and discard any that violates the non-destructive rule.
- REQ-FR-SAFE-9: The system shall record every request sent during a scan so an operator can audit exactly what was sent to the target.

### Reporting (RPT)

- REQ-FR-RPT-1: The system shall produce a scan report summarizing findings by severity, with unverified findings shown separately.
- REQ-FR-RPT-2: The system shall include evidence and remediation for each finding in the report.
- REQ-FR-RPT-3: The system shall compare a scan to the previous scan and label each finding New, Fixed or Still open.
- REQ-FR-RPT-4: The system shall export reports as PDF.
- REQ-FR-RPT-5: The system shall export reports as XLSX.

### Progress and Narration (NARR)

- REQ-FR-NARR-1: The system shall show live scan progress through the stages checking connection, authenticating, discovering, testing and analyzing.
- REQ-FR-NARR-2: The system shall present the scan log as a readable, first-person step-by-step timeline.
- REQ-FR-NARR-3: The system shall show a readable timeline when the AI model is unavailable.
- REQ-FR-NARR-4: The system shall show live counters and a severity breakdown while a scan runs.

### User Interface (UI)

- REQ-FR-UI-1: The system shall provide a DAST dashboard listing recent scans with their status and finding counts, filterable by project.
- REQ-FR-UI-2: The system shall provide a New Scan form covering target, identities and roles, scope and safety settings, rule packs and model selection.
- REQ-FR-UI-3: The system shall provide a scan detail view with the progress timeline, discovery results, analysis results and findings.
- REQ-FR-UI-4: The system shall provide a settings area for per-task model routing, credentials, scan defaults, the out-of-band callback address and rule-set management.
- REQ-FR-UI-5: The system shall mask stored credentials and treat them as write-only.
- REQ-FR-UI-6: The system shall handle empty, loading, running, failed and cancelled states in every data view.
- REQ-FR-UI-7: The system shall ask for confirmation before a destructive action such as deleting a scan or cancelling a running one.

## Additional Requirements

### Platform Integration (INT)

- REQ-INT-1: The system shall present DAST scans and findings alongside other scan types in the existing platform.
- REQ-INT-2: The system shall keep each project's scan history so scans can be compared over time.
- REQ-INT-3: The system shall require authentication for every backend interface except the health check.
- REQ-INT-4: The system shall never expose the platform's access token to the browser.

### Security and Privacy (SEC)

- REQ-SEC-1: The system shall hold scan credentials in memory only for the life of the scan.
- REQ-SEC-2: The system shall keep scan credentials out of logs.
- REQ-SEC-3: The system shall discard scan credentials when the scan ends.
- REQ-SEC-4: The system shall use training data only from targets the operator is authorized to test.
- REQ-SEC-5: The system shall restrict access to stored training data of confirmed test inputs to authorized operators.
- REQ-SEC-6: The system shall strip target identifiers from stored training examples.

### Quality and Reproducibility (NFR)

- REQ-NFR-1: The system shall produce the same verdicts when the same target in the same state is scanned twice.
- REQ-NFR-2: The system shall let the full scan pipeline run offline against a simulated target for automated testing, with no browser, model or network.
- REQ-NFR-3: The system shall be measurable against deliberately vulnerable practice applications using a fixed list of expected findings, scored for precision and recall.
- REQ-NFR-4: The system shall make no regression in recall or precision against that measurement before a change ships.
- REQ-NFR-5: The system shall let an operator run a scan against a practice target on a local machine without cloud services.

### Constraints (CON)

- REQ-CON-1: The system shall build its interface within the existing frontend, reusing its navigation, page layout, colours, typography, form styles, scan-status display, findings panel and dialogs.
- REQ-CON-2: The system shall present the interface in the existing light-only theme.
- REQ-CON-3: The system shall never rely on colour alone to convey severity, verdict or matrix result.
- REQ-CON-4: The system shall label severity and verdict with text.
- REQ-CON-5: The system shall make every interactive control keyboard-accessible with a visible focus indicator.
- REQ-CON-6: The system shall not require a CAPTCHA, one-time-password or full single-sign-on flow to be automated; pre-authenticated sessions cover those cases.

## Not in Scope

Taken from the source documents:

- Replacing a human penetration tester on business-logic flaws; these are assist-only.
- Defeating CAPTCHA, one-time-password or multi-factor flows.
- Testing gRPC or custom protocols (REST and GraphQL are first-class; SOAP and others are best-effort via schema).
- Dark mode, per-tenant theming, and a cross-scan program dashboard in the first release.

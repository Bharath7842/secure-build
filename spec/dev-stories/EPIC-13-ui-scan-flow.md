## [EPIC-13] UI: Dashboard, New Scan and Scan Detail

**Goal:** Operators can list DAST scans, start one with identities, scope/safety, rule packs and model choice, and watch it run, all inside the existing frontend using its existing styles.
**Depends On:** EPIC-00 (frontend stubs), EPIC-05, EPIC-12 (progress/narration data); each story names its backend dependency
**Blocks:** EPIC-14
**Teams:** Dev

Requirements: REQ-FR-UI-1 to -3, -6, -7, REQ-FR-ROLE-1, REQ-FR-NARR-\*, REQ-CON-1 to -5. Constraints for every story in this epic:
- Extend the existing components (`DastScanForm`, `DastScanDetail`, `DastNarrationTimeline`, `DastAnalysisPanel`, `AgentArtifactCard`, `frontend/app/dast/page.tsx`); do not create a parallel UI or a second navigation rail.
- Use existing tokens and utilities only (`--ink`, `--muted`, `--accent`, `inputClass`/`selectClass` from `lib/formStyles.ts`, `ScanStatusBadge`, `ConfirmDialog`/`useConfirmDialog`). No new colours, no new UI dependency, light theme only.
- Check `node_modules/next/dist/docs/` before writing Next-specific code (see `frontend/AGENTS.md`).
- The frontend has no test runner: verification is `npm run lint`, `npm run build`, and the manual checklist in each story's Dev Testing section, run by the developer.
- Every data view must handle empty, loading, running, failed and cancelled states using the existing empty/error box styles.

---

### DAST-13-010 DAST dashboard

**Epic:** EPIC-13 UI: Dashboard, New Scan and Scan Detail        **Parent:** EPIC-13
**Parallelism:** Parallel    **Sprint:** 2

**Story**
As an operator, I want a list of recent DAST scans with status and finding counts, filterable by project, so that I can see activity at a glance.

**Acceptance Criteria**
- The existing `/dast` page lists recent scans with `ScanStatusBadge`, target, project, version, started time, and counts (confirmed by severity, unverified).
- The project filter that exists keeps working.
- Clicking a row opens the scan detail.
- Deleting a scan (where the platform already allows it) asks for confirmation through the existing confirm dialog before anything is removed.
- Empty, loading and error states use the existing box styles.
- Optional stat tiles, if added, use the same card style and no new colours.

**Dev Notes**
- Counts from the list endpoint (extend `GET /scans` summary for DAST) or a lightweight per-scan summary; avoid N+1 fetches from the page.
- Add the fields to `lib/types.ts` and `lib/api.ts`.

**Dev Testing**
- Test level: lint + build + manual.
- Manual: with mock data, list shows scans of each status; filter by project narrows the list; empty project shows the empty state; backend down shows the error state.
- Entry point: `/dast`.

**Dependencies:** DAST-00-090, DAST-00-050
**Blocks:** —

**Definition of Done:** code merged + developer tests green

---

### DAST-13-020 New Scan form: target, authorization and safety

**Epic:** EPIC-13 UI: Dashboard, New Scan and Scan Detail        **Parent:** EPIC-13
**Parallelism:** Serial/Blocking    **Sprint:** 2

**Story**
As an operator, I want to set the target, confirm authorization and choose scope and safety settings so that a scan is configured deliberately.

**Acceptance Criteria**
- Extends `DastScanForm` (no replacement) with sections: Target (address, project pick or inline create as today, authorization confirm, disposable-target toggle), Scope & safety (intensity preset light/standard/deep, method policy with a clear warning when allowing state-changing methods, request rate limit).
- Submit is disabled until the address is valid and authorization is confirmed.
- Safe mode is the default and is visibly on; turning off requires an explicit control, not a default.
- Validation messages appear inline; server errors appear in the existing error box.
- The existing form behavior (creating a project inline, login fields) still works until DAST-13-030 replaces the login block.

**Dev Notes**
- Use `inputClass`/`selectClass`; section labels use the `text-xs font-semibold uppercase tracking-wide text-[var(--muted)]` style.
- Preset descriptions come from the backend settings (no hard-coded numbers in the UI).

**Dev Testing**
- Test level: lint + build + manual.
- Manual: submit disabled without authorization; invalid URL message; safe mode default on; enabling state-changing methods shows the warning; request payload matches the create-scan contract (inspect network call).
- Entry point: `/scans/new?type=dast`.

**Dependencies:** DAST-05-010, DAST-00-090
**Blocks:** DAST-13-030, DAST-13-040

**Definition of Done:** code merged + developer tests green

---

### DAST-13-030 New Scan form: identities and roles

**Epic:** EPIC-13 UI: Dashboard, New Scan and Scan Detail        **Parent:** EPIC-13
**Parallelism:** Parallel    **Sprint:** 2

**Story**
As an operator, I want to add identities by role, each with its own authentication method, so that cross-role authorization testing is possible.

**Acceptance Criteria**
- Replaces the single login block with an identity list: one card per identity with label, role (Admin, User, Viewer, Custom with a name), and an auth-method switch (Form, Token, Pre-authenticated state).
- Form: login URL, username, password. Token: header name/scheme and token value. Pre-auth: storage-state file upload.
- Anonymous is shown as an implied, non-removable identity.
- Secret fields are masked, never pre-filled, and not retained in browser storage.
- A live preview of the authorization matrix shows which role pairs will be tested, or that only anonymous replay will run with one identity.
- Role badges use the shared tone mapping from DAST-00-090; the role name is always shown as text.
- Duplicate labels are blocked inline.

**Dev Notes**
- `dast_new_scan_ui.html` is a behaviour reference only (identity add/remove, auth switching, matrix preview); do not copy its styling.
- Uploads go through a proxy route; check the Next.js docs for multipart handling.

**Dev Testing**
- Test level: lint + build + manual.
- Manual: add and remove identities; each auth method shows the right fields; matrix preview updates; password field masked; reload shows no secrets; payload contains identities in the contract shape; file upload sent.

**Dependencies:** DAST-13-020, DAST-06-040
**Blocks:** DAST-14-020

**Definition of Done:** code merged + developer tests green

---

### DAST-13-040 New Scan form: rule packs and model

**Epic:** EPIC-13 UI: Dashboard, New Scan and Scan Detail        **Parent:** EPIC-13
**Parallelism:** Parallel    **Sprint:** 2

**Story**
As an operator, I want to choose which rule packs run and which model is used so that a scan matches its purpose.

**Acceptance Criteria**
- A rule-pack picker lists available packs (from the backend) with descriptions, pre-selected from project defaults, with per-scan overrides.
- Checks that are off by default (resource consumption) and checks that need a dependency are visible with a note and a disabled or explained state.
- Model section: provider and model for the scan, defaulting to the configured routing; when the chosen provider lacks credentials, the form says so before submit.
- A summary line shows the number of checks that will run.

**Dev Notes**
- Reads the effective-rule-set preview endpoint from DAST-03-040.

**Dev Testing**
- Test level: lint + build + manual.
- Manual: pack toggles change the check count; API4 shows as off-by-default; missing OAST shows the SSRF note; payload carries pack ids.

**Dependencies:** DAST-13-020, DAST-03-040
**Blocks:** DAST-15-030

**Definition of Done:** code merged + developer tests green

---

### DAST-13-050 Scan detail: timeline, counters and cancel

**Epic:** EPIC-13 UI: Dashboard, New Scan and Scan Detail        **Parent:** EPIC-13
**Parallelism:** Serial/Blocking    **Sprint:** 2

**Story**
As an operator, I want a live timeline, counters and a cancel button on the scan page so that I can follow and control a running scan.

**Acceptance Criteria**
- `DastScanDetail` shows the timeline (`DastNarrationTimeline`) through the stages in the requirements, live counters and severity breakdown, status badge, and the Cancel button.
- Polls the incremental log and counters at a modest interval, stopping when the scan is finished.
- Cancel asks for confirmation through the existing confirm dialog and then reflects `cancelled`.
- Failed scans show the failure reason prominently; skipped and degraded checks are listed.
- Timeline shows a template summary when narration came from the fallback, without error styling.
- All five states (empty, loading, running, failed, cancelled) render correctly.

**Dev Notes**
- Keep the existing polling approach; do not add a push channel.
- Update `parseScanLog.ts` for new stage labels (DAST-12-010).

**Dev Testing**
- Test level: lint + build + manual.
- Manual: run a mock scan and a cancelled scan and a failed scan; counters tick; cancel dialog appears; reload mid-run resumes the timeline.

**Dependencies:** DAST-12-010, DAST-12-020, DAST-12-030, DAST-05-050
**Blocks:** DAST-13-060, DAST-14-010, DAST-14-030, DAST-14-040

**Definition of Done:** code merged + developer tests green

---

### DAST-13-060 Scan detail: discovery and analysis panels

**Epic:** EPIC-13 UI: Dashboard, New Scan and Scan Detail        **Parent:** EPIC-13
**Parallelism:** Parallel    **Sprint:** 2

**Story**
As an operator, I want discovery and analysis results available as click-to-open summaries so that I can inspect what the scan found and tested.

**Acceptance Criteria**
- Discovery and Analysis appear as `AgentArtifactCard` summaries that open side panels, like the existing Discovery card for SAST.
- Discovery panel: fingerprint (shape, auth, schema), pages, forms, endpoints with source (observed/schema/both), undocumented endpoints, identities reached.
- Analysis panel (extends `DastAnalysisPanel`): checks run per target, passive results, tests sent, dropped/unsafe counts, guardrail downgrades.
- Panels show their empty and loading states and never block the timeline.

**Dev Notes**
- Extend, do not duplicate, `DastAnalysisPanel` and `ScanDiscoveryPanel` styles.

**Dev Testing**
- Test level: lint + build + manual.
- Manual: panels open and close; sections show seeded data; empty scan shows empty states.

**Dependencies:** DAST-13-050, DAST-07-060
**Blocks:** —

**Definition of Done:** code merged + developer tests green

## [EPIC-14] UI: Findings, Authorization Matrix and Report

**Goal:** Operators review evidence-backed findings, see the role-by-role authorization matrix, and read and export the report with the scan-to-scan diff.
**Depends On:** EPIC-04, EPIC-10, EPIC-11, EPIC-13
**Blocks:** —
**Teams:** Dev

Requirements: REQ-FR-FIND-7, -9, REQ-FR-ROLE-6, -7, REQ-FR-RPT-\*, REQ-FR-UI-6, REQ-CON-3 to -5. The same frontend constraints listed at the top of [EPIC-13](EPIC-13-ui-scan-flow.md) apply to every story here.

---

### DAST-14-010 Findings panel: DAST evidence and filters

**Epic:** EPIC-14 UI: Findings, Authorization Matrix and Report        **Parent:** EPIC-14
**Parallelism:** Serial/Blocking    **Sprint:** 2

**Story**
As an operator, I want to filter findings and read the evidence behind each one so that I can trust and act on them.

**Acceptance Criteria**
- Reuses `ScanFindingsPanel` severity chips and verdict rows (confirmed = red, false positive = emerald, unverified = amber) and the existing `verdictKind()` wording.
- Adds filters for role (and role pair) and check, alongside severity and verdict.
- A DAST evidence block per finding: target (`METHOD path`), parameter, location, baseline vs. test excerpts in monospace, detector signals, HTTP status of each, standards, remediation text.
- Unverified findings are always visible by default, grouped and labelled, never hidden behind a toggle that defaults to hiding.
- Severity and verdict always carry a text label, not only colour.
- SAST/SCA/SBOM views are unchanged.

**Dev Notes**
- Add optional DAST fields to the shared finding type; render the evidence block only when present.
- Monospace only for evidence and payload text.

**Dev Testing**
- Test level: lint + build + manual.
- Manual: with mixed confirmed/unverified data, each filter works alone and combined; evidence block shows all parts; unverified present on first load; SAST scan page unchanged.

**Dependencies:** DAST-04-060, DAST-13-050, DAST-00-050
**Blocks:** DAST-14-020, DAST-14-040

**Definition of Done:** code merged + developer tests green

---

### DAST-14-020 Authorization matrix component

**Epic:** EPIC-14 UI: Findings, Authorization Matrix and Report        **Parent:** EPIC-14
**Parallelism:** Parallel    **Sprint:** 2

**Story**
As an operator, I want a role-by-role grid showing which role pairs are exposed so that I can find access-control gaps at a glance.

**Acceptance Criteria**
- New `DastAuthzMatrix` renders rows (owner role) by columns (acting role), with each cell showing `OK`, `n FAIL` or `untested` as text, plus colour from the existing red/emerald/slate tones.
- Cells are buttons with `aria-label` naming both roles and the result; focus ring as elsewhere.
- Clicking a failing cell filters the findings panel to that role pair; clicking again clears it.
- `untested` cells show the reason on focus/hover (for example, no second identity).
- Role headers use the shared role badges.
- Works for running scans (cells update) and shows an explanatory empty state when only one identity exists.

**Dev Notes**
- Composed from existing Tailwind utilities; no charting or UI library.
- Data from `GET /scans/{id}/authz-matrix`.

**Dev Testing**
- Test level: lint + build + manual (including keyboard).
- Manual: tab to a cell and activate with keyboard; screen-reader label reads role pair and result; filter sync with findings; three-role and one-role cases.

**Dependencies:** DAST-10-040, DAST-14-010, DAST-13-030
**Blocks:** DAST-14-040

**Definition of Done:** code merged + developer tests green

---

### DAST-14-030 Report view and exports

**Epic:** EPIC-14 UI: Findings, Authorization Matrix and Report        **Parent:** EPIC-14
**Parallelism:** Parallel    **Sprint:** 2

**Story**
As an engineering lead, I want a report view with the severity summary and the New/Fixed/Still-open comparison, and buttons to export, so that I can review and share results.

**Acceptance Criteria**
- Report section shows: severity summary (unverified separate), New / Fixed / Still-open lists with counts, skipped/degraded checks, rule packs used.
- A compare control picks the baseline scan (defaults to the previous scan).
- `ScanExportButtons` is reused for PDF and XLSX; both download for DAST scans.
- No-baseline and no-findings states have clear empty messages.

**Dev Notes**
- Existing proxy route `app/api/scans/[id]/export/[format]/route.ts` serves the downloads.

**Dev Testing**
- Test level: lint + build + manual.
- Manual: diff lists match seeded data; compare control changes the baseline; both exports download and open.

**Dependencies:** DAST-11-020, DAST-11-030, DAST-11-040, DAST-13-050
**Blocks:** —

**Definition of Done:** code merged + developer tests green

---

### DAST-14-040 Accessibility and states pass

**Epic:** EPIC-14 UI: Findings, Authorization Matrix and Report        **Parent:** EPIC-14
**Parallelism:** Serial/Blocking    **Sprint:** 2

**Story**
As a user who relies on a keyboard or screen reader, I want every DAST screen usable without colour or a mouse so that nothing depends on sight or pointing.

**Acceptance Criteria**
- Every interactive control across EPIC-13 and EPIC-14 is reachable by keyboard with a visible focus indicator.
- No severity, verdict, role or matrix result is conveyed by colour alone.
- Every data view renders its empty, loading, running, failed and cancelled states.
- Forms associate labels with inputs and announce validation errors.
- A short audit checklist and results are saved with the story.

**Dev Notes**
- Fix, do not just report: this story closes defects found against REQ-CON-3 to -5 and REQ-FR-UI-6.

**Dev Testing**
- Test level: manual (keyboard-only pass, screen-reader spot check) + lint.
- Manual: complete a scan setup and a findings review using only the keyboard; run each screen through the five states.

**Dependencies:** DAST-14-010, DAST-14-020, DAST-13-050
**Blocks:** —

**Definition of Done:** code merged + developer tests green

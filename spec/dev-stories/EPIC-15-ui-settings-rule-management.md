## [EPIC-15] UI: Settings and Rule-Set Management

**Goal:** Operators configure per-task model routing, provider credentials, scan defaults, the OAST address, and manage rule packs, per-check overrides and custom rules from the settings pages.
**Depends On:** EPIC-02, EPIC-03, EPIC-13
**Blocks:** —
**Teams:** Dev

Requirements: REQ-FR-UI-4, -5, REQ-FR-RULE-3 to -7, REQ-FR-MDL-5. The same frontend constraints listed at the top of [EPIC-13](EPIC-13-ui-scan-flow.md) apply to every story here. Follow the `/projects/[id]/settings` pattern (`ScanLimitationsPanel` renders whatever the backend catalog returns generically, with no ids hard-coded in the UI).

---

### DAST-15-010 Model routing settings

**Epic:** EPIC-15 UI: Settings and Rule-Set Management        **Parent:** EPIC-15
**Parallelism:** Serial/Blocking    **Sprint:** 2

**Story**
As an operator, I want to choose a provider and model for each task so that I can keep planning local and send only the high-stakes call to a stronger model.

**Acceptance Criteria**
- Settings page lists the six tasks (fingerprint, crawl plan, login selectors, construct, rule, narrate) with provider (local, Bedrock, OpenAI, Anthropic) and model for each.
- Backend endpoints read and update routing; changes affect new scans only; running and past scans keep their snapshot.
- Choosing a provider with no credentials configured shows a warning on the row.
- A "test connection" action makes one harmless call per selected provider and reports success or the failure reason.
- Defaults come from backend settings.

**Dev Notes**
- Persist overrides (project-level or global) without storing secrets in the same record.
- Backend: routing read/write plus a test-connection endpoint behind the bearer token.

**Dev Testing**
- Test level: integration (backend, fake adapters) + lint + build + manual (UI).
- Assert: routing change visible on next scan's snapshot only; invalid provider rejected; test-connection reports failure reason without leaking keys.

**Dependencies:** DAST-02-030, DAST-02-040, DAST-00-090
**Blocks:** DAST-15-020

**Definition of Done:** code merged + developer tests green

---

### DAST-15-020 Credential entry with masking

**Epic:** EPIC-15 UI: Settings and Rule-Set Management        **Parent:** EPIC-15
**Parallelism:** Parallel    **Sprint:** 2

**Story**
As an operator, I want to enter provider keys once, write-only and masked, so that secrets are never displayed back or leaked.

**Acceptance Criteria**
- Provider credential fields accept a value and display only "set" / "not set" afterwards; the stored value is never returned by any API.
- Replacing a value requires entering a new one; clearing is an explicit action with confirmation.
- Values are stored using the platform's existing secret handling approach, or environment configuration if none exists; the story records which was chosen.
- No secret appears in logs, error messages, network responses or the browser's storage.

**Dev Notes**
- If the platform has no secret store, v1 may be environment-only with this page showing read-only "set/not set" status; record that decision here rather than inventing storage.

**Dev Testing**
- Test level: integration + manual.
- Assert: GET never returns a value; set then GET shows "set"; seeded key string absent from logs and responses; clear works.

**Dependencies:** DAST-15-010
**Blocks:** —

**Definition of Done:** code merged + developer tests green

---

### DAST-15-030 Rule-set management

**Epic:** EPIC-15 UI: Settings and Rule-Set Management        **Parent:** EPIC-15
**Parallelism:** Parallel    **Sprint:** 2

**Story**
As a security engineer, I want to enable packs and adjust individual checks so that I control what scans test by default.

**Acceptance Criteria**
- Global settings and project settings pages list packs with enable toggles and, per check, enable/disable, severity override and mode (automated, opt-in, assist-only).
- The list is rendered from whatever the backend returns, with no check ids hard-coded in the UI.
- Each level shows the effective value and where it came from (default, global, project).
- Checks that need a dependency show it; load-generating checks show their off-by-default state.
- Changes apply to new scans; the page says so.

**Dev Notes**
- Follows `ScanLimitationsPanel` and `PATCH /projects/{id}/limitations` precedent.

**Dev Testing**
- Test level: lint + build + manual + backend integration from DAST-03-040.
- Manual: toggle a pack, override a severity, confirm the next scan's snapshot reflects it and a past scan's does not.

**Dependencies:** DAST-03-040, DAST-13-040
**Blocks:** DAST-15-040

**Definition of Done:** code merged + developer tests green

---

### DAST-15-040 Custom rule authoring

**Epic:** EPIC-15 UI: Settings and Rule-Set Management        **Parent:** EPIC-15
**Parallelism:** Parallel    **Sprint:** 2

**Story**
As a security engineer, I want to add a custom check by pasting or uploading YAML and see validation errors immediately so that I can extend coverage without a deployment.

**Acceptance Criteria**
- A custom-rules section lists existing rules with version, and allows add, edit, delete.
- Entering YAML validates against the backend and shows each error with its field and reason (unknown signal, fixed payload string, missing tags).
- A rule that can only be assist-only or unverified says so before save.
- Deleting asks for confirmation through the existing dialog and does not alter past scans.

**Dev Notes**
- Use a plain text area in monospace; no editor dependency.
- Reuses the custom-rule endpoints from DAST-03-050.

**Dev Testing**
- Test level: lint + build + manual.
- Manual: valid rule saves and appears in the pack picker; each invalid case shows its error; delete confirms.

**Dependencies:** DAST-03-050, DAST-15-030
**Blocks:** —

**Definition of Done:** code merged + developer tests green

---

### DAST-15-050 Scan defaults and OAST address

**Epic:** EPIC-15 UI: Settings and Rule-Set Management        **Parent:** EPIC-15
**Parallelism:** Parallel    **Sprint:** 2

**Story**
As an operator, I want to set default crawl budgets, rate limit, safe mode and the OAST callback address so that new scans start from my preferred settings.

**Acceptance Criteria**
- Settings page edits defaults for runtime, depth, pages, per-pattern cap, same-domain mode, rate limit, safe-mode default, and the OAST callback URL.
- Safe-mode default cannot be turned off without an explicit confirmation.
- Validation rejects out-of-range values with inline messages.
- Changes apply to new scans only.

**Dev Notes**
- Backed by the settings surface from DAST-00-030; decide whether edits persist to the database or stay environment-only and record it here.

**Dev Testing**
- Test level: lint + build + manual + backend unit.
- Manual: edit values, create a scan, confirm snapshot; invalid values rejected; safe-mode confirm appears.

**Dependencies:** DAST-00-030, DAST-00-090
**Blocks:** —

**Definition of Done:** code merged + developer tests green

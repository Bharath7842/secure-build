## [EPIC-11] Reporting, Roll-up & Diff

**Goal:** A client-readable report with severity roll-up, evidence, remediation, skipped/degraded checks and a scan-to-scan comparison, exported as PDF and XLSX.
**Depends On:** EPIC-03, EPIC-04, EPIC-08, EPIC-09
**Blocks:** EPIC-14 (report view)
**Teams:** Dev

Requirements: REQ-FR-RPT-1 to -5. Existing: `scan_export.py` (grouping, PDF, XLSX) and the export proxy route; extend, do not fork.

---

### DAST-11-010 Severity roll-up and report data

**Epic:** EPIC-11 Reporting, Roll-up & Diff        **Parent:** EPIC-11
**Parallelism:** Serial/Blocking    **Sprint:** 2

**Story**
As an operator, I want a report data set that summarizes findings by severity, shows unverified findings separately, and lists skipped checks so that the report is complete and honest.

**Acceptance Criteria**
- A report builder produces: severity counts (confirmed only), unverified count and list shown separately, per-finding evidence and remediation, rule packs and versions used, skipped/degraded checks with reasons, scan settings snapshot summary.
- Counts equal the stored findings (no recomputation drift).
- A DAST branch is added to the existing report path; SAST/SCA/SBOM reports are unchanged.
- Report data is available through an API for the UI and export.

**Dev Notes**
- `scan_runner._build_report_from_db_findings` is the SAST precedent; add a DAST equivalent rather than reusing SAST OWASP tallies.
- Keep `unverified` wording and colour mapping consistent with `verdictKind()`.

**Dev Testing**
- Test level: integration.
- Assert: counts match seeded findings; unverified not included in severity totals; skipped checks listed; SAST report regression.

**Dependencies:** DAST-04-050, DAST-03-060, DAST-08-020, DAST-08-030, DAST-09-050, DAST-00-040
**Blocks:** DAST-11-020, DAST-11-030, DAST-11-040

**Definition of Done:** code merged + developer tests green

---

### DAST-11-020 Scan-to-scan diff

**Epic:** EPIC-11 Reporting, Roll-up & Diff        **Parent:** EPIC-11
**Parallelism:** Parallel    **Sprint:** 2

**Story**
As an engineering lead, I want to see what is new, fixed and still open since the previous scan so that I can track risk over time.

**Acceptance Criteria**
- Diff keyed on `(check, endpoint path template, parameter)` between a scan and the previous successful DAST scan of the same project and target.
- Each finding is labelled `New`, `Still open` or `Fixed`; Fixed items are drawn from the previous scan.
- `first_seen_scan_id` and `last_seen_scan_id` are maintained on findings.
- The comparison target can be overridden (compare to a chosen earlier scan).
- A scan with no prior comparable scan reports "no baseline" and treats all findings as New.
- A comparison across different rule sets notes which checks were not run in one of the scans, so a missing check is not reported as Fixed.

**Dev Notes**
- Pure function in `domain/diff.py`; uses each scan's stored rule-set snapshot.
- Does not hide unverified findings; they diff on the same key with their verdict shown.

**Dev Testing**
- Test level: unit + integration.
- Assert: new/fixed/still-open classification; override comparison; no-baseline case; check-not-run handling; unverified diffed.
- Test data: two seeded scans with overlapping findings.
- Entry point: `GET /scans/{id}/diff`.

**Dependencies:** DAST-11-010
**Blocks:** DAST-11-030, DAST-11-040, DAST-14-030

**Definition of Done:** code merged + developer tests green

---

### DAST-11-030 PDF export

**Epic:** EPIC-11 Reporting, Roll-up & Diff        **Parent:** EPIC-11
**Parallelism:** Parallel    **Sprint:** 2

**Story**
As a consultant, I want a PDF I can hand to a client with severity summary, findings, evidence, remediation and the diff so that the report stands on its own.

**Acceptance Criteria**
- `GET /scans/{id}/export.pdf` for a DAST scan produces: cover and summary, severity table, unverified section clearly separated and labelled, per-finding detail (target, parameter, location, standards, evidence excerpt, remediation), skipped/degraded list, New/Fixed/Still-open section.
- Unverified findings use the amber treatment already used in the SAST PDF.
- Evidence excerpts never contain credentials or unredacted sensitive matches.
- Large scans paginate cleanly with no truncated tables.

**Dev Notes**
- Extend `scan_export.py` with a DAST branch; reuse the existing PDF styles and pill colours.
- The proxy route `export/[format]` already exists.

**Dev Testing**
- Test level: integration.
- Assert: PDF generated for a mock DAST scan; text extraction contains each required section and the unverified label; no seeded secret string present; SAST PDF regression.

**Dependencies:** DAST-11-010, DAST-11-020
**Blocks:** DAST-14-030

**Definition of Done:** code merged + developer tests green

---

### DAST-11-040 XLSX export

**Epic:** EPIC-11 Reporting, Roll-up & Diff        **Parent:** EPIC-11
**Parallelism:** Parallel    **Sprint:** 2

**Story**
As an analyst, I want an XLSX of the findings so that I can filter, sort and track them in a spreadsheet.

**Acceptance Criteria**
- `GET /scans/{id}/export.xlsx` for a DAST scan has sheets for Summary, Findings, Unverified, Diff, Skipped Checks.
- Findings sheet columns include check id, severity, confidence, verdict, target, parameter, location, standards, remediation, first and last seen.
- Cells starting with `=`, `+`, `-` or `@` in evidence or titles are neutralized so opening the file cannot execute a formula.
- SAST/SCA/SBOM exports are unchanged.

**Dev Notes**
- Extend the openpyxl writer in `scan_export.py`; add the formula-injection guard here since evidence contains target-controlled text.

**Dev Testing**
- Test level: integration.
- Assert: sheet names and headers; counts match; a finding whose evidence begins with `=` is stored as text; regression for other scan types.

**Dependencies:** DAST-11-010, DAST-11-020
**Blocks:** DAST-14-030, DAST-16-060

**Definition of Done:** code merged + developer tests green

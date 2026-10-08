## [EPIC-12] Narration & Progress

**Goal:** Operators see live, readable progress through every stage, with counters and a severity breakdown, and the timeline still works when the model is down.
**Depends On:** EPIC-02, EPIC-05, and the stages that emit banners (EPIC-07 to EPIC-10)
**Blocks:** EPIC-13 (timeline UI)
**Teams:** Dev

Requirements: REQ-FR-NARR-1 to -4. Existing: `services/dast_narration.py`, `scan_progress.PROGRESS_MARKERS`, `DastNarrationTimeline.tsx`, `parseScanLog.ts`.

---

### DAST-12-010 Banners and progress markers for new stages

**Epic:** EPIC-12 Narration & Progress        **Parent:** EPIC-12
**Parallelism:** Parallel    **Sprint:** 2

**Story**
As an operator, I want accurate progress as the scan moves through connection, authentication, discovery, passive analysis, testing and authorization checks so that I know where it is.

**Acceptance Criteria**
- Every stage prints exactly one `### DAST: <label>` banner on entry; labels: checking connection, fingerprinting, logging in, crawling, importing schemas, passive analysis, testing apis, checking authorization, finishing.
- `scan_progress.PROGRESS_MARKERS` maps each label to a progress percentage in increasing order; unknown labels do not move progress backwards.
- Old labels already persisted on historical scans keep rendering (same rule as the SAST naming note in the root `CLAUDE.md`).
- Progress reaches 100 only on success.

**Dev Notes**
- Add the markers alongside existing ones; do not rename existing ones.
- `frontend/lib/parseScanLog.ts` must learn the new labels in the same change.

**Dev Testing**
- Test level: unit.
- Assert: each label advances progress monotonically; replaying a historical log still yields its old progress; progress is never 100 on failure or cancel.

**Dependencies:** DAST-00-050
**Blocks:** DAST-12-020, DAST-13-050

**Definition of Done:** code merged + developer tests green

---

### DAST-12-020 Narration for new stages with template fallback

**Epic:** EPIC-12 Narration & Progress        **Parent:** EPIC-12
**Parallelism:** Parallel    **Sprint:** 2

**Story**
As an operator, I want the log turned into a readable first-person timeline for every stage, even when the model is unavailable, so that the scan is understandable at a glance.

**Acceptance Criteria**
- The log is split on stage banners; each segment becomes a timeline step with a short first-person summary and reasoning bullets.
- Uses the `narrate` gateway task; on any failure or unparseable reply, a deterministic template summary is produced per stage.
- Raw model JSON, reasoning tokens and log noise never appear as prose (regression for recent fixes in `dast_narration.py`).
- Credentials never appear in narration input or output (redactor applies).
- Narration is cached per scan and persisted; regenerated only when new log lines arrive.

**Dev Notes**
- Extend `dast_narration.py`; keep its parsing/guards from the recent narration fixes.
- Add template text for the new stages.

**Dev Testing**
- Test level: unit.
- Assert: template path for each new stage; gateway failure uses templates; raw JSON in a model reply is rejected; secret not present; cache hit when log unchanged.

**Dependencies:** DAST-12-010, DAST-02-020
**Blocks:** DAST-13-050

**Definition of Done:** code merged + developer tests green

---

### DAST-12-030 Live counters and severity breakdown

**Epic:** EPIC-12 Narration & Progress        **Parent:** EPIC-12
**Parallelism:** Parallel    **Sprint:** 2

**Story**
As an operator, I want live counters (pages, endpoints, requests, tests, findings by severity) while a scan runs so that I can judge its progress and yield.

**Acceptance Criteria**
- A summary endpoint (or an addition to the scan response) returns: pages crawled, endpoints discovered, requests sent and denied, tests run, findings by severity and verdict, skipped checks, model calls and cost so far.
- Values update during the run as findings and audit rows are written.
- Returns consistent values for finished, running and cancelled scans.
- Cheap to poll every 2 seconds without scanning large tables (counts maintained or indexed).

**Dev Notes**
- Counts from indexed queries on findings and audit tables; cache briefly if needed.

**Dev Testing**
- Test level: integration.
- Assert: counters change as a mock/fake scan progresses; final values match stored findings and audit; response time on a seeded large audit table is acceptable (record baseline).

**Dependencies:** DAST-04-050, DAST-01-050, DAST-02-050
**Blocks:** DAST-13-050

**Definition of Done:** code merged + developer tests green

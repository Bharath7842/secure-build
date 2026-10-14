# DAST Readability Improvements Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the DAST scan page readable by collapsing repeated model scratchpad logs, clarifying coverage/verdict terminology, and exposing request provenance.

**Architecture:** Keep durable scan logs unchanged for auditability. Normalize only the evidence returned to the timeline, while retaining a compact repeat count. Extend the existing DAST request display with explicit proposal, actual request, sender, and source metadata.

**Tech Stack:** FastAPI/Python, Next.js/React/TypeScript, pytest, ESLint.

---

### Task 1: Normalize noisy DAST timeline evidence

**Files:**
- Modify: `backend/app/services/dast_narration.py`
- Test: `backend/tests/test_dast_narration.py`

- [ ] Add failing tests for collapsing repeated `[thinking]`/`[planner]` lines while retaining ordinary evidence and a repeat summary.
- [ ] Implement bounded evidence normalization before building the narration payload.
- [ ] Run the focused narration tests.

### Task 2: Clarify DAST summary terminology

**Files:**
- Modify: `frontend/components/DastScanDetail.tsx`
- Modify: `frontend/components/DastAnalysisPanel.tsx`
- Modify: `frontend/lib/types.ts`

- [ ] Add separate confirmed, unverified, and false-positive labels where the API provides them.
- [ ] Rename ambiguous counters and coverage text to distinguish discovered, tested, sent, and untested.
- [ ] Keep the current API contract backward-compatible with fallbacks.

### Task 3: Show DAST request provenance

**Files:**
- Modify: `backend/app/dast/active.py`
- Modify: `frontend/components/DastHttpExchange.tsx`
- Modify: `frontend/components/DastAnalysisPanel.tsx`
- Modify: `frontend/lib/types.ts`

- [ ] Add source/model and identity metadata to API-analysis request records where available.
- [ ] Render separate LLM proposal, actual payload, sender identity, source, and sent/blocked state.
- [ ] Add readable JSON formatting and copy affordances only where existing UI patterns support them.

### Task 4: Verify

- [ ] Run backend focused tests and frontend lint/build.
- [ ] Re-query the sample scan narration and confirm the repeated block is compacted.
- [ ] Inspect the scan page at the provided URL and report any remaining limitations.

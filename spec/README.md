# DAST Complete Design Package

A greenfield, end-to-end design for a Dynamic Application Security Testing engine. LLM-agnostic (gpt-oss:20b primary, plus Bedrock/OpenAI/Claude), OWASP API Security Top 10 coverage, multi-role authorization testing, and a complete UI specification.

## Files in this package

### Core design documents

- **`DAST_complete_design.md`** (40 KB) — **Start here.** The full system design covering:
  - Architecture (5 tiers + cross-cutting)
  - Scan pipeline (fingerprint → discover → passive analyze → active test → report)
  - Discovery subsystem (browser crawler, network recorder, schema ingestion)
  - Analysis tier (passive analyzer, active check engine, detectors)
  - OWASP API Security Top 10 (2023) coverage
  - LLM-agnostic model layer with fine-tuning flywheel
  - Safety tier (scope lock, method gating, rate control)
  - Data shapes and findings persistence
  - Testing and evaluation strategy

- **`DAST_ui_design.md`** (23 KB) — Complete UI specification covering:
  - Information architecture (dashboard, new scan, findings, report)
  - Every screen as a wireframe + field/component spec
  - Role-based multi-identity form (the signature: add Admin/User/Viewer/etc., unlock cross-role authorization testing)
  - Authorization matrix (role × role access heatmap)
  - Evidence-backed findings view (true-positive vs. unverified)
  - Scan-to-scan diff in reports
  - Design system (colors, components, accessibility)
  - UI → engine mapping table

- **`DAST_completion_spec.md`** (14 KB) — *Optional:* If you're continuing an existing DAST implementation instead of greenfield, this is a phased plan (Phases 0–6) tagged [IMPLEMENTED] vs. [RECOMMENDED].

### Reference data

- **`dast_fewshot_examples.json`** (9 KB) — Example records organized by task (rule, construct, fingerprint, crawl_plan). Drop these into prompts as few-shot demonstrations — works with any LLM provider, no training needed.

- **`dast_training_samples.jsonl`** (6 KB) — Same examples in JSONL format. Use this if you ever do a LoRA fine-tune on gpt-oss:20b.

- **`dast_new_scan_ui.html`** (14 KB) — Live interactive mockup of the New Scan form. Open in a browser to see multi-role identity management, auth-method switching, and the authorization test matrix preview.

## How to use these

### If you're building from scratch (greenfield):

1. Read **`DAST_complete_design.md`** to understand the architecture and pipeline.
2. Read **`DAST_ui_design.md`** to see what the operator interacts with.
3. Start with Phase 0 from the design (measurement harness + mock engine + config surface).
4. Use **`dast_fewshot_examples.json`** in your model prompts immediately (no fine-tuning required).
5. Open **`dast_new_scan_ui.html`** to see the multi-role form in action.

### If you're extending an existing DAST:

Read **`DAST_completion_spec.md`** for a phased approach, but note: it's a plan to finish your current tool. The greenfield design (`DAST_complete_design.md`) is what you want if you're rebuilding from scratch.

### For the model layer (few-shot or fine-tune):

- **Few-shot** (recommended, no GPU needed): Use `dast_fewshot_examples.json` — copy a few examples from the matching task block into your prompt.
- **Fine-tune** (optional, requires GPU): Use `dast_training_samples.jsonl` or grow your own dataset from authorized scans (the flywheel in §8.3 of the design).

## Key design decisions

- **LLM-agnostic:** gpt-oss:20b is the primary and default; Bedrock Haiku, OpenAI and Claude work via a Model Gateway (§8.1). Per-task provider routing means you can send only the high-stakes *ruling* call to a stronger model while planning stays local.
- **Evidence-backed verdicts:** Every active finding must carry a deterministic detector signal. The model constructs payloads and proposes verdicts, but a guardrail downgrades any FAIL without supporting evidence to INCONCLUSIVE (unverified). Training can't manufacture evidence.
- **Role-aware authorization:** Identities are organized by role (Admin/User/Viewer/etc.), and every role pair is cross-tested automatically. This is what makes OWASP API1 (BOLA) and API5 (BFLA) testable.
- **Passive-first:** A passive analyzer runs on already-observed traffic with zero risk and zero model calls, surfacing missing headers, cookie flags, CORS, and leaks before any active testing starts.
- **Target-agnostic:** The engine fingerprints the target (classic site / SPA / API-only) and adapts — browser crawl for SPAs, schema ingestion for APIs, both captured traffic, one unified active-test pipeline.

## Assumptions to confirm

(All flagged in the design docs; these are the key ones):

1. **Authorization is a precondition:** Every scan carries an explicit operator authorization for the target. Active testing is confined to the authorized host(s).
2. **LLM-agnostic model routing:** You want to support multiple providers (Ollama, Bedrock, OpenAI, Claude) and route per-task, not per-scan.
3. **Multi-role auth testing:** You want to add identities by role and automatically cross-test them (BOLA/BFLA).
4. **OWASP API Security Top 10 (2023):** You want coverage of the API-specific risks (BOLA, BFLA, mass-assignment, improper inventory, etc.) in addition to the general Web Top 10.
5. **No fine-tuning by default:** The engine works well with gpt-oss:20b + few-shot examples and deterministic detectors; fine-tuning is an optimization, not a dependency.

## What's NOT in scope

- CAPTCHA defeat, full OAuth/SSO automation, complex MFA flows — handled by accepting pre-authenticated state (§5).
- Business-logic flaw detection — flagged as assist-only for human review.
- Crawling non-web (gRPC, gRPC-web, custom protocols) — REST and GraphQL are first-class; others best-effort via schema.

## Next steps

1. Confirm the assumptions above with your team.
2. Start with Phase 1 of the greenfield design: measurement harness (ground truth against practice targets) + mock engine.
3. Sketch the Model Gateway adapter interface once you know which providers to support.
4. Build the Tier 4 passive analyzer first — zero risk, immediate value.
5. Wire the detectors and the active engine together, then add the model calls on top.

---

**Questions?** The design docs are self-contained and cross-referenced. Every [DECISION] is tagged so you can override it; every [ASSUMPTION] is flagged so you can confirm or change it.

Good luck with the build. The design holds whether you use gpt-oss:20b, Haiku, or any other small model. Start with deterministic signals and the guardrail, and the model becomes a nice-to-have optimization rather than a dependency.

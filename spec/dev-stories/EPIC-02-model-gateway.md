## [EPIC-02] Model Gateway

**Goal:** One provider-neutral gateway is the only component that calls a model, routed per task, schema-validated, with fallbacks and cost accounting.
**Depends On:** EPIC-00
**Blocks:** EPIC-05, EPIC-09, EPIC-12
**Teams:** Dev

Requirements: REQ-FR-MDL-1 to -8. Today the engine calls the local model directly through `app/dast/llm_utils.py` (`call_llm_json`, `call_llm_tool_choice`); this epic replaces those call sites with the gateway.

---

### DAST-02-010 Gateway core and request contract

**Epic:** EPIC-02 Model Gateway        **Parent:** EPIC-02
**Parallelism:** Serial/Blocking    **Sprint:** 1

**Story**
As a developer, I want a single gateway with a provider-neutral request so that engine code never depends on which model is behind it.

**Acceptance Criteria**
- Request: `{task, system, prompt, schema, max_tokens, temperature}`; response: JSON validated against `schema`.
- The task selects the provider and model from settings (DAST-00-030); an unknown task raises a clear error.
- A malformed reply gets one repair attempt, then the task's deterministic fallback is returned and the call is flagged `fallback_used`.
- A provider error (timeout, unavailable, auth) returns the fallback and is logged; the scan does not fail.
- The gateway interface is declared in `domain/interfaces.py`; the implementation lives outside the domain package.
- No code outside the gateway imports a model SDK (enforced by the layering test).

**Dev Notes**
- Fallbacks are registered per task by the caller (for example, selector fallback list for `login_selectors`).
- Keep adapters behind a small interface: `call(system, prompt, schema, max_tokens, temperature)`.
- Preserve the existing streaming of reasoning tokens to the console only if it can be done through the adapter without leaking provider specifics into callers.

**Dev Testing**
- Test level: unit (fake adapter).
- Assert: routing by task; schema-valid pass-through; invalid reply → one repair → fallback; adapter exception → fallback with flag; unknown task error; no SDK imports outside adapters.

**Dependencies:** DAST-00-020, DAST-00-030
**Blocks:** DAST-02-020, DAST-02-030, DAST-02-040, DAST-02-060, DAST-05-030, DAST-09-020

**Definition of Done:** code merged + developer tests green

---

### DAST-02-020 Local model adapter and migration of existing callers

**Epic:** EPIC-02 Model Gateway        **Parent:** EPIC-02
**Parallelism:** Serial/Blocking    **Sprint:** 1

**Story**
As an operator, I want the local model (default) behind the gateway and the existing pipeline moved onto it so that nothing in the engine calls the model directly.

**Acceptance Criteria**
- An Ollama adapter calls the configured base URL and model; default is `gpt-oss:20b`.
- All existing model calls (login classification, login selectors, crawl planning, API analysis, narration) go through the gateway with their respective task names.
- Existing behavior is preserved: same prompts, same fallbacks (including the hard-coded login selector list).
- `llm_utils.py` is reduced to the adapter internals or removed; `app/dast/app.py` and `server.py` read the base URL from settings.
- `tests/test_dast_scan.py`, `test_dast_api_analysis.py`, `test_dast_narration.py` still pass.

**Dev Notes**
- Migrate one call site at a time, keeping tests green between each.
- Structured-tool-choice calls (crawl planner) need an adapter capability flag; where unsupported, fall back to strict-JSON.

**Dev Testing**
- Test level: unit + integration (`live` for one real-model call).
- Assert: each migrated call site produces the same result with the fake gateway as before; live smoke returns valid JSON for each task.

**Dependencies:** DAST-02-010
**Blocks:** DAST-02-050, DAST-12-020

**Definition of Done:** code merged + developer tests green

---

### DAST-02-030 Anthropic and OpenAI adapters

**Epic:** EPIC-02 Model Gateway        **Parent:** EPIC-02
**Parallelism:** Parallel    **Sprint:** 1

**Story**
As an operator, I want to route a task to a hosted Anthropic or OpenAI model so that I can use a stronger model for high-stakes calls.

**Acceptance Criteria**
- Both adapters implement the same adapter interface and return schema-validated JSON.
- SDKs are imported lazily inside the adapter; the mock suite runs with them uninstalled.
- A missing API key produces a clear configuration error naming the setting, not a stack trace.
- API keys come from settings as secret values and never appear in logs or audit rows.

**Dev Notes**
- Use `langchain-anthropic` 1.7.5 and `langchain-openai` 1.6.7 per the tech stack.
- Honour `max_tokens` and `temperature` from the request.

**Dev Testing**
- Test level: unit (stubbed client) + `live` smoke gated on keys being present.
- Assert: request mapping; missing-key error; key redaction in logs; lazy import (module not imported until first call).

**Dependencies:** DAST-02-010
**Blocks:** DAST-15-010

**Definition of Done:** code merged + developer tests green

---

### DAST-02-040 Bedrock adapter

**Epic:** EPIC-02 Model Gateway        **Parent:** EPIC-02
**Parallelism:** Parallel    **Sprint:** 1

**Story**
As an operator, I want to route a task to AWS Bedrock so that hosted calls can stay inside our cloud account.

**Acceptance Criteria**
- Calls Bedrock directly through `boto3` (Converse API), not through the Anthropic API client.
- Default model id is the repo's existing `bedrock_model_id` setting.
- Region and credentials follow the standard AWS resolution; a missing region or credentials gives a clear error.
- Returns schema-validated JSON through the same adapter interface.

**Dev Notes**
- Reuse patterns from the SAST engine's LLM client where possible; do not couple to it.
- Correct the earlier design sketch which used `ChatAnthropic` for Bedrock.

**Dev Testing**
- Test level: unit (stubbed boto3 client) + `live` gated on AWS credentials.
- Assert: request shape includes system, messages, inference config; throttling error → fallback; credentials missing error.

**Dependencies:** DAST-02-010
**Blocks:** DAST-15-010

**Definition of Done:** code merged + developer tests green

---

### DAST-02-050 Token and cost accounting

**Epic:** EPIC-02 Model Gateway        **Parent:** EPIC-02
**Parallelism:** Parallel    **Sprint:** 1

**Story**
As an operator, I want token usage and estimated cost recorded per scan so that I can see what a scan cost and compare providers.

**Acceptance Criteria**
- Each gateway call records task, provider, model, input and output tokens, latency, and fallback flag.
- The scan's `usage_summary` aggregates totals per task and per provider.
- Local-model calls record tokens and zero cost; hosted calls use a configurable price table.
- Usage appears in the existing usage card/panel without breaking SAST usage rendering.

**Dev Notes**
- Extend `Scan.metadata_json["usage_summary"]`; keep existing keys for SAST.
- `frontend/lib/formatUsage.ts` already renders SAST steps; add DAST task names there.

**Dev Testing**
- Test level: unit + integration.
- Assert: totals equal sum of calls; fallback calls counted; price table override; a DAST scan under the mock engine still produces a valid usage summary.

**Dependencies:** DAST-02-020
**Blocks:** DAST-12-030

**Definition of Done:** code merged + developer tests green

---

### DAST-02-060 Task prompts and few-shot loader

**Epic:** EPIC-02 Model Gateway        **Parent:** EPIC-02
**Parallelism:** Parallel    **Sprint:** 1

**Story**
As a developer, I want each task's system prompt and few-shot examples loaded from files so that prompt behaviour can be tuned without code changes.

**Acceptance Criteria**
- Prompts live under `backend/app/data/dast/prompts/` one file per task (`fingerprint`, `crawl_plan`, `login_selectors`, `construct`, `rule`, `narrate`).
- One shared ethical-testing system preamble is prepended to every task.
- `dast_fewshot_examples.json` (from `spec/`) is copied into the app data directory and loaded; a task includes at most a configured number of examples from its block.
- The `construct` prompt states the non-destructive requirement and the JSON reply shape.
- A missing or invalid prompt file fails fast at startup with the file name.

**Dev Notes**
- Keep example loading deterministic (fixed ordering) so scans are reproducible.
- Replace the existing in-code `SYSTEM_PROMPT` with the shared preamble file.

**Dev Testing**
- Test level: unit.
- Assert: each task loads; ordering stable; example cap respected; invalid file error; shared preamble present in every composed prompt.

**Dependencies:** DAST-02-010
**Blocks:** DAST-05-030, DAST-05-040, DAST-09-020

**Definition of Done:** code merged + developer tests green

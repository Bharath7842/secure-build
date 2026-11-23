# Strix (`usestrix/strix`) — Source-Code Feature Breakdown & What Secure Build Can Adopt

> Reference repository: [https://github.com/usestrix/strix](https://github.com/usestrix/strix) (`v1.7.0`, Python 3.12+, `openai-agents[litellm]`)  
> Target codebase: **Secure Build** (`backend/app/dast/`, `backend/sast_engine/`, `frontend/`)

---

## Part 1: How Strix Works (By Source Code Module)

Strix is built on top of the **OpenAI Agents SDK** (`agents.sandbox.SandboxAgent`) bridged to **LiteLLM** (`StrixProvider`), executing inside an isolated **Docker container sandbox** with a host-side **Caido HTTP proxy** and **SQLite-persisted agent sessions**.

### 1. Scan Bootstrap, Target Resolution & Diff Scope
**Source files:**
- `strix/interface/scan_setup.py`
- `strix/interface/utils.py`
- `strix/utils/api_spec.py`
- `strix/core/inputs.py`

**How it works in code:**
1. **Model Preflight (`preflight_model_connection` in `scan_setup.py`):**
   - Validates that API keys and `LLM_EXTRA_HEADERS` contain only ASCII characters (`check_header_safe_credentials`) so HTTP headers don't crash mid-run.
   - Sends a tiny 1-turn probe (`"Reply with just 'OK'."`) with `LLM_PREFLIGHT_TIMEOUT` before spinning up Docker or cloning repos.
2. **Multi-Target & Spec Resolution (`build_targets_info` in `scan_setup.py`, `api_spec.py`):**
   - Accepts `-t` (multiple times) or `--target-list`: local directories, git URLs, live URLs, OpenAPI/Swagger files, or `postman://<collection_uid>`.
   - **Host-side Spec Parsing (`_resolve_api_spec` / `api_spec.py`):** Strix intentionally parses **only two things** on the host:
     1. Is the file a valid `openapi`, `swagger`, or `postman` spec? (`classify_spec`)
     2. What base URLs (`servers[].url`, `host` + `basePath`, or Postman request URLs with `{{var}}` substitution) does it declare as **authorized in-scope hosts**? (`spec_base_urls`)
   - If the target is `postman://<uid>`, the host fetches the collection and environment via `POSTMAN_API_KEY` (`fetch_postman_collection`) and writes a static JSON file into the sandbox workspace so the `POSTMAN_API_KEY` **never enters the container**.
   - Rewrites `localhost` / `127.0.0.1` target URLs to `host.docker.internal` (`rewrite_localhost_targets`) so tools inside Docker reach the host app.
3. **PR / Diff-Scoped Scanning (`resolve_diff_scope_context` in `interface/utils.py`):**
   - In `quick` scan mode or PR runs, computes the git diff against `diff_base` and injects a structured `<diff_scope>` instruction block into `args.instruction` so agents focus on changed files/routes.

---

### 2. Multi-Agent Graph & Orchestration (`AgentCoordinator`)
**Source files:**
- `strix/core/runner.py` (`run_strix_scan`)
- `strix/core/agents.py` (`AgentCoordinator`)
- `strix/core/execution.py` (`run_agent_loop`, `spawn_child_agent`)
- `strix/agents/factory.py` (`build_strix_agent`, `make_child_factory`)
- `strix/tools/agents_graph/tools.py`

**How it works in code:**
1. **Root vs. Child Specialist Agents (`factory.py`):**
   - Every agent is a `SandboxAgent` with `Shell` and `Filesystem` capabilities mounted on `/workspace` inside Docker.
   - **Root agent** gets `finish_scan` (and optional `wait_for_user` in interactive mode).
   - **Child agents** get `agent_finish` and inherit the parent's conversation history + selected `skills=[...]` (up to 5 domain skill markdown files injected into their system prompt).
2. **Graph Tools (`strix/tools/agents_graph/tools.py`):**
   - `create_agent(name, task, skills, inherit_context)`: Spawns an async child task (`start_child_agent`) with its own `SQLiteSession` and optional turn limit.
   - `view_agent_graph()`: Renders an ASCII tree of all agents (`running`, `waiting`, `completed`, `crashed`, `stopped`) with `← you` marking the caller.
   - `send_message_to_agent(target_agent_id, message, message_type, priority)`: Appends a message to another agent's inbox and interrupts/wakes it.
   - `wait_for_agents(agent_ids, timeout)`: Parks the calling agent (`_PARKING_TOOLS` in `factory.py`) until children finish or send a message.
   - `agent_finish(result_summary, findings, recommendations, open_items)`: Terminates the child, looks up **authoritative** vulnerability IDs actually filed by that `agent_id` in `ReportState` (`_filed_reports_by`), and pushes a structured plain-text completion report into the parent's session (`notify_parent_on_terminal`).

---

### 3. Threat Modeling Shared State
**Source files:**
- `strix/tools/threat_model/tools.py`

**How it works in code:**
- Before spawning deep exploitation sub-agents, the root agent builds a structured threat model persisted to `{state_dir}/threat_model.json`:
  - `save_threat_model(overview, trust_boundaries, assets, entry_points, attack_scenarios, ...)`: Validates and writes the canonical threat model (`entry_points`, `trust_boundaries`, `attack_scenarios` with priority and skills).
  - `amend_threat_model(...)`: Allows agents to add newly discovered entry points or attack scenarios mid-scan without overwriting existing entries.
  - `get_threat_model()`: Any sub-agent can read the shared threat model.

---

### 4. Negative-Space Coverage Ledger (`coverage.json`)
**Source files:**
- `strix/tools/coverage/tools.py`
- `strix/report/coverage.py`

**How it works in code:**
- Solves the classic scanner problem: *"You found 2 bugs, but what did you actually test?"*
- Shared, thread-locked ledger persisted atomically via temp-file rename (`_persist_locked` in `coverage/tools.py`) to `{state_dir}/coverage.json`.
- **Tools:**
  - `record_coverage(surface, risk_area, outcome, evidence)`
  - `update_coverage(entry_id, outcome, evidence)`
  - `list_coverage(outcome, surface)`
- **Strict Outcome Contract (`VALID_OUTCOMES`):**
  - `reported` — confirmed vulnerability filed.
  - `no_issue_found` — tested properly, nothing found.
  - `ruled_out` — candidate disproved (**requires `evidence`** naming the exact control + location).
  - `not_applicable` — risk cannot apply (**requires `evidence`**).
  - `needs_follow_up` — plausible lead that couldn't be closed due to missing creds/service/reachability (**requires `evidence`**).
- **Anti-duplication with history:** If Agent B calls `record_coverage` on a `(surface, risk_area)` Agent A already logged, the tool **rejects** the duplicate and returns `existing_entry_id`, forcing Agent B to call `update_coverage`, which moves the previous conclusion into `entry["history"]`.
- At scan end, `finish_scan` reconciles unresolved `needs_follow_up` items into the final report and pairs agent-reported coverage with machine-observed facts (which agents ran, which skills loaded, exit reason).

---

### 5. Caido HTTP Interception Proxy Integration
**Source files:**
- `strix/tools/proxy/tools.py`
- `strix/tools/proxy/caido_api.py`
- `strix/runtime/caido_bootstrap.py`

**How it works in code:**
- Container traffic is routed through a Caido instance; all agents share one host-side GraphQL `caido_sdk_client.Client` serialized behind an `asyncio.Lock` (`_CAIDO_CALL_LOCK`).
- **Agent Proxy Tools (`strix/tools/proxy/tools.py`):**
  - `list_requests(httpql_filter, first, after, sort_by, sort_order, scope_id)`: Queries captured traffic using Caido HTTPQL (e.g., `req.method.eq:"POST" AND resp.code.gte:400`, or bare string search `"password" OR "secret"` across raw req/resp).
  - `view_request(request_id, part, search_pattern, page)`: Inspects raw HTTP request/response headers/body with regex search and pagination so huge responses don't blow up context.
  - `repeat_request(request_id, modifications)`: Replays a captured request with mutated method/headers/query/body through Caido and returns the new exchange ID.
  - `list_sitemap` / `view_sitemap_entry` / `scope_rules`: Inspects discovered host/path trees and manages proxy scope rules.

---

### 6. Dynamic Skill Injection (`strix/skills/` vs `skills/`)
**Source files:**
- `strix/tools/load_skill/tool.py`
- `strix/skills/` (internal agent knowledge packs)
- `skills/` (consumer `SKILL.md` files for Cursor / Claude Code)

**How it works in code:**
- Strix separates **internal skills** (`strix/skills/**/*.md` — payload cheat sheets, framework quirks, XSS/SQLi/IDOR/JWT playbooks) from **external skills** (`skills/` for `npx skills add usestrix/strix`).
- Agents don't stuff every vulnerability playbook into the base system prompt:
  - When spawning a specialist via `create_agent(..., skills=["idor", "jwt"])`, those markdown files are compiled into the child's system prompt.
  - Mid-investigation, any agent can call `load_skill(skills=["sql_injection"])` (`strix/tools/load_skill/tool.py`) to pull up to 5 markdown playbooks inline as a tool result right when needed.

---

### 7. Vulnerability Reporting, Evidence Verification & LLM Deduplication
**Source files:**
- `strix/tools/reporting/tool.py`
- `strix/report/dedupe.py`
- `strix/report/state.py`

**How it works in code:**
1. **Strict Filing Gate (`create_vulnerability_report` in `reporting/tool.py`):**
   - Rejects any report missing required fields: `title`, `description`, `impact`, `target`, `technical_analysis`, `poc_description`, **`poc_script_code`** (mandatory working exploit/payload), `remediation_steps`, **`evidence`**, and **`assumptions`**.
   - **CVSS 3.1 Calculation (`_calculate_cvss`):** The agent supplies the 8 CVSS v3.1 metric values (`AV`, `AC`, `PR`, `UI`, `S`, `C`, `I`, `A`), and Python (`cvss.CVSS3`) deterministically computes the numeric score, vector string, and severity band.
   - **Proxy Evidence Verification (`_verify_http_exchange_ids`):** When a DAST agent cites `http_exchange_ids` (up to 10 numeric Caido request IDs), the tool queries Caido (`existing_request_ids`) to verify those request IDs actually exist in the proxy log before accepting the report!
   - **Code Locations (`_validate_code_locations`):** Validates relative paths, `start_line <= end_line`, `snippet`, and optional `fix_before` / `fix_after` patches.
2. **Two-Tier Deduplication (`check_duplicate` in `strix/report/dedupe.py`):**
   - **Tier 1 (Deterministic Dependency Identity):** For SCA/CVE findings (`create_dependency_report`), deduplicates deterministically on `(CVE, ecosystem, package_name, manifest_path)` (`_check_dependency_duplicate`).
   - **Tier 2 (Dedicated LLM Judge):** For SAST/DAST findings, calls a configurable dedupe model (`DEDUPE_SYSTEM_PROMPT`) comparing `candidate` against `existing_reports` on root cause, endpoint, parameter, auth state, and whether the same patch fixes both. Returns `{is_duplicate, duplicate_id, confidence, reason}`.

---

### 8. Context Compaction, Tool Output Bounding & Budget Reserve Hooks
**Source files:**
- `strix/llm/compaction.py`
- `strix/tools/output_store.py`
- `strix/core/hooks.py` (`ReportUsageHooks`)
- `strix/agents/factory.py`

**How it works in code:**
1. **Tool Output Spill Store (`bound_and_store` in `output_store.py`, `_with_bounded_result` in `factory.py`):**
   - Wraps every tool so outputs exceeding `tool_output_max_lines` / `tool_output_max_bytes` are truncated before entering LLM history, while the full output is spilled to `/workspace/.strix_output/` so the agent can `grep` or read slices of it if needed.
   - Also auto-coerces common LLM tool-argument mistakes (`_with_coerced_arguments`: stringified JSON arrays/objects, `"null"` strings on query tools, non-TTY shell warnings on `exec_command`).
2. **Security-Preserving Conversation Compaction (`maybe_compact` in `strix/llm/compaction.py`):**
   - When an agent session nears the model's context window (or hits a `ContextWindowExceededError`), `_select_split` walks backward to keep `keep_tokens` of recent history and **snaps to a boundary where no `function_call` is awaiting its `function_call_output`** (`_open_calls_at`).
   - Summarizes the older head using `_SUMMARY_INSTRUCTIONS`, which explicitly forbids merging or dropping distinct findings, URLs, payloads, credentials, or **Failed Attempts & Dead Ends** (so the agent never repeats dead ends after compaction).
3. **Sub-Agent Budget Reserve & Progressive Wind-Down (`ReportUsageHooks` in `strix/core/hooks.py`):**
   - Tracks cumulative scan cost across all agents.
   - Injects `[NOTICE]` (70%), `[URGENT]` (85%), and `[CRITICAL]` (95%) user messages directly into `input_items` before the LLM call (`_maybe_warn_budget`, `_maybe_warn_turns`), telling agents to stop opening new leads and wrap up.
   - **Hard 90% Sub-Agent Reserve (`_SUBAGENT_BUDGET_RESERVE = 0.90`):** In non-interactive runs, sub-agents are killed at **90%** of `max_budget_usd` (`SubagentBudgetReservedError`), reserving the final 10% of the dollar budget exclusively for the root orchestrator to reconcile coverage and generate the final report.

---

## Part 2: What You Can Use for Secure Build (Concrete Mapping)

Your DAST (`backend/app/dast/`) and SAST (`backend/sast_engine/`) already have strong architectural bones (LangGraph pipeline, `SafetyGuard`, `GuardedExecutor`, `BrowserProbe`, CVSS v3.1 scoring in `app/services/severity.py`, and per-occurrence facts). You **should not** replace your guarded DAST with Strix's unrestricted Docker shell agent.

Instead, here are the **8 highest-leverage mechanisms from Strix's source code** you can port directly into Secure Build:

### 1. Port Strix's Negative-Space Coverage Ledger (`coverage.json`) to DAST & SAST
- **What Strix does:** `strix/tools/coverage/tools.py` tracks `(surface, risk_area, outcome, evidence)` with outcomes `reported`, `no_issue_found`, `ruled_out`, `not_applicable`, `needs_follow_up`, requiring evidence for `ruled_out` and `needs_follow_up`.
- **How to use in Secure Build:**
  - In `backend/app/dast/`, you already have an `Inventory` (`domain/inventory.py`) and active check loop (`analyze_apis.py`). Right now, when an endpoint is tested and no detector fires, it only increments counters.
  - Add a structured **`DastSurfaceCoverage`** table or `Scan.metadata_json["coverage"]` ledger recording every `(method + path_template, check_id)` with outcomes: `reported`, `no_signal`, `skipped_safe_mode`, `skipped_auth_lost`, `needs_follow_up` (with the baseline/test status codes as evidence).
  - Surface this in `ScanDiscoveryPanel.tsx` and the PDF/Excel export as **"What We Tested & Ruled Out"** — customers love seeing proof of negative results.

### 2. Port Strix's `api_spec.py` Postman Collection + Variable Resolution into `endpoint_input.py`
- **What Strix does:** `strix/utils/api_spec.py` detects Postman Collection v2.1 (`_postman_id` / `item`), recursively walks nested folder items (`_walk_postman_hosts`), resolves `{{variable}}` templates from collection variables + Postman environment JSON (`postman_variables`, `_resolve_postman_vars`), and extracts requests.
- **How to use in Secure Build:**
  - Extend `backend/app/dast/domain/endpoint_input.py` (which stays pure stdlib per `test_dast_layering.py`) to parse pasted **Postman Collection v2.1 JSON** alongside OpenAPI/Swagger and `curl` lines.
  - Feed the extracted `(method, path, query_params, body_fields, content_type)` into `ingest_user_endpoints` in `backend/app/dast/nodes/ingest_schemas.py`.

### 3. Port Strix's Exchange-ID Evidence Verification to DAST Agent / Rule Step
- **What Strix does:** In `strix/tools/reporting/tool.py` (`_verify_http_exchange_ids`), when an LLM files a finding citing proxy `http_exchange_ids`, the tool verifies those IDs exist in the proxy database and attaches the exact recorded HTTP exchange to the finding.
- **How to use in Secure Build:**
  - In `backend/app/dast/`, `dast_request_audit` already records every guarded HTTP exchange.
  - Give each audited exchange in `GuardedExecutor` a sequential `exchange_id` (e.g., `req_0001`).
  - When `analyze_apis` / `browser_probe` / `check_authorization` produces a finding, link the exact baseline + attack `exchange_id`s onto `Finding.facts` / `Finding.reachability` so the UI and PDF report can render the exact **Baseline vs. Attack HTTP diff** verified by the executor.

### 4. Port Strix's Progressive Budget Wind-Down & Reserve into `plan_tests` / `run_target_agentic`
- **What Strix does:** `strix/core/hooks.py` (`ReportUsageHooks`) injects `[NOTICE]` / `[URGENT]` / `[CRITICAL]` budget warnings into the prompt at 70% / 85% / 95% of the turn/cost cap, and stops sub-agents at 90% so the finalizer never runs out of budget.
- **How to use in Secure Build:**
  - In `backend/app/dast/` (`agent_mode` with `max_agent_turns` and `max_turns_per_hypothesis` in `domain/agent.py`), when a hypothesis reaches its final turn (`turn == max_turns_per_hypothesis - 1`) or global turns cross 80%, inject a wind-up directive into the `construct` prompt telling the model to send its highest-probability proving probe now rather than an exploratory probe.
  - In `backend/sast_engine/pipeline/llm_client.py`, you already have `reserve_stage_budgets` (55% deep, 10% flows, 35% triage/confirm); you can add Strix's `preflight_model_connection` check (`scan_setup.py`) before starting live SAST/DAST runs so bad API keys or unreachable endpoints fail in 3 seconds instead of mid-scan.

### 5. Port Strix's "Dead Ends & Failed Attempts" Memory to DAST Agent Mode
- **What Strix does:** `strix/llm/compaction.py` maintains an explicit `## Failed Attempts & Dead Ends` section (WAF blocks, filtered chars, non-exploitable parameters) so the agent never wastes turns retrying the same blocked payload pattern.
- **How to use in Secure Build:**
  - In `backend/app/dast/active.py` (`run_target_agentic`), your turn history currently records `(status, byte_delta, duration, signal_names)`.
  - Add a compact deterministic classification of **why** the previous probe failed (e.g., `400_bad_request_filter`, `403_waf_or_authz`, `unchanged_reflection_escaped`, `timeout`) so the next `construct` turn knows *what was filtered* without storing raw response bodies.

### 6. Port Strix's Scoped Operator Instructions (`--instruction`) & PR Diff Scope to `DastInput`
- **What Strix does:** `scan_setup.py` accepts `--instruction` (e.g. *"Focus on `/api/v2/billing` and test role escalation between manager and viewer"*) and combines it with git diff scope (`resolve_diff_scope_context`) so CI runs only test changed routes.
- **How to use in Secure Build:**
  - Add an optional `operator_instructions: str | None` (redacted through `domain/redaction.py`) and `changed_paths: list[str] | None` to `DastInput`.
  - Use `changed_paths` (or SAST's discovered controller routes from the same project!) in `nodes/plan_tests.py` to prioritize endpoints touched in the current PR/commit.

### 7. Link SAST Threat Model -> DAST `plan_tests` (Your Biggest Advantage Over Strix)
- **What Strix does:** Strix uses `strix/tools/threat_model/tools.py` (`save_threat_model`) so its code-review agent writes `entry_points` and `attack_scenarios` that its dynamic exploitation sub-agents then read.
- **How to use in Secure Build:**
  - Secure Build already runs **both SAST and DAST under one `Project`**!
  - In `backend/app/dast/CLAUDE.md`, *"SAST endpoint linking"* is noted as deferred. You can implement this cleanly right now:
    1. Read the project's latest successful SAST scan (`Scan.metadata_json["discovery"]` + SAST `Finding` rows with CWEs and controller paths).
    2. Feed those SAST routes and suspected CWEs into DAST's `Inventory` (as `sast_discovered` endpoints) and `nodes/plan_tests.py` (as pre-seeded hypotheses: e.g., SAST saw an unverified SQLi or missing `@PreAuthorize` on `POST /api/orders` -> DAST prioritizes `dast-sqli-*` and `check_authorization` on `/api/orders`).

### 8. Ship a Consumer `SKILL.md` for Cursor / Claude Code (Like `usestrix/strix/skills/`)
- **What Strix does:** Ships `skills/` so developers can run `npx skills add` and let Cursor/Claude trigger scans via CLI/REST, inspect findings, and patch code.
- **How to use in Secure Build:**
  - You already have a CI token (`Authorization: Bearer <SAST_API_TOKEN>`) with `CI_SERVICE_PERMISSIONS` (projects, SAST/DAST scans, exports).
  - Add a `skills/secure-build/SKILL.md` in your repo that teaches Cursor / Claude Code how to call your FastAPI endpoints (`POST /scans`, poll `GET /scans/{id}`, fetch `GET /scans/{id}/findings`, and verify fixes with a rescan + `GET /scans/{id}/decision-diff`).

---

## Summary Comparison Table

| Capability | Strix (`usestrix/strix`) | Secure Build (`app/dast` + `sast_engine`) | Action for Secure Build |
| :--- | :--- | :--- | :--- |
| **Execution Model** | OpenAI Agents SDK + Docker PTY shell + Caido | Guarded LangGraph state machine (`SafetyGuard` + `GuardedExecutor`) | **Keep Secure Build's model** (safe for staging/CI without rogue container shell execution) |
| **Multi-Agent Coordination** | Dynamic tree (`create_agent`, `wait_for_agents`, inbox messages) | Fixed LangGraph stages + bounded `plan_tests` (`agent_mode`) | **Keep LangGraph**; optionally split `plan_tests` into specialist planners (Authz vs. Injection) |
| **API Spec Ingestion** | OpenAPI 3, Swagger 2, **Postman v2.1 + Env vars** (`api_spec.py`) | OpenAPI/Swagger, GraphQL introspection, pasted `curl`/paths (`endpoint_input.py`) | **Adopt Postman v2.1 + `{{var}}` parser** in `domain/endpoint_input.py` |
| **Negative Coverage Tracking** | `coverage.json` (`reported`, `no_issue_found`, `ruled_out`, `needs_follow_up`) | Discovery inventory + counters only | **Adopt Coverage Ledger** so reports prove what was tested and ruled out |
| **Threat Model Handoff** | `threat_model.json` shared from white-box agent to dynamic agent | SAST and DAST are separate scans on the same `Project` | **Connect SAST findings/routes -> DAST `Inventory` & `plan_tests`** |
| **Finding Validation** | PoC script required + Caido `http_exchange_ids` existence check + CVSS 3.1 | Proving detector guardrail (`guardrail.py`) + browser `window.__dast_<id>` + CVSS 3.1 | **Adopt `exchange_id` linking** so findings cite exact audited HTTP request pairs |
| **Budget & Preflight** | 1-turn `preflight_model_connection` + 70/85/95% wind-down + 90% sub-agent cap | Per-stage budget shares (SAST) + turn caps (DAST) | **Adopt LLM preflight check + last-turn wind-down prompt** in DAST `agent_mode` |

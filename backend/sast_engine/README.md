# SAST Engine

LangGraph agent: maps a repo's structure, tech stack, and file-level risk,
then runs vulnerability detection.

```mermaid
flowchart TD
    Repo[Repository] --> Scan[Scan directory]
    Scan --> Stack[Analyze tech stack]
    Stack --> Categorize[Categorize files]
    Categorize --> Risk[Map modules and risk]
    Risk --> DeepScan["LLM scan: top 100 CRITICAL/HIGH (whole file)"]
    Risk --> Triage["Regex only: MEDIUM/LOW + overflow CRITICAL/HIGH"]
    Triage -->|no hit| Skipped["Skipped — nothing recorded"]
    Triage -->|hits| Unverified["Published as 'unverified', batched by module"]
    DeepScan --> Report[Generate report]
    Unverified --> Report
```

1. **Scan directory** — walk the repo (or scoped subdirectory), list files,
   record extension/language, size, and depth. Skips generated/vendor dirs
   (`node_modules`, `target`, `.venv`, etc.).
2. **Analyze tech stack** — three deterministic, LLM-free evidence passes,
   no LLM call in this step at all:
   1. **Marker-file heuristic** — which build tool is present, from
      dependency-manifest filenames (`pom.xml`, `package.json`,
      `requirements.txt`, `go.mod`, `Gemfile`, `composer.json`,
      `Cargo.toml`, `*.csproj`, ...).
   2. **Dependency-manifest scan** (`pipeline/dependency_scan.py`) — parses
      the actual declared dependencies in those manifests
      (`pipeline/manifest_parsers.py`) and matches them against a curated
      framework signature table (`pipeline/stack_signatures.py`) to name
      the real frameworks in use. This works for *any* ecosystem the
      marker heuristic recognizes — Java, Node, Python, Go, Ruby, PHP,
      .NET, Rust — not just the two the AST pass below can structurally
      parse. This is what correctly identifies non-Spring Java stacks
      (JAX-RS/RESTEasy, EJB, Struts, Axis2 SOAP, Drools, ...), which score
      zero on the Spring-only AST pass but still declare real, parseable
      dependencies. A few frameworks are config-file-driven rather than
      just dependency-driven (Struts' `struts-config.xml`, Axis2's
      `*.wsdl`); the dependency scan corroborates those with a small
      deterministic file-presence check when the corroborating file is
      also found in the scan.
   3. **Tree-sitter AST pass** (`ast_struct.py`) — parses real Java/Angular
      source for annotation/decorator usage, REST entry points, and
      Angular route-guard coverage. Covers Spring-style annotations and
      Angular decorators only — the two stacks with conventions rich
      enough for structural parsing to pay off; every other ecosystem's
      "what's really in use" story comes entirely from the dependency
      scan above.

   Confidence is layered across all three passes: a bare marker-file match
   is `low`/`medium`, a recognized dependency or real AST signal raises it
   to `medium`/`high`, and dependency evidence corroborated by an actual
   config file (or genuine AST structural evidence) is `high`.
3. **Categorize files** — buckets every file into source / config /
   dependency / test / build / other, using per-stack rule profiles (Maven,
   Angular, .NET, Python, Node) with a generic fallback for unrecognized
   stacks.
4. **Map modules and risk** — per-file risk level (CRITICAL / HIGH / MEDIUM /
   LOW) from path heuristics (auth/security code, DB/repository layers,
   runtime config, etc.) plus a peek at Java file heads (HTTP/SOAP entry
   points and servlet filters become CRITICAL, EJB interfaces LOW), and
   module boundary discovery (e.g. multi-module Maven builds). Test code —
   by directory or by name (`FooTest.java`, `*.spec.ts`, ...) — stays in
   Discovery but leaves both scan tiers.
5. **Deep LLM scan (top `DEEP_SCAN_FILE_CAP` CRITICAL / HIGH)** — the top 100
   CRITICAL/HIGH files by priority (CRITICAL first, then HIGH; once the call
   graph exists the set is re-picked by framework entry points, then typed
   sinks, per file — cap overridable via `deep_scan_file_cap`) are
   sent to the LLM in full, with the `rules/` catalog as prompt guidance (not
   a regex gate). Findings are written incrementally (`kind=llm`). This tier
   also owns the *absence* checks a regex cannot express — a missing
   `@PreAuthorize`, an unset `HttpOnly`, no CSRF token — since it sees the
   whole file, which is why the cap matters: only files that make it into
   this tier get absence-check coverage.

   Small files (under 6,000 characters) whose language's system prompt isn't
   prompt-cached share calls, up to 8 files / 16,000 characters each. "Not
   cached" means a non-Bedrock provider, or a prompt under the model's cache
   minimum (4,096 tokens on Haiku), which is typical for the TypeScript, HTML,
   XML and YAML prompts. Each finding names its `"file"`, and a failed batch
   falls back to one call per file (`scan_file_batch`,
   `--no-batch-small-files`). Declaration-only files never reach this tier.
   That covers Spring Data repository interfaces with derived queries only,
   and `.ts` files of only interfaces/types/enums
   (`llm_file_scan.looks_declaration_only`): they drop to LOW at risk mapping
   and the deep scan skips them.
6. **Regex triage (MEDIUM / LOW + overflow CRITICAL/HIGH)** — every file that
   didn't fit in step 5's cap joins MEDIUM/LOW here, keeping its true
   `risk_level` for reporting but losing the whole-file pass. `rules/` patterns
   run locally, and **that is the whole tier** — there is no LLM call. A file
   with zero hits is skipped entirely (no database write); every hit in a file
   that matches is written as a finding with `kind=regex` and
   **`verdict=unverified`** — a pattern matched, nobody reviewed it. Every file
   goes to one worker pool; batches (one per real module, else
   `triage_batch_size` slices) only report progress, each logging its "done"
   line when its last file finishes. Past 500 files the regex pass runs in
   worker processes, with the same findings.

   The mode is a toggle, not a hard-coding: `triage_mode` (`--triage-mode`)
   accepts `regex_only` (the default) or `llm_triage`, which restores the
   previous behaviour — hits plus a ±10-line window each go to the LLM for a
   TP/FP ruling, with `_hit_matches_finding` dropping anything the model invents
   outside the candidates it was handed.

   Files carrying a generated-code marker in their first 4000 characters
   (`@Generated`, `DO NOT EDIT`, "automatically generated", a Castor/JAXB
   banner) are skipped and counted separately — detection is by content, not by
   path, so hand-written files in the same directory are still scanned.
7. **Generate report** — TP/FP/unverified totals and counts by OWASP category.

MEDIUM is the largest tier in most repos — the Maven profile sends every
unclassified `src/main/java/` file there, Angular every bare `.ts` — which is
why it is regex-only: on a ~3000-file repo the local pass costs seconds where
per-file LLM round-trips cost hours. The tradeoff is that both recall *and*
precision in this tier come entirely from the catalog: anything no pattern
describes is not reported, and a noisy pattern produces noisy `unverified`
findings with nothing downstream to filter them.

Bedrock scans keep a **$2 spend cutoff** (`LLM_COST_CUTOFF_USD`): once
estimated Bedrock cost reaches $2, remaining calls in that scan continue on
fallback Ollama. Both finding stages share one usage dict so the cutoff applies
across the whole run — though in the default `regex_only` mode step 6 makes no
LLM calls, so the deep scan is effectively the only spender.

## Parallel stages

API scans (limitation `parallel-scan-stages`, default on) and the CLI (unless
`--sequential`) run three stages side by side after runtime-rule derivation,
joining for grouping and confirmation:

```
derive_runtime_rules -> fan_out -> flows (discover -> verify -> Joern queries)
                                -> scan_deep_files
                                -> scan_triage_files
                     -> corroborate_flows -> group_triage_findings -> confirm_triage_groups
                     -> generate_report
```

This cuts wall-clock time, not tokens. The LLM cutoff is split into reserved
shares (deep 55%, flows 10%, triage/confirm 35%); a stage that finishes under
its share releases the rest. All provider calls share one concurrency limit
(`LLM_MAX_CONCURRENCY`, default 8) that halves on throttling, and throttled
calls back off with jitter. Each stage's log lines are prefixed
`[[stage:<name>]] ` so progress and the UI can tell them apart.

## Reachability evidence (`corroborate_flows`)

`pipeline/reachability.py` turns flow discovery into evidence for findings
from the *other* tiers. `discover_flows` indexes every path by its sink
(file, line) as `state["reachability_index"]` — every `flows.sc` path and every
call-graph flow, taken **before** the verify cap and before single-file Joern
paths in deep-scanned files are dropped, so evidence the flow stage didn't
spend LLM calls on isn't lost. `corroborate_flows` runs right after the
stages join. It matches deep-scan, regex-triage and Joern-query findings to a
sink in the same file within ±2 lines whose kind fits the finding's CWE
(`SINK_KIND_CWES`; a finding with no CWE never matches), and stores the best
match on `finding["reachability"]` (persisted as `Finding.reachability`).

| status | from | meaning | effect |
|---|---|---|---|
| `path` | Joern | this request value reaches the sink's argument | a `true_positive` is raised to 0.9 confidence |
| `sanitized_path` | Joern | as above, through a taint-spec sanitizer | attached only |
| `entry_reachable` | call graph | an entry point calls down to the sink's method; doesn't show which value | attached only |

Evidence only adds. A finding with no path is never dropped and its
confidence is never lowered, because neither analysis models every
framework's sources. Because corroboration runs before
`confirm_triage_groups`, grouped confirmation picks the occurrence with the
strongest evidence as the group's representative and adds the path to that
prompt (`render_evidence`). The 0.9 floor is applied again after the verdict,
per occurrence. Joern `kind=flow` findings carry their own path from
`flow_verify`. Without Joern, the call graph alone still produces
`entry_reachable` evidence on Java/Python repos. With neither, the node is a
no-op. The UI shows the path on the finding card, and the PDF/Excel exports
add it to the data-flow text.

## Per-occurrence decisions

Every finding is decided as one concrete occurrence before it is grouped; no verdict is copied between occurrences that differ.

* **Facts** (`pipeline/occurrence_facts.py`): tree-sitter facts for a finding — enclosing method, the call at the anchor, receiver type, argument kinds, declaration/stub/comment flags. Java and TypeScript; `None` (and old behaviour) when unavailable. `finding_facts.prepare_findings` attaches them, then runs the validators.
* **Validators** (`pipeline/validators/`): deterministic checks with a fixed precedence against the model verdict (negative proof → false positive; positive fact vs. a dismissal → unresolved `conflict`; evidence gap → unresolved). Switch: `--no-occurrence-validators` / scan limitation `occurrence-validators`.
* **Publish filters, dedupe, group keys, per-member confirmation, explanation check**: described in the repository `CLAUDE.md` under *Per-occurrence decisions (EPIC-01)*. Entry points: `llm_file_scan.publish_decision`, `merge_dedupe`, `group_key_for_finding`, `confirm_finding_group` / `confirm_finding_group_batch`, `explanation_check.annotate`.
* Counters land in `usage_summary` (`validators`, `publish_filter`, `dedupe_conflicts`, `explanation_contradictions`, `group_confirm_coverage`, `facts_coverage`).

## Joern (optional)

When [Joern](https://joern.io) is installed (`joern` / `joern-parse` on
`PATH`, or `JOERN_HOME` pointing at the install dir; JDK 17+), two extra
graph nodes use it. Without Joern both nodes log one line and do nothing, and
the scan behaves exactly as before.

- **`build_joern_cpg`** (after risk mapping) — `pipeline/joern_runner.py`
  builds one code property graph per dominant language (`joern-parse` handles
  one frontend per CPG; up to 3 languages with at least 3 files each; tests,
  vendored and build dirs excluded). The CPGs are shared by both uses below,
  so the parse cost is paid once.
- **Dataflow → flow verification** (`discover_flows`) — `joern/flows.sc`
  runs `reachableByFlows` from request inputs (Spring/JAX-RS entry params,
  servlet accessors, `request.args`, `req.body`, ...) to the sinks in
  `joern/taint_spec.json` (SQL, command, eval, file, SSRF, XSS, redirect,
  deserialization, XXE, LDAP, reflection, plus Joern-only response header,
  Spring `ResponseEntity` body and logger sinks). Framework-injected entry
  params (`HttpServletResponse`, `Model`, `Principal`, ...;
  `non_source_param_types`) are not sources. `pipeline/joern_flows.py` turns
  each path into the same `Flow` the tree-sitter call graph produces, plus
  `Flow.taint_path` (each expression the value passes through), which
  `flow_verify` adds to the LLM prompt. Each flow also carries the CPG's
  control dependence — `Flow.guards`, the conditions the path's nodes depend
  on, e.g. an `if (!id.matches("\\d+")) return` before the sink — and
  `Flow.sanitizers`, the taint-spec `sanitizers` calls the value passes
  through (scoped per sink kind: `parseInt` counts for SQL, not XSS). Both
  only annotate: no flow is dropped for them; the prompt lists them and
  sanitized flows rank last. `authenticated` comes from `@PreAuthorize`/
  `@Secured`/`@RolesAllowed` on the source method. Sink kinds run one at a
  time in `kind_order` (most severe first), `maxFlows` applies per kind, and
  the output file is rewritten after each kind, so a timeout returns the
  finished kinds (`complete: false`) instead of nothing. Header, response-body
  and log flows rank behind every other kind. Joern flows rank first, with up to a
  third of `FLOW_VERIFY_CAP` reserved for tree-sitter flows Joern didn't also
  find (e.g. Spring Data repository sinks). Flows reaching the same sink
  (file, line, kind) collapse to the best-ranked one, which lists the other
  entry points in its prompt (`call_graph.collapse_flows_by_sink`), so one
  sink costs one verification. Single-file Joern flows in files
  the deep scan already reviewed are not re-verified, though they still feed
  reachability evidence (above). Because Joern isn't limited to
  Java/Python, this also gives JS/TS, C/C++, Go, PHP, ... repos flow
  verification.
- **`joern_scan`** (after regex triage) — `joern/queries.sc` runs structural
  queries a regex can't express (XML parser built with no hardening call in
  the same method, trust-all TrustManager/HostnameVerifier, non-literal C
  format string, unbounded libc copies, weak hash/cipher, cookie without
  Secure/HttpOnly, `shell=True`, Flask `debug=True`, hardcoded credentials).
  `pipeline/joern_findings.py` writes the hits as `kind=joern`,
  `verdict=unverified` findings and confirms them with the same grouped LLM
  confirmation regex hits use. This node runs the confirmation itself because
  `group/confirm_triage_groups` are skipped under `llm_triage`.

Every Joern failure (missing binary, timeout, bad exit, unreadable JSON)
degrades to "no Joern results" (or, for `flows.sc`, the kinds finished
before it) and never fails the scan. Joern runs with the session's temp dir
as its working directory, because `importCpg` copies each CPG into
`./workspace/` — run from the backend directory, those copies used to pile up
in `backend/workspace/` forever. Per-project
toggles are `joern-dataflow` and `joern-scan-queries` in
`app/defaults/scan_limitations.py`. CLI flags are `--no-joern`,
`--no-joern-dataflow`, `--no-joern-queries` and `--joern-timeout`. Backend
settings are `JOERN_HOME`, `JOERN_TIMEOUT_SEC` (default 900) and
`JOERN_JAVA_OPTS` (default `-Xmx4g`). Built against Joern 4.0.653. The
scripts use the `io.shiftleft`/`io.joern.dataflowengineoss` APIs, so
re-check them after a major Joern upgrade (`pytest -m live
tests/test_joern.py`).

## Ripgrep catalog prefilter

`pipeline/rg_prefilter.py` (limitation `ripgrep-catalog-prefilter`, on by
default for API scans; `--catalog-prefilter` on the CLI): rg narrows which
(file, rule) pairs the Python catalog pass checks, using a literal every match
must contain (taken from Python's own regex parse). Python stays the authority,
so findings are identical either way. Searches batch up to eight literals
with the same case mode per invocation. Each rule receives the union of its
batch's candidate files; Python checks the actual pattern. A failed or
truncated batch leaves every rule in that batch on the full Python pass.
This trades broader candidate sets for fewer process launches and directory
walks. On a local 1,000-file / 9 MB sample, the 185-rule catalog needed 15
searches instead of 111: prefilter time fell from 3.4–4.3s to 0.6–0.7s,
and prefilter plus regex time from 5.2–5.7s to 2.5–4.3s with identical hits.
These are local sample timings, not full-scan estimates; the plain regex
pass can still be faster on small repositories.

rg runs through `pipeline/rg_runner.py`: patterns go in as `--regexp=`, globs
are repo-confined and relative, results are post-filtered to the inventory,
and size limits, a streamed 8 MB output cap and timeouts apply. Each rg runs
under `/bin/sh -c 'ulimit -v <kb>; exec "$0" "$@"'` (`RG_MEMORY_LIMIT_MB`,
default 2048), which Linux enforces and macOS treats as best-effort. An
abnormal rg exit is an error (or truncation), never "no matches". The binary
comes from the pinned `ripgrep` wheel in requirements.txt; `RG_PATH`
overrides it.

The agentic hunt (`pipeline/hunt/`, node `hunt_security`, learned rules) was
removed. Old scans can still hold `kind=hunt` findings, and
`scan_runner.reconcile_unverified_findings` skips them because their
`unverified` is an evidence cap.

Offline tests: `tests/test_rg_runner.py`, and `tests/test_rg_prefilter.py`
against `tests/fixtures/java_corpus`.

## Rule catalog and vulnerability surfaces

Patterns live in `rules/`, split per language, plus `rules/surfaces.json`
which maps detected stack signals to named vulnerability surfaces — the
`Tech Stack Detected -> Known Vulnerability Surface -> Targeted Regex` chain
the legacy audit docs in `regex_data/` spell out by hand, made reproducible
for any repo. Active surfaces are logged during step 2 and sort their rules to
the front of the prompt catalog; they never gate a rule.

Rules can also carry `requires_dependency`, so a pattern fires only when the
vulnerable library is actually declared (`implements Serializable` matters
because commons-collections < 3.2.2 is on the classpath, not on its own).
Unknown versions fail open. See `rules/README.md` for the full field
reference.

Standalone CLI runs may optionally persist JSON + SQLite after the graph
finishes; API-driven scans never write local files.

## Output shape

`{"scan": ..., "llm_analysis": ..., "categorized": ..., "module_plan": ..., "report": ...}` —
see `agent_bridge.run_real_scan` for how this is slimmed into the `discovery`
dict stored on `Scan.metadata_json`.

## CLI

```
python sast_scan_agent.py --path /path/to/project
python sast_scan_agent.py --path /path/to/project --no-llm
python sast_scan_agent.py --path /path/to/project --llm-provider ollama --llm-model granite-code:3b-instruct
python sast_scan_agent.py --path /path/to/project --no-joern
python sast_scan_agent.py --path /path/to/project --sequential   # one stage at a time
python sast_scan_agent.py --path /path/to/project --llm-provider openai_compat \
    --llm-base-url http://localhost:8000/v1 --llm-model Qwen/Qwen2.5-Coder-32B-Instruct
```

## LLM backends

- **bedrock** — Claude on AWS Bedrock (default preset: Haiku 4.5)
- **openai_compat** — any OpenAI-compatible `/chat/completions` server (vLLM,
  LM Studio, llama.cpp server, OpenAI, ...). Base URL/API key per scan via
  `init_usage(provider_options=...)` (projects: `llm_base_url`/`llm_api_key`),
  else `OPENAI_COMPAT_BASE_URL`/`OPENAI_COMPAT_API_KEY`. JSON mode sends
  `response_format`, dropped (and remembered per endpoint) when a server
  rejects it; a leading `<think>` block is stripped. Priced at
  `OPENAI_COMPAT_INPUT/OUTPUT_PRICE_PER_MTOK` (default 0 — local).
- **ollama** — local models at `OLLAMA_BASE_URL` (optional; nothing requires it)

All are reached through the shared `llm_client.call_llm`; an unknown provider
name raises rather than falling through to Bedrock. Tech-stack detection
(step 2) is fully deterministic. Past the soft spend cutoff, calls switch to
the configured fallback provider — default `none`, which raises
`LlmBudgetExhausted` so each stage records its remaining work as unverified.
`call_llm(meta_out=...)` reports one call's own tokens.

`call_llm` also owns the two token-saving mechanisms shared by every stage:

- **Bedrock prompt caching**: once the system prompt clears the model's
  minimum cacheable size (`should_cache_system_prompt`), it is sent with a
  `cache_control` checkpoint. Cache reads and writes are reported separately
  and only discount `cost_usd`; `input_tokens` stays the logical prompt size.
- **Result cache**: when the shared usage dict carries a cache object under
  `RESULT_CACHE_USAGE_KEY`, JSON-mode calls are answered from it on an exact
  prompt/model match, and complete responses are stored. The API attaches a
  per-project DB cache. The CLI attaches none.

Every array-returning prompt asks for an object envelope (`{"findings": [...]}`,
`{"decisions": [...]}`, `{"rules": [...]}`) so it agrees with JSON mode's `{`
prefill.

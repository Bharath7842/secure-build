# User Stories — Graph + LLM SAST Scanner (v3)

Derived from `graph_augmented_sast_requirements.md` (v3). Ordered for implementation, not by epic
alphabetically — the sequencing itself is a decision worth stating up front.

## Build order rationale

Build a **walking skeleton** before building any stage completely: one Language Adapter, no caching,
no dedup, no scoring sophistication — just Stage 1 → Stage 2 → Stage 3 → Stage 4 working end to end
on a small real repo (Phase 1). That proves the core idea (structural facts → LLM judgment → graph
traversal → scoped verification) actually works before investing in the things that make it scale
(caching, dedup, budget scoring — Phase 2), the things that make it complete (config review, deep
review, reporting — Phase 3), the things that make it broad (more languages — Phase 4), and the things
that make it operable long-term (calibration, monorepo scoping — Phase 5).

Do not build Phase 4 (more languages) before Phase 2 (caching/scoring) — a second language adds
coverage to a pipeline that doesn't yet control its own cost or noise. Get the loop right on one
language first.

Every story lists **Depends on** (other stories) and **Maps to** (requirement IDs from the spec) for
traceability.

---

## Phase 0 — Foundation

**US-0.1 — Feature-flag the graph layer**
As a platform engineer, I want the entire graph+LLM pipeline behind a feature flag (default off),
so that the existing regex/SQL pipeline keeps working unmodified while the new system is built
alongside it.
- AC: `--enable-graph-scan` off by default; with it off, output is byte-identical to the current pipeline.
- AC: New `SastState` fields (FR-8.3) added without breaking existing nodes.
- Depends on: —
- Maps to: FR-8.3, NFR-7 (backward compatibility principle from §1)

**US-0.2 — Common schema as code**
As a platform engineer, I want the File/Type/Function/Calls/Imports schema (§9) implemented as
typed data classes, so that every later stage reads/writes one agreed-upon shape.
- AC: Schema matches §9 exactly, including nullable `containing_type_id` for free functions.
- AC: Unit tests construct each node/edge type and round-trip through (de)serialization.
- Depends on: —
- Maps to: §9 Data model

**US-0.3 — Pluggable GraphStore interface**
As a platform engineer, I want a `GraphStore` interface with a default SQLite-backed implementation,
so that storage can later be swapped (Kuzu/Neo4j) without touching Stages 2-8.
- AC: Interface exposes create/query methods for all node/edge types in §9, no SQL leaks into calling code.
- AC: SQLite implementation passes the same interface test suite any future backend must pass.
- Depends on: US-0.2
- Maps to: FR-9.3

---

## Phase 1 — Walking skeleton (one language, end to end)

**US-1.1 — Language Adapter interface + registry**
As a platform engineer, I want a `LanguageAdapter` interface (file extensions, grammar, node-type
mapping) and a registry that dispatches files to the right adapter, so that adding a language later
is pure addition, not modification.
- AC: Registry resolves a file path to zero or one adapter by extension.
- AC: Interface signature matches FR-6.1 exactly (fields: extensions, grammar, node-type mapping).
- Depends on: US-0.2
- Maps to: FR-6.1, FR-6.2

**US-1.2 — First Language Adapter (pick one: Python or Java)**
As a platform engineer, I want one working Language Adapter using tree-sitter, so that Stage 1 has
something real to parse.
- AC: Correctly extracts functions/methods, containing types, signatures, annotations/decorators, imports, and call expressions from a sample file in the chosen language.
- AC: Contains zero security classification logic (FR-6.2) — verified by a lint/test asserting no keyword lists like "sql", "exec", "auth" appear in adapter code.
- Depends on: US-1.1
- Maps to: FR-1.1, FR-1.2, FR-6.3

**US-1.3 — Stage 1: populate the graph from parsed facts**
As a platform engineer, I want parsed files converted into File/Type/Function/CALLS/IMPORTS records
in the GraphStore, so that later stages query structure instead of re-parsing.
- AC: Running Stage 1 on a sample repo produces the expected node/edge counts (fixture-based test).
- AC: Parse failure on one file is logged and skipped without aborting (NFR-4).
- Depends on: US-0.3, US-1.2
- Maps to: FR-1.1, FR-1.3, FR-1.5

**US-1.4 — Exclude vendored/generated paths**
As a platform engineer, I want a configurable path-exclusion list applied before parsing, so that
generated code and vendored dependencies don't pollute the graph.
- AC: Default exclusion list matches FR-1.4's examples; override via config.
- AC: Excluded files are logged as skipped-by-exclusion, distinct from parse failures.
- Depends on: US-1.3
- Maps to: FR-1.4

**US-1.5 — Stage 2: batched semantic tagging (no caching yet)**
As a platform engineer, I want function signatures sent to the LLM in large batches to be classified
as entry point / sink / neither, so that Stage 3 has something to traverse from.
- AC: Batch size configurable (target 100-200 signatures/call per FR-2.1); bodies never included (FR-2.4).
- AC: Detected stack passed as prompt context (FR-2.3).
- AC: Output includes confidence score per function; malformed LLM JSON degrades to "untagged" for that batch, not a crash.
- Depends on: US-1.3
- Maps to: FR-2.1, FR-2.2, FR-2.3, FR-2.4

**US-1.6 — Stage 3: raw flow discovery (no dedup, no scoring)**
As a platform engineer, I want a graph traversal from every tagged entry point to every reachable
tagged sink up to a max hop depth, so that candidate flows exist to verify.
- AC: Max hop depth configurable (default 6, FR-3.1).
- AC: Traversal terminates on cyclic call graphs (recursion) without infinite looping.
- Depends on: US-1.5
- Maps to: FR-3.1

**US-1.7 — Stage 4: flow slice + LLM verification**
As a security engineer, I want each discovered flow's real code sent to the LLM for a verdict, so
that I get true/false-positive judgments grounded in actual code instead of a bare rule match.
- AC: Flow slice contains only the methods on that flow's path, with line numbers (FR-4.1).
- AC: Verdict schema matches FR-4.2 (verdict, reasoning, severity, exploit, impact, fix).
- AC: FALSE_POSITIVE findings routed to a dismissed-findings list, not the main findings list (FR-4.3).
- Depends on: US-1.6
- Maps to: FR-4.1, FR-4.2, FR-4.3

**US-1.8 — Wire Phase 1 into the LangGraph pipeline**
As a platform engineer, I want Stages 1-4 registered as new LangGraph nodes gated behind
`--enable-graph-scan`, so that the walking skeleton is actually runnable end to end.
- AC: `python sast_scan_agent.py --enable-graph-scan --path <repo>` runs Stages 1-4 and reaches report generation without error on a small fixture repo.
- Depends on: US-0.1, US-1.7
- Maps to: FR-8.3

**US-1.9 — Validate the skeleton on a real repo**
As a security engineer, I want to run the walking skeleton against one real small-to-medium repo in
the chosen language and manually check results, so that we know the core idea works before investing
further.
- AC: At least one known true positive is correctly flagged `TRUE_POSITIVE` with grounded reasoning.
- AC: At least one known-safe pattern (e.g. parameterized query) is correctly flagged `FALSE_POSITIVE` or not flagged at all.
- AC: Findings/dismissals written up as a short validation note before Phase 2 starts.
- Depends on: US-1.8
- Maps to: (validation gate, not a spec item)

---

## Phase 2 — Harden the core loop

**US-2.1 — Flow deduplication**
As a platform engineer, I want flows sharing a common sub-path collapsed into one representative flow
with an occurrence count, so that 40 controllers hitting the same service method don't become 40
separate LLM calls.
- AC: Matches existing `dedupe_structural_findings` pattern already in the codebase.
- Depends on: US-1.6
- Maps to: FR-3.2

**US-2.2 — Per-stack weight profile (Decision D2)**
As a platform engineer, I want the LLM to propose risk-scoring weights once per detected stack,
cached alongside the tech-stack cache, so that Stage 3 scoring is fast and deterministic at run time.
- AC: One LLM call per unique stack fingerprint, not per flow or per run.
- AC: Cached profile reused on subsequent runs against the same/similar stack without a new call.
- Depends on: US-2.1
- Maps to: Decision D2

**US-2.3 — Deterministic risk scoring + budget selection**
As a platform engineer, I want each flow scored by a fixed formula (exposure, sensitivity, sink
severity) using the cached weight profile, and only the top-scored flows selected within a configured
budget, so that cost is bounded and predictable.
- AC: `--flow-budget` (max flows and/or token cap) enforced; excess flows go to a backlog, not silently dropped (FR-3.4).
- AC: Same input + same weight profile produces the same scores and selection every run (NFR-3).
- Depends on: US-2.2
- Maps to: FR-3.3, FR-3.4, NFR-3

**US-2.4 — Unresolved dispatch handling (Decision D1)**
As a platform engineer, I want virtual/interface call edges fanned out up to a cap and flagged
`needs_review_unresolved_dispatch` above it, so that ambiguous dispatch is visible, not silently
guessed or silently dropped.
- AC: Fan-out cap configurable, default 5.
- AC: Any flow crossing an unresolved edge carries the status through to the report (AC-4 in spec).
- Depends on: US-1.3
- Maps to: FR-1.3, Decision D1, AC-4

**US-2.5 — Tag fingerprint caching**
As a platform engineer, I want each function's tag fingerprint cached, so that unchanged functions
are never re-sent to the LLM for tagging on a subsequent run.
- AC: Second run against unchanged code makes zero Stage 2 LLM calls (AC-3 in spec).
- AC: Changed function (fingerprint mismatch) is re-tagged; unchanged siblings are not.
- Depends on: US-1.5
- Maps to: FR-7.1

**US-2.6 — Flow fingerprint caching**
As a platform engineer, I want each verified flow's fingerprint cached with its verdict, so that
unchanged flows skip Stage 4 entirely on the next run.
- AC: Second run against unchanged code makes zero Stage 4 LLM calls for previously verified flows (AC-6 in spec).
- AC: Cached verdict/enrichment reused verbatim in the report for cache-hit flows.
- Depends on: US-2.3, US-2.5
- Maps to: FR-7.2

**US-2.7 — Cache TTL and manual refresh (Decision D3)**
As a platform engineer, I want cached tags/flows to expire after a configurable TTL (default 90
days) and support a manual `--refresh-cache` override, so that judgment quality doesn't silently
stagnate.
- AC: Entries older than TTL are treated as cache misses automatically.
- AC: `--refresh-cache` forces full re-tag/re-verify regardless of TTL.
- Depends on: US-2.5, US-2.6
- Maps to: FR-7.3, Decision D3

---

## Phase 3 — Fill out the remaining stages

**US-3.1 — Config file structural parsers**
As a platform engineer, I want `.env`, YAML, JSON, and Dockerfile files parsed with real format-aware
parsers into key/value or directive structures, so that Stage 5 has structured input instead of raw
text to pattern-match.
- AC: Each parser handles multiline values, quoting, and comments correctly (the exact class of bug regex line-matching gets wrong).
- Depends on: —
- Maps to: FR-5.1

**US-3.2 — Stage 5: LLM judgment on config structure**
As a security engineer, I want the LLM to judge parsed config values as real secrets vs.
placeholders/env-references, and to flag non-secret misconfigurations (wildcard CORS, disabled TLS
verification), so that config findings are judgment-based, not pattern-based.
- AC: Batched per file; matches FR-5.2/FR-5.3 output schema (same shape as flow verdicts where applicable).
- Depends on: US-3.1
- Maps to: FR-5.2, FR-5.3

**US-3.3 — Secret redaction before persistence**
As a security engineer, I want values judged as likely-real secrets masked before they're written to
logs or the report, so that the report itself doesn't become a new place secrets leak from.
- AC: Redaction applied after LLM judgment, before any file write (NFR-5).
- Depends on: US-3.2
- Maps to: NFR-5

**US-3.4 — Deep-review candidate selection**
As a platform engineer, I want security-relevant files with zero matched flows identified as deep-
review candidates, so that Stage 6 targets actual graph blind spots, not arbitrary files.
- AC: Candidate ranking reuses/adapts the existing `_rank_deep_review_candidates` logic against the new flow data instead of `scan_log`.
- Depends on: US-2.3
- Maps to: FR-6.1 (deep review), existing Step 5d logic

**US-3.5 — Wire Stage 6 deep review**
As a security engineer, I want the existing capped whole-file review reused against the new
candidate list, so that novel logic bugs outside any flow are still caught.
- AC: Cap configurable (`--deep-review-max-files`, already exists); findings fully reasoned in one LLM call as today.
- Depends on: US-3.4
- Maps to: FR-6.1 (deep review)

**US-3.6 — Extend the HTML report**
As a security engineer, I want the report to distinguish flow-derived findings from deep-review
findings, show a flow's entry→sink path, and show tagging/flow/cache coverage stats, so that I can
tell what was actually analyzed and how.
- AC: Report includes: methods tagged, flows discovered/selected/deferred, cache-hit count (FR-8.1).
- AC: Dismissed findings, deferred flows, and low-confidence tags all visible in an audit section (FR-8.2, AC-5).
- Depends on: US-2.6, US-3.5
- Maps to: FR-8.1, FR-8.2, AC-5

---

## Phase 4 — Expand language breadth

Each story below is independent of the others and can be parallelized once Phase 1-3 are stable.

**US-4.1 — Second Language Adapter** (e.g. TypeScript/JavaScript if Phase 1 used Python, or vice versa)
- AC: Same acceptance bar as US-1.2 for the new language.
- Depends on: US-3.6 (core loop stable)
- Maps to: FR-6.1, FR-6.3

**US-4.2 through US-4.N — Remaining adapters** (Java, Go, C#, Ruby, Kotlin, ...)
- One story per language, same shape as US-4.1.
- Depends on: US-3.6
- Maps to: FR-6.3

**US-4.X — Monorepo/module scoping**
As a platform engineer, I want `--scope <path>` to limit a run to a subdirectory/module, so that a
2,000-file monorepo can be scanned service by service.
- AC: Stage 1 only parses within scope; cross-scope calls are recorded as unresolved external edges, not silently dropped.
- Depends on: US-1.3
- Maps to: NFR-7

---

## Phase 5 — Operate & calibrate

**US-5.1 — Calibration sampling workflow**
As a security engineer, I want to periodically sample N tagged functions and N flow verdicts for
manual review, so that I have a feedback signal on judgment quality with no rule catalog to audit
directly.
- AC: Sampling is configurable (N, frequency); output is a reviewable list with the original LLM reasoning attached.
- Depends on: US-2.5, US-2.6
- Maps to: NFR-6

**US-5.2 — Disagreement-rate tracking**
As a security engineer, I want disagreement rate from calibration reviews tracked over time per tag
category (e.g. "sink: deserialization"), so that systematic judgment drift is visible as a metric,
not discovered anecdotally.
- AC: Metric exported/logged per calibration run; historical trend viewable across runs.
- Depends on: US-5.1
- Maps to: NFR-6, OQ-3 (flagged as still open — start with reporting-only, no automatic action)

**US-5.3 — CLI cleanup**
As a platform engineer, I want the obsolete `--rule-scope`/`--rule-ids` flags and
`SAST_SQLITE_RULES_FILE`/`SAST_CONFIG_RULES_FILE` env vars removed, and the new flags
(`--tag-batch-size`, `--max-hop-depth`, `--flow-budget`, `--refresh-cache`, `--cache-ttl-days`,
`--scope`) added, so that the CLI matches what the system actually does.
- AC: Removed flags produce a clear "no longer applicable in v3" error rather than being silently ignored.
- Depends on: Phase 2 complete
- Maps to: FR-9.1, FR-9.2

**US-5.4 — Migration notes**
As a platform engineer, I want a short migration doc explaining what was removed (regex/SQL
catalogs) and what replaced it, so that anyone maintaining the old catalogs knows why they're gone
and what to look at instead.
- AC: Doc covers: what's removed, what's new, how to run with `--enable-graph-scan` off for the old behavior during transition.
- Depends on: US-5.3
- Maps to: (documentation, not a spec item)

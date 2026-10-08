# Requirements — Graph + LLM SAST Scanner (v3, rule-free, language-agnostic)

**Status:** Draft v3 — supersedes v2
**What changed from v2:** v2 removed regex/SQL detection rules but still described Stage 1 parsing
loosely around Java/TypeScript examples. v3 makes the language/framework independence explicit and
architectural — see §6 (Language & framework coverage) — and adds a recommended technology stack
(§14) so this is buildable, not just specified.

---

## 1. Why regex/SQL rules are being removed

A rule catalog (regex or SQL) is a human's best guess, frozen in text, about what a vulnerability
looks like syntactically. Three problems compound at enterprise scale:

1. **It goes stale.** A new annotation, a custom internal framework, a wrapper around `execute()` —
   anything the catalog's author didn't anticipate — is invisible, silently, forever, until someone
   notices and adds a rule.
2. **It can't tell context from text.** `@RequestMapping` matches whether or not the method actually
   does anything dangerous with its input. A SQL rule that finds "any method calling
   `Statement.execute`" can't tell a raw-concatenated query from a safely parameterized one without
   layers of increasingly complicated rule logic trying to fake understanding it doesn't have.
3. **Two detection paradigms disagree.** Running LLM-derived regex *and* a SQL rule catalog *and* LLM
   verification means three different systems can each have blind spots the others don't cover, with
   no single place that "understands" the code end to end.

v2's split is instead: **structural parsing extracts facts (deterministic, cheap, no judgment)** →
**the LLM makes every judgment call (tagging, verification, secrets, deep review)** → **graph
traversal connects facts to facts (deterministic math, not a detection rule)**. One reasoning system,
applied consistently, instead of three that can disagree.

## 2. Goals

- G1: Zero hand-written or LLM-generated regex/SQL detection logic anywhere in the pipeline.
- G2: All "is this dangerous" judgment is made by the LLM reasoning over real code/structure, not by
  matching against a pre-written catalog.
- G3: Structural extraction and graph traversal remain fast, deterministic, and LLM-free — cost and
  judgment only enter where judgment is actually needed.
- G4: Cross-file flow tracing (unchanged from v1's core idea) so the LLM reasons over connected code,
  not isolated lines or whole-file dumps.
- G5: Caching so a 2,000-file app is scanned incrementally after the first run, not re-judged from
  zero every time.
- G6: Language- and framework-agnostic by construction. Adding a new language is adding a thin
  structural adapter (§6), never writing new detection rules — the judgment layer (LLM) doesn't
  change per language.

## 3. Non-goals

- NG1: No hand-maintained catalog of "these annotations mean entry point" / "these calls mean sink."
  That knowledge lives in the LLM's judgment, applied per method, not in a config file someone has to
  keep updated as frameworks change. (Contrast with v1's `SQLITE_RULES_FILE` / `CONFIG_RULES_FILE`,
  both removed.)
- NG2: No claim of formal/sound taint analysis. Best-effort graph traversal plus LLM judgment,
  same honesty as v1 — false negatives are possible and must be visible in the audit trail, not
  hidden.
- NG3: Dependency scanning against OSV (existing Step 6) is unchanged and out of scope for this
  redesign — it's an authoritative CVE database lookup, not a text/SQL detection rule, so it isn't
  part of the problem this doc is solving.
- NG4: Dynamic/runtime analysis remains out of scope, same as v1.

## 4. Definitions

| Term | Definition |
|---|---|
| **Structural fact** | Something extracted by parsing alone, with zero security judgment attached: a function/method's name, signature, annotations/decorators, containing type (or none, for free functions), imports, and call sites. |
| **Semantic tag** | The LLM's judgment about a structural fact: is this function an entry point (and what kind — HTTP, queue consumer, scheduled job...), a sink (and what kind — SQL, exec, deserialization...), or neither. Includes a confidence score. |
| **Tag fingerprint** | Hash of a function's structural facts (signature + annotations + containing type, if any), used to cache its semantic tag so unchanged functions are never re-judged. |
| **Flow** | Ordered path in the call graph from a tagged entry point to a tagged sink, capped at a max hop depth. Finding flows is graph traversal — math, not judgment. |
| **Flow slice** | The real source of every method on a flow's path — what actually gets sent to the LLM for verification. |
| **Flow verdict** | The LLM's judgment on a flow slice: `TRUE_POSITIVE` / `FALSE_POSITIVE` / `NEEDS_REVIEW`, with reasoning, severity, exploit scenario, and fix. |

## 5. Architecture overview

| Stage | What happens | Judgment made by |
|---|---|---|
| 1. Structural parse | Parse every in-scope file into facts: files, types, functions, signatures, annotations, imports, call sites | Nobody — pure parsing |
| 2. Semantic tagging | Batch structural facts (signatures only, not bodies) to the LLM; it judges entry/sink/neither per function | LLM (batched, cheap — no code bodies) |
| 3. Flow discovery & scoring | Traverse the call graph from tagged entries to tagged sinks; dedupe shared paths; score by exposure/sensitivity/sink type; select top flows within budget | Graph math + a deterministic scoring formula (see Decision D2) |
| 4. Flow verification | Send each selected flow's real code (the flow slice) to the LLM; get a verdict, reasoning, severity, exploit, fix | LLM (scoped to the flow, full reasoning) |
| 5. Config/secrets review | Parse config files with real format parsers (dotenv/YAML/JSON/Dockerfile parsers — not regex); send the parsed structure to the LLM to judge real-secret vs. placeholder/env-reference | LLM (structured input, no regex value-matching) |
| 6. Deep review | Capped whole-file LLM read for security-relevant files that matched no flow (graph blind spots) | LLM (unchanged from v1) |
| 7. Cache & diff | Persist tag fingerprints and flow fingerprints; skip LLM calls for anything unchanged next run | Deterministic cache lookup |
| 8. Report | Aggregate findings, dismissed false positives, coverage stats, cost | Deterministic |

## 6. Language & framework coverage

Nothing in this design is Java-specific or TypeScript-specific — that was an artifact of the
originating script's `SCAN_EXTENSIONS`, not a property of the architecture. Two separate concerns
were conflated in v1/v2 examples and need to be pulled apart explicitly:

**Syntax (per-language, purely structural, not a "rule"):** knowing that `def foo(x):` in Python and
`func Foo(x int)` in Go and `public void foo(int x)` in Java are all "a function/method definition"
is a parsing fact, not a security judgment. This is handled by a **Language Adapter**: a thin mapping
from that language's grammar (via tree-sitter or an equivalent parser) to the common schema in §9 —
what counts as a function/callable, a type (class/struct/interface/trait), an import, a call
expression, and an annotation/decorator-equivalent (Java annotations, Python decorators, Go struct
tags, C# attributes, Ruby macros — all map to the same schema field). Adding a language means adding
one adapter, not new detection logic.

**Semantics (framework-aware, entirely LLM judgment, already language-independent):** "is this method
an entry point" or "is this call a sink" was never encoded per-language in v2 — it's Stage 2's LLM
judgment, given the detected stack as context. That already generalizes for free: the same judgment
step handles a Spring Boot `@RestController`, an Express `app.post(...)` handler, a Django/FastAPI
view function, an ASP.NET Core `[HttpPost]` action, a Rails controller action, a Go `net/http`
handler or gRPC service method, and a Laravel route closure — because the model is reasoning about
what the code *does* in context, not matching a per-framework pattern list. No new work is needed
here per language beyond making sure the Language Adapter surfaces the right structural facts
(decorators, attributes, route registrations) for the LLM to reason over.

- FR-6.1: The system **shall** support a registry of Language Adapters, each declaring: file
  extensions handled, the grammar/parser used, and a mapping from grammar node types to the common
  schema (function/callable, type, import, call, annotation-equivalent, doc-comment).
- FR-6.2: A Language Adapter **shall not** contain any security classification logic — enforced the
  same way as FR-1.2 — it maps syntax to structure, nothing more.
- FR-6.3: The system **shall** ship with adapters for at least: Java, Kotlin, TypeScript/JavaScript,
  Python, Go, C#, Ruby. Additional languages **shall** be addable without modifying Stages 2-8.
- FR-6.4: Framework detection (Spring, Express, Django, ASP.NET Core, Rails, gRPC, etc.) **shall**
  remain part of the existing stack-detection step (unchanged from the original script's Step 1) and
  is passed as context into Stage 2 tagging — it is not a separate per-framework rule set.

## 7. Functional requirements

### 6.1 Stage 1 — Structural parse (no LLM, no rules)

- FR-1.1: The system **shall** parse every in-scope source file using a real parser/AST (e.g.
  tree-sitter, or a language-native parser), not regex, into files/classes/methods/signatures/
  annotations/imports/call sites.
- FR-1.2: The parser **shall not** contain any security classification logic — its only job is
  producing structural facts. Entry/sink classification is explicitly out of scope for this stage.
- FR-1.3: Call edges **shall** be resolved statically wherever possible (direct calls); unresolved
  virtual/interface dispatch is handled per Decision D1 below, not silently guessed.
- FR-1.4: Vendored, generated, and build-output directories/files **shall** be excluded from parsing
  by a configurable path-exclusion list (e.g. `node_modules/`, `vendor/`, `target/`, `dist/`,
  `*_pb2.py`, `*.g.cs`, `*.g.ts`, migration/scaffold directories) — this is scope reduction, not a
  detection rule, and ships with sensible per-adapter defaults (§6).
- FR-1.5: Parse failures on individual files **shall** be logged and skipped, never abort the scan.

### 6.2 Stage 2 — Semantic tagging (LLM, batched, structure-only)

- FR-2.1: For every method not already cached (FR-7.1), the system **shall** send its structural
  facts — signature, annotations, containing class, one-line doc comment if present — to the LLM in
  large batches (target: 100-200 methods per call; this is signatures, not bodies, so it stays cheap).
- FR-2.2: The LLM **shall** return, per method: `is_entry_point` (+ kind), `is_sink` (+ kind + CWE
  category if applicable), and a confidence score. No method is force-fit into a category it doesn't
  clearly belong to — the model may return "neither" for the majority of methods.
- FR-2.3: Tagging **shall** be given the detected tech stack (framework, language) as context, so the
  same signature can be judged correctly for different frameworks without a separate rule set per
  framework.
- FR-2.4: This stage **shall never** send full method bodies — only signatures/metadata. Bodies are
  only sent later, for methods that end up on a selected flow (Stage 4) or in deep review (Stage 6).

### 6.3 Stage 3 — Flow discovery & scoring (deterministic, no LLM)

- FR-3.1: The system **shall** enumerate flows from every tagged entry point to every reachable
  tagged sink, bounded by a configurable max hop depth (default 6).
- FR-3.2: Flows sharing a common sub-path **shall** be deduplicated into one representative flow plus
  an occurrence count.
- FR-3.3: Each flow **shall** receive a deterministic risk score from a fixed formula over: entry
  exposure, sensitivity keywords in the path, and sink kind/severity, using a weight profile (see
  Decision D2) — never a live LLM call per flow at this stage.
- FR-3.4: The system **shall** accept a configurable budget (max flows and/or estimated token cap)
  and select top-scored flows up to that budget; the remainder is deferred to a backlog, not dropped.

### 6.4 Stage 4 — Flow verification (LLM, scoped)

- FR-4.1: For each selected flow, the system **shall** build a flow slice from the real source of
  every method on that flow's path, with line numbers, and send only that slice to the LLM — no
  unrelated file content.
- FR-4.2: The LLM **shall** return a verdict (`TRUE_POSITIVE` / `FALSE_POSITIVE` / `NEEDS_REVIEW`),
  one-sentence reasoning grounded in the actual code shown, adjusted severity, exploit scenario,
  business impact, and secure fix — reusing OWASP/CWE knowledge as prompt context, not as a compiled
  pattern.
- FR-4.3: `FALSE_POSITIVE` verdicts **shall** be removed from reported findings and kept in a
  `dismissed_findings` audit list.

### 6.5 Stage 5 — Config/secrets review (structural parse + LLM, no regex)

- FR-5.1: Known config file formats (`.env`, `.properties`, YAML, JSON, Dockerfile,
  docker-compose) **shall** be parsed with a real format-aware parser into key/value or directive
  structures — not regex line-matching.
- FR-5.2: The parsed structure **shall** be sent to the LLM (batched per file) to judge which values
  are likely real hardcoded secrets versus placeholders/environment-variable references/safe
  defaults — this replaces the old regex placeholder heuristic with LLM judgment on the actual value
  and its context.
- FR-5.3: Misconfigurations that aren't secrets (e.g. wildcard CORS, disabled TLS verification,
  exposed admin consoles) **shall** likewise be judged by the LLM from the parsed structure, not a
  pattern list.

### 6.6 Stage 6 — Deep review (unchanged from v1)

- FR-6.1: Security-relevant files that matched zero flows in Stage 3 **shall** be eligible for a
  capped, whole-file LLM read (default cap configurable), producing fully-reasoned findings directly.

### 6.7 Stage 7 — Caching & diff

- FR-7.1: Every method's tag fingerprint (Stage 2) **shall** be cached; unchanged methods skip
  re-tagging on subsequent runs.
- FR-7.2: Every verified flow's fingerprint (hash of its slice's normalized source) **shall** be
  cached; unchanged flows skip re-verification (Stage 4) and reuse the cached verdict.
- FR-7.3: Cache entries **shall** respect a TTL and manual refresh override (see Decision D3).

### 6.8 Cross-cutting

- FR-8.1: The report **shall** distinguish flow-derived findings from deep-review findings, and show
  tagging/flow/cache coverage stats (methods tagged, flows discovered/selected/deferred, cache hits).
- FR-8.2: Every dismissed finding, deferred flow, and low-confidence tag **shall** be visible in an
  audit trail — nothing is silently dropped for being "probably fine."
- FR-8.3: All new state **shall** live in the existing `SastState` object; this remains one LangGraph
  pipeline, not a parallel system.

## 8. Non-functional requirements

| ID | Requirement |
|---|---|
| NFR-1 | **No detection rule catalogs.** A code review of the shipped system must find zero regex patterns or SQL queries whose purpose is "decide if this code is vulnerable." Structural parsing and graph traversal are the only rule-free, judgment-free stages. |
| NFR-2 | **Cost control.** Stage 2 tagging must be cheap by construction (signatures only, large batches) and must approach zero cost on repeat runs via caching. Stages 4-6 (real-code LLM calls) must respect a hard budget. |
| NFR-3 | **Determinism where it matters.** Stages 1, 3, and 7 (parsing, scoring/selection, caching) are deterministic given the same input — reproducible without an LLM call, so a scan is debuggable and diffable run to run. |
| NFR-4 | **Fault isolation.** A parse failure, an unresolved call edge, or an LLM failure on one batch/flow must not abort the scan. |
| NFR-5 | **Data handling.** Config values judged as likely real secrets (Stage 5) must not be echoed verbatim into the LLM prompt beyond what's needed for judgment, and must be redacted/truncated in the report. |
| NFR-6 | **Calibration.** Because there's no rule catalog to audit line-by-line, the system must support a periodic calibration workflow: sample N tagged methods and N flow verdicts for manual review, and surface disagreement rate as a tracked metric over time. |
| NFR-7 | **Monorepo scoping.** A scan must be runnable against a subdirectory/module boundary, not only the full 2,000-file tree at once. |

## 9. Data model

Terminology is deliberately language-neutral: **Function** covers methods, free functions, closures,
and lambdas alike; **Type** covers classes, structs, interfaces, traits, and modules-as-namespaces —
whatever the Language Adapter's target language uses as a containing unit. A free function in Go or
Python simply has `containing_type_id = null`.

**Nodes**
- `File(id, path, language)`
- `Type(id, file_id, name, kind)` — `kind` ∈ `{class, struct, interface, trait, module, ...}` per adapter
- `Function(id, file_id, containing_type_id?, name, signature, start_line, end_line, tag_fingerprint, is_entry_point, entry_kind, is_sink, sink_kind, sink_cwe, tag_confidence, tagged_at)`

**Edges**
- `CALLS(caller_function_id, callee_function_id, call_site_line, resolved: bool)`
- `IMPORTS(file_id, imported_symbol)`

**Derived**
- `FLOW(id, entry_function_id, sink_function_id, path[function_id...], fingerprint, risk_score, status)`
  where `status` ∈ `{selected, deferred, verified, cached_skip, needs_review_unresolved_dispatch}`

No table in this schema encodes "this pattern = vulnerability." `Function.is_sink` etc. are LLM
judgments, stored as data, not derived by a query that itself contains detection logic.

## 10. Decisions (resolving the three open questions)

**D1 — Unresolved virtual/interface dispatch:**
Fan out to all statically-resolvable implementers when the count is small (default cap: 5). Above
the cap, do not enumerate — mark the call edge `resolved: false` and any flow crossing it gets status
`needs_review_unresolved_dispatch` automatically, surfaced in the audit trail rather than silently
dropped or silently guessed at one implementer.

**D2 — Risk-scoring weights:**
The LLM proposes an initial weight profile once per detected tech stack (e.g. "for this Spring Boot +
Postgres app, weight raw-SQL sinks and auth-adjacent entry points highest") — a single cheap call,
cached alongside the existing tech-stack cache. All actual per-flow scoring at scan time then uses
that cached, static profile through a deterministic formula — never a live LLM call per flow. This
keeps Stage 3 fast and reproducible while still letting the LLM contribute domain judgment where it's
cheap (once per stack, not once per flow).

**D3 — Cache retention:**
90-day TTL by default on both tag and flow caches, auto-invalidated immediately whenever the
underlying fingerprint changes (i.e. the code itself changed). A `--refresh-cache` flag forces a full
re-tag/re-verify regardless of TTL, for cases like "we upgraded the LLM model and want fresh
judgments."

## 11. Interfaces

- FR-9.1: CLI flags: `--tag-batch-size`, `--max-hop-depth`, `--flow-budget`, `--deep-review-max-files`
  (retained), `--refresh-cache`, `--cache-ttl-days`, `--scope <path>` (monorepo module scoping).
- FR-9.2: `--rule-scope` / `--rule-ids` and the `SAST_SQLITE_RULES_FILE` / `SAST_CONFIG_RULES_FILE`
  env vars from v1 **shall be removed** — there is no rule catalog left to scope.
- FR-9.3: The graph store **shall** be pluggable (default: SQLite as a plain data store — not a rule
  engine — behind a `GraphStore` interface) so a dedicated graph database can be substituted for very
  large monorepos.

## 12. Acceptance criteria

- AC-1: A source audit of the shipped codebase finds zero regex patterns or SQL queries used for
  vulnerability detection (parsing/storage regex, if any, is fine — detection logic is what's banned).
- AC-2: Stage 1 parsing of a 2,000-file repo completes with zero LLM calls.
- AC-3: Stage 2 tagging of that same repo, on a clean cache, completes within a defined token/cost
  budget (batched signatures only); a second run against unchanged code makes zero Stage 2 calls.
- AC-4: Every flow crossing an unresolved dispatch edge is marked `needs_review_unresolved_dispatch`
  and visible in the report — none are silently included as confirmed or silently excluded.
- AC-5: Every dismissed finding, deferred flow, and low-confidence tag is visible in the audit trail.
- AC-6: Disabling caching reproduces full re-tagging/re-verification; enabling it reproduces the prior
  run's results for unchanged code with zero additional LLM calls.

## 13. Remaining open questions

- OQ-1: What confidence threshold on a semantic tag (FR-2.2) is low enough to route a method to
  manual/calibration review instead of trusting it outright in flow discovery?
- OQ-2: Should Stage 2 tagging run once up front for the whole repo, or lazily/on-demand only for
  methods that end up near a discovered flow — trading a bigger one-time cost against slower
  incremental discovery on the very first run?
- OQ-3: For the calibration workflow (NFR-6), who reviews the sampled disagreements, and does a
  sustained high disagreement rate on a given tag category (e.g. "sink: deserialization") trigger
  anything automatically, or is it purely a reporting metric?

## 14. Recommended technology stack

Concrete tool choices per stage — defaults, not hard requirements (§11 already requires the graph
store and LLM provider to be pluggable).

| Concern | Recommended default | Why | Swap-in alternative |
|---|---|---|---|
| Parsing (§6 Language Adapters) | **tree-sitter** — one library, ~40+ language grammars, incremental, fast, used by GitHub/Semgrep for exactly this purpose | Single dependency covers Java, Kotlin, TS/JS, Python, Go, C#, Ruby, PHP, Rust, C/C++ via the same query mechanism; a new language is a grammar + a small adapter, not a new tool | Per-language native tooling (`ts-morph`/TS compiler API, `javalang`, Python `ast`, Go `go/packages`, Roslyn for C#) for languages where deeper semantic resolution is worth the extra integration cost |
| Call-graph storage | **SQLite** as a plain data store (extends the existing `symbol_index.db`) | Already used in the current script, zero extra infra, fine up to a few million edges | **Kuzu** (embedded graph DB) or **Neo4j/Memgraph** for very large monorepos or when Cypher-style traversal queries are wanted |
| Graph algorithms (traversal, path-finding, dedup) | **networkx** (Python) over the SQLite-loaded graph | Pure-Python, no extra service, good enough for per-run traversal at this scale | Native graph-DB traversal if already on Neo4j/Kuzu |
| Pipeline orchestration | **LangGraph** (already in use) | Existing pipeline is already a LangGraph `StateGraph`; new stages are new nodes, not a new framework | — |
| LLM provider | **Claude via Bedrock or the Anthropic API** (already pluggable per `call_llm`) | Already integrated; keep the existing provider abstraction | Local model via Ollama for the high-volume Stage 2 tagging calls specifically, if a smaller local model proves accurate enough on structure-only input |
| Model tiering | **Cheaper/faster model for Stage 2 tagging** (high call volume, signatures only) vs. **stronger model for Stage 4 verification and Stage 6 deep review** (low volume, high-stakes reasoning) | Stage 2 is volume-bound, Stages 4/6 are reasoning-bound — matching model cost to what each stage actually needs is the single biggest lever on total spend | Single model throughout, if operational simplicity matters more than cost |
| Caching (tag/flow fingerprints) | **SQLite key-value table**, same file as the call graph | Consistent with the existing `techstack_cache.json` pattern, no new infra | Redis if the scanner becomes a shared service across many concurrent scans |
| Config/secrets parsing (Stage 5) | Format-native parsers: `python-dotenv`/manual parser for `.env`, `PyYAML`/`js-yaml` for YAML, standard JSON parsers, a small Dockerfile line-directive parser | Each format has an unambiguous grammar; a real parser is barely more code than a regex and removes an entire class of "regex doesn't handle multiline/quoting/escaping" bugs | — |
| Secret redaction before logging/reporting (NFR-5) | Simple entropy/length-based masking of values judged likely-real by the LLM, applied before writing to the report | Keeps real secret values out of persisted output even though the LLM saw them for judgment | A dedicated secret-scanning library (e.g. `detect-secrets`) purely for the masking step, not for detection |

**On adding a language:** implement or reuse a tree-sitter grammar, write the Language Adapter's node-
type mapping (typically under a day for a common language — this is the only per-language engineering
work in the whole system), and register its file extensions. Everything from Stage 2 onward requires
no change.

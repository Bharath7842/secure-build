# SAST Accuracy — EPIC-02 SQL Injection: Bound Parameters and Method Identity

Source: `output/secure-build-npg-pakistan-accuracy-review.md` (§2, §3, §4 SQL rows, §5.2, §5.5, §6 `derive_rules.py`/`flow_verify.py`, §7 P1, §8, §9.2 SQL rows). Template: `spec/chain-templates/scaffolding-sprint-story-generation-prompt-simple.md`.

## [EPIC-02] SQL Injection: Bound Parameters and Method Identity

**Goal:** A SQL-injection finding means external text can change the *executed SQL grammar*. A value bound to a placeholder, a constant query, or a different method that shares a name is no longer reported as injection. Real string-built SQL (#1/#2, the unsafe #78 members) stays detected.
**Depends On:** EPIC-00 (gate), EPIC-01 (SAST-01-010 facts, SAST-01-020 validator hook, SAST-01-040, SAST-01-060)
**Blocks:** —
**Teams:** Dev / Test / DevOps

**Scope note.** This epic covers **38** of the 141 findings that developers marked false positive. The causes:

**SQL semantics (31 findings).**
- **Treated as TP (20):** #15, #26, #28, #36, #38, #45, #46, #49, #50, #51, #54, #61, #62, #65, #66, #67, #72, #73, #74, #209.
- **Sent to Needs Review (11):** #33, #34, #35, #37, #39, #40, #47, #59, #63, #68, #75.
- What goes wrong:
  - `setObject` is treated as a SQL-text sink (#15/#209).
  - Visibly bound numeric parameters still get "validate the caller" warnings (#36/#66).
  - Generated DAO and batch helpers are never summarised (#45/#46/#67/#73).
  - Commented-out legacy concatenation is read as live code (#33/#34/#40/#59).
  - Method declarations, getters, stubs and zero-argument methods inherit a sink because a `runtime-sink-sql-<name>` rule matches the bare method name (#37/#39/#49/#50/#61/#62).

**SQL reachability (7 findings):** #29, #30, #31, #55, #57, #60, #76.
- These methods really do concatenate SQL. Developers dismissed them as "no callers", which nothing has proven.
- They must become *inactive code* only with a proof. Otherwise they stay findings.

**How the review's assessments map to this epic's corpus.**
- **Supported** findings become negative cases: #15, #26, #28, #34, #36, #47, #66, #75, #209.
- **Conditional** findings become uncertain cases until the missing method body is resolved: once the validator reads the full method, they turn into negative cases. Where the review says the excerpt alone cannot decide, they stay uncertain.
- **Preservation positives:**
  - #1/#2: a SOAP string concatenated into `prepareStatement`;
  - the unsafe #78 members;
  - #53's stored string concatenated into a DELETE (second-order).

**Design rule (review §5.2).**
- Never mark `prepareStatement(dynamicConcatenatedText)` safe.
- Never treat `setX(...)` as a SQL-text sink.
- An unknown callee is a *named evidence gap*, not a true positive ("if it concatenates") and not a false positive.

---

### SAST-02-010 JDBC statement model per method

**Epic:** EPIC-02 SQL Injection: Bound Parameters and Method Identity        **Parent:** EPIC-02
**Parallelism:** Serial/Blocking    **Sprint:** 4

**Story**
As a scanner engineer, I want each method's JDBC statements modelled (which query each statement was prepared with, which values are bound to it and where it executes), so that "this value is bound to this statement" is a checked fact rather than a model's guess.

**Acceptance Criteria**
- `pipeline/sql_semantics.py` exposes `statements_in_method(method_node, src) -> list[StatementFact]`, built on the SAST-01-010 tree-sitter parse. Each `StatementFact` holds:
  - `var`: the statement variable or field, plus the allocation call (`prepareStatement`, `prepareCall` or `createStatement`) and its line;
  - `query_expr`: the AST node passed to the allocation, or to `execute*(String)` for a plain `Statement`;
  - `binds`: `setXxx(index, valueExpr)` calls on the same variable, with the index and the value's argument kind (from facts);
  - `executions`: `executeQuery()`, `executeUpdate()`, `execute()`, `addBatch()`, `executeBatch()`, and their `(String)` overloads, each flagged with whether a SQL string argument was passed;
  - `branch_ids`: for each bind and execution, the branch it sits in (if/else or loop body), so branch-specific binding is visible.
- Statement identity follows the variable: reassigning `ps = conn.prepareStatement(q2)` starts a new `StatementFact`. Binds and executions attach to the most recent assignment that dominates them in source order within the method.
- A statement held in a **field** (allocated in one method, bound or executed in another) gives `StatementFact(scope="field", complete=False)`. SAST-02-050 completes it.
- Comment tokens are excluded everywhere. Commented-out concatenation (#33/#34/#35/#40/#59) is not part of `query_expr`.
- Calling `executeQuery(String)`/`execute(String)` on a `PreparedStatement` is recorded as `api_misuse=True` (#54).
- Covers `java.sql` and `javax.sql` types and Spring `JdbcTemplate`/`NamedParameterJdbcTemplate` (`query`/`update` with a SQL string plus an args array or `Map`/`SqlParameterSource`, which count as bound).

**Dev Notes**
- Reuse `call_graph`'s `_CHAIN_TO_TYPE` and receiver resolution to recognise statement types; don't introduce a second type table.
- Exact control-flow dominance isn't required. Ordering by source position plus branch IDs is enough for the corpus. Note the limitation in the module docstring.
- Keep the module free of LLM and I/O dependencies (source text in, facts out).

**Test Notes**
- Test level(s): unit (table-driven over Java snippets).
- What to assert:
  - `ps = c.prepareStatement("... where id = ?"); ps.setObject(1, id); ps.executeQuery();` → one statement, one bind at index 1, one execution, query is a literal.
  - Reassigning `ps` to a second query → two statements, each with its own binds.
  - A bind only in the `else` branch → `branch_ids` differ.
  - `ps.executeQuery(sql)` on a `PreparedStatement` → `api_misuse=True`.
  - `// String sql = "... " + id;` above a fixed query → the comment doesn't appear in `query_expr`.
  - A field statement set in another method → `complete=False`.
  - `jdbcTemplate.query("... ?", rowMapper, id)` → bound.
- Test data / fixtures needed: `backend/tests/fixtures/sql_semantics/` with one construct per file. Re-create the review's shapes (#15, #34, #45, #54, #66) synthetically.
- Entry point to exercise: `sql_semantics.statements_in_method`.

**DevOps Notes**
- Build/CI impact: none.
- Deploy impact: none.
- Observability: none at this layer (counts appear in SAST-02-030).

**Dependencies:** SAST-01-010
**Blocks:** SAST-02-020, SAST-02-030, SAST-02-050

**Definition of Done:** code merged + tests green (dev + test) + builds/deploys clean (devops)

---

### SAST-02-020 Query-text classification: fixed grammar vs dynamic text

**Epic:** EPIC-02 SQL Injection: Bound Parameters and Method Identity        **Parent:** EPIC-02
**Parallelism:** Serial/Blocking    **Sprint:** 4

**Story**
As a scanner engineer, I want each executed query string classified as fixed grammar, fixed grammar with placeholders, or dynamic text (and where the dynamic part sits), so that only text that can change the SQL grammar leads to an injection finding.

**Acceptance Criteria**
- `classify_query(query_expr, method_ctx) -> QueryClass` returns one of:
  - `fixed`: literals and compile-time constants only;
  - `fixed_placeholders`: as `fixed`, plus `?` or `:name` placeholders;
  - `dynamic_value`: a non-constant expression in a value position;
  - `dynamic_identifier`: a non-constant expression in a table, column, `ORDER BY` or `IN (...)` list position, without placeholders;
  - `unknown`: the query is built in another method, read from configuration, or the expression cannot be folded.

  Each result also carries `dynamic_parts`, which lists every non-constant expression with its argument kind.
- Folding covers:
  - `+` chains;
  - `StringBuilder`/`StringBuffer` `append` chains within the method, including loops;
  - `String.format` and `MessageFormat.format` with a constant format string;
  - `static final` fields of the same class, and of other classes when the parsed repo resolves them;
  - local `final` or single-assignment variables;
  - `String.join` over constant collections.
- **Placeholder lists** are recognised as fixed grammar (#67): a loop or `Collections.nCopies`/`String.join(",", nCopies(n, "?"))`/`"?,".repeat(n)` that appends only `?` and separators. Binding is then checked per index by SAST-02-030.
- `TO_CHAR(?)`, `TO_DATE(?, 'fmt')` and similar function calls *over a placeholder* are fixed grammar (#209, #26).
- `unknown` results name the method or field that would resolve them. SAST-02-050 consumes that name.

**Dev Notes**
- This is the generic replacement for the `_SQL_BUILD_RE` heuristic. Keep `_SQL_BUILD_RE` for when facts are `None`.
- Folding across classes uses only the parsed repo. A constant from a jar is `unknown`, never assumed constant.
- A numeric-typed `dynamic_value` is still classified as `dynamic_value`. Its kind (`numeric`) travels in `dynamic_parts`, and SAST-02-040 decides what it means.

**Test Notes**
- Test level(s): unit (table-driven).
- What to assert:
  - `"SELECT a FROM t WHERE id = ?"` → `fixed_placeholders`.
  - `BASE + " WHERE x = ?"` with `static final String BASE` → `fixed_placeholders`.
  - `"... WHERE id = " + id` → `dynamic_value` with `id`.
  - `"... ORDER BY " + col` → `dynamic_identifier`.
  - A StringBuilder loop appending `"?,"` n times then trimming → `fixed_placeholders`.
  - `"... IN (" + idsCsv + ")"` → `dynamic_identifier`.
  - `getDefaultWhere()` returning a string from another class → `unknown`, naming `getDefaultWhere`.
  - `"TO_CHAR(?, 'YYYYMM')"` → `fixed_placeholders`.
- Test data / fixtures needed: snippets in `backend/tests/fixtures/sql_semantics/`.
- Entry point to exercise: `sql_semantics.classify_query`.

**DevOps Notes**
- Build/CI impact: none.
- Deploy impact: none.
- Observability: none at this layer.

**Dependencies:** SAST-02-010
**Blocks:** SAST-02-030, SAST-02-040, SAST-02-050

**Definition of Done:** code merged + tests green (dev + test) + builds/deploys clean (devops)

---

### SAST-02-030 Bound-parameter validator for SQL findings

**Epic:** EPIC-02 SQL Injection: Bound Parameters and Method Identity        **Parent:** EPIC-02
**Parallelism:** Serial/Blocking    **Sprint:** 5

**Story**
As a developer, I want a SQL-injection finding on a query whose text is fixed and whose values are all bound to be dismissed with that proof, while string-built SQL is kept, so that I stop reviewing parameterised queries and still see every real injection.

**Acceptance Criteria**
- A validator `sql_binding` is registered on the SAST-01-020 hook for:
  - `java-sql-string-concat`, `java-jdbc-prepare-concat` and `java-jdbc-statement-exec-variable`;
  - every `runtime-sink-sql-*` derived rule;
  - deep-scan and flow-verify findings with CWE-89.
- It locates the statement facts for the finding's sink (the execution or allocation the anchor points at, or every statement in the anchored method when the anchor is a call into it) and decides:
  - **Negative proof `sql_fixed_template_bound`** when all of these hold:
    - the query is `fixed` or `fixed_placeholders`;
    - every execution on the statement uses that query (no `(String)` overload with different text);
    - every placeholder index has a bind on each branch that reaches the execution.

    The proof text names the query line, the binds and the execution line.
  - **Positive fact `sql_dynamic_text`** when the query is `dynamic_value` or `dynamic_identifier` and a dynamic part is `string_var`, `call_result` or `unknown`.
  - **Positive fact `sql_api_misuse_dynamic`** when `api_misuse` holds and the string passed is dynamic.
  - **`api_misuse` with fixed text:** not injection. `issue_class=quality` and a negative proof for CWE-89, `sql_api_misuse_constant` (#54).
  - **Evidence gap** when the query is `unknown` or the statement is `complete=False`, naming what is missing. SAST-02-050 fills most of these.
- A bind call (`setObject`/`setString`/`setInt`/...) is never treated as a SQL-text sink. A finding anchored on a bind whose statement passes the negative proof gets it too (#15/#209).
- Numeric `dynamic_value` parts are left to SAST-02-040. Until that lands, this validator gives `no_opinion` for them.
- Corpus pairs added, each a positive and a negative:
  - `sql-bound-setobject` (#15/#209 shape, negative) vs `sql-concat-into-prepare` (#1/#2 shape, positive);
  - `sql-bound-numeric-param` (#36/#66, negative) vs `sql-mixed-bound-and-concat` (positive);
  - `sql-commented-legacy-concat` (#34, negative) vs `sql-live-concat-below-comment` (positive);
  - `sql-constant-select` (#47, negative);
  - `sql-dynamic-order-by` (positive);
  - `sql-wrong-statement-bound` (binds go to `ps1` but `ps2` executes; positive).

**Dev Notes**
- The validator's proofs feed the prompts through the facts block (SAST-01-020). The deep-scan system prompt also gets one sentence: "A value passed to a `PreparedStatement` setter is data, not SQL text." The review notes a prompt reminder alone is not enough, which is why the deterministic proof is the primary mechanism.
- For `runtime-sink-sql-*` findings anchored on a *call site* of a wrapper, judge the **wrapper's** statements, using the summary from SAST-02-050 when it exists. The call-site line itself has no statement.

**Test Notes**
- Test level(s): unit (validator decisions), corpus (pairs above), integration (deep-scan with patched `call_llm` returning a TP for a bound query).
- What to assert:
  - Each corpus pair gives its expected verdict and `reason_tag`.
  - An LLM TP on a bound query → `false_positive` with `sql_fixed_template_bound` (validator precedence).
  - An LLM FP on `prepareStatement("..." + s)` → `unverified/conflict`.
  - `executeQuery(sqlConst)` on a PreparedStatement → CWE-89 FP plus `issue_class=quality`.
  - A missing bind for one placeholder on one branch → no negative proof (`no_opinion`).
- Test data / fixtures needed: the corpus pairs above, with recorded responses.
- Entry point to exercise: `validators.sql_binding`, `pytest -m accuracy`.

**DevOps Notes**
- Build/CI impact: accuracy gate.
- Deploy impact: none. Expect a drop in CWE-89 findings on parameterised legacy Java codebases.
- Observability: validator outcome counts by `reason_tag` in `usage_summary.validators`.

**Dependencies:** SAST-02-010, SAST-02-020, SAST-01-020, SAST-01-040
**Blocks:** SAST-02-040, SAST-02-060, SAST-02-080

**Definition of Done:** code merged + tests green (dev + test) + accuracy gate green + builds/deploys clean (devops)

---

### SAST-02-040 Numeric values and stored strings in SQL

**Epic:** EPIC-02 SQL Injection: Bound Parameters and Method Identity        **Parent:** EPIC-02
**Parallelism:** Parallel (with SAST-02-050)    **Sprint:** 5

**Story**
As a security reviewer, I want a numeric value concatenated into SQL to be classified by the value actually used, and a string read back from the database to stay untrusted, so that numeric "injections" stop being reported as security issues while second-order injection is still caught.

**Acceptance Criteria**
- When every dynamic part of a query is `numeric` (a primitive, a boxed numeric, `BigInteger`, a `parseX` result *that is the expression used*, or a `BigDecimal` from a trusted constructor per SAST-01-010), the `sql_binding` validator returns:
  - a **negative proof for CWE-89**, `sql_numeric_only`;
  - and sets `issue_class=quality`, with the reason "Parameterisation hygiene: numeric value concatenated; bind it".

  This follows review §8: the behaviour is real, but no injection.
- When the original string is concatenated (the parsed result is computed but unused), the part stays `string_var` and the finding stays positive.
- `ResultSet.getString`/`getObject`/`getNString`/`getClob` results, and fields assigned from them, are `string_var` with origin `persisted`. Concatenating them gives the positive fact `sql_second_order` (#53 preservation). `getInt`/`getLong`/`getBigDecimal` results are numeric.
- A query selected by user criteria does not taint the *numeric* columns it returns (review §5.2).
- Corpus pairs added:
  - `sql-numeric-concat` (from #4/#5, issue_class quality, not CWE-89) vs `sql-parse-result-ignored` (`parseLong(s)` computed, `s` concatenated; positive);
  - `sql-second-order-string` (#53 shape: a stored string concatenated into DELETE; positive) vs `sql-second-order-numeric` (stored `long` id; quality).

**Dev Notes**
- The value-domain information comes from SAST-01-010 facts. Don't recompute it here.
- Numeric proofs apply only to SQL. A numeric value still matters for other sinks (array index, resource sizing). Do not add a global "numeric is safe" rule.
- `BigDecimal` concatenation calls `toString()`, which can produce scientific notation (`1E+3`). That is still no SQL grammar, but note it in the proof text.

**Test Notes**
- Test level(s): unit, corpus.
- What to assert:
  - The four corpus cases.
  - `"... id=" + Long.parseLong(s)` (the parse result is inline) → `sql_numeric_only`.
  - `long n = parseLong(s); "... id=" + s` → positive.
  - `rs.getString("name")` into a field, later concatenated in another method → positive (this needs SAST-02-050 for the cross-method part; until then, assert the same-method case only).
  - The issue class appears in the API and exports (SAST-00-030 columns).
- Test data / fixtures needed: the corpus cases above.
- Entry point to exercise: `validators.sql_binding`, `pytest -m accuracy`.

**DevOps Notes**
- Build/CI impact: accuracy gate.
- Deploy impact: none. The quality-class findings move out of security totals (`count_findings` reports them per issue class).
- Observability: counter `sql_numeric_only` per scan.

**Dependencies:** SAST-02-030
**Blocks:** SAST-02-080

**Definition of Done:** code merged + tests green (dev + test) + accuracy gate green + builds/deploys clean (devops)

---

### SAST-02-050 Method summaries for helpers, facades and generated DAO code

**Epic:** EPIC-02 SQL Injection: Bound Parameters and Method Identity        **Parent:** EPIC-02
**Parallelism:** Parallel (with SAST-02-040)    **Sprint:** 6

**Story**
As a scanner engineer, I want each method summarised once (does it execute SQL, with fixed or dynamic text, and which parameters reach the SQL text versus a bind), and reused at every call, so that wrapper, batch, facade and generated-DAO findings are decided from the code they actually run rather than from a declaration window.

**Acceptance Criteria**
- `sql_semantics.summarise(method_key) -> SqlSummary`. `method_key` is the owner FQN, name and parameter types. The summary holds:
  - `executes`: `none`, `fixed_bound`, `dynamic` (with the parameter positions that reach SQL text) or `unknown` (naming the unresolved callee);
  - `returns_sql`: `none`, `fixed`, `placeholder_list` or `dynamic` (with parameter positions);
  - `binds_params`: the parameter positions that reach setters.

  Summaries are computed bottom-up over the call graph and cached per scan.
- Resolution follows the call graph by **resolved receiver and signature**, not by name. That covers:
  - interface or EJB facade methods, summarised as the union of every implementation the graph resolves (#38, #54, #72, #74, #68);
  - overloads, kept separate by parameter types (#38, #66).
  - Unresolved implementations name the gap.
- Field-held statements (`complete=False`, SAST-02-010) are completed by following the field across the class's methods. Allocation, binds, `addBatch` and `executeBatch` are joined by field identity (#45/#46).
- Query-building helpers are summarised by `returns_sql`, and a call site uses the helper's result in place of `unknown`. These are recognised generically, not by project name:
  - default-WHERE builders (#46);
  - generated insert, update and delete builders that take a parameter bag such as `SQLParams` (#73);
  - placeholder-list builders (#67).
- Recursion and cycles end with `unknown` for the cycle members, unless every non-cyclic path is decided (#57).
- `sql_binding` (SAST-02-030) uses summaries for `unknown` and incomplete statements. Gaps it still cannot close stay `evidence_gap` with the method named.
- Corpus pairs added:
  - `sql-batch-field-statement` (#45/#46 shape; negative) vs `sql-batch-unsafe-overload` (one overload concatenates; positive);
  - `sql-generated-dao-param-bag` (#73; negative);
  - `sql-in-list-placeholders` (#67; negative) vs `sql-in-list-raw-csv` (positive);
  - `sql-facade-two-impls-one-unsafe` (#38/#74 shape; positive for the unsafe implementation only);
  - `sql-helper-unavailable` (callee not in repo; uncertain → `evidence_missing`).

**Dev Notes**
- Project-specific helper names (`Xnp_*`, `getDefaultWhere`, `SQLParams`) appear in the review. The detection must be **structural** (what the method body does), never a name list. Use the names only in corpus `seed_findings`.
- Bound the summary depth (e.g. 6 calls) and the per-scan time. Past the bound, return `unknown` with reason `summary_depth_exceeded` and count it.
- The tree-sitter call graph already resolves receivers for Java. Where Joern is installed, `flows.sc` paths can confirm a dynamic parameter-to-text link, but must not be required.

**Test Notes**
- Test level(s): unit (summaries over a small multi-class fixture), corpus.
- What to assert:
  - The corpus pairs above.
  - An interface method with two implementations, one fixed-bound and one dynamic → `executes=dynamic` at the interface level. The call site on the safe implementation's resolved receiver → negative.
  - A recursion cycle → `unknown/cycle` unless decided.
  - The depth bound is honoured and counted.
  - Summaries are computed once per method per scan (assert the cache hit count).
- Test data / fixtures needed: `backend/tests/fixtures/sql_summaries/`, a 6–8 class mini project re-creating the facade, batch, generated-DAO and IN-list shapes.
- Entry point to exercise: `sql_semantics.summarise`, `validators.sql_binding`, `pytest -m accuracy`.

**DevOps Notes**
- Build/CI impact: accuracy gate. Fixture-project tests may take a few seconds longer.
- Deploy impact: some scan-time CPU for summaries. Measure on the npg-pakistan rescan and keep it under 5% of the scan's wall time.
- Observability: `usage_summary.sql_summaries` reports methods summarised, cache hits, `unknown` by reason and depth-exceeded count.

**Dependencies:** SAST-02-010, SAST-02-020
**Blocks:** SAST-02-060, SAST-02-070, SAST-02-080

**Definition of Done:** code merged + tests green (dev + test) + accuracy gate green + builds/deploys clean (devops)

---

### SAST-02-060 Runtime SQL wrapper rules keyed by method identity

**Epic:** EPIC-02 SQL Injection: Bound Parameters and Method Identity        **Parent:** EPIC-02
**Parallelism:** Serial/Blocking    **Sprint:** 6

**Story**
As a developer, I want a "project wrapper reaches a SQL sink" finding raised only for the specific method whose parameter reaches SQL text, and only at calls that resolve to that method, so that getters, stubs, zero-argument queries and same-named methods in other classes stop inheriting someone else's sink.

**Acceptance Criteria**
- `derive_rules.wrappers_from_graph` derives a `runtime-sink-sql-*` rule only when the wrapper's SAST-02-050 summary is `executes=dynamic`, i.e. at least one *parameter* reaches SQL text. These derive no rule:
  - `fixed_bound` wrappers;
  - zero-argument wrappers (#49/#50);
  - getters and stubs (#61/#39).
- Dedupe identity is `(owner FQN, name, parameter types)`, not `name.lower()`. The rule id stays stable and unique: `runtime-sink-sql-<name>-<8-char hash of owner+signature>`. The rule carries `wrapper_owner`, `wrapper_signature` and `tainted_params`.
- Regex hits of a derived rule are validated per call site by a `wrapper_call_identity` validator (SAST-01-020). The call must resolve, via facts, to the same owner and arity; otherwise there is a negative proof `wrapper_identity_mismatch`. For #62, the DAO `getPortID(long)` call is a mismatch, while `xmlPortMsg.getPortID()` feeding #1 is kept. An unresolvable receiver gives `no_opinion` and stays unverified.
- The argument at a tainted position must be non-constant at the call site. Otherwise there is a negative proof `wrapper_arg_constant`.
- `group_by_rule` stays `true`, but grouping now also splits by semantic signature (SAST-01-060).
- **Rule derivation and its cache:** the derived rule set is embedded in the deep-scan system prompt. The change in rule ids changes that prompt once, and it must then be byte-stable across reruns. A test runs derivation twice and compares.
- Corpus cases added:
  - `wrapper-getter-not-sink` (#61, negative);
  - `wrapper-zero-arg` (#49, negative);
  - `wrapper-same-name-other-owner` (#62: DAO negative, DTO path positive);
  - `wrapper-tainted-param-call` (positive).

**Dev Notes**
- Today's rule pattern `\bname\s*\(` stays as the candidate matcher; identity is enforced by the validator. A regex cannot express owner identity reliably.
- `PASS_B_MAX_RULES_PER_CALL` and the Pass A/Pass B split are unchanged. Expect fewer Pass A rules.
- Bump `RESULT_CACHE_VERSION` only if response handling changes. The prompt bytes change by themselves, which invalidates the deep-scan keys once.

**Test Notes**
- Test level(s): unit (derivation over the SAST-02-050 fixture project), corpus.
- What to assert:
  - No rule is derived for fixed-bound, zero-argument, getter or stub wrappers.
  - One rule per distinct owner and signature, for two same-named methods where both are dynamic.
  - Rule ids are identical across two derivation runs.
  - A call with a mismatched owner → FP `wrapper_identity_mismatch`.
  - A constant argument at the tainted position → FP `wrapper_arg_constant`.
  - The corpus cases above.
- Test data / fixtures needed: the SAST-02-050 mini project plus a DTO class with a same-named getter.
- Entry point to exercise: `derive_rules.wrappers_from_graph`, `validators.wrapper_call_identity`, `pytest -m accuracy`.

**DevOps Notes**
- Build/CI impact: accuracy gate.
- Deploy impact: the deep-scan system prompt changes once, so the first scan per project after release misses its cache (expect one full-cost scan per project).
- Observability: log derived-rule counts (before and after the identity filter) per scan.

**Dependencies:** SAST-02-030, SAST-02-050, SAST-01-060
**Blocks:** SAST-02-080

**Definition of Done:** code merged + tests green (dev + test) + accuracy gate green + builds/deploys clean (devops)

---

### SAST-02-070 Entry-point model and proof of inactive code

**Epic:** EPIC-02 SQL Injection: Bound Parameters and Method Identity        **Parent:** EPIC-02
**Parallelism:** Parallel (with SAST-02-060)    **Sprint:** 6

**Story**
As a security reviewer, I want "no callers" to be a claim the scanner proves from a complete model of entry points, so that genuinely unused unsafe SQL is recorded as inactive code (still visible) and anything not proven unused stays a finding.

**Acceptance Criteria**
- The call graph's entry-point set gains, beyond today's annotations:
  - **descriptor-registered entry points:** `web.xml` servlets, filters and listeners; `ejb-jar.xml` session beans and MDBs; `webservices.xml`/`sun-jaxws.xml` endpoints; Spring XML `<bean>` classes with their `init-method`, `destroy-method` and handler methods; `faces-config.xml` managed beans;
  - **EJB remote and local business interface methods** (`@Remote`, `@Local`, and `ejb-jar.xml` `<remote>`/`<local>`);
  - **JMS `onMessage`** implementations;
  - **reflection targets** named by string literals (`Class.forName("...")`, `getMethod("...")`).
- `reachability_status(method_key) -> reachable | unreferenced | unknown`:
  - **`unreferenced`** requires all of:
    - no resolved reference anywhere in the parsed code;
    - not an entry point;
    - not a public method of a type in a descriptor, an interface or the reflection list;
    - no files failed to parse. Parse coverage must be complete for that language; otherwise the status is `unknown`.
  - **`reachable`** when a path from an entry point exists.
  - **`unknown`** otherwise.
- For CWE-89 findings with the positive fact `sql_dynamic_text`:
  - `unreferenced`: verdict stays `true_positive`, `issue_class=inactive`, and the proof lists what was checked. The unsafe construct is kept, per review §5.1.
  - `reachable`: unchanged.
  - `unknown`: unchanged, with no inactive label.
- A model "no callers / unused / dead code" claim is handled by SAST-01-090 check 5. With this model in place, that check fires only when the status is not `unreferenced`.
- The reachability findings #29, #30, #31, #55, #57, #60 and #76 each become corpus cases:
  - an `unreferenced` private method → TP plus inactive;
  - the same method referenced from an EJB interface → TP plus security;
  - the same method named in `ejb-jar.xml` → TP plus security.

**Dev Notes**
- Descriptors are XML. Parse them with the stdlib parser the dependency scan already uses, and register the classes and methods by FQN.
- Keep the entry-point additions in `call_graph`, so the Joern and flow-discovery paths benefit too. Re-run `tests/test_call_graph.py` and `test_reachability.py`.
- `inactive` changes the issue class, not the verdict. Inactive findings appear in exports under their own class total (SAST-00-060).

**Test Notes**
- Test level(s): unit (entry-point discovery, reachability status), corpus.
- What to assert:
  - A servlet in `web.xml` only (no annotation) → entry point.
  - An MDB `onMessage` → entry point.
  - A private method with no references and full parse coverage → `unreferenced`.
  - The same with one file failing to parse → `unknown`.
  - A public method on a `@Remote` interface implementation → not `unreferenced`.
  - A `Class.forName("com.x.Foo")` target → entry point.
  - The corpus cases above.
- Test data / fixtures needed: `backend/tests/fixtures/entry_points/` with descriptors, EJB interfaces, an MDB, a reflection target and an unreferenced method.
- Entry point to exercise: `call_graph.build_call_graph`, `reachability_status`, `pytest -m accuracy`.

**DevOps Notes**
- Build/CI impact: accuracy gate; the call-graph tests must stay green.
- Deploy impact: none.
- Observability: log parse coverage and the entry-point count by source (annotation, descriptor, interface, reflection) per scan.

**Dependencies:** SAST-02-050, SAST-01-090
**Blocks:** SAST-02-080

**Definition of Done:** code merged + tests green (dev + test) + accuracy gate green + builds/deploys clean (devops)

---

### SAST-02-080 Rescan, diff and adjudicate the 38 SQL findings

**Epic:** EPIC-02 SQL Injection: Bound Parameters and Method Identity        **Parent:** EPIC-02
**Parallelism:** Serial/Blocking    **Sprint:** 7

**Story**
As the release owner, I want the npg-pakistan application rescanned with this epic's changes, and each of the 38 SQL findings checked against its expected outcome, so that the epic is closed on measured, per-occurrence results.

**Acceptance Criteria**
- The application at `ae38067c239e` is rescanned (`force: true`, cache bypassed) and diffed against the SAST-01-100 "after" scan.
- Each of the 38 findings is in the close-out table with its old verdict, new verdict, `reason_tag` and expected outcome:
  - **Supported** findings (#15, #26, #28, #34, #36, #47, #66, #75, #209) → `false_positive` with a SQL proof tag.
  - **Conditional** findings → either `false_positive` with a proof, or `unverified` with a named gap. Neither TP nor an unexplained FP.
  - **Reachability** findings → TP with `issue_class=inactive` only when `unreferenced`; otherwise unchanged.
- Preservation positives still TP: #1, #2, the unsafe #78 members, and #53's string member.
- Every `true_positive → false_positive` transition outside the 38 is reviewed by a second person and labelled.
- Findings still `unverified` are listed with the evidence package from review §10 that would resolve them.
- The accuracy gate is green.

**Dev Notes**
- Join old and new rows with the SAST-00-080 label file. Expect `fuzzy` joins for historical rows, and resolve them manually.

**Test Notes**
- Test level(s): acceptance (real scan), corpus.
- What to assert: the acceptance criteria above.
- Test data / fixtures needed: the application checkout; the labels file.
- Entry point to exercise: `POST /scans`, `GET /scans/{id}/decision-diff?base=`.

**DevOps Notes**
- Build/CI impact: none.
- Deploy impact: one real scan with LLM spend.
- Observability: archive the exports, the diff and the close-out table.

**Dependencies:** SAST-02-030 to SAST-02-070, SAST-01-100
**Blocks:** —

**Definition of Done:** close-out table reviewed + labels updated + accuracy gate green

---

## Finding coverage

| Story | Primary findings |
|---|---|
| SAST-02-030 | #15, #26, #28, #33, #34, #35, #36, #37, #40, #47, #59, #63, #66, #75, #209 |
| SAST-02-040 | #4/#5 (outside the 141, §8), #53 (preservation) |
| SAST-02-050 | #38, #45, #46, #51, #54, #57, #65, #67, #68, #72, #73, #74 |
| SAST-02-060 | #39, #49, #50, #61, #62 |
| SAST-02-070 | #29, #30, #31, #55, #57, #60, #76 |

## Story order and parallelism

| Story | Title | Parallelism | Sprint | Depends On |
|---|---|---|---|---|
| SAST-02-010 | JDBC statement model | Serial/Blocking | 4 | SAST-01-010 |
| SAST-02-020 | Query-text classification | Serial/Blocking | 4 | 010 |
| SAST-02-030 | Bound-parameter validator | Serial/Blocking | 5 | 010, 020, SAST-01-020, 01-040 |
| SAST-02-040 | Numeric values and stored strings | Parallel | 5 | 030 |
| SAST-02-050 | Method summaries | Parallel | 6 | 010, 020 |
| SAST-02-060 | Wrapper rules by method identity | Serial/Blocking | 6 | 030, 050, SAST-01-060 |
| SAST-02-070 | Entry-point model and inactive proof | Parallel | 6 | 050, SAST-01-090 |
| SAST-02-080 | Rescan, diff and adjudicate | Serial/Blocking | 7 | 030–070, SAST-01-100 |

Sprint numbers are provisional until the Sprint Plan is agreed.

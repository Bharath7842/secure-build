# SAST Accuracy — EPIC-03 Log and Output Sinks: Exact Call Boundaries and Render Context

Source: `output/secure-build-npg-pakistan-accuracy-review.md` (§2, §3, §4 log/XSS rows, §5.3, §5.4, §5.5, §6 `java.json:370`/`java.json:451`/`taint_spec.json`, §7 P1, §8, §9.2 log/stdout/Angular rows). Template: `spec/chain-templates/scaffolding-sprint-story-generation-prompt-simple.md`.

## [EPIC-03] Log and Output Sinks: Exact Call Boundaries and Render Context

**Goal:** Log-injection and output-XSS findings are decided on the exact call and the exact output context: the logger invocation's own arguments, the type of the value logged, where the exception message came from, how the log layout encodes it, the real receiver of a print, and the Angular template context a value ends up in. Attacker-controlled content reaching a log or page stays detected.
**Depends On:** EPIC-00 (gate), EPIC-01 (SAST-01-010 facts, SAST-01-020 validator hook, SAST-01-030, SAST-01-050)
**Blocks:** —
**Teams:** Dev / Test / DevOps

**Scope note.** This epic covers **62** of the 141 findings developers marked false positive:

| Cause | Findings | Count |
|---|---|---|
| Log call boundaries | #93, #96, #97, #98, #101, #110, #115, #117, #120, #127, #132, #135, #137, #140, #143, #144, #186, #198, #199, #200 | 20 |
| Exception provenance | #81, #86, #100, #103, #108, #109, #111, #116, #119, #129, #130, #141, #192, #197, #203, #204, #205, #206 | 18 |
| Log value constraints | #16, #83, #118, #126, #128, #133, #134, #136, #139, #146, #170, #195 | 12 |
| Stdout reported as XSS | #211, #212, #213, #214, #215, #216 | 6 |
| Angular render context | #27, #79, #80, #208, #210, #273 | 6 |

Three shared causes:

1. **The log-injection regex reaches past the call.** `java-log-injection-unsanitized-input` (`rules/java.json:451`) allows up to 200 characters, newlines included, between `log.x(` and `getMessage()`/`request.get*`. That window crosses into the *next* statement (a `throw new DBException(e.getMessage())`, a later logger call), so a constant log line gets the neighbour's source.
2. **The servlet XSS rule matches text, not types.** `java-xss-jsp-servlet` (`java.json:370`) matches `out.println` inside `System.out.println`, and the word "request" inside a string literal.
3. **Throwable overloads are assumed safe.** The model, the scanner rationale and the developers alike treat `logger.error(msg, ex)` or `{}` parameterised logging as a sanitiser. It is not; the review marks #130, #197, #203, #204, #205 and #206 as **Disputed** for exactly this reason.

**How the review's assessments map to this epic's corpus.**
- **Supported** findings (e.g. #93, #98, #115, #117, #120, #127, #132, #135, #137, #140, #143, #144, #186, #198–#200, #211–#216) become **negative** cases.
- **Conditional** findings become **uncertain** cases until their evidence (exception constructors, layout) is modelled.
- **Disputed** findings must **never** become FP.
- **Preservation positives:**
  - #257/#258/#270, credential logging (CWE-532);
  - #138/#194/#202/#207, message-derived log content (CWE-117, review §8);
  - a tainted `HttpServletResponse`/`JspWriter` write;
  - native `innerHTML` or a trusted-value bypass in Angular.

---

### SAST-03-010 Logger and output receiver resolution

**Epic:** EPIC-03 Log and Output Sinks: Exact Call Boundaries and Render Context        **Parent:** EPIC-03
**Parallelism:** Serial/Blocking    **Sprint:** 4

**Story**
As a scanner engineer, I want every print or log call classified by what its receiver really is (a logger, a process stream, an HTTP response writer, or something else), so that the log, disclosure and XSS rules each judge only the sinks they apply to.

**Acceptance Criteria**
- `pipeline/output_sinks.py` exposes `sink_class(facts) -> SinkClass`, one of:
  - **`logger`**: the receiver type resolves to SLF4J `Logger`, Log4j 1/2 `Logger`, JUL `Logger`, Commons `Log`, or JBoss `Logger`, whatever the variable name; includes static imports and `LoggerFactory.getLogger(..).x(..)` chains. TypeScript: `console.*`, `NGXLogger`, or an injected service whose class wraps one of these.
  - **`process_stream`**: `System.out` or `System.err` (`java.io.PrintStream`), and `e.printStackTrace()` with no argument.
  - **`http_response`**:
    - `HttpServletResponse.getWriter()`/`getOutputStream()` and the variables assigned from them;
    - `JspWriter`, including the implicit `out` in `.jsp` scriptlets;
    - `PrintWriter` built over one of these.
  - **`other`**: any other `PrintWriter`/`PrintStream`, e.g. a file.
  - **`unknown`**: the receiver cannot be resolved.
- Each class carries `exposure`: log record, process output, or HTTP body.
- SAST-01-030's logger detection uses `sink_class == logger` instead of its own list.

**Dev Notes**
- Build on the SAST-01-010 receiver resolution. The type lists live in one constant module, next to `call_graph`'s `_WELL_KNOWN_TYPES`.
- In JSP files, `out` resolves to `JspWriter` only inside scriptlets. A tree-sitter Java parse of the scriptlet body is enough. If no JSP parse is available, the result is `unknown`, which is safe because it gives no negative proof.

**Test Notes**
- Test level(s): unit (table-driven).
- What to assert:
  - `private static final Logger AUDIT = LoggerFactory.getLogger(..); AUDIT.info(x)` → `logger`.
  - `System.out.println(x)` → `process_stream`.
  - `response.getWriter().println(x)` → `http_response`.
  - `PrintWriter w = response.getWriter(); w.write(x)` → `http_response`.
  - A JSP scriptlet `out.println(x)` → `http_response`.
  - `new PrintWriter(new FileWriter(f)).println(x)` → `other`.
  - An unresolvable `out.println(x)` in a plain `.java` file → `unknown`.
  - TS: `this.logger.error(x)` with `NGXLogger` injected → `logger`.
- Test data / fixtures needed: `backend/tests/fixtures/output_sinks/`.
- Entry point to exercise: `output_sinks.sink_class`.

**DevOps Notes**
- Build/CI impact: none.
- Deploy impact: none.
- Observability: none at this layer.

**Dependencies:** SAST-01-010
**Blocks:** SAST-03-020, SAST-03-060, SAST-03-070

**Definition of Done:** code merged + tests green (dev + test) + builds/deploys clean (devops)

---

### SAST-03-020 Log-injection findings bound to the logger call's own arguments

**Epic:** EPIC-03 Log and Output Sinks: Exact Call Boundaries and Render Context        **Parent:** EPIC-03
**Parallelism:** Serial/Blocking    **Sprint:** 5

**Story**
As a developer, I want a log-injection finding raised only when the untrusted value is an argument of *that* logger call, and anchored on that call, so that a constant log line is no longer blamed for a `getMessage()` in the next `throw`, `return` or log statement.

**Acceptance Criteria**
- A validator `log_call_boundary` is registered (SAST-01-020) for `java-log-injection-unsanitized-input`, for any derived log-sink rules, and for deep-scan CWE-117 findings. It works as follows:
  1. It resolves the logger call that **starts at the regex match start**. When the call is not a `logger` (SAST-03-010), the regex hit is dropped as a non-match. It is not a finding, but it is counted.
  2. It reads that call's argument nodes only.
  3. If none of the source expressions the rule names (`getMessage()`, `getLocalizedMessage()`, `request.getParameter/getHeader/getRequestURI/getRequestURL/getQueryString`), and no `throwable` argument, appear *inside those argument nodes*, it returns a negative proof `log_source_outside_call`. The proof names the line where the source actually is (the following `throw`, `return` or call).
  4. Otherwise it passes the finding on, with the matched argument recorded, to SAST-03-030/040/050.
- The finding's line is the logger call's line. Multi-line calls are handled: the argument list spans lines, and the regex window plays no part in the decision.
- A source in a *different* logger call nearby is not lost. That call produces its own regex hit (the pattern starts at each `log.x(`), and SAST-01-050 keeps the two apart.
- A rethrown exception (`throw new DBException(e.getMessage())`) is not a log sink. It is reported only where it is actually consumed by a sink (handled by SAST-03-040's provenance tracking, not by this rule).
- The regex pattern is unchanged in this story. It stays the candidate generator, and the validator decides. Its `examples.no_match` gains the cross-statement case, run through the validator path in `test_rule_catalog.py`.
- Corpus pairs added, each a negative and a positive:
  - `log-literal-then-throw-getmessage` (#93/#115/#143/#144, negative) vs `log-getmessage-in-same-call` (positive);
  - `log-count-then-getmessage-log` (#98: the count log is negative, the next call is evaluated separately);
  - `log-banner-then-soap-tostring` (#198–#200: the banner is negative, the next call is evaluated separately);
  - `log-multiline-parameterized` (positive: `request.getRequestURI()` as the third line of a parameterised call).

**Dev Notes**
- The SAST-01-050 de-duplication change is what keeps the neighbouring call's finding alive. Verify with the #98 case that two findings come out.
- The validator never looks at logger *spelling*. Use `sink_class`.

**Test Notes**
- Test level(s): unit (validator), corpus, rule-catalog test.
- What to assert:
  - Each corpus pair.
  - A literal-only log followed within 200 characters by `throw new X(e.getMessage())` → FP `log_source_outside_call`, and the proof names the throw line.
  - `log.error("x {}", e.getMessage())` → passed on.
  - `log.error("x", e)` → passed on with a `throwable` argument.
  - A regex hit on `catalog.info(...)`, where `catalog` is not a logger → dropped and counted.
  - Anchor line equals the call's line for a call split over three lines.
- Test data / fixtures needed: the corpus cases above.
- Entry point to exercise: `validators.log_call_boundary`, `pytest -m accuracy`, `tests/test_rule_catalog.py`.

**DevOps Notes**
- Build/CI impact: accuracy gate.
- Deploy impact: none. Expect a large drop in CWE-117 findings on legacy Java code with a log-then-throw idiom.
- Observability: counts of `log_source_outside_call` and `non_logger_regex_hit_dropped`.

**Dependencies:** SAST-03-010, SAST-01-020, SAST-01-050
**Blocks:** SAST-03-030, SAST-03-040, SAST-03-050, SAST-03-060

**Definition of Done:** code merged + tests green (dev + test) + accuracy gate green + builds/deploys clean (devops)

---

### SAST-03-030 Log value-domain proofs: constant, numeric and enumerated arguments

**Epic:** EPIC-03 Log and Output Sinks: Exact Call Boundaries and Render Context        **Parent:** EPIC-03
**Parallelism:** Parallel (with SAST-03-040, SAST-03-050)    **Sprint:** 5

**Story**
As a developer, I want a log call whose arguments can only be constants, numbers, enums or counts to be dismissed for log forging with that proof, so that "rows updated: " + count is never reported as log injection.

**Acceptance Criteria**
- For a logger call that passes SAST-03-020, when **every** non-literal argument is one of:
  - `constant`, including `static final` class-name constants (#186);
  - `numeric`: a primitive, boxed numeric, or `BigInteger` getter return type (#146/#195); `int` from `executeUpdate` (#98/#118); or the `parseX` result actually used (#133/#170);
  - `boolean`, `enum`, or a `size()`/`length` value,

  the validator returns a negative proof for CWE-117, `log_arg_constrained`. The proof lists each argument with its kind.
- Getter return types are resolved through the call graph's method declarations, e.g. `getResultCode()` returning `BigInteger`. An unresolved getter makes the argument `unknown`, so there is no proof.
- `ServletRequest.getLocale()` is **not** proven safe. A `Locale` from the container is constrained only to the container's grammar, so the result is an evidence gap: "container Accept-Language parsing and Locale serialisation" (#16).
- Grouped members are judged one by one (SAST-01-070). In #146, the `setResultDesc` occurrence is not a logger call and is dropped by SAST-03-020; the adjacent `getResultDesc` string log is evaluated on its own.
- Corpus pairs added:
  - `log-int-count` (negative) vs `log-string-param` (positive);
  - `log-parse-result-used` (negative) vs `log-parse-original-used` (positive);
  - `log-biginteger-getter` (negative) vs `log-string-getter-same-class` (positive);
  - `log-request-locale` (uncertain).

**Dev Notes**
- Reuse SAST-01-010 argument kinds. Don't re-derive numeric typing here.
- CWE-117 needs a line-breaking or delimiter-capable value. Constrained values cannot carry one. This proof says nothing about CWE-532 (SAST-03-060): a numeric account number can still be sensitive.

**Test Notes**
- Test level(s): unit, corpus.
- What to assert:
  - The corpus pairs.
  - `log.info(CLASS_NAME + ": no connection")` → negative.
  - `log.info("job " + jobId)` with `int jobId = Integer.parseInt(s)` → negative.
  - The same with `s` logged → positive candidate.
  - `getLocale()` → `unverified/evidence_missing`.
- Test data / fixtures needed: the corpus cases above.
- Entry point to exercise: `validators.log_value_domain`, `pytest -m accuracy`.

**DevOps Notes**
- Build/CI impact: accuracy gate.
- Deploy impact: none.
- Observability: counter `log_arg_constrained`.

**Dependencies:** SAST-03-020
**Blocks:** SAST-03-090

**Definition of Done:** code merged + tests green (dev + test) + accuracy gate green + builds/deploys clean (devops)

---

### SAST-03-040 Exception-message provenance summaries

**Epic:** EPIC-03 Log and Output Sinks: Exact Call Boundaries and Render Context        **Parent:** EPIC-03
**Parallelism:** Parallel (with SAST-03-030, SAST-03-050)    **Sprint:** 6

**Story**
As a security reviewer, I want the scanner to work out what text a logged exception can actually carry (from which exceptions reach the catch, and how their messages and fields are built), so that fixed-message exceptions are dismissed with proof, parser and remote-call exceptions stay flagged, and "it's a Throwable overload" is never treated as a sanitiser.

**Acceptance Criteria**
- `pipeline/exception_provenance.py` computes, for a logged `throwable` argument or a `getMessage()`/`getLocalizedMessage()`/`toString()`/field getter on a caught exception:
  1. **Candidate exception types:** the catch type; the `throw new X(..)` statements in the try body; and the declared `throws` of methods called in the try body (resolved by call graph). Multi-catch and `catch (Exception e)` widen the set (#130 versus #129).
  2. **For project exception classes:** a constructor and throw-site summary of `message` and of named fields (e.g. a `reason` or `errorCode` field). The domain is one of:
     - `literal_set`: every construction passes literals or constants (#83, #126, #128, #134, #136, #139 when proven);
     - `from_parameter`: summarised from the throw sites' arguments, recursively;
     - `unknown`.
  3. **For JDK and library exceptions,** a fixed table of message behaviour, each entry citing its source:
     - `InterruptedException` from `Thread.sleep`: no external text (#86).
     - `NullPointerException`: JVM-generated vs `new NullPointerException(msg)` in the try body (#129).
     - `StackOverflowError`: VM-generated unless constructed explicitly (#192).
     - `SQLException`, `SAXException`/`SAXParseException`, `WebServiceException`/`SOAPFaultException`, `JMSException`, `IOException` and generic `Exception`: **may embed external or remote text** (#197, #203, #204, #205, #130, #206).
- Decision for CWE-117:
  - every candidate is `literal_set` or "no external text" → negative proof `exception_message_constrained`;
  - any candidate may embed external text → passed on, as a positive candidate, to SAST-03-050 (layout);
  - any candidate is `unknown` → evidence gap `exception_provenance_unknown`, naming the types and methods (#81, #100, #103, #108, #109, #111, #116, #119, #141).
- **No negative proof is ever based on the overload or the message format.** That covers `logger.error(msg, ex)`, `{}` placeholders and structured fields. A unit test asserts that the validator never reads the overload shape.
- A rethrow (`throw new DBException(e.getMessage())`) carries the source exception's domain into the new exception's summary, so a later log of the new exception is judged correctly (#96, #97, #110, #115).
- Corpus pairs added:
  - `exc-literal-only-project-exception` (negative) vs `exc-project-exception-from-request` (positive);
  - `exc-thread-sleep-interrupted` (negative) vs `exc-generic-catch-around-parser` (positive);
  - `exc-sax-parse-message` (#205: positive or uncertain, never FP);
  - `exc-npe-explicit-message` (#129 counter-case: positive candidate).

**Dev Notes**
- Keep the JDK/library table small, explicit and documented per entry. Default to "may embed external text" for anything not listed.
- Summaries are per scan and cached. Bound the depth, as in SAST-02-050; past the bound the result is `unknown`.
- Do not change `taint_spec.json`'s sanitiser list in this story. §6 flags it, but Joern flows only *annotate*, so leave that to a follow-up.

**Test Notes**
- Test level(s): unit (provenance over a fixture project), corpus.
- What to assert:
  - Each corpus pair.
  - An overload-only change (`log.error(e.getMessage())` → `log.error("x", e)`) never changes the decision.
  - A `catch (Exception e)` around a body calling a parser → includes `SAXException` and is positive.
  - A project exception with one constructor taking `String msg`, thrown only with literals → `literal_set`.
  - The same with one throw site passing `req.getParameter("x")` → positive.
  - An unresolved called method → `unknown` naming it.
  - The rethrow carries the domain.
- Test data / fixtures needed: `backend/tests/fixtures/exception_provenance/`, a mini project with 3–4 exception classes and throw sites.
- Entry point to exercise: `exception_provenance.summarise`, `validators.log_exception_provenance`, `pytest -m accuracy`.

**DevOps Notes**
- Build/CI impact: accuracy gate.
- Deploy impact: some scan-time CPU. Measure on the rescan.
- Observability: counts of `exception_message_constrained`, `exception_provenance_unknown` and `external_text_possible`.

**Dependencies:** SAST-03-020
**Blocks:** SAST-03-060, SAST-03-090

**Definition of Done:** code merged + tests green (dev + test) + accuracy gate green + builds/deploys clean (devops)

---

### SAST-03-050 Logging layout and encoder model

**Epic:** EPIC-03 Log and Output Sinks: Exact Call Boundaries and Render Context        **Parent:** EPIC-03
**Parallelism:** Parallel (with SAST-03-030, SAST-03-040)    **Sprint:** 5

**Story**
As a security reviewer, I want the scanner to read the project's logging configuration and know whether the appender a logger writes to neutralises line breaks in messages and stack traces, so that log forging is confirmed where nothing encodes, dismissed where the layout provably does, and left unresolved when the layout isn't in the repository.

**Acceptance Criteria**
- `pipeline/logging_config.py` finds and parses, in the repository and its resources:
  - `logback.xml`, `logback-spring.xml`;
  - `log4j2.xml`/`.json`/`.yaml`/`.properties`;
  - `log4j.xml`/`.properties`;
  - JUL `logging.properties`.

  It builds a logger-category → appenders → layout map, with the root as fallback.
- For each layout it records:
  - **`message_crlf`**: one of
    - `neutralised`: `%replace(%msg){'[\r\n]',...}`, `%enc{%m}{CRLF}`/`%encode{..}{CRLF}`, or a JSON layout (Log4j2 `JsonLayout`/`JsonTemplateLayout`, logstash-logback `LogstashEncoder`);
    - `raw`: a pattern with `%m`/`%msg` and no encoder;
    - `unknown`.
  - **`throwable_crlf`**, decided the same way for `%ex`, `%throwable` and `%xEx`. A pattern that encodes `%m` but prints `%ex` raw is `raw` for throwables.
- For a CWE-117 candidate that survives SAST-03-020 to 040, the logger's category (the class FQN for `getLogger(X.class)`, or the string name) is resolved to its appenders. Then:
  - every appender `neutralised` for the relevant part (message or throwable) → negative proof `log_layout_neutralises`, naming the config file and line;
  - any appender `raw` → stays a true-positive candidate, with the layout cited as evidence;
  - no configuration found, configuration external (e.g. container-managed `standalone.xml` not in the repo), or layout `unknown` → evidence gap `log_layout_unknown` (review §9.2: "unknown layout is unresolved").
- The deep-scan system prompt (`llm_file_scan._SYSTEM_HEAD`) states that parameterised logging, a Throwable argument and structured fields are **not** CRLF defences, and that only the layout or explicit encoding is.

**Dev Notes**
- Profile-specific Spring configs (`logback-<profile>.xml`) all count. When they disagree, the outcome is the least safe one.
- This is the only place encoder evidence comes from. Never infer it from the logging *library* (review §10: "no inference that SLF4J/Log4j syntax automatically provides safety").
- Prompt change: cache keys change automatically. Bump `RESULT_CACHE_VERSION` only if response handling changes.

**Test Notes**
- Test level(s): unit (config parsing, category resolution), corpus.
- What to assert:
  - A logback pattern `%d %msg%n` → `raw`.
  - `%replace(%msg){'[\r\n]','_'}%n` → `neutralised` message, and `throwable_crlf=raw` when `%ex` is present.
  - A Log4j2 `JsonTemplateLayout` → `neutralised` for both.
  - A logger `com.x.Foo` mapped through `<logger name="com.x">` to a raw appender → `raw`.
  - No config file → `log_layout_unknown`.
  - Two profiles, one raw → `raw`.
- Test data / fixtures needed:
  - `backend/tests/fixtures/logging_config/` with 6–8 config variants;
  - corpus cases `log-forging-raw-layout` (positive), `log-forging-json-layout` (negative) and `log-forging-no-config` (uncertain).
- Entry point to exercise: `logging_config.load`, `validators.log_layout`, `pytest -m accuracy`.

**DevOps Notes**
- Build/CI impact: accuracy gate.
- Deploy impact: none. Many legacy repos have no logging config in source control, so expect more `log_layout_unknown`. Tell report readers this is a request for the deployed config, not a scanner failure.
- Observability: log per scan which logging configs were found and how many logger categories resolved to each outcome.

**Dependencies:** SAST-03-020
**Blocks:** SAST-03-060, SAST-03-090

**Definition of Done:** code merged + tests green (dev + test) + accuracy gate green + builds/deploys clean (devops)

---

### SAST-03-060 Separate log forging, sensitive-data disclosure and logging quality

**Epic:** EPIC-03 Log and Output Sinks: Exact Call Boundaries and Render Context        **Parent:** EPIC-03
**Parallelism:** Serial/Blocking    **Sprint:** 6

**Story**
As a security reviewer, I want each log or print finding classified as log forging, sensitive-data disclosure or a logging-quality issue, each with its own proof, so that a finding dismissed as "not forgeable" is not also dismissed as "not a leak", and quality warnings stop inflating security totals.

**Acceptance Criteria**
- Every finding whose sink is `logger` or `process_stream` is assigned exactly one outcome per question:
  - **CWE-117 (log forging):** needs a value that can carry delimiters and is attacker-controlled (SAST-03-020 to 040) *and* a layout that is not `neutralised` (SAST-03-050). Applies only to `logger` sinks, and to `process_stream` when output is captured into a log (unknown → evidence gap).
  - **CWE-532 / CWE-312 (sensitive disclosure):** needs a sensitive value (a credential, token or personal data, as matched by `java-sensitive-data-in-logs`, `secret-password-assign` and deep-scan reasoning) reaching **any** of `logger`, `process_stream` or `other`. Log level and an operator-only audience do not dismiss it (review §5.3). #257/#258/#270 are preservation positives on both `logger` and `System.out`.
  - **Quality** (`issue_class=quality`):
    - `logger-exception-tostring`;
    - a swallowed exception with no fail-open security effect;
    - `printStackTrace()`;
    - stdout debug prints (`java-stdout-debug-print`) with no sensitive value.
- A negative proof for one CWE never removes a finding raised under another. The CWE-117 proofs (`log_arg_constrained`, `exception_message_constrained`, `log_layout_neutralises`) carry `applies_to_cwe: ["CWE-117"]`, and the validator hook enforces this.
- `_SYSTEM_HEAD` names CWE-117 and CWE-532 as separate questions, and says stdout is a disclosure sink but not an XSS sink.
- Preservation corpus cases added (positives): `log-credential-logger` (#257), `log-credential-stdout` (#270), `log-message-derived-content` (#138/#194/#202/#207 shape). Negative: `log-tostring-quality` (quality, not security).

**Dev Notes**
- The sensitive-*value* semantics (passport number vs password, token counts, process names, #17/#22/#25/#261–#268) belong to the follow-up value-semantics epic. Here, keep the current sensitive-value detection and only make sure it isn't suppressed by a CWE-117 proof or a logging-line filter (SAST-01-030).
- Implement `applies_to_cwe` in the SAST-01-020 hook. It is a small extension there, so coordinate with the EPIC-01 owner.

**Test Notes**
- Test level(s): unit (classification), corpus.
- What to assert:
  - A password in `logger.debug(..)` with a JSON layout → CWE-117 FP *and* CWE-532 TP, both rows present.
  - A password in `System.out.println` → CWE-532 TP.
  - `log.error(e.toString())` → `issue_class=quality`.
  - A CWE-117 proof doesn't touch a CWE-532 finding on the same line (`applies_to_cwe`).
  - The four corpus cases above.
- Test data / fixtures needed: the corpus cases above.
- Entry point to exercise: `validators.*` via `run_validators`, `pytest -m accuracy`.

**DevOps Notes**
- Build/CI impact: accuracy gate.
- Deploy impact: none. Quality findings move to their own totals (SAST-00-060).
- Observability: counts of log/print findings by outcome class per scan.

**Dependencies:** SAST-03-010, SAST-03-020, SAST-03-040, SAST-03-050, SAST-01-030
**Blocks:** SAST-03-090

**Definition of Done:** code merged + tests green (dev + test) + accuracy gate green + builds/deploys clean (devops)

---

### SAST-03-070 Servlet and JSP output: real response writers only

**Epic:** EPIC-03 Log and Output Sinks: Exact Call Boundaries and Render Context        **Parent:** EPIC-03
**Parallelism:** Parallel    **Sprint:** 5

**Story**
As a developer, I want servlet XSS findings raised only when request-derived data is written to an HTTP response or JSP writer, so that `System.out.println("requests: " + count)` is no longer reported as cross-site scripting, while real reflected XSS still is.

**Acceptance Criteria**
- A validator `servlet_output_sink` is registered for `java-xss-jsp-servlet` and for deep-scan CWE-79 findings on Java files. It decides:
  - `sink_class != http_response` (SAST-03-010) → negative proof for CWE-79, `xss_sink_not_http_response`, naming the receiver type (#211–#216). `unknown` → no opinion.
  - `http_response` with no argument node that is a request-derived expression → negative proof `xss_no_request_source`. A request-derived expression is a `HttpServletRequest`-typed variable's accessor, or a value traced from one in the method. The word "request" inside a string literal does not count (#212, #216).
  - `http_response` with numeric or constant arguments only → negative proof `xss_arg_constrained`.
  - Otherwise → passed on as a positive candidate.
- The regex in `java.json` is tightened:
  - `out.println` must not be preceded by `System.` (a lookbehind);
  - `request` must be followed by `.` or `)` (an expression, not a word).

  `examples.match` and `examples.no_match` cover both, and still match `response.getWriter().write(request.getParameter("q"))` and a JSP-scriptlet `out.println(request.getParameter("q"))`.
- CWE-532 on the same stdout line is untouched (SAST-03-060).
- Corpus pairs added:
  - `stdout-count-not-xss` (#213/#214, negative) vs `response-writer-request-param` (positive);
  - `stdout-literal-with-word-request` (#212/#216, negative);
  - `jsp-scriptlet-request-param` (positive);
  - `stdout-password` (CWE-532 positive, from SAST-03-060).

**Dev Notes**
- The rule's `frameworks` filter (`Java Servlet/JSP`) stays. The validator is the real defence; the regex change only reduces noise early.
- `tests/test_rule_catalog.py` runs the examples through the real scan path. Make sure the lookbehind compiles under the engine's regex flags.

**Test Notes**
- Test level(s): unit (validator), rule-catalog test, corpus.
- What to assert:
  - The corpus pairs.
  - The regex no longer matches `System.out.println("x request y")`.
  - It still matches the two positive forms.
  - An LLM CWE-79 TP on a `System.out` line → FP `xss_sink_not_http_response` (validator precedence).
- Test data / fixtures needed: the corpus cases above.
- Entry point to exercise: `validators.servlet_output_sink`, `tests/test_rule_catalog.py`, `pytest -m accuracy`.

**DevOps Notes**
- Build/CI impact: accuracy gate, rule-catalog test.
- Deploy impact: none.
- Observability: counter by `reason_tag`.

**Dependencies:** SAST-03-010, SAST-01-020
**Blocks:** SAST-03-090

**Definition of Done:** code merged + tests green (dev + test) + accuracy gate green + builds/deploys clean (devops)

---

### SAST-03-080 Angular render-context continuation for translated and assigned values

**Epic:** EPIC-03 Log and Output Sinks: Exact Call Boundaries and Render Context        **Parent:** EPIC-03
**Parallelism:** Parallel    **Sprint:** 6

**Story**
As a frontend developer, I want an Angular XSS or code-execution finding on a translation lookup or a component property to follow the value to where it is actually rendered, so that text shown through escaped interpolation is dismissed with proof, while `innerHTML`, trusted-value bypasses and direct DOM writes stay detected.

**Acceptance Criteria**
- A validator `angular_render_context` is registered for TypeScript CWE-79 and CWE-94 findings. It applies when the anchor is any of:
  - a `TranslateService.get/instant/stream` call or the `translate` pipe;
  - an assignment to a component property, including inside `subscribe(...)`;
  - an array `push`/assignment on a component property.
- It resolves:
  1. The component class: its `@Component` `templateUrl` (the file read from the repo) or its inline `template`.
  2. Every template consumer of the property, including through `*ngFor`/`@for` loop variables and `async` pipes.
  3. Each consumer's context:
     - `text`: `{{ }}`, or a property binding to `textContent` or a plain attribute → escaped;
     - `angular_html`: `[innerHTML]`/`[outerHTML]` → sanitised by Angular;
     - `bypass`: the value went through `DomSanitizer.bypassSecurityTrust*` on its way;
     - `raw_dom`: the component TS also writes it via `ElementRef.nativeElement.innerHTML`, `Renderer2.setProperty(.., 'innerHTML', ..)`, `insertAdjacentHTML` or `document.write`;
     - `evaluator`: it reaches `eval`, `new Function`, `setTimeout(string)`, or dynamic template compilation.
  4. Whether the app registers a custom `TranslateCompiler`, `MissingTranslationHandler`, a custom `TranslateLoader` that executes content, or a custom pipe on the path.
- Decision:
  - every consumer `text`, with no custom translation pipeline → negative proof `angular_text_interpolation`, listing each template file and line (#27, #79, #80, #208);
  - any `bypass`, `raw_dom` or `evaluator` → positive fact;
  - `angular_html` only → negative for script execution, noted as "Angular-sanitised HTML" (content injection stays a quality note);
  - a custom translation pipeline, an unresolved template, or no consumer found → evidence gap naming what is missing.
- CWE-94 on a translation lookup requires an `evaluator` consumer. A dictionary lookup alone is never code execution (#210).
- **Each code path is judged on its own.** For #273, the dynamic-key `else` branch is judged, not the constant-key `if` branch DEV cited (Disputed). It must not become FP unless its own consumers are all `text`.
- Corpus pairs added:
  - `ng-translate-to-interpolation` (negative) vs `ng-translate-to-innerhtml-bypass` (positive);
  - `ng-push-to-ngfor-text` (negative) vs `ng-nativeelement-innerhtml` (positive);
  - `ng-custom-translate-compiler` (uncertain);
  - `ng-dynamic-key-else-branch` (#273 shape; uncertain or positive, never FP).

**Dev Notes**
- Templates: a light parser is enough. Angular template syntax isn't full HTML, but interpolation and binding attributes are regular enough for tree-sitter-html or a tolerant HTML parser. No Angular compiler dependency.
- Existing rules `innerhtml-assign`, `angular-renderer-setproperty-innerhtml` and `angular-bypass-security-trust` stay as they are. They are the `raw_dom` and `bypass` positives this validator must not suppress.
- `ast_struct.analyze_ts_source` already reads `@Component` decorators. Extend it rather than re-parsing.

**Test Notes**
- Test level(s): unit (template consumer resolution, context classification), corpus.
- What to assert:
  - Each corpus pair.
  - A property rendered in two places, one `{{ }}` and one `[innerHTML]` with a bypass → positive.
  - `templateUrl` pointing to a missing file → evidence gap.
  - A loop variable from `*ngFor="let m of errorMsg"` rendered as `{{ m }}` → `text`.
  - The new control-flow `@for (m of errorMsg; track m)` behaves the same.
  - A custom `TranslateCompiler` provider in `app.module.ts` or `app.config.ts` → evidence gap.
- Test data / fixtures needed: `backend/tests/fixtures/angular_render/`, a 3-component mini app re-creating the #27/#79/#80/#208/#210/#273 shapes.
- Entry point to exercise: `validators.angular_render_context`, `pytest -m accuracy`.

**DevOps Notes**
- Build/CI impact: accuracy gate. `tree-sitter-html` is not in `requirements.txt` today; add it pinned (`>=0.23`, matching the other grammars), or use a stdlib-tolerant parser.
- Deploy impact: none.
- Observability: counts by context class per scan.

**Dependencies:** SAST-01-010, SAST-01-020
**Blocks:** SAST-03-090

**Definition of Done:** code merged + tests green (dev + test) + accuracy gate green + builds/deploys clean (devops)

---

### SAST-03-090 Rescan, diff and adjudicate the 62 log and output findings

**Epic:** EPIC-03 Log and Output Sinks: Exact Call Boundaries and Render Context        **Parent:** EPIC-03
**Parallelism:** Serial/Blocking    **Sprint:** 7

**Story**
As the release owner, I want the npg-pakistan application rescanned with this epic's changes, and each of the 62 log and output findings checked against its expected outcome, so that the epic is closed on measured results and no preserved positive was lost.

**Acceptance Criteria**
- The application at `ae38067c239e` is rescanned (`force: true`, cache bypassed) and diffed against the previous accepted scan.
- Each of the 62 findings is in the close-out table with its old verdict, new verdict, `reason_tag` and expected outcome:
  - **Supported** call-boundary, stdout and value findings → `false_positive` with the matching proof tag.
  - **Conditional** exception, layout and Angular findings → FP with a proof, or `unverified` with a named gap.
  - **Disputed** (#130, #197, #203, #204, #205, #206, #273) → never FP.
- Preservation positives still TP: #257, #258, #270 (CWE-532), and the message-derived log findings #138, #194, #202, #207.
- The logging configuration actually deployed for npg-pakistan (review §10) is requested from the project owner. When received, it is added to the rescan as an override input, and the `log_layout_unknown` count before and after is recorded.
- Every `true_positive → false_positive` transition outside the 62 is reviewed by a second person and labelled.
- The accuracy gate is green.

**Dev Notes**
- An externally supplied logging config needs a way into the scan. Add an optional per-project upload or path setting **only if** the owner supplies one; otherwise record the gap and close.

**Test Notes**
- Test level(s): acceptance (real scan), corpus.
- What to assert: the acceptance criteria above.
- Test data / fixtures needed: the application checkout; the labels file; the deployed logging config (if supplied).
- Entry point to exercise: `POST /scans`, `GET /scans/{id}/decision-diff?base=`.

**DevOps Notes**
- Build/CI impact: none.
- Deploy impact: one real scan with LLM spend.
- Observability: archive the exports, the diff and the close-out table.

**Dependencies:** SAST-03-030 to SAST-03-080, SAST-01-100
**Blocks:** —

**Definition of Done:** close-out table reviewed + labels updated + accuracy gate green

---

## Finding coverage

| Story | Primary findings |
|---|---|
| SAST-03-020 | #93, #96, #97, #98, #101, #110, #115, #117, #120, #127, #132, #135, #137, #140, #143, #144, #186, #198, #199, #200 |
| SAST-03-030 | #16, #118, #133, #146, #170, #195 |
| SAST-03-040 | #81, #83, #86, #100, #103, #108, #109, #111, #116, #119, #126, #128, #129, #130, #134, #136, #139, #141, #192, #197, #203, #204, #205, #206 |
| SAST-03-050 | Secondary for every exception-provenance finding that still has an external-text path (layout decides) |
| SAST-03-060 | Preservation: #257, #258, #270, #138, #194, #202, #207 |
| SAST-03-070 | #211, #212, #213, #214, #215, #216 |
| SAST-03-080 | #27, #79, #80, #208, #210, #273 |

## Story order and parallelism

| Story | Title | Parallelism | Sprint | Depends On |
|---|---|---|---|---|
| SAST-03-010 | Logger and output receiver resolution | Serial/Blocking | 4 | SAST-01-010 |
| SAST-03-020 | Log findings bound to the call's arguments | Serial/Blocking | 5 | 010, SAST-01-020, 01-050 |
| SAST-03-030 | Log value-domain proofs | Parallel | 5 | 020 |
| SAST-03-050 | Logging layout and encoder model | Parallel | 5 | 020 |
| SAST-03-070 | Servlet/JSP real response writers only | Parallel | 5 | 010, SAST-01-020 |
| SAST-03-040 | Exception-message provenance | Parallel | 6 | 020 |
| SAST-03-060 | Forging vs disclosure vs quality | Serial/Blocking | 6 | 010, 020, 040, 050, SAST-01-030 |
| SAST-03-080 | Angular render-context continuation | Parallel | 6 | SAST-01-010, 01-020 |
| SAST-03-090 | Rescan, diff and adjudicate | Serial/Blocking | 7 | 030–080, SAST-01-100 |

Sprint numbers are provisional until the Sprint Plan is agreed.

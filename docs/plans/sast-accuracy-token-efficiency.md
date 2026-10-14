# Plan: better SAST accuracy at lower token cost, plus a generic Java and frontend rule pack

## Context

Scan v2 of `npg-chile-wom` (dev/rel10.5) used **1.09M tokens / $2.04** and still finished poorly:

| Symptom (from the log) | Cause |
|---|---|
| Only **7 files** were deep-scanned, and 4 of them are EJB `Home`/`Local` interfaces or Angular `environment*.ts`. 93 of the 100 deep-scan slots went unused. | `deep-scan-critical-only` (default on) moves HIGH files to triage **and** disables backfill (`sast_scan_agent.py:1343-1373`). The `security/` directory rule marks interface stubs CRITICAL. |
| **269 HIGH + 2,281 MEDIUM/LOW** files went to `llm_triage` (one LLM call per file with hits). The $2 cutoff was reached in batch 4 of 12. | `triage-mode-llm-confirm` (default on) skips the grouped path. Batches 6–12 (REST controllers, SOAP, Angular) ended **all unverified**. |
| The agentic hunt got **$0** (planner failed, 20 hypotheses "budget exhausted"). | **Resolved by removing the hunt** (it was on by default and added no findings). Its budget now goes to the deep scan and group-confirm. |
| The post-scan sweep resolved **69 groups covering 1,084 findings** cheaply. | Group-confirm costs far less per finding than per-file triage. |
| About **900 findings came from `Simulators/`**. | The scan root was the whole repo, not `NPGParent`. |
| `*Test.java` and `ejbclient/*TestClient*` under `src/main` were triaged. | `_is_test_path` (`pipeline/call_graph.py:279`) only recognises `/src/test/`. |
| `HisClean` 102, `RequestsMgr` 109, `Trace` 34 hits, each one triaged separately. | `llm_triage` doesn't group before it calls the LLM. |
| The PDF shows CRITICAL 17 / HIGH 95 / MEDIUM 88 / LOW 19. | These are already group counts, but they include dismissed groups and aren't labelled. |
| The catalog has **no SQL-concatenation rule at all**, almost nothing for Spring/JPA/Hibernate data access, and only 7 frontend rules. Vue `.vue` and Angular `.html` templates get no XSS coverage. | The rules were grown one repo at a time. |

**Goal:** spend the budget on the code most exposed to attackers, resolve repetitive regex hits by group, report the final actionable group counts, and ship a **generic** rule pack for any Java project (JDBC, Spring, Jakarta EE, Hibernate/JPA, Struts, SOAP) and any frontend (Angular, React, Vue, plain JS/jQuery).

## Part A — Configuration only for NPG (no code; do first and re-run)
1. Set scan `scope` = `NPGParent` (`agent_bridge.py:204` → `sast_scan_agent.py:758`).
2. Project Limitations page: turn `deep-scan-critical-only` **off** and `triage-mode-llm-confirm` **off**.
3. Re-run with `force: true`. The result cache still serves unchanged prompts.

## Part B — Engine fixes

**B1. Defaults.** In `app/defaults/scan_limitations.py`, set `triage-mode-llm-confirm` and `deep-scan-critical-only` to `enabled_by_default=False`, and update their descriptions. Update the default assertions in `test_scan_limitations.py` / agent_bridge tests.

**B2. Don't waste deep-scan slots.**
- In `STACK_PROFILES["maven-java"]["rules"]`, put a filename rule ahead of the `security/` directory rule that demotes EJB `*Home.java`/`*LocalHome.java`/`*Local.java`/`*Remote.java` to LOW.
- Angular `environment*.ts`: drop from CRITICAL to MEDIUM. The secret rules still cover it.

**B3. Rank deep-scan files by attack surface.**
- At the start of `node_scan_deep_files`, re-rank CRITICAL/HIGH by `(risk_rank, -entry_points_in_file, -typed_sinks_in_file)`.
- Entry points come from the call graph's `_is_framework_entry`: `@RestController`, `@Path`, `@WebService`, servlets, `@Controller`, Struts actions. The graph already exists by then.
- Add filename and content rules that make these CRITICAL, so they reach the deep scan, which handles absence checks:
  - REST resource classes (`@Path`/`@RestController`)
  - `@WebService` implementations
  - `web.xml`
  - `*SecurityConfig*`
  - `*Filter.java` that implements a servlet `Filter`

**B4. Detect test code by name, not only by directory.**
- Extend `_is_test_path` to cover `*Test.java`, `*Tests.java`, `*IT.java`, `*Test\d*.java`, `*TestClient*.java`, `/test/`, and `/ejbclient/`.
- For JS/TS, cover `*.spec.ts`, `*.test.(t|j)sx?`, `__tests__/`, `e2e/`, `cypress/`.
- Use it in `llm_file_scan.files_for_risk_levels` and add a `files_skipped_test` counter.
- Add a display-only `test-files-skipped` entry to the limitations catalog.

**B5. Group in `llm_triage` mode too.** In `triage_regex_hits`, collapse hits that share a `group_key_for_finding` into one candidate (occurrence count plus the first 3 windows). Fan the verdict out to every line through `verdict_updates_writer`.

## Part C — The report headline shows final actionable group counts
- `scan_export.py`: `group_findings_by_issue` stamps `occurrence_count = len(members)` on each representative (an ORM instance that is never flushed, like `affected_files`).
- New `_count_groups_by_severity` that leaves out `false_positive`.
- `_severity_strip` shows `N` / `SEV` / `groups · M occurrences`, with a separate line "Dismissed: N groups (M occurrences)".
- Apply the same counts to the Excel summary and the OWASP table. SCA and DAST are unchanged.
- Check `ScanFindingsPanel.tsx` and `ScanFindingsOut` (`routers/scans.py:520-540`) for the same basis, and add `severity_group_counts` if needed.
- Test: 3 TP rows of one construct + 2 FP rows of another should give HIGH = 1 group / 3 occurrences, and dismissed = 1 / 2.

## Part D — Generic rule pack (Java and frontend)

**Principles**
- No project class names.
- Use `frameworks` / `requires_dependency` filters where an idiom belongs to one stack, so a rule never fires on a stack that can't have it.
- Use a zero-width look-ahead for "not followed by" checks, so `matched_text` stays short and groups well.
- Use `group_by_rule: true` where the matched text varies by variable name.
- Every rule ships with `examples: {match, no_match}` (D5).
- "Missing X" absence checks stay with the deep scan (rules/README).

New rules go in `rules/java.json` and `rules/typescript.json`. Add a new `rules/frontend-templates.json` for HTML/Vue templates. The FP-guard prefix `LOGLINE` below means a leading negative look-ahead: `^(?!\s*(?:\w+\.)*(?:log\w*|_?logger|LOG|trace|System\.(?:out|err))\b)`.

### D1. Java: injection (any Java)
| id | CWE/sev | filters | pattern idea | must NOT match |
|---|---|---|---|---|
| `java-sql-string-concat` | 89/HIGH | java | `(?i)LOGLINE.*"[^"]*\b(select\s\|insert\s+into\|update\s\|delete\s+from\|where\s\|order\s+by\|group\s+by\|values\s*\(\|\sand\s\|\sor\s\|like\s)[^"]*"\s*\+\s*[A-Za-z_]` | logger lines; `" = ? "`; `"…" + CONSTANT_NAME` (look-ahead `(?![A-Z_]+\b)`) |
| `java-sql-quote-concat` | 89/HIGH | java | `LOGLINE.*'"\s*\+\s*[a-z_]\w*` on a line containing an SQL keyword | `"Participant id '" + x` in logs |
| `java-jdbc-prepare-concat` | 89/HIGH | java | `\.(prepareStatement\|prepareCall)\(\s*(?:"[^"]*"\s*\+\|[a-z]\w*\s*\+)` | `prepareStatement(sql)` |
| `java-jdbc-statement-exec-variable` | 89/MEDIUM, GBR | java | `\.(executeQuery\|executeUpdate\|execute\|executeLargeUpdate\|addBatch)\(\s*[a-z]\w*\s*\)` | `ps.executeQuery()` |
| `jpa-query-concat` | 89/HIGH | frameworks JPA, JPA (Jakarta), Hibernate ORM, Spring Data | `\.(createQuery\|createNativeQuery\|createSQLQuery)\(\s*(?:"[^"]*"\s*\+\|[a-z]\w*\s*\+)` | `createQuery("… :id")` |
| `spring-jdbctemplate-concat` | 89/HIGH | Spring Framework, Spring Boot | `\b\w*[jJ]dbc\w*\.(query\w*\|update\|execute\|batchUpdate)\(\s*(?:"[^"]*"\s*\+\|[a-z]\w*\s*\+)` | `jdbcTemplate.query(SQL, args…)` |
| `spring-data-query-concat` | 89/HIGH | Spring Data | `@Query\(\s*(?:value\s*=\s*)?"[^"]*"\s*\+` | `@Query("… ?1")` |
| `java-sql-orderby-param` | 89/MEDIUM | java | `(?i)"[^"]*order\s+by\s*"\s*\+\s*[a-z]\w*` | literal column |
| `java-exec-string-concat` | 78/HIGH | java | `\.exec\(\s*(?:"[^"]*"\s*\+\|[a-z]\w*\s*\+)` (any Runtime variable; `java-runtime-exec` only matches `Runtime.getRuntime().exec`) | `exec(new String[]{…})` |
| `java-processbuilder-shell` | 78/HIGH | java | `new ProcessBuilder\(\s*"(?:/bin/)?(?:sh\|bash\|cmd(?:\.exe)?)"\s*,\s*"[-/]c"` | — |
| `spring-spel-parse-variable` | 917/HIGH | Spring | `\.parseExpression\(\s*[a-z]\w*` | `parseExpression("literal")` |
| `java-el-createvalueexpression-variable` | 917/HIGH | Servlet/JSP, JSF | `createValueExpression\([^,]+,\s*[a-z]\w*` | — |
| `java-xpath-concat` | 643/HIGH | java | `\.(compile\|evaluate)\(\s*"[^"]*"\s*\+` on a line mentioning `xpath`/`XPath` | — |
| `java-jndi-lookup-variable` | 74/MEDIUM, GBR | java | `\.lookup\(\s*(?:get\w+\(\)\|[a-z]\w*)\s*\)` | `lookup("java:comp/env/jdbc/x")`, `lookup(CONST)` |
| `java-reflection-invoke-variable` | 470/MEDIUM | java | `\.getMethod\(\s*[a-z]\w*` or `Class\.forName\([^)]*\)\.(getDeclaredConstructor\(\)\.)?newInstance` | `forName("oracle.jdbc…")` |
| `java-template-injection` | 1336/HIGH | java | `new Template\([^,]+,\s*new StringReader\(\s*[a-z]\w*` or `Velocity\.evaluate\(` / `\.process\(\s*[a-z]\w*Template` | — |

### D2. Java: web, authorization, error handling (stack-scoped)
| id | CWE/sev | filters | pattern idea |
|---|---|---|---|
| `java-file-from-request-getter` | 22/HIGH | java | `new\s+(File\|FileInputStream\|FileReader\|FileOutputStream\|RandomAccessFile)\(\s*\w+\.get\w*(File\|Path\|Name\|Dir)\w*\(\)\s*[,)]` and `Paths\.get\(\s*\w+\.get\w*(File\|Path\|Name)\w*\(\)` |
| `java-file-path-concat` (GBR) | 22/MEDIUM | java | `new\s+(File\|FileInputStream\|FileOutputStream\|FileReader\|FileWriter)\(\s*[\w.()]+\s*\+\s*(?:"[/\\]"\|File\.separator)\s*\+\s*\w` |
| `spring-requestparam-to-file` | 22/HIGH | Spring | **[ML]** `@(RequestParam\|PathVariable)[^)]*\)\s*String\s+(\w+)[\s\S]{0,600}?new\s+File\w*\(\s*[^)]*\b\2\b` |
| `jaxrs-param-to-file` | 22/HIGH | JAX-RS family | the same shape with `@(QueryParam\|PathParam\|FormParam)` |
| `spring-requestparam-redirect` | 601/MEDIUM | Spring | `return\s+"redirect:"\s*\+\s*[a-z]\w*` and `new RedirectView\(\s*[a-z]\w*` |
| `jaxrs-exception-message-in-response` | 209/HIGH | JAX-RS family, CXF | `\.(setError\|setMessage\|setErrorMsg\|setDescription\|entity)\(\s*[^;]*\.(getMessage\|getLocalizedMessage\|toString)\(\)` (the Spring rule doesn't cover JAX-RS) |
| `java-exception-object-serialized` | 209/HIGH | java | `\.set(Exception\|Throwable\|Cause\|StackTrace)\(\s*\w+\s*\)` (a DTO carrying a Throwable gets serialized) |
| `spring-responsestatus-exception-message` | 209/MEDIUM | Spring | `new ResponseStatusException\([^;]*\.getMessage\(\)` |
| `java-client-supplied-authz` | 602/HIGH | java | `\.get\w*(Session\|Context\|User)\w*\(\)\.(get\|is)\w*(Permission\|Role\|Admin\|Authorit)\w*\(` on a DTO, or `@RequestBody[^)]*\)\s*\w+\s+\w+[\s\S]{0,400}?\.(isAdmin\|getRole)\(` [ML] |
| `spring-mass-assignment-entity` | 915/MEDIUM | Spring + JPA | **[ML]** `@RequestBody\s+(?:@Valid\s+)?(\w+)\s+\w+` where the same file has `@Entity` (use multiline look-ahead) |
| `spring-cors-wildcard-credentials` | 942/HIGH | Spring | `allowedOrigins\s*=\s*"\*"` / `@CrossOrigin(\s*\)\|\(\s*origins\s*=\s*"\*")` / `allowedOriginPatterns\("\*"\)` with `allowCredentials\(true\)` [ML] |
| `spring-actuator-exposed` | 200/HIGH | properties/yaml | `management\.endpoints\.web\.exposure\.include\s*[:=]\s*["']?\*` |
| `spring-h2-console-enabled` | 489/MEDIUM | properties/yaml | `spring\.h2\.console\.enabled\s*[:=]\s*true` |
| `spring-debug-or-trace-enabled` | 489/LOW | properties/yaml | `^(debug\|trace)\s*[:=]\s*true\|server\.error\.include-stacktrace\s*[:=]\s*always` |
| `spring-security-ignoring-all` | 862/HIGH | Spring Security | `web\.ignoring\(\)\.(antMatchers\|requestMatchers)\(\s*"/\*\*"` |
| `java-plaintext-password-equals` | 256/HIGH | java | `(?i)\b\w*pass(word\|wd)?\w*\s*\.equals\(\s*[\w.]*getPass\w*\(\)\|\.equals\(\s*\w+\.getPass(word)?\(\)\s*\)\|\.password\.equals\(` (not `newPassword.equals(confirm…)`) |
| `java-session-fixation-no-invalidate` | 384/LOW | Servlet | leave to the deep scan (it's an absence check). Document it only. |
| `java-cookie-from-request-value` | 113/MEDIUM | Servlet | `new Cookie\(\s*"[^"]*"\s*,\s*request\.getParameter\(` |
| `java-unvalidated-content-disposition` | 113/MEDIUM | java | `"Content-Disposition"\s*,\s*"[^"]*filename=[^"]*"\s*\+\s*[a-z]\w*` |
| `java-bearer-substring-indexof` | 287/LOW | java | `indexOf\(\s*"Bearer\s?"\s*\)\s*\+\s*7` |
| `java-jwt-parse-unsigned` | 347/HIGH | requires_dependency jjwt / java-jwt | `\.parseClaimsJwt\(\|\.parseUnsecuredClaims\(\|JWT\.decode\(` (decode without verify) |
| `java-jwt-hardcoded-secret` | 798/HIGH | jjwt/java-jwt | `\.(signWith\|setSigningKey\|verifyWith)\([^)]*"[^"]{6,}"\|Algorithm\.HMAC\d+\(\s*"` |

### D3. Java: crypto, secrets, transport, XML, logging, concurrency
| id | CWE/sev | pattern idea |
|---|---|---|
| `java-key-from-password-no-kdf` | 916/HIGH | `Arrays\.copyOf\(\s*[\w.()]+\.getBytes\([^)]*\)\s*,\s*(16\|24\|32)\s*\)` or `new SecretKeySpec\(\s*\w+\.getBytes\(` (a variable, not a literal; the literal case already exists) |
| `java-aes-cbc-unauthenticated` | 327/MEDIUM | `Cipher\.getInstance\(\s*"AES/CBC/` |
| `java-cipher-default-mode` | 327/MEDIUM | `Cipher\.getInstance\(\s*"(AES\|DES\|DESede\|RSA)"\s*\)` (provider default ECB or PKCS1) |
| `java-rsa-no-oaep` | 780/MEDIUM | `Cipher\.getInstance\(\s*"RSA/[^"]*/(PKCS1Padding\|NoPadding)"` |
| `java-weak-key-size` | 326/MEDIUM | `\.initialize\(\s*(512\|768\|1024)\s*\)` / `\.init\(\s*(40\|56\|64)\s*\)` on a generator |
| `java-legacy-base64-or-xor-cipher` | 327/MEDIUM | `\bnew\s+(sun\.misc\.)?BASE64(En\|De)coder\(\|\bnew\s+[\w.]*Xor\w*\(` |
| `java-password-stored-base64` | 261/HIGH | `(?i)setPass\w*\(\s*[^;]*(Base64\|BASE64Encoder\|encodeBase64)` |
| `java-unsalted-hash-password` | 759/HIGH | `(?i)MessageDigest\.getInstance\([^)]*\)[\s\S]{0,200}?pass` [ML] (complements `java-weak-messagedigest`) |
| `java-jdbc-url-inline-credentials` | 798/HIGH | `jdbc:\w+:[^"\s]*(?:\w+/[^@"\s]+@\|[?&;]password=[^&;"\s]+)` |
| `java-hardcoded-credential-field` | 798/HIGH | `(?i)\b(?:pwd\|passwd\|password\|secret\|apikey\|api_key\|token)\w*\s*=\s*"[^"$%{][^"]{2,}"` with `(?<![A-Z_])` so ALL_CAPS constants are skipped, and a look-ahead that skips values equal to the key name. Replaces or narrows `secret-password-assign` (D4). |
| `java-cleartext-protocol-url` | 319/MEDIUM | `"(t3\|telnet\|ftp\|ldap)://` and `"http://(?!localhost\|127\.\|www\.w3\.org\|schemas\.\|xmlns\.\|java\.sun\.com\|xml\.apache)` (skip namespace literals) |
| `java-plain-socket` (GBR) | 319/LOW | `new\s+(java\.net\.)?(Server)?Socket\(` |
| `java-ldap-anonymous-or-simple` | 522/MEDIUM | `Context\.SECURITY_AUTHENTICATION\s*,\s*"(none\|simple)"` |
| `java-jaxb-unmarshal-unhardened` | 611/MEDIUM | `\.unmarshal\(\s*new\s+(InputSource\|StringReader\|FileReader\|StreamSource\|File)\(` |
| `java-xxe-transformerfactory` | 611/MEDIUM | `TransformerFactory\.newInstance\(\)(?![\s\S]{0,300}?ACCESS_EXTERNAL)` [ML] |
| `java-xxe-schemafactory` / `-xmlreader` / `-domparser` | 611/MEDIUM | `SchemaFactory\.newInstance\(`, `XMLReaderFactory\.createXMLReader\(`, `new\s+(org\.apache\.xerces\.parsers\.)?(DOM\|SAX)Parser\(`, each with the same hardening look-ahead |
| `java-xstream-fromxml` | 502/HIGH | `\.fromXML\(` with requires_dependency xstream |
| `java-snakeyaml-unsafe` | 502/HIGH | `new Yaml\(\s*\)` / `new Yaml\(\s*new Constructor\(` (requires_dependency snakeyaml version_lt 2.0) |
| `java-kryo-registration-off` | 502/MEDIUM | `setRegistrationRequired\(\s*false\s*\)` |
| `java-secret-in-log-concat` | 532/HIGH | `(?i)\b(?:log\w*\|_?logger\|LOG\|System\.(?:out\|err))\.\w+\(.*(?:\+\s*\|,\s*)[\w.]*\b(?:get)?(?:pass(?:word\|wd)?\|pwd\|secret\|token\|apikey\|credential)s?\b(?:\(\))?\s*[,)+]` (the keyword is an identifier, not text inside a literal) |
| `java-sql-in-log` (GBR) | 532/LOW | `(?i)\b(log\w*\|_?logger)\.\w+\(.*\+\s*(sql\|query\|sqlstmt\|sqlString)\b` |
| `java-insecure-random-security-context` | 330/HIGH [ML] | `(?i)\b\w*(session\|token\|nonce\|otp\|salt\|password\|secret\|key)\w*\s*\([^)]*\)\s*\{[\s\S]{0,500}?(new\s+(java\.util\.)?Random\(\|Math\.random\(\)\|ThreadLocalRandom)` |
| `java-static-dateformat` (GBR) | 362/LOW | `static\s+(final\s+)?(java\.text\.)?(SimpleDateFormat\|DateFormat)\b` |
| `java-tls-protocol-weak` | 326/MEDIUM | `"(SSLv3\|TLSv1\|TLSv1\.1)"` passed to `getInstance\|setEnabledProtocols` |
| `java-trustmanager-trustall-alt` | 295/HIGH | `getAcceptedIssuers\(\)\s*\{\s*return\s+(null\|new X509Certificate\[0\])` (complements the empty-check rule) |
| `java-cookie-secure-false` | 614/MEDIUM | `\.setSecure\(\s*false\s*\)\|\.setHttpOnly\(\s*false\s*\)` |

### D4. Frontend (Angular, React, Vue, plain JS/jQuery)
Infrastructure:
- Map `.vue` and `.svelte` → `javascript` in `llm_file_scan._EXT_TO_LANG`, and make sure they count as source in categorize and walk.
- Angular templates are `.html`. Template rules use `languages: ["html","javascript","typescript"]`.

| id | CWE/sev | filters | pattern idea | must NOT match |
|---|---|---|---|---|
| `angular-innerhtml-binding` | 79/MEDIUM | Angular | `\[(innerHTML\|outerHTML)\]\s*=\s*"` (template binding) | — |
| `angular-domsanitizer-bypass-variable` | 79/HIGH | Angular | narrow the existing bypass rule to a non-literal argument: `bypassSecurityTrust\w+\(\s*(?!['"\x60])` | literal argument |
| `angular-elementref-nativeelement-html` | 79/HIGH | Angular | `nativeElement\.(innerHTML\|outerHTML\|insertAdjacentHTML)\s*[=(]` |
| `angular-renderer-setproperty-innerhtml` | 79/MEDIUM | Angular | `setProperty\([^,]+,\s*['"]innerHTML['"]` |
| `angular-http-interceptor-token-to-any-url` | 201/LOW | Angular | **[ML]** `implements HttpInterceptor[\s\S]{0,800}?setHeaders[\s\S]{0,200}?Authorization(?![\s\S]{0,400}?(startsWith\|includes\|apiUrl))` |
| `react-dangerously-set-variable` | 79/HIGH | React | `dangerouslySetInnerHTML=\{\{\s*__html:\s*(?!['"\x60])` (narrows the existing rule) |
| `react-href-javascript-or-variable` | 79/MEDIUM | React | `href=\{\s*(?!['"\x60]https?:)[a-z]\w*` / `href=["']javascript:` |
| `react-ref-innerhtml` | 79/HIGH | React | `\.current\.(innerHTML\|outerHTML)\s*=` |
| `vue-v-html` | 79/MEDIUM | Vue.js | `\bv-html\s*=\s*"` |
| `vue-dynamic-component-template` | 94/HIGH | Vue.js | `template:\s*(?!['"\x60])\w+` / `compile\(\s*[a-z]\w*` |
| `jquery-html-sink` | 79/MEDIUM | requires_dependency jquery | `\.(html\|append\|prepend\|after\|before\|replaceWith)\(\s*(?!['"\x60]\s*<?\w*['"\x60]?\s*\))[a-z]\w*` |
| `js-innerhtml-variable` | 79/MEDIUM | js/ts | `\.(innerHTML\|outerHTML)\s*[+]?=\s*(?!\s*['"\x60])` (replaces `innerhtml-assign`; skips a literal right-hand side) | `x = el.innerHTML` (read) |
| `js-insertadjacenthtml` | 79/MEDIUM | js/ts | `\.insertAdjacentHTML\(\s*[^,]+,\s*(?!['"\x60])` |
| `js-function-constructor-or-string-timer` | 95/HIGH | js/ts | `new Function\(\|set(Timeout\|Interval)\(\s*['"\x60]` |
| `js-location-assign-variable` | 601/MEDIUM | js/ts | `(window\.\|document\.)?location(\.href)?\s*=\s*(?!['"\x60]/)[a-z]\w*\|location\.(assign\|replace)\(\s*[a-z]\w*\|window\.open\(\s*[a-z]\w*` |
| `js-postmessage-wildcard` | 345/MEDIUM | js/ts | `\.postMessage\([^)]*,\s*['"]\*['"]` |
| `js-message-listener-no-origin` | 346/MEDIUM | js/ts | **[ML]** `addEventListener\(\s*['"]message['"][\s\S]{0,400}?\}(?<!origin[\s\S]{0,400})` (fall back to the plain listener plus no `.origin` within 400 chars) |
| `js-target-blank-no-noopener` | 1022/LOW | html/js/ts | `target=["']_blank["'](?![^>]*rel=["'][^"']*noopener)` |
| `js-token-in-web-storage` | 922/MEDIUM | js/ts | broaden `token-in-localstorage`: `(local\|session)Storage\.(setItem\(\s*[^,]*\|\[\s*)['"\x60]?\w*(token\|jwt\|auth\|session\|refresh\|bearer\|access\|secret\|password\|service_id)` |
| `js-document-cookie-write` | 1004/LOW | js/ts | `document\.cookie\s*=` (client-set cookies can't be HttpOnly) |
| `js-hardcoded-http-endpoint` | 319/MEDIUM | js/ts | `['"\x60]http://(?!localhost\|127\.0\.0\.1\|www\.w3\.org)[\w.-]+` (skip localhost and namespaces) |
| `js-hardcoded-api-key` | 798/HIGH | js/ts | `(?i)(api[_-]?key\|client[_-]?secret\|secret[_-]?key\|access[_-]?token)\s*[:=]\s*['"\x60][A-Za-z0-9_\-]{16,}` plus vendor prefixes `AIza[0-9A-Za-z_-]{35}`, `sk_live_`, `ghp_`, `xox[baprs]-` |
| `js-console-log-sensitive` | 532/LOW | js/ts | `console\.(log\|debug\|info)\([^)]*\b(token\|password\|jwt\|secret\|authorization)\b` |
| `angular-debug-logger` | 532/LOW | Angular | `NgxLoggerLevel\.(DEBUG\|TRACE\|LOG)\|enableProdMode` absent is not regexable, so skip that half |
| `js-prototype-pollution-merge` | 1321/MEDIUM | js/ts | `(Object\.assign\|_\.merge\|_\.defaultsDeep\|\$\.extend\(\s*true)\([^)]*(JSON\.parse\|req\.body\|params)` |
| `js-jwt-decode-trust` | 345/LOW | js/ts | `jwt_decode\(\|jwtDecode\(` followed by `\.(role\|isAdmin\|permissions)` within 200 chars [ML] (authorization decided on the client) |
| `js-regex-dos-user-input` | 1333/LOW | js/ts | `new RegExp\(\s*(?:req\.\|this\.\w*[iI]nput\|\w*[sS]earch\w*)` (narrows `js-non-literal-regexp`) |
| `html-inline-event-handler-template` | 79/LOW | html | `\son\w+\s*=\s*["'][^"']*\{\{` (an interpolated value inside an inline handler) |
| `html-form-autocomplete-sensitive` | — | — | already covered by `password-input-missing-autocomplete` |
| `js-npm-insecure-registry` | 829/LOW | json/npmrc | `"resolved":\s*"http://` / `registry\s*=\s*http://` |

### D5. Changes to existing rules (fewer false positives)
- `innerhtml-assign`: replaced by `js-innerhtml-variable`. `dangerously-set-html` and `angular-bypass-security-trust`: narrow them to a non-literal argument and keep the ids, so persisted findings still resolve.
- `secret-password-assign`: skip ALL_CAPS constants, property-key-name values (`TRUST_STORE_PWD = "TrustStorePassword"`), and empty placeholders (`""`, `"changeme"` stays flagged).
- `java-xxe-documentbuilder`, `java-xxe-sax-factory`, `java-xxe-xmlinputfactory`: add a bounded look-ahead `(?![\s\S]{0,400}?(disallow-doctype-decl\|FEATURE_SECURE_PROCESSING\|SUPPORT_DTD\|IS_SUPPORTING_EXTERNAL_ENTITIES))`. This switches them to multiline mode, which needs D6's finditer change.
- `java-sensitive-data-in-logs`: retire it in favour of `java-secret-in-log-concat`, which skips the keyword when it only appears inside a literal. Keep the id as an alias so old persisted findings still resolve.
- `java-insecure-cookie`: fire only when the file has no `setSecure(true)`/`setHttpOnly(true)` within 300 chars (look-ahead).
- `java-runtime-exec`: keep it. `java-exec-string-concat` adds the concatenated-argument case with HIGH confidence.
- `surfaces.json`:
  - Add a **"SQL injection (JDBC/JPA/Spring Data)"** surface with all the D1 SQL rules, triggered by `languages: ["java"]`. The current "SQL injection via JDBC" surface only lists `java-sql-error-detail-exposed`.
  - Add a **"Frontend DOM XSS and client trust"** surface (Angular/React/Vue.js/jQuery).
  - Extend the crypto, XXE, logging and REST surfaces with the new ids.

### D6. Engine and test support
- **`examples` field.** Add optional `examples: {match: [...], no_match: [...]}` (with an optional `path` to pick the language) to `RegexRule` in `pipeline/regex_scan.py`; it is ignored at scan time. Add a test in `tests/test_rule_catalog.py` that runs every shipped rule's examples through the real scan path (line or multiline, comment masking, framework filter). Also fail when a shipped pattern doesn't compile, since `load_rules` skips those silently today. Optionally require at least 1 example per new rule.
- **Multiline rules return only the first match per file** (`regex_scan.py`, around line 184). Switch to `finditer` with a per-rule cap (25 per file) and compute line numbers from offsets.
- **Block-comment masking.** Verify that lines inside `/* … */` are masked for line rules, and fix it if they aren't. Commented-out SQL is common in legacy Java.
- **Derived-rule ranking.** This scan dropped 244 derived candidates as `over_cap`. Rank derive candidates by sink severity (SQL, command, deserialization, file, then the rest) before the cap, so project-specific wrappers like `selectCount(String)` win slots. That covers repo-specific SQL wrappers without hand-written rules.
- **Docs.** `rules/README.md`: document `examples`, the LOGLINE guard idiom, and the frontend template languages.

## Part E — Run independent stages in parallel instead of in sequence

**Today:**
- *Within* each stage, work already runs in parallel:
  - deep scan: 8 file workers × 3 chunk workers (`llm_file_scan.DEFAULT_FILE_WORKERS`/`DEFAULT_CHUNK_WORKERS`)
  - group-confirm: parallel batches
  - rg prefilter: a thread pool
- *Between* stages, everything is serial. The LangGraph graph is a single chain of 15 nodes (`sast_scan_agent.py:2680-2696`).
- Triage batches (one per module) run one after another, so the worker pool drains to empty at every batch boundary.

Parallelism lowers **wall time, not tokens**. Token savings come from B and D. The risks are Bedrock throttling and overshooting the cutoff, so E3 covers those.

**E1. Fan out the graph after `derive_runtime_rules`.** Ordering constraints:
- The deep-scan system prompt and the triage catalog both embed the derived rules, so derive must finish first.

```
scan_directory → analyze_tech_stack → categorize_files → map_modules_and_risk
   ├─ build_joern_cpg ─┐   (CPU/IO, runs alongside the call graph)
   └─ build_call_graph ┴→ derive_runtime_rules
        ├─ discover_flows → verify_flow_slices   (LLM)
        ├─ scan_deep_files                        (LLM)
        ├─ scan_triage_files [regex pass]         (local CPU)
        └─ joern_scan                             (local, then its own group confirm)
   join → group_triage_findings → confirm_triage_groups → generate_report
```

- Implement this with LangGraph parallel edges (several `add_edge` calls from one node plus a join node). Any state key written by more than one branch needs an `Annotated[..., reducer]` in the `TypedDict` (around `sast_scan_agent.py:385`). The shared `usage` dict and `findings_writer` are mutated in place, so they need thread safety (E3).
- Put this behind a flag, `state["parallel_stages"]`, default on for API scans. The CLI gets `--sequential` for debugging. With the flag off, the graph is today's chain, so tests can pin either mode.

**E2. Flatten the triage batches into one pool.** In `node_scan_triage_files`, submit every file from every module to a single `ThreadPoolExecutor`, while still logging each module's "Batch i/N done" line once that module's last file finishes. That removes the idle tail at each batch boundary. The regex pass is CPU-bound under the GIL: keep the rg prefilter, and run the catalog over files with a `ProcessPoolExecutor` (with a chunk size) only when the file count exceeds about 500. Results must be identical either way; test that.

**E3. Safety rails needed before turning parallelism on.**
- **Shared usage and budget:** guard the `usage` dict updates in `llm_client` with a lock. Use atomic per-stage reservations: each stage reserves its share of `LLM_COST_CUTOFF_USD` up front, for example deep 55%, flows 10%, triage/confirm 35%, and returns unused budget to a shared pool when it finishes. This replaces "first come, first served", which is how per-file triage used up the budget in this scan.
- **Bedrock throttling:** add one process-wide semaphore around `call_llm` (`LLM_MAX_CONCURRENCY`, default 8, per-project override). On `ThrottlingException`, back off exponentially with jitter and lower the concurrency on the fly. Without this, 3 parallel LLM stages × 8 workers = 24 requests in flight, which will get throttled on Haiku.
- **Prompt-cache warm gate:** `_warm_gate_for` is already keyed per (model, system prompt), so each parallel stage warms its own cache entry. No change needed; keep the test.
- **Logs and progress:** parallel stages interleave log lines. Tag each line with its stage (`AgentTrace` already knows the step) and keep emitting the existing `### ` banners once per stage. In `scan_progress.PROGRESS_MARKERS`, report progress as the sum of per-stage weights instead of "last banner seen". Change `frontend/lib/parseScanLog.ts` to route lines into section cards by stage tag instead of by position after a banner, and keep the positional fallback for persisted logs.
- **DB writes:** `findings_writer` / `verdict_updates_writer` (`scan_runner._make_*_writer`) each open their own session per call, or serialize through a lock. SQLite in particular needs one writer at a time.

**E4. Parallel implementation work (dev side).** Parts B/C/D/E touch mostly separate files and can be built on separate branches or worktrees at the same time:
- Agent 1: D rules + `regex_scan` examples/finditer + `test_rule_catalog`
- Agent 2: C export counts + frontend panel
- Agent 3: B1–B5 engine routing
- Agent 4: E graph fan-out and safety rails

Merge order: D → C → B → E. Then run the full `pytest` and the live NPG re-run.

## Part 0 — Save the plan in the repo
On approval, the first step is to write this plan to `docs/plans/sast-accuracy-token-efficiency.md` (create `docs/plans/`), so the team can review it with the code.

## Files to change
- `backend/sast_engine/rules/java.json`, `typescript.json`, `common.json`, `web.json`, new `frontend-templates.json`, `surfaces.json`, `README.md`
- `backend/sast_engine/pipeline/regex_scan.py` (examples, multiline finditer, comment masking), `pipeline/llm_file_scan.py` (`.vue`/`.svelte` mapping, test-path skip, B5 grouping), `pipeline/call_graph.py` (`_is_test_path`), `pipeline/derive_rules.py` (ranking)
- `backend/sast_engine/sast_scan_agent.py` (B2 risk rules, B3 re-rank)
- `backend/app/defaults/scan_limitations.py` (B1, test-files entry), `backend/app/services/scan_export.py` (C), `frontend/components/ScanFindingsPanel.tsx` (C, if needed)
- Tests: `test_rule_catalog.py`, `test_scan_limitations.py`, `test_sast_scan_agent.py`, `test_llm_file_scan.py`, `test_scan_export*.py`
- `CLAUDE.md` / `backend/sast_engine/README.md`
- E: `sast_scan_agent.py` (graph edges, state reducers, `parallel_stages`, flattened triage pool), `pipeline/llm_client.py` (usage lock, concurrency semaphore, throttle backoff, stage reservations), `app/services/scan_runner.py` (thread-safe writers), `app/services/scan_progress.py`, `frontend/lib/parseScanLog.ts`
- New: `docs/plans/sast-accuracy-token-efficiency.md`

## Verification
1. `cd backend && pytest` (mock engine, offline). The new catalog test runs every rule's match/no_match examples.
2. **Corpus check across stacks.** Run the regex-only CLI (`sast_scan_agent.py --triage-mode regex_only`, no LLM) against:
   - NPG (legacy JDBC/EJB/JAX-RS/Angular). Required hits:
     - `RequestsMgr.java:13455` (SQL concat)
     - `ListLicense.java:47` (prepare concat)
     - `HisClean.java:498` (exec concat)
     - `ReportsService.java:403` (file from getter)
     - `AESGCMEncrypter.java:25` (key without KDF)
     - `TelnetClient.java:100` (secret in log)
     - `ChangePasswordService.java:68` (plaintext equals)
     - `SecurityMgrImpl.java:757` (Random session id)
     - `HandleException.java:33` (message in response)
     - `ChangePasswordService.java:274` (client authz)
     - `custom-file-input.js:23` (innerHTML variable)
     - `environment.ts:9` (http endpoint)
   - At least one Spring Boot + JPA repo and one React or Vue repo (for example OWASP WebGoat, the Juice Shop frontend, or a vulnerable Vue app) to confirm the stack-scoped rules fire there and stay silent on NPG.

   Record hits per rule. Any rule above about 300 hits on one repo, or one that hits a listed safe look-alike, gets tightened before merge.
3. Parallel mode:
   - Run the mock-engine suite with `parallel_stages` on and off. Findings and report totals must be identical.
   - Unit-test that the stage reservations never exceed the cutoff in total, with simulated concurrent `call_llm`.
   - Unit-test that a simulated `ThrottlingException` triggers backoff.
   - Test that the flattened triage pool gives the same hits as sequential batches.
4. Live re-run on NPG (scope `NPGParent`, `force: true`). Also compare wall-clock time against the sequential baseline. Compare with the baseline:
   - cost ≤ $2, with the deep scan and group-confirm getting the budget
   - about 100 files deep-scanned, REST and SOAP among them
   - `unverified` near 0 (was 1,084)
   - no Simulators/test findings
   - the PDF strip shows actionable groups with occurrence counts
   - spot-check 20 true positives for precision

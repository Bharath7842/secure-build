# Security review of the DAST safety controls (DAST-16-060)

Written for: the maintainers who will sign off the release, and anyone changing the guard, the validator, credential handling or the audit trail.

| | |
|---|---|
| Scope | The request guard, the non-destructive input validator, credential handling, the request audit trail, the export writers, and the model-driven test loop's exposure to hostile target content |
| Method | Adversarial tests against an in-process hostile target (`backend/tests/dast_fixtures/hostile.py`) and a deliberately compromised model; every attack below is a regression test in `backend/tests/test_dast_security_review.py` |
| Result | **11 defects found and fixed, 8 risks accepted** (listed with owners) |
| Not done here | Sign-off. Accepting residual risk is a human decision; the sign-off block at the end is unsigned. A live pass against a real browser and real network (DNS, redirects, TLS) has not been run |

Everything the tests do is offline: an httpx mock transport stands in for the network, so no socket is opened and the results do not depend on the machine.

## What was attacked, and what held

| Attack class | Attempts | Outcome |
|---|---|---|
| **Scope bypass by URL form** | 41 denied spellings: look-alike hosts (`target.test.evil.test`, `evil-target.test`), userinfo (`target.test@evil.test`, `%40`, `%2f@`), backslash and tab/CR/LF/NUL smuggling, IPv6 and IPv4-mapped literals, decimal/hex/octal/short IPv4, cloud metadata address, bad ports, `file:`/`ftp:`/`gopher:`/`data:`/`javascript:` schemes, scheme-relative and `http:///`, IDN homographs and punycode, fragment/query tricks, doubled dots and ports | All denied as `off_scope`. Ordinary spellings of the authorized host (case, trailing dot, explicit port, `..` paths) are allowed |
| **Scope bypass in root-domain mode** | Tenants of shared hosting (`evil.github.io` for target `bar.github.io`, `herokuapp.com`, `vercel.app`, `azurewebsites.net`), `co.uk` siblings, IPs, single-label hosts | **Defect F1, fixed** (below); everything else held |
| **Redirects** | Off-scope, look-alike, scheme-relative, userinfo, `[::1]`, `file:`, loops, an in-scope redirect | Each off-scope hop is denied, audited (`off_scope`) and never sent; a loop stops after the redirect bound; an in-scope redirect is followed |
| **DNS rebinding** | The guard compares host *names* | **Accepted risk R1** |
| **Method gate bypass** | 15 method spellings (case, padding, CRLF, zero-width), `TRACE`/`CONNECT`/WebDAV verbs, a POST inside the login window to another host, a forged GraphQL-introspection POST, method-override headers and parameters, a marker POST outside its window, a marker POST whose body is not this scan's marker, a marker POST to logout | All denied, except the three documented exceptions (login POST inside its window, a pure introspection query, and a marker POST inside its window when marker submits are enabled, the body is that scan's marker, and the URL is in scope and not logout, delete or payment). Override headers and parameters were **Defect F5, fixed** |
| **Validator evasion** | 56 encoded, split, obfuscated and tool-specific destructive inputs (case, Unicode and fullwidth forms, zero-width characters, URL/HTML/`\u` escapes, base64, SQL block and line comments, MySQL conditional comments, `${IFS}` and quote tricks, `find -delete`, fork bombs, pipes into a shell, JNDI lookups, protocol-smuggling schemes) and 14 harmless detection canaries | **Defects F2, F3, F4 fixed**; the rest were already rejected; every canary (`1'`, `' OR '1'='1`, a timing canary, a script tag, a traversal read, an out-of-band callback address) is still accepted |
| **Validator cost** | 100 KB and 60 K-repetition adversarial strings | Under 1.5 s each |
| **Prompt injection from target content** | A hostile page and API responses carrying "ignore all previous instructions" text, off-host links, and a *fully compromised* model that obeys it (proposes `DROP TABLE`, a method-override header, `_method=DELETE`, a `Host:` header, a URL for the target to fetch, `x \| sh`, an unknown check id, and an unconditional CRITICAL FAIL) | **Defect F6 found** (the target could be made to fetch an arbitrary URL), fixed. After the fix: zero requests to any host but the target, zero non-GET methods, none of the forbidden strings in any request, every rejected input counted and logged without its text, and the model's "critical FAIL" produced no confirmed finding (a confirmed finding needs a detector signal) |
| **Credential leakage** | A token sent to a target that echoes it back in a JSON body, an error page and an audit-visible header; a model that repeats it in its own reply | **Defects F8, F9, F10 fixed**. After the fix the token appears in none of: finding rows, evidence, audit rows, the stored discovery, the scan log, narration prompts, or any model prompt |
| **Audit completeness** | Every request the target received versus the audit rows; refusals | One allowed audit row per request that reached the target (redirect hops included); every refusal has a row with its reason; audit rows hold redacted header values and no bodies |
| **Hostile and oversized responses** | A 6 MB body, binary content labelled JSON, 5000-deep JSON, 20 KB headers, a 5000-attribute cookie, ReDoS-shaped bodies for every detector and passive pattern | Bounded body kept (64 KB; the true size is still reported), all patterns finish well inside a second. **Defect F7 fixed** |
| **Formula injection in exports** | `=`, `+`, `-`, `@`, leading tab in titles, evidence and reasons | Stored as text and quote-prefixed; no formula element is written (covered in `test_dast_reporting.py`) |

## Defects found and fixed

| # | Defect | Impact | Fix |
|---|---|---|---|
| F1 | Root-domain mode used the public-suffix list without its private section, so `evil.github.io` counted as the same site as `bar.github.io` | A scan of one tenant of a shared-hosting platform could wander onto any other tenant | `safety_guard._EXTRACT` now includes private suffixes |
| F2 | The validator did not join tokens across a SQL line comment (`DROP --`⏎`TABLE users`, `DROP #`⏎`TABLE users`) | A destructive statement slipped through | Decoded views now include a form with line and block comments removed |
| F3 | No rule for `find … -delete/-exec`, fork bombs, or input piped into a shell or interpreter | Destructive or host-exhausting shell input accepted | New rules `shell-fork-bomb`, `shell-pipe-to-interpreter`; `find` added to the delete rule |
| F4 | No rule for `${jndi:…}` (including obfuscated forms) or for `gopher:`/`dict:`/`ldap:`/`rmi:`/`tftp:`/`smb:` schemes | An input could make the target load code from, or speak a smuggled protocol to, another host | New rules `jndi-lookup`, `smuggling-scheme` |
| F5 | Method-override headers (`X-HTTP-Method-Override`, …) and parameters (`_method`, …) were allowed as test inputs | A GET could become a DELETE on frameworks that honour them, past the method gate | Refused by the parameter gate, in any location |
| F6 | An input could be an arbitrary absolute URL | A compromised model could make the *target* call any host, internal addresses and cloud metadata included | New `foreign-host` rule: an input may name only the target host or the configured out-of-band host (the active stage supplies both; encoded, base64 and protocol-relative forms are checked) |
| F7 | `redact_body` recursed without bound, so deeply nested JSON raised `RecursionError` | The recorder dropped that exchange silently, hiding it from discovery and passive analysis | Depth-limited redaction; a body that cannot be parsed is redacted as plain text |
| F8 | The preflight's root response reached passive analysis without the scan's secrets being applied | A target echoing the token in an error page leaked it into evidence | `run_passive` redacts every stored text with the scan's secrets |
| F9 | The model's own words (finding text, reason, evidence) were stored as written | A model that repeats a credential would store it | Redacted with the scan's secrets before they are stored |
| F10 | SSRF findings were built without the scan's secrets | Same as F9 | `run_ssrf` takes and applies them |
| F11 | Parameter names went into the model prompt uncapped | Prompt stuffing from a hostile schema | Names capped at 60 characters |

## Accepted risks (each needs an owner to confirm)

| # | Risk | Why it is accepted for now | Mitigation in place | Owner |
|---|---|---|---|---|
| R1 | **DNS rebinding.** Scope is by host name; the resolved address is not checked, so an authorized name that rebinds to an internal address would be reached | Pinning the resolved address needs a connection-level hook in the HTTP client and is a larger change | Run the scanner where internal networks and the cloud metadata address are unreachable; a literal internal address is always off-scope | Platform security (to be named) |
| R2 | **The login-window POST.** While an identity signs in, any in-scope POST is allowed (the login submit cannot be told apart from, say, an analytics beacon) | Form login cannot work without it | The window is short, scoped to the scan's own identity login, in-scope only, POST only, and fully audited | DAST maintainers |
| R3 | **The validator is a deny-list.** A creative encoding or an application-specific destructive verb can still pass | No deny-list is complete | Safe mode, scope and the disposable-target requirement are the real backstops; the list is data and grows with each review | DAST maintainers |
| R4 | **Inputs split across parameters.** Each input is validated alone; a target that concatenates two parameters server-side could assemble something neither contains | Out of reach of a per-input check | Same backstops as R3; safe mode blocks the writes that would make it matter | DAST maintainers |
| R5 | **Training-data scrubbing is pattern-based.** A hostname on an unlisted TLD, a personal name or an unusual identifier may survive | A perfect scrubber needs target-specific knowledge | The scan's own hosts and secrets are replaced exactly first; capture is off by default, opt-in per project, reads need a second token and are audited; the dataset should be reviewed before it leaves the team | Data owner of the project that opts in |
| R6 | **One shared training admin token**, no per-user roles | The platform has no user model | Reads and enabling are audited by the reader name the caller supplies; rotate the token on departures | Platform security (to be named) |
| R7 | **Authorization checks cannot tell public from protected.** A page that is public by design looks like a missing check | Intent is not observable from outside | Well-known public paths and pages Anonymous was seen reaching are skipped; findings are labelled with the role pair and evidence for a person to confirm | DAST maintainers |
| R8 | **The marker-window POST.** While one stored-XSS probe is submitted, an in-scope POST is allowed when its body is exactly this scan's marker template. Companion fields the page itself added (a CSRF token) are allowed if they are at most 512 characters and contain no markup. Browser probes are not rate-limited by the guard | Stored XSS cannot be tested without writing the marker. The login window (R2) allows any in-scope POST; this window allows only a marker body | Off unless the setting is on and the target is disposable. The input gate still rejects a marker that matches the deny-list. Logout, delete and payment URLs are refused. A per-scan cap (the opt-in request ceiling) bounds how many submits land. Every request is audited. Probes pause between themselves and stop at the page and per-page input caps. Residual: a short, markup-free companion field added by the page is submitted with the marker, and the guard does not pace the browser's own requests | DAST maintainers |

## Things the review confirmed are *not* a problem

- `true_positive` always carries a detector signal, however the model answers (also property-tested over 250 random scenarios in `test_dast_determinism.py`).
- The OAST poll is the one request that bypasses the scope check; it uses its own client, is audited under `check_id = oast-poll`, and never carries the scan's credentials.
- Credentials exist only in the in-memory holder; a restart fails the scan rather than continuing without them.

## Re-running the review

```bash
cd backend && pytest tests/test_dast_security_review.py tests/test_dast_input_validation.py tests/test_dast_safety_guard.py -q
```

Add a case to `EVASIONS` / `DENIED_URLS` / `FOREIGN` whenever a new bypass is thought of; a case that fails is a defect to fix before release.

## Sign-off

| Reviewer | Decision on the accepted risks R1 to R8 | Date |
|---|---|---|
| (unsigned) | (accept / reject / fix first) | |

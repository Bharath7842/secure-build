"""Coverage for the rule catalog machinery in pipeline/regex_scan.py — the
directory loader, dependency/version conditions, and the stack->surface map.

These are the pieces that decide *which* patterns run against a repo, so a
silent regression here shows up as "scanned, found nothing" rather than as a
failure. Everything is offline; no LLM is involved anywhere in this module.
"""

import json
from pathlib import Path

import pytest

pytest.importorskip("langgraph")

from app.config import settings  # noqa: E402
from app.services.agent_bridge import _load_agent_module  # noqa: E402

_ENGINE_DIR = Path(__file__).resolve().parents[1] / "sast_engine"
_RULES_DIR = _ENGINE_DIR / "rules"


@pytest.fixture()
def agent(monkeypatch):
    import sys

    monkeypatch.setattr(settings, "sast_framework_path", str(_ENGINE_DIR))
    sys.modules.pop("sast_scan_agent", None)
    return _load_agent_module()


@pytest.fixture()
def regex_scan(agent):
    import sys

    return sys.modules["pipeline.regex_scan"]


def _rule(**overrides):
    base = {
        "id": "r1", "title": "t", "description": "d", "cwe": "CWE-1",
        "severity": "HIGH", "category": "code", "owasp": "A03:2021-Injection",
        "languages": [], "frameworks": [], "pattern": "needle",
    }
    base.update(overrides)
    return base


# --- the shipped catalog -----------------------------------------------------

def test_shipped_catalog_loads_with_unique_ids_and_valid_patterns(regex_scan):
    """Guards the hand-written JSON: every rule compiles, ids are unique, and
    every rule carries the metadata the prompt and OWASP rollup depend on."""
    rules = regex_scan.load_rules(_RULES_DIR)
    assert len(rules) > 80
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids))
    for rule in rules:
        assert rule.pattern and rule.regex is not None
        assert rule.owasp, f"{rule.id} has no OWASP label"
        assert rule.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        assert rule.category in {"code", "secrets", "dependency"}


def _shipped_rule_entries():
    for path in sorted(_RULES_DIR.glob("*.json")):
        if path.name == "surfaces.json":
            continue
        for entry in json.loads(path.read_text(encoding="utf-8")):
            yield path.name, entry


def test_every_shipped_pattern_compiles():
    """load_rules skips a pattern that fails to compile so one bad entry
    can't block a scan — which also means a typo silently drops a rule. The
    shipped catalog must have none."""
    import re

    bad = []
    for fname, entry in _shipped_rule_entries():
        try:
            re.compile(entry["pattern"])
        except re.error as exc:
            bad.append(f"{fname}:{entry['id']}: {exc}")
    assert bad == []


# Rules that predate the `examples` field. Every other rule must ship at least
# one match example — don't add to this list.
_LEGACY_RULES_WITHOUT_EXAMPLES = frozenset({
    'auth-exception-message-concat', 'castor-unmarshaller-untrusted',
    'clickjacking-frameoptions-disabled', 'cors-allow-origin-reflect',
    'cors-wildcard-with-credentials', 'corsfilter-reflect-origin', 'csrf-disabled',
    'custom-account-status-grants-auth', 'debug-enabled', 'drools-rule-external-load',
    'entire-file-block-commented', 'eval-call', 'exec-call', 'http-trace-webxml',
    'java-class-forname', 'java-config-default-credential', 'java-deskeyspec',
    'java-empty-catch-block', 'java-empty-trust-check', 'java-hardcoded-local-endpoint',
    'java-header-from-request', 'java-insecure-random-security', 'java-jackson-default-typing',
    'java-ldap-injection', 'java-log-injection-unsanitized-input', 'java-objectinputstream',
    'java-open-redirect', 'java-path-file-constructor', 'java-printstacktrace',
    'java-processbuilder-concat', 'java-runtime-exec', 'java-scriptengine-eval',
    'java-secretkeyspec-string-literal', 'java-session-never-expires',
    'java-sql-error-detail-exposed', 'java-sslcontext-ssl', 'java-ssrf-url-request',
    'java-static-iv-from-key', 'java-stdout-debug-print', 'java-trust-all-hostname',
    'java-upload-extension-only-check', 'java-weak-cipher-des', 'java-weak-cipher-ecb',
    'java-weak-messagedigest', 'java-weak-pbe-md5-des', 'java-xmldecoder', 'java-xss-jsp-servlet',
    'jaxrs-container-response-cors', 'jaxrs-exception-in-response-entity', 'jaxrs-path-sensitive',
    'jaxrs-permit-all', 'js-document-write', 'js-outerhtml-assign',
    'jsch-stricthostkeychecking-disabled', 'jsp-raw-request-expression', 'jwt-none-alg',
    'logger-exception-tostring', 'maven-known-eol-artifact', 'maven-snapshot-version', 'md5-hash',
    'npm-deprecated-package', 'os-system', 'password-input-missing-autocomplete', 'pickle-loads',
    'python-ssl-verify-false', 'resteasy-corsfilter-allowed-origins-star', 'secret-api-key-token',
    'secret-aws-key', 'secret-bearer-token', 'secret-config-unquoted', 'secret-private-key-pem',
    'sensitive-endpoint-permit-all', 'serializable-missing-svuid',
    'servlet-cors-allow-origin-star', 'servlet-corsfilter-class', 'spring-any-request-permit-all',
    'spring-exception-message-in-response-body', 'spring-sensitive-url-permit-all',
    'ssrf-endpoint-from-config-property', 'struts-formfile-upload-handling', 'subprocess-shell',
    'webxml-cors-filter-name', 'webxml-filter-class-cors', 'webxml-sensitive-url-pattern',
    'webxml-wildcard-url-pattern', 'xml-axis2-admin-surface-exposed',
    'xml-session-timeout-excessive', 'xml-transport-guarantee-none', 'yaml-unsafe-load',
})


def test_new_rules_ship_examples(regex_scan):
    missing = sorted(
        r.id for r in regex_scan.load_rules(_RULES_DIR)
        if not r.examples.get("match") and r.id not in _LEGACY_RULES_WITHOUT_EXAMPLES
    )
    assert missing == [], "add examples.match (and ideally no_match) to these rules"


def _example_cases(regex_scan):
    from pipeline.llm_file_scan import lang_for_path

    for rule in regex_scan.load_rules(_RULES_DIR):
        for kind in ("match", "no_match"):
            for ex in rule.examples.get(kind, []):
                code, path = (ex["code"], ex.get("path")) if isinstance(ex, dict) else (ex, None)
                lang = lang_for_path(path) if path else (rule.languages[0] if rule.languages else None)
                yield rule, kind, code, lang


def test_rule_examples_through_the_real_scan_path(regex_scan):
    """Each rule's examples run exactly as triage runs them: line or
    multiline mode, comment masking for the example's language, and the
    rule's own language/framework filter."""
    failures = []
    for rule, kind, code, lang in _example_cases(regex_scan):
        assert rule.applies_to(lang, set(rule.frameworks), None), f"{rule.id}: example language {lang!r} is filtered out"
        mask = regex_scan._comment_line_mask(code, lang)
        hits = regex_scan.scan_text_by_rule(code, rule, comment_lines=mask)
        if (kind == "match") != bool(hits):
            failures.append(f"{rule.id} [{kind}]: {code!r}")
    assert failures == []


def test_multiline_rules_report_every_match_up_to_the_cap(regex_scan):
    rule = regex_scan.RegexRule(_rule(pattern=r"open\((?=[\s\S]{0,20}?close)"))
    text = "\n".join(["open(a); close(a);", "x", "open(b); close(b);"])
    assert [h["line"] for h in regex_scan.scan_text_by_rule(text, rule)] == [1, 3]

    many = "\n".join("open(x); close(x);" for _ in range(40))
    hits = regex_scan.scan_text_by_rule(many, rule)
    assert len(hits) == regex_scan.MULTILINE_HITS_PER_FILE_CAP


def test_multiline_hit_starting_in_a_comment_is_masked(regex_scan):
    rule = regex_scan.RegexRule(_rule(pattern=r"open\((?=[\s\S]{0,40}?close)"))
    text = "\n".join(["// open(a);", "close(a);", "open(b);", "close(b);"])
    mask = regex_scan._comment_line_mask(text, "java")
    assert [h["line"] for h in regex_scan.scan_text_by_rule(text, rule, comment_lines=mask)] == [3]


def test_rule_group_by_rule_defaults_false_and_is_settable(regex_scan):
    default_rule = regex_scan.RegexRule(_rule())
    assert default_rule.group_by_rule is False

    opted_in = regex_scan.RegexRule(_rule(group_by_rule=True))
    assert opted_in.group_by_rule is True


def test_serializable_missing_svuid_rule_opts_into_group_by_rule(regex_scan):
    """Regression guard: this rule's matched text always differs (it captures
    the class declaration, so the class name varies per occurrence) while
    every hit describes the same issue — group_by_rule must stay set so the
    report collapses them into one row instead of one per class."""
    rules = regex_scan.load_rules(_RULES_DIR)
    rule = next(r for r in rules if r.id == "serializable-missing-svuid")
    assert rule.group_by_rule is True


def test_serializable_missing_svuid_pattern_matches_class_declaration_only(regex_scan):
    """The pattern uses a zero-width lookahead for 'no serialVersionUID within
    250 chars', not a consuming quantifier — so matched_text stays the short
    class declaration instead of swallowing ~250 chars of unrelated trailing
    code (which used to make every occurrence's matched_text unique)."""
    rules = regex_scan.load_rules(_RULES_DIR)
    rule = next(r for r in rules if r.id == "serializable-missing-svuid")

    source = (
        "class Foo implements Serializable {\n"
        "    private String name;\n"
        "    private int age;\n"
        "    public String getName() { return name; }\n"
        "}\n"
    )
    match = rule.regex.search(source)
    assert match is not None
    assert match.group(0) == "class Foo implements Serializable"
    assert "getName" not in match.group(0)  # trailing class body not consumed


@pytest.mark.parametrize("rule_id", ["logger-exception-tostring", "java-path-file-constructor"])
def test_group_by_rule_opted_in_for_variable_capturing_rules(regex_scan, rule_id):
    """These rules capture a variable/keyword name into matched_text (the
    exception variable, the path variable), which would otherwise vary per
    occurrence and defeat (rule_id, matched_text) grouping — same shape of bug
    serializable-missing-svuid had, fixed here by collapsing on rule_id alone
    instead of rewriting the pattern."""
    rules = regex_scan.load_rules(_RULES_DIR)
    rule = next(r for r in rules if r.id == rule_id)
    assert rule.group_by_rule is True


def test_sensitive_data_in_logs_stays_ungrouped(regex_scan):
    """Unlike the toString()/file-path cases, which sensitive keyword matched
    (password vs ssn vs token vs ...) is security-relevant, not cosmetic — this
    rule must keep grouping by (rule_id, matched_text), not collapse by rule_id
    alone."""
    rules = regex_scan.load_rules(_RULES_DIR)
    rule = next(r for r in rules if r.id == "java-sensitive-data-in-logs")
    assert rule.group_by_rule is False


def test_spring_exception_message_in_response_body_matches_the_gitlab_caught_idiom(regex_scan):
    """Regression guard for the gap GitLab's taint-flow SAST caught and ours
    missed: an exception message reflected directly into a Spring ResponseEntity
    body/ok() call is the exact idiom behind several real reflected-XSS findings
    on a target repo our regex-only catalog (JAX-RS-scoped
    jaxrs-exception-in-response-entity) couldn't match."""
    rules = regex_scan.load_rules(_RULES_DIR)
    rule = next(r for r in rules if r.id == "spring-exception-message-in-response-body")
    assert rule.cwe == "CWE-79"
    assert "Spring Boot" in rule.frameworks

    hit = rule.regex.search(
        "return ResponseEntity.badRequest().body(ex.getMessage());"
    )
    assert hit is not None

    hit_ok = rule.regex.search("return ResponseEntity.ok(ex.getMessage());")
    assert hit_ok is not None

    # A response body built from a literal/constant, not an exception message,
    # must not match.
    assert rule.regex.search('return ResponseEntity.ok("done");') is None


def test_spring_exception_message_in_response_body_matches_variable_indirection(regex_scan):
    """The single most common GlobalExceptionHandler/@ControllerAdvice idiom is
    assigning ex.getMessage() to a local variable before returning it, not
    passing it inline — the original pattern only matched the inline form."""
    rules = regex_scan.load_rules(_RULES_DIR)
    rule = next(r for r in rules if r.id == "spring-exception-message-in-response-body")

    hit = rule.regex.search(
        "String msg = ex.getMessage();\n"
        "return ResponseEntity.status(500).body(msg);"
    )
    assert hit is not None

    # Still must not fire on an unrelated getMessage() far from any response body.
    assert rule.regex.search("String msg = ex.getMessage();\nlog.info(msg);") is None


def test_csrf_disabled_matches_multiline_lambda_dsl(regex_scan):
    """Spring Security 6's lambda DSL (.csrf(csrf -> csrf.disable())) is
    routinely formatter-wrapped across lines; the old single-line-only pattern
    silently missed that wrapped form."""
    rules = regex_scan.load_rules(_RULES_DIR)
    rule = next(r for r in rules if r.id == "csrf-disabled")

    single_line = rule.regex.search("http.csrf().disable();")
    assert single_line is not None

    single_line_lambda = rule.regex.search(
        "http.csrf(AbstractHttpConfigurer::disable);"
    )
    assert single_line_lambda is not None

    multi_line_lambda = rule.regex.search(
        "http.csrf(csrf ->\n    csrf.disable()\n);"
    )
    assert multi_line_lambda is not None

    # A csrf(...) call that configures (not disables) protection must not match.
    assert rule.regex.search(
        "http.csrf(csrf -> csrf.csrfTokenRepository(repo()));"
    ) is None


def test_java_log_injection_unsanitized_input_matches_exception_and_request_data(regex_scan):
    rules = regex_scan.load_rules(_RULES_DIR)
    rule = next(r for r in rules if r.id == "java-log-injection-unsanitized-input")
    assert rule.cwe == "CWE-117"

    exception_hit = rule.regex.search('log.error("failed: {}", ex.getMessage());')
    assert exception_hit is not None

    request_hit = rule.regex.search(
        'log.warn("bad input: " + request.getParameter("x"));'
    )
    assert request_hit is not None

    header_hit = rule.regex.search("logger.info(request.getHeader(\"X-Forwarded-For\"));")
    assert header_hit is not None

    # Literal-only log content must not match.
    assert rule.regex.search('log.info("startup complete");') is None


def test_java_log_injection_matches_multi_arg_parameterized_logging_and_request_uri(regex_scan):
    """Regression guard: a real @RestControllerAdvice handler logging
    log.warn("... {}: {}", request.getRequestURI(), ex.getMessage()) was
    missed entirely — request.getRequestURI() has its own closing paren
    earlier in the same call, and the rule's old [^)]* prefix couldn't cross
    it to reach .getMessage() later in the argument list. Also verifies
    getRequestURI()/getRequestURL()/getQueryString() are recognized sources,
    not just getParameter()/getHeader()."""
    rules = regex_scan.load_rules(_RULES_DIR)
    rule = next(r for r in rules if r.id == "java-log-injection-unsanitized-input")

    multi_arg_hit = rule.regex.search(
        'log.warn("Validation failed at {}: {}", request.getRequestURI(), ex.getMessage());'
    )
    assert multi_arg_hit is not None

    uri_only_hit = rule.regex.search(
        'log.error("Error at " + request.getRequestURI(), ex);'
    )
    assert uri_only_hit is not None

    query_string_hit = rule.regex.search(
        'logger.debug("Query: " + request.getQueryString());'
    )
    assert query_string_hit is not None


def test_spring_exception_message_matches_dto_setter_returned_via_constructor(regex_scan):
    """Regression guard: the common GlobalExceptionHandler idiom builds a DTO
    via a builder/setter (error.message(ex.getMessage())) and returns it via
    `new ResponseEntity<>(error, status)` — the constructor form, never
    .body()/.ok(). The original pattern only recognized the fluent-builder
    form and missed this entirely."""
    rules = regex_scan.load_rules(_RULES_DIR)
    rule = next(r for r in rules if r.id == "spring-exception-message-in-response-body")

    builder_hit = rule.regex.search(
        "ErrorResponse error = ErrorResponse.builder()\n"
        "    .message(ex.getMessage())\n"
        "    .build();\n"
        "return new ResponseEntity<>(error, HttpStatus.BAD_REQUEST);"
    )
    assert builder_hit is not None

    setter_hit = rule.regex.search(
        "ErrorResponse error = new ErrorResponse();\n"
        "error.setMessage(fieldError.getDefaultMessage());\n"
        "return new ResponseEntity<>(error, HttpStatus.BAD_REQUEST);"
    )
    assert setter_hit is not None


def test_serializable_missing_svuid_pattern_skips_when_svuid_present(regex_scan):
    rules = regex_scan.load_rules(_RULES_DIR)
    rule = next(r for r in rules if r.id == "serializable-missing-svuid")

    source = (
        "class Foo implements Serializable {\n"
        "    private static final long serialVersionUID = 1L;\n"
        "}\n"
    )
    assert rule.regex.search(source) is None


def test_every_surface_references_a_real_rule(regex_scan):
    """A typo in surfaces.json would silently drop that rule from the prompt
    priority set rather than erroring, so assert the ids resolve."""
    rules = {r.id for r in regex_scan.load_rules(_RULES_DIR)}
    surfaces = regex_scan.load_surfaces(_RULES_DIR)
    assert surfaces
    dangling = {
        (s.surface, rid) for s in surfaces for rid in s.rules if rid not in rules
    }
    assert not dangling, f"surfaces reference unknown rule ids: {sorted(dangling)}"


# --- directory loader --------------------------------------------------------

def test_load_rules_merges_directory_and_ignores_surfaces(tmp_path, regex_scan):
    (tmp_path / "a.json").write_text(json.dumps([_rule(id="a1")]), encoding="utf-8")
    (tmp_path / "b.json").write_text(json.dumps([_rule(id="b1"), _rule(id="b2")]), encoding="utf-8")
    # surfaces.json is not a rule array — the loader must skip it, not choke.
    (tmp_path / "surfaces.json").write_text(
        json.dumps([{"surface": "s", "when": {}, "rules": ["a1"]}]), encoding="utf-8"
    )
    rules = regex_scan.load_rules(tmp_path)
    assert {r.id for r in rules} == {"a1", "b1", "b2"}


def test_load_rules_still_accepts_a_single_file(tmp_path, regex_scan):
    path = tmp_path / "only.json"
    path.write_text(json.dumps([_rule(id="solo")]), encoding="utf-8")
    assert [r.id for r in regex_scan.load_rules(path)] == ["solo"]


def test_load_rules_rejects_duplicate_ids_across_files(tmp_path, regex_scan):
    """Triage looks rules up by id, so a collision would shadow one rule with
    another — that has to be loud."""
    (tmp_path / "a.json").write_text(json.dumps([_rule(id="dupe")]), encoding="utf-8")
    (tmp_path / "b.json").write_text(json.dumps([_rule(id="dupe")]), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate rule id"):
        regex_scan.load_rules(tmp_path)


def test_load_rules_skips_uncompilable_pattern_but_keeps_the_rest(tmp_path, regex_scan):
    (tmp_path / "a.json").write_text(
        json.dumps([_rule(id="bad", pattern="([unclosed"), _rule(id="good")]), encoding="utf-8"
    )
    assert [r.id for r in regex_scan.load_rules(tmp_path)] == ["good"]


def test_load_rules_raises_on_empty_directory(tmp_path, regex_scan):
    with pytest.raises(FileNotFoundError):
        regex_scan.load_rules(tmp_path)


# --- version parsing ---------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("3.2", (3, 2)),
    ("3.2.2", (3, 2, 2)),
    ("6.0.0.Final", (6, 0, 0)),   # trailing qualifier carries no digits
    ("1.3.10", (1, 3, 10)),
    ("^2.88.0", (2, 88, 0)),
    ("0.1.38", (0, 1, 38)),
])
def test_parse_version_handles_qualifiers_and_ranges(regex_scan, raw, expected):
    assert regex_scan.parse_version(raw) == expected


@pytest.mark.parametrize("raw", [None, "", "${spring.version}", "RELEASE"])
def test_parse_version_returns_none_when_nothing_numeric(regex_scan, raw):
    assert regex_scan.parse_version(raw) is None


# --- dependency conditions ---------------------------------------------------

def _dep_summary(*deps):
    return {"declared_dependencies": [{"name": n, "version": v} for n, v in deps]}


def test_dependency_index_covers_declared_not_just_frameworks(regex_scan):
    """commons-collections is not a framework, so it never appears under
    `frameworks` — indexing only those would make the whole gadget-chain
    condition dead on arrival."""
    index = regex_scan.build_dependency_index(
        _dep_summary(("commons-collections:commons-collections", "3.2"))
    )
    # indexed under both the full coordinate and the bare artifact id
    assert index["commons-collections:commons-collections"] == ["3.2"]
    assert index["commons-collections"] == ["3.2"]


def test_dependency_index_folds_in_framework_matches(regex_scan):
    summary = {"frameworks": [{"matched_dependencies": [
        {"name": "org.apache.struts:struts-core", "version": "1.3.10"},
    ]}]}
    index = regex_scan.build_dependency_index(summary)
    assert index["struts-core"] == ["1.3.10"]


def test_rule_without_condition_is_unaffected(regex_scan):
    rule = regex_scan.RegexRule(_rule())
    assert rule.applies_to(None, set(), {}) is True


def test_rule_fires_when_vulnerable_version_declared(regex_scan):
    rule = regex_scan.RegexRule(_rule(
        requires_dependency=[{"name": "commons-collections", "version_lt": "3.2.2"}]
    ))
    index = regex_scan.build_dependency_index(_dep_summary(("commons-collections", "3.2")))
    assert rule.applies_to(None, set(), index) is True


def test_rule_is_skipped_when_patched_version_declared(regex_scan):
    rule = regex_scan.RegexRule(_rule(
        requires_dependency=[{"name": "commons-collections", "version_lt": "3.2.2"}]
    ))
    index = regex_scan.build_dependency_index(_dep_summary(("commons-collections", "3.2.2")))
    assert rule.applies_to(None, set(), index) is False


def test_rule_is_skipped_when_dependency_absent(regex_scan):
    rule = regex_scan.RegexRule(_rule(requires_dependency=[{"name": "jsch"}]))
    index = regex_scan.build_dependency_index(_dep_summary(("guava", "33.0")))
    assert rule.applies_to(None, set(), index) is False


@pytest.mark.parametrize("version", [None, "", "${jsch.version}"])
def test_unknown_version_fails_open(regex_scan, version):
    """A missing or unresolved version must never be what silently disables a
    security rule — we would rather report against an unknown version."""
    rule = regex_scan.RegexRule(_rule(
        requires_dependency=[{"name": "commons-collections", "version_lt": "3.2.2"}]
    ))
    index = regex_scan.build_dependency_index(_dep_summary(("commons-collections", version)))
    assert rule.applies_to(None, set(), index) is True


def test_no_dependency_data_never_excludes_a_rule(regex_scan):
    """dependency_index=None means "we don't know what's declared", which is
    different from "it isn't declared"."""
    rule = regex_scan.RegexRule(_rule(
        requires_dependency=[{"name": "commons-collections", "version_lt": "3.2.2"}]
    ))
    assert rule.applies_to(None, set(), None) is True


# --- surfaces ----------------------------------------------------------------

def test_surface_activates_on_framework_match(regex_scan):
    s = regex_scan.Surface({"surface": "SOAP", "when": {"frameworks": ["Apache Axis2 SOAP"]},
                            "rules": ["java-xxe-xmlinputfactory"], "rationale": "r"})
    assert s.is_active(active_frameworks={"Apache Axis2 SOAP"}) is True
    assert s.is_active(active_frameworks={"Spring Boot"}) is False


def test_surface_activates_on_dependency_version(regex_scan):
    s = regex_scan.Surface({
        "surface": "gadget", "rules": ["java-objectinputstream"], "rationale": "r",
        "when": {"dependencies": [{"name": "commons-collections", "version_lt": "3.2.2"}]},
    })
    vulnerable = regex_scan.build_dependency_index(_dep_summary(("commons-collections", "3.2")))
    patched = regex_scan.build_dependency_index(_dep_summary(("commons-collections", "3.2.2")))
    assert s.is_active(dependency_index=vulnerable) is True
    assert s.is_active(dependency_index=patched) is False


def test_surface_with_no_when_clause_is_always_active(regex_scan):
    s = regex_scan.Surface({"surface": "secrets", "when": {}, "rules": ["secret-aws-key"], "rationale": "r"})
    assert s.is_active() is True


def test_surfaces_never_reduce_the_applicable_rule_set(regex_scan):
    """Surfaces reorder the prompt catalog; they must not gate execution. A
    project matching no surface at all still gets every applicable rule."""
    rules = regex_scan.load_rules(_RULES_DIR)
    without = regex_scan.rules_for_prompt(rules, "java", set(), max_rules=1000)
    with_priority = regex_scan.rules_for_prompt(
        rules, "java", set(), max_rules=1000,
        priority_rule_ids={"java-printstacktrace"},
    )
    assert {r["id"] for r in without} == {r["id"] for r in with_priority}


def test_priority_rule_ids_survive_catalog_truncation(regex_scan):
    """The point of surface prioritisation: when the catalog is trimmed it is
    the stack-relevant guidance that stays, not just whatever ranked highest
    by severity."""
    rules = regex_scan.load_rules(_RULES_DIR)
    # a deliberately low-severity rule that would be truncated on severity alone
    catalog = regex_scan.rules_for_prompt(
        rules, "java", set(), max_rules=3,
        priority_rule_ids={"java-stdout-debug-print"},
    )
    assert "java-stdout-debug-print" in {r["id"] for r in catalog}


def test_active_surfaces_filters_by_language(regex_scan):
    surfaces = regex_scan.load_surfaces(_RULES_DIR)
    python_only = regex_scan.active_surfaces(surfaces, languages={"python"})
    names = {s.surface for s in python_only}
    assert "Python injection sinks" in names
    assert "SQL injection (JDBC/JPA/Spring Data)" not in names


# --- comment-line masking ----------------------------------------------------

def test_comment_mask_skips_full_line_java_comments_but_keeps_live_code(regex_scan):
    """The NPG false positive: a hit inside a //-commented-out block. The same
    file's uncommented assignment must still be reported."""
    rule = regex_scan.RegexRule(_rule(
        id="secret-password-assign",
        pattern=r'(?i)(password|pwd|passwd)\s*=\s*["\'][^"\']{3,}["\']',
    ))
    text = "\n".join([
        "class SecurityMgr {",
        "    // if (legacy) {",
        "    //     String password = \"commented\";",
        "    // }",
        "    String password = \"hunter2\";",
        "}",
    ])
    hits = regex_scan.scan_text(text, [rule], file_lang="java")
    assert [h["line"] for h in hits] == [5]


def test_comment_mask_skips_java_block_comment_body(regex_scan):
    rule = regex_scan.RegexRule(_rule(
        id="secret-password-assign",
        pattern=r'(?i)(password|pwd|passwd)\s*=\s*["\'][^"\']{3,}["\']',
    ))
    text = "\n".join([
        "class Foo {",
        "    /*",
        "    String password = \"dead\";",
        "    */",
        "    String password = \"hunter2\";",
        "}",
    ])
    hits = regex_scan.scan_text(text, [rule], file_lang="java")
    assert [h["line"] for h in hits] == [5]


def test_comment_mask_does_not_hide_code_with_trailing_comment(regex_scan):
    """Conservative: a mixed code+comment line is never masked."""
    rule = regex_scan.RegexRule(_rule(
        id="secret-password-assign",
        pattern=r'(?i)(password|pwd|passwd)\s*=\s*["\'][^"\']{3,}["\']',
    ))
    text = '    String password = "hunter2"; // ignore me'
    hits = regex_scan.scan_text(text, [rule], file_lang="java")
    assert [h["line"] for h in hits] == [1]


def test_comment_mask_is_off_when_file_lang_is_omitted(regex_scan):
    """Callers that don't pass file_lang keep the old unmasked behaviour."""
    rule = regex_scan.RegexRule(_rule(
        id="secret-password-assign",
        pattern=r'(?i)(password|pwd|passwd)\s*=\s*["\'][^"\']{3,}["\']',
    ))
    text = '// String password = "commented";'
    hits = regex_scan.scan_text(text, [rule])
    assert len(hits) == 1


def test_scan_comments_rule_is_never_masked(regex_scan):
    """entire-file-block-commented matches a comment by design, so it opts
    out of the comment mask with scan_comments."""
    rule = next(
        r for r in regex_scan.load_rules(_RULES_DIR)
        if r.id == "entire-file-block-commented"
    )
    text = "/*\nclass Dead {}\n*/\n"
    hits = regex_scan.scan_text(text, [rule], file_lang="java")
    assert len(hits) == 1


# --- secret-password-assign lookbehind --------------------------------------

def test_secret_password_assign_skips_url_password_keeps_camelcase(regex_scan):
    """URL_PASSWORD / PATH_ / ROUTE_ name a route, not a secret. camelCase
    identifiers like userPassword are the real hardcoded-secret style and
    must still match — a leading \\b would drop them."""
    rule = next(
        r for r in regex_scan.load_rules(_RULES_DIR) if r.id == "secret-password-assign"
    )
    ts = "\n".join([
        "export const URL_PASSWORD = 'changepassword';",
        "export const PATH_PASSWORD = 'reset';",
        "export const ROUTE_PASSWORD = 'login';",
        'const userPassword = "hunter2";',
        'const dbPassword = "s3cret";',
    ])
    hits = regex_scan.scan_text(ts, [rule], file_lang="typescript")
    assert [h["line"] for h in hits] == [4, 5]


# --- JSP/servlet XSS gated on the servlet signature -------------------------

def test_jsp_xss_rules_do_not_fire_without_servlet_framework(regex_scan):
    """A SOAP client (or any plain Java class) must not match these rules
    just because .java and .jsp share the `java` language tag. They fire
    only when the repo actually declared a servlet/JSP dependency."""
    rules = {r.id: r for r in regex_scan.load_rules(_RULES_DIR)}
    xss = rules["java-xss-jsp-servlet"]
    raw = rules["jsp-raw-request-expression"]
    assert xss.frameworks == ["Java Servlet/JSP"]
    assert raw.frameworks == ["Java Servlet/JSP"]

    java = 'out.println(request.getParameter("q"));\n<%= request.getParameter("q") %>\n'
    assert regex_scan.scan_text(java, [xss, raw], file_lang="java", active_frameworks=set()) == []

    hits = regex_scan.scan_text(
        java, [xss, raw], file_lang="java",
        active_frameworks={"Java Servlet/JSP"},
    )
    assert {h["rule"] for h in hits} == {"java-xss-jsp-servlet", "jsp-raw-request-expression"}

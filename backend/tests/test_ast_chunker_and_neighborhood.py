"""Phase 1 context engineering: declaration-boundary chunking with a pinned
class header (`ast_chunker`), whole-method windows and resolved callee /
constant context in grouped confirmation, and the repository security summary
in a web entry point's deep scan (`neighborhood`)."""

import json
import re
import sys
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("boto3", reason="pipeline modules import llm_client")

_ENGINE = Path(__file__).resolve().parents[1] / "sast_engine"
if str(_ENGINE) not in sys.path:
    sys.path.insert(0, str(_ENGINE))

from pipeline import ast_chunker  # noqa: E402
from pipeline import call_graph as cg  # noqa: E402
from pipeline import llm_file_scan as lfs  # noqa: E402
from pipeline import neighborhood  # noqa: E402
from pipeline import occurrence_facts as of  # noqa: E402
from pipeline import sql_semantics as sq  # noqa: E402
from pipeline.regex_scan import load_rules  # noqa: E402
from pipeline.validators import VALIDATOR_CONTEXT_USAGE_KEY, ValidatorContext  # noqa: E402

pytestmark = pytest.mark.unit


def _write(root: Path, rel: str, text: str) -> str:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return rel


# --- AST chunking --------------------------------------------------------------

def _big_controller(methods: int = 70, giant_body_lines: int = 0) -> str:
    out = [
        "package com.acme.web;",
        "",
        "import org.springframework.web.bind.annotation.*;",
        "",
        "/** Orders. */",
        "@RestController",
        '@RequestMapping("/api/orders")',
        "@PreAuthorize(\"hasRole('USER')\")",
        "public class OrderController {",
        "",
        "    private final OrderService orders;",
        "    private final AuditLog audit;",
        "",
    ]
    for i in range(methods):
        out += [
            f"    /** Handler {i}. */",
            f'    @GetMapping("/m{i}")',
            f"    public String m{i}(@RequestParam String id) {{",
        ]
        out += [f"        String v{k} = orders.lookup(id, {k}); // padding padding padding" for k in range(12)]
        out += ["        return v0;", "    }", ""]
    if giant_body_lines:
        out += ["    public String giant(String id) {"]
        out += [f"        String g{k} = orders.lookup(id, {k}); // padding padding padding padding" for k in range(giant_body_lines)]
        out += ["        return g0;", "    }"]
    out.append("}")
    return "\n".join(out) + "\n"


def _method_spans(text: str):
    lines = text.splitlines()
    spans = []
    for n, line in enumerate(lines, start=1):
        if re.match(r"\s+/\*\* Handler \d+", line):
            end = n
            while lines[end - 1] != "    }":
                end += 1
            spans.append((n, end))
    return spans


def test_oversized_java_class_is_cut_only_between_methods_with_a_pinned_header():
    text = _big_controller()
    assert len(text) > lfs.SINGLE_CALL_CHAR_BUDGET
    chunks = lfs.chunk_file(text, "java", "src/main/java/com/acme/web/OrderController.java")
    assert len(chunks) > 1

    # Contiguous, complete coverage, no overlap between clean cuts.
    assert chunks[0]["start_line"] == 1
    assert chunks[-1]["end_line"] == len(text.splitlines())
    for before, after in zip(chunks, chunks[1:]):
        assert after["start_line"] == before["end_line"] + 1
    assert all(len(c["text"]) <= lfs.SINGLE_CALL_CHAR_BUDGET for c in chunks)

    # Every method, with its doc comment and annotations, sits in one chunk.
    for start, end in _method_spans(text):
        assert any(c["start_line"] <= start and end <= c["end_line"] for c in chunks), (start, end)

    assert "class_header" not in chunks[0]
    lines = text.splitlines()
    for chunk in chunks[1:]:
        header = chunk["class_header"]
        assert '@RequestMapping("/api/orders")' in header
        assert "@PreAuthorize" in header
        assert "public class OrderController {" in header
        assert "private final OrderService orders;" in header
        # True line numbers, none of them inside the chunk.
        for n in chunk["class_header_lines"]:
            assert f"{n}: {lines[n - 1].rstrip()}" in header
            assert not chunk["start_line"] <= n <= chunk["end_line"]


def test_a_method_larger_than_the_budget_is_windowed_with_overlap():
    text = _big_controller(methods=2, giant_body_lines=600)
    chunks = lfs.chunk_file(text, "java", "OrderController.java")
    assert len(chunks) > 2
    assert chunks[-1]["end_line"] == len(text.splitlines())
    giant = [c for c in chunks if "g10 = " in c["text"] or "g400 = " in c["text"]]
    # Windows inside the giant method overlap, like the line-window splitter.
    assert any(b["start_line"] <= a["end_line"] for a, b in zip(chunks, chunks[1:]))
    assert len(giant) >= 2
    assert all("public class OrderController {" in c["class_header"] for c in giant)


def test_jsp_and_unknown_languages_keep_the_line_window_splitter():
    text = _big_controller()
    jsp = lfs.chunk_file(text, "java", "web/page.jsp")
    assert all("class_header" not in c for c in jsp)
    assert any(b["start_line"] <= a["end_line"] for a, b in zip(jsp, jsp[1:]))
    assert ast_chunker.ast_lang_for("a.tsx", "typescript") is None
    assert ast_chunker.ast_lang_for(None, "typescript") == "typescript"


def test_typescript_class_keeps_decorated_members_whole():
    members = []
    for i in range(80):
        members += [
            f"  /** handler {i} */",
            f"  @HostListener('click{i}')",
            f"  onClick{i}(event: Event): void {{",
        ] + [f"    this.items.push(this.render(event, {k}, 'padding padding padding'));" for k in range(6)] + ["  }", ""]
    text = "\n".join(
        ["@Component({ selector: 'app-x', templateUrl: './x.html' })",
         "export class XComponent {", "  @Input() name: string;", ""] + members + ["}"]
    ) + "\n"
    chunks = lfs.chunk_file(text, "typescript", "src/app/x.component.ts")
    assert len(chunks) > 1
    lines = text.splitlines()
    for n, line in enumerate(lines, start=1):
        if line.strip().startswith("/** handler"):
            holder = [c for c in chunks if c["start_line"] <= n <= c["end_line"]]
            assert len(holder) == 1 and holder[0]["end_line"] >= n + 9
    assert all("@Component" in c["class_header"] and "@Input() name" in c["class_header"] for c in chunks[1:])


def test_deep_scan_prompt_of_a_later_chunk_carries_the_class_header(tmp_path):
    rel = _write(tmp_path, "src/main/java/com/acme/web/OrderController.java", _big_controller())
    prompts = []

    def fake_llm(system, user, **kwargs):
        prompts.append(user)
        return '{"findings": []}'

    lfs.scan_file(
        repo_root=tmp_path, rel_path=rel, rules=load_rules(_ENGINE / "rules"),
        call_llm_fn=fake_llm, chunk_workers=1,
    )
    assert len(prompts) > 1
    assert "Enclosing class declaration and fields" not in prompts[0]
    later = prompts[1]  # chunk_workers=1: prompts arrive in chunk order
    assert "Enclosing class declaration and fields" in later
    assert '@RequestMapping("/api/orders")' in later.split("Code under review")[0]


# --- grouped confirmation windows ----------------------------------------------

def _java_method(name: str, guard: bool, filler: int = 0) -> str:
    body = ["        if (!Validator.isSafe(sql)) {", "            throw new IllegalArgumentException();", "        }"] if guard \
        else ["        log.debug(sql);", "        audit(sql);", "        count++;"]
    return "\n".join(
        ["package com.acme;", "", "public class " + name + " {", "    private int count;",
         "    public void run(java.sql.Statement stmt, String sql) throws Exception {"]
        + body
        + [f"        int pad{k} = {k};" for k in range(filler)]
        + ["        String a = sql;", "        String b = a;", "        String c = b;", "        String d = c;",
           "        stmt.execute(d);", "    }", "}"]
    ) + "\n"


def _member_for(root: Path, rel: str) -> dict:
    text = (root / rel).read_text()
    line = next(n for n, l in enumerate(text.splitlines(), start=1) if "stmt.execute(d)" in l)
    facts = of.facts_for(rel, text, line)
    assert facts is not None and facts.get("enclosing")
    return {
        "rule_id": "java-jdbc-statement-exec-variable", "title": "SQL", "severity": "HIGH",
        "cwe": "CWE-89", "line": line, "matched_text": "stmt.execute(d)", "verdict": "unverified",
        "file_path": rel, "facts": dict(facts), "kind": "regex",
    }


def _entry(root: Path, members, ctx=None):
    return {
        "group_index": 0, "members": members, "rule": None,
        "text_for": lambda p: (root / p).read_text() if p else "", "explain": False, "context": ctx,
    }


def test_member_window_is_the_whole_enclosing_method_and_separates_guarded_code(tmp_path):
    _write(tmp_path, "A.java", _java_method("A", guard=True))
    _write(tmp_path, "B.java", _java_method("B", guard=False))
    _write(tmp_path, "C.java", _java_method("C", guard=False))
    members = [_member_for(tmp_path, p) for p in ("A.java", "B.java", "C.java")]
    entry = _entry(tmp_path, members)

    lo, hi, _lines = lfs._member_window(entry, 0)
    enclosing = members[0]["facts"]["enclosing"]
    assert (lo, hi) == (enclosing["start_line"], enclosing["end_line"])

    # The guard is 6 lines above the sink, outside a ±4 window: only the
    # whole-method window tells A apart from B. B and C are identical code.
    variants = lfs._variant_of(entry)
    assert variants[0] == [0]
    assert variants[1] == [1, 2]

    _system, user = lfs.build_group_confirm_prompt(entry=entry, shown=[0, 1])
    assert "Validator.isSafe(sql)" in user


def test_long_method_window_is_bounded_and_pins_the_signature(tmp_path):
    _write(tmp_path, "L.java", _java_method("L", guard=True, filler=60))
    member = _member_for(tmp_path, "L.java")
    entry = _entry(tmp_path, [member])
    lo, hi, _lines = lfs._member_window(entry, 0)
    line = member["line"]
    assert (lo, hi) == (line - lfs.GROUP_CONFIRM_LONG_METHOD_BEFORE, min(member["facts"]["enclosing"]["end_line"], line + 6))
    signature = lfs._signature_line(entry, 0)
    assert "public void run(" in (tmp_path / "L.java").read_text().splitlines()[signature - 1]

    _system, user = lfs.build_group_confirm_prompt(entry=entry, shown=[0])
    block = user.split(f"--- L.java lines {lo}-{hi} ---\n", 1)[1]
    assert block.startswith(f"{signature}:     public void run(")
    assert block.splitlines()[1] == "…"


def test_two_matches_in_one_method_are_not_one_variant(tmp_path):
    rel = _write(tmp_path, "T.java", "\n".join([
        "public class T {", "    void run(java.sql.Statement s, String a) throws Exception {",
        "        s.execute(a);", "        s.execute(a);", "    }", "}"]) + "\n")
    text = (tmp_path / rel).read_text()
    members = []
    for line in (3, 4):
        members.append({"rule_id": "r", "line": line, "matched_text": "s.execute(a)", "file_path": rel,
                        "facts": dict(of.facts_for(rel, text, line))})
    assert lfs._variant_of(_entry(tmp_path, members)) == {0: [0], 1: [1]}


# --- callee / constant neighborhood --------------------------------------------

_CONTROLLER = """package com.acme.web;

import com.acme.util.Sanitizer;
import com.acme.db.Queries;

public class UserController {
    private java.sql.Connection conn;

    public void find(String name) throws Exception {
        String safe = Sanitizer.clean(name);
        java.sql.Statement stmt = conn.createStatement();
        stmt.execute(Queries.FIND_USER + safe);
    }
}
"""

_SANITIZER = """package com.acme.util;

public class Sanitizer {
    public static String clean(String raw) {
        if (raw == null) {
            return "";
        }
        return raw.replaceAll("[^A-Za-z0-9]", "");
    }
}
"""

_QUERIES = """package com.acme.db;

public final class Queries {
    public static final String FIND_USER = "SELECT * FROM users WHERE name = ";
}
"""


def _neighborhood_repo(tmp_path):
    paths = [
        _write(tmp_path, "src/main/java/com/acme/web/UserController.java", _CONTROLLER),
        _write(tmp_path, "src/main/java/com/acme/util/Sanitizer.java", _SANITIZER),
        _write(tmp_path, "src/main/java/com/acme/db/Queries.java", _QUERIES),
    ]
    graph = cg.build_call_graph(tmp_path, paths)
    ctx = ValidatorContext(repo_root=tmp_path, call_graph=graph)
    ctx.sql = sq.SqlSummaries(graph, ctx.read_text)
    rel = paths[0]
    text = (tmp_path / rel).read_text()
    line = next(n for n, l in enumerate(text.splitlines(), start=1) if "stmt.execute" in l)
    member = {
        "rule_id": "java-jdbc-statement-exec-variable", "title": "SQL", "severity": "HIGH",
        "cwe": "CWE-89", "line": line, "matched_text": "stmt.execute(Queries.FIND_USER + safe)",
        "verdict": "unverified", "unresolved_reason": "not_reviewed_regex", "kind": "regex",
        "file_path": rel, "facts": dict(of.facts_for(rel, text, line)),
        "owasp_category": "A03:2021-Injection",
    }
    return ctx, member


def test_neighborhood_resolves_callee_bodies_and_cross_file_constants(tmp_path):
    ctx, member = _neighborhood_repo(tmp_path)
    block = neighborhood.member_neighborhood([("m1", member)], ctx)
    assert block.startswith("Neighborhood context")
    assert "Callee Sanitizer.clean (called by m1 at line 10)" in block
    assert 'return raw.replaceAll("[^A-Za-z0-9]", "");' in block
    assert "src/main/java/com/acme/util/Sanitizer.java lines 4-9" in block
    assert 'Constant Queries.FIND_USER (used by m1) = "SELECT * FROM users WHERE name = "' in block

    # Without a call graph or SQL summaries there is nothing to add.
    assert neighborhood.member_neighborhood([("m1", member)], ValidatorContext(repo_root=tmp_path)) == ""
    assert neighborhood.member_neighborhood([("m1", member)], None) == ""


def test_group_confirmation_prompt_carries_the_neighborhood(tmp_path):
    ctx, member = _neighborhood_repo(tmp_path)
    prompts = []

    def fake_llm(system, user, **kwargs):
        prompts.append(user)
        return json.dumps({"decisions": [{"group_index": 0, "member": "m1", "verdict": "true_positive",
                                          "confidence": 0.9, "verdict_reason": "concatenated"}]})

    lfs.group_confirm_unverified_findings(
        file_results=[{"file_path": member["file_path"], "findings": [member]}],
        repo_root=tmp_path, rules=load_rules(_ENGINE / "rules"), call_llm_fn=fake_llm,
        group_workers=1, usage={VALIDATOR_CONTEXT_USAGE_KEY: ctx}, occurrence_validators=False,
    )
    assert prompts and "Callee Sanitizer.clean" in prompts[0]
    assert "Constant Queries.FIND_USER" in prompts[0]


# --- repository security summary -----------------------------------------------

_SECURITY_CONFIG = """package com.acme.config;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/public/**").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated());
        return http.build();
    }
}
"""

_WEB_XML = """<web-app>
  <!-- <security-constraint><url-pattern>/commented/*</url-pattern></security-constraint> -->
  <security-constraint>
    <web-resource-collection>
      <url-pattern>/secure/*</url-pattern>
      <http-method>POST</http-method>
    </web-resource-collection>
    <auth-constraint><role-name>manager</role-name></auth-constraint>
    <user-data-constraint><transport-guarantee>CONFIDENTIAL</transport-guarantee></user-data-constraint>
  </security-constraint>
  <filter-mapping>
    <filter-name>jwtAuthFilter</filter-name>
    <url-pattern>/api/*</url-pattern>
  </filter-mapping>
  <filter-mapping>
    <filter-name>encodingFilter</filter-name>
    <url-pattern>/*</url-pattern>
  </filter-mapping>
</web-app>
"""

_ROUTING = """const routes: Routes = [
  { path: 'home', component: HomeComponent },
  {
    path: 'admin',
    component: AdminComponent,
    canActivate: [AuthGuard],
  },
];
"""

_USER_API = """package com.acme.web;

@RestController
@RequestMapping("/api/admin/users")
public class UserApi {
    @DeleteMapping("/{id}")
    public void delete(@PathVariable String id) { }
}
"""


def _security_repo(tmp_path):
    _write(tmp_path, "src/main/java/com/acme/config/SecurityConfig.java", _SECURITY_CONFIG)
    _write(tmp_path, "src/main/webapp/WEB-INF/web.xml", _WEB_XML)
    _write(tmp_path, "web/src/app/app-routing.module.ts", _ROUTING)
    _write(tmp_path, "src/main/java/com/acme/web/UserApi.java", _USER_API)
    _write(tmp_path, "src/main/java/com/acme/util/Strings.java", "package com.acme.util;\npublic class Strings { }\n")
    _write(tmp_path, "src/test/java/com/acme/TestSecurityConfig.java",
           '@EnableWebSecurity class TestSecurityConfig { void c() { http.requestMatchers("/test/**").permitAll(); } }\n')


def test_security_entries_read_spring_chain_web_xml_and_route_guards(tmp_path):
    _security_repo(tmp_path)
    entries = neighborhood.security_entries(tmp_path)
    text = "\n".join(f"{p}:{n}: {t}" for p, n, t in entries)
    assert 'SecurityConfig.java:12: .requestMatchers("/api/admin/**").hasRole("ADMIN")' in text
    assert "SecurityConfig.java:9: .csrf(AbstractHttpConfigurer::disable)" in text
    assert "SecurityConfig.java:4: @EnableWebSecurity" in text
    assert "web.xml:3: security-constraint url /secure/* methods POST: roles manager; transport CONFIDENTIAL" in text
    assert "filter jwtAuthFilter on /api/*" in text
    assert "encodingFilter" not in text and "/commented/" not in text
    assert "app-routing.module.ts:6: route 'admin': canActivate: [AuthGuard]," in text
    assert "/test/**" not in text  # test code is not configuration


def test_render_security_summary_excludes_files_and_caps_length(tmp_path):
    entries = [("a/Sec.java", n, f".requestMatchers(\"/p{n}/**\").authenticated()") for n in range(1, 200)]
    summary = neighborhood.render_security_summary(entries + [("web.xml", 3, "rule")], exclude_paths={"web.xml"})
    assert len(summary) <= neighborhood.SECURITY_SUMMARY_MAX_CHARS + 60
    assert summary.endswith("more rule line(s) not shown)")
    assert "web.xml" not in summary


def test_controller_deep_scan_is_shown_the_repository_security_configuration(tmp_path):
    _security_repo(tmp_path)
    usage = {VALIDATOR_CONTEXT_USAGE_KEY: ValidatorContext(repo_root=tmp_path)}
    rules = load_rules(_ENGINE / "rules")

    def prompts_for(rel):
        seen = []

        def fake_llm(system, user, **kwargs):
            seen.append(user)
            return '{"findings": []}'

        lfs.scan_file(repo_root=tmp_path, rel_path=rel, rules=rules, call_llm_fn=fake_llm, usage=usage)
        return seen[0]

    controller = prompts_for("src/main/java/com/acme/web/UserApi.java")
    block = controller.split("Code under review")[0]
    assert "Repository security configuration" in block
    assert '.requestMatchers("/api/admin/**").hasRole("ADMIN")' in block
    assert "canActivate: [AuthGuard]" in block

    # The configuration file itself is not summarised back to itself.
    own = prompts_for("src/main/java/com/acme/config/SecurityConfig.java").split("Code under review")[0]
    assert "Repository security configuration" in own
    assert "SecurityConfig.java:" not in own

    # A file that is no web entry point gets no summary (and no system-prompt change).
    assert "Repository security configuration" not in prompts_for("src/main/java/com/acme/util/Strings.java")


def test_batched_small_files_get_the_summary_once(tmp_path):
    _security_repo(tmp_path)
    usage = {VALIDATOR_CONTEXT_USAGE_KEY: ValidatorContext(repo_root=tmp_path)}
    files = [(p, (tmp_path / p).read_text()) for p in (
        "src/main/java/com/acme/web/UserApi.java", "src/main/java/com/acme/util/Strings.java")]
    prompts = []

    def fake_llm(system, user, **kwargs):
        prompts.append(user)
        return '{"findings": []}'

    lfs.scan_file_batch(files=files, catalog=[], system_prompt="s", usage=usage, call_llm_fn=fake_llm)
    assert prompts[0].count("Repository security configuration") == 1
    assert prompts[0].index("Repository security configuration") < prompts[0].index("File: ")

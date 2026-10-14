"""Joern integration — pipeline/joern_runner.py, joern_flows.py, joern_findings.py
and the build_joern_cpg / discover_flows / joern_scan graph nodes.

Offline by default: fixtures under tests/fixtures/joern/ are real flows.sc /
queries.sc output captured from Joern 4.0.x against the sources embedded below
(line numbers matter), and subprocess calls go to fake `joern` scripts. The one
`live` test runs the real install (pytest -m live).
"""

import json
import os
import stat
import sys
from pathlib import Path

import pytest

pytest.importorskip("langgraph")

from app.config import settings  # noqa: E402
from app.services.agent_bridge import _load_agent_module  # noqa: E402

_ENGINE_DIR = Path(__file__).resolve().parents[1] / "sast_engine"
_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "joern"

USER_CONTROLLER = """package com.x;
import org.springframework.web.bind.annotation.*;
@RestController
public class UserController {
    private final UserDao dao = new UserDao();
    @GetMapping("/user")
    public String get(@RequestParam String id) {
        String clean = id.trim();
        return dao.find(clean);
    }
}
"""

USER_DAO = """package com.x;
import java.sql.*;
public class UserDao {
    Connection conn;
    public String find(String userId) {
        try {
            Statement st = conn.createStatement();
            ResultSet rs = st.executeQuery("select * from users where id='" + userId + "'");
            return rs.getString(1);
        } catch (SQLException e) { return null; }
    }
}
"""

BAD_JAVA = """package com.x;
import javax.xml.parsers.*;
import javax.net.ssl.*;
import java.security.*;
import javax.crypto.Cipher;
import javax.servlet.http.Cookie;
public class Bad implements X509TrustManager {
    private String dbPassword = "Sup3rS3cretPw!";
    public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) { }
    public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) {
        throw new RuntimeException("no");
    }
    public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
    void parse(java.io.InputStream in) throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.newDocumentBuilder().parse(in);
    }
    void parseSafe(java.io.InputStream in) throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        f.newDocumentBuilder().parse(in);
    }
    byte[] h(byte[] b) throws Exception { return MessageDigest.getInstance("MD5").digest(b); }
    Cipher c() throws Exception { return Cipher.getInstance("AES"); }
    Cookie k() { Cookie ck = new Cookie("s", "v"); ck.setSecure(true); return ck; }
}
"""

# Source for fixtures/joern/flows_java_extra.json (line numbers matter): a
# guarded + @PreAuthorize SQL sink, a parseInt-sanitized one, an escaped XSS
# write, a response header, a ResponseEntity body and an SLF4J log call.
EXTRA_CONTROLLER = r"""package com.x;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.util.HtmlUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.servlet.http.HttpServletResponse;
import java.sql.*;
@RestController
public class ExtraController {
    private static final Logger log = LoggerFactory.getLogger(ExtraController.class);
    Connection conn;
    @GetMapping("/echo")
    public ResponseEntity<String> echo(@RequestParam String q) {
        log.warn("echo called with {}", q);
        return ResponseEntity.ok("You searched: " + q);
    }
    @GetMapping("/safe")
    public void safe(@RequestParam String name, HttpServletResponse resp) throws Exception {
        String esc = HtmlUtils.htmlEscape(name);
        resp.getWriter().write(esc);
        resp.setHeader("X-Name", name);
    }
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String admin(@RequestParam String id) throws Exception {
        if (!id.matches("\\d+")) {
            return "bad";
        }
        Statement st = conn.createStatement();
        st.executeQuery("select * from t where id=" + id);
        return "ok";
    }
    @GetMapping("/num")
    public void num(@RequestParam String id) throws Exception {
        int n = Integer.parseInt(id);
        conn.createStatement().executeQuery("select * from t where id=" + n);
    }
}
"""


@pytest.fixture()
def agent(monkeypatch):
    monkeypatch.setattr(settings, "sast_framework_path", str(_ENGINE_DIR))
    sys.modules.pop("sast_scan_agent", None)
    return _load_agent_module()


@pytest.fixture()
def jr(agent):
    return sys.modules["pipeline.joern_runner"]


def _fixture(name: str) -> dict:
    return json.loads((_FIXTURES / name).read_text(encoding="utf-8"))


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _sqli_repo(root: Path) -> None:
    _write(root, "src/main/java/com/x/UserController.java", USER_CONTROLLER)
    _write(root, "src/main/java/com/x/UserDao.java", USER_DAO)


def _extra_repo(root: Path) -> None:
    _write(root, "src/main/java/com/x/ExtraController.java", EXTRA_CONTROLLER)


def _fake_joern_home(tmp_path: Path, *, joern_body: str, parse_body: str = "") -> Path:
    """A JOERN_HOME with shell-script stand-ins for joern / joern-parse."""
    home = tmp_path / "fake-joern"
    home.mkdir()
    default_parse = (
        'out=""; while [ $# -gt 0 ]; do [ "$1" = "-o" ] && out="$2"; shift; done\n'
        'echo cpg > "$out"\n'
    )
    for name, body in (("joern", joern_body), ("joern-parse", parse_body or default_parse)):
        p = home / name
        p.write_text("#!/bin/sh\n" + body, encoding="utf-8")
        p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return home


_WRITE_OUTFILE = (
    'out=""; for a in "$@"; do case "$a" in outFile=*) out="${a#outFile=}";; esac; done\n'
    "cat > \"$out\" <<'EOF'\n{payload}\nEOF\n"
)


# ---------------------------------------------------------------------------
# joern_runner
# ---------------------------------------------------------------------------

def test_unavailable_when_joern_home_empty(jr):
    # conftest points JOERN_HOME at an empty dir for every test.
    assert jr.joern_available() is False
    build = jr.build_cpg(Path("."), Path("x.bin"), "javasrc")
    assert build.cpg_path is None and "not found" in build.error


@pytest.mark.skipif(os.name == "nt", reason="shell-script stand-ins")
def test_build_cpg_and_run_script_with_fake_binaries(jr, tmp_path, monkeypatch):
    payload = json.dumps({"flows": [], "sources": 0, "sinks": 0})
    home = _fake_joern_home(tmp_path, joern_body=_WRITE_OUTFILE.replace("{payload}", payload))
    monkeypatch.setenv("JOERN_HOME", str(home))
    assert jr.joern_available() is True

    session = jr.start_session(tmp_path, ["javasrc", "pythonsrc"], work_dir=tmp_path / "work")
    assert [b.language for b in session.cpgs] == ["javasrc", "pythonsrc"]
    assert jr.run_flows(session.cpgs[0].cpg_path) == {"flows": [], "sources": 0, "sinks": 0}
    session.cleanup()
    assert not (tmp_path / "work").exists()


@pytest.mark.skipif(os.name == "nt", reason="shell-script stand-ins")
def test_failures_return_none_instead_of_raising(jr, tmp_path, monkeypatch):
    home = _fake_joern_home(
        tmp_path,
        joern_body="echo boom >&2; exit 3\n",
        parse_body="sleep 5\n",
    )
    monkeypatch.setenv("JOERN_HOME", str(home))
    build = jr.build_cpg(tmp_path, tmp_path / "cpg.bin", "javasrc", timeout=1)
    assert build.cpg_path is None and "timeout" in build.error
    (tmp_path / "cpg.bin").write_text("x")
    assert jr.run_queries(tmp_path / "cpg.bin") is None


@pytest.mark.skipif(os.name == "nt", reason="shell-script stand-ins")
def test_scripts_run_in_cpg_dir_and_flows_keep_partial_output(jr, tmp_path, monkeypatch):
    # importCpg copies the graph into ./workspace — that must be the session
    # dir (deleted by cleanup), not wherever the backend was started.
    partial = json.dumps({"flows": [], "kinds_done": ["sql"], "complete": False})
    home = _fake_joern_home(
        tmp_path,
        joern_body="mkdir -p workspace\n" + _WRITE_OUTFILE.replace("{payload}", partial) + "exit 1\n",
    )
    monkeypatch.setenv("JOERN_HOME", str(home))
    monkeypatch.chdir(tmp_path)
    session = jr.start_session(tmp_path, ["javasrc"], work_dir=tmp_path / "work")
    cpg = session.cpgs[0].cpg_path

    flows = jr.run_flows(cpg)
    assert flows["complete"] is False and flows["kinds_done"] == ["sql"]
    assert flows["error"].startswith("exit 1")
    # queries.sc only writes at the end: a failed run is no result.
    assert jr.run_queries(cpg) is None
    assert (tmp_path / "work" / "workspace").is_dir()
    assert not (tmp_path / "workspace").exists()
    session.cleanup()
    assert not (tmp_path / "work").exists()


def test_error_summary_prefers_joern_error_line(jr):
    # Real jssrc failure on an arm64 Joern run by an x86 JDK: the stack tail
    # only names the call site; the ERROR line names the missing binary.
    stderr = (
        "2026-10-13 17:10:06.838 ERROR AstGenRunner              Local astgen binary not found "
        "at '/x/astgen-macos' or is not executable!\n"
        "2026-10-13 17:10:06.880 ERROR ExternalCommand$          Process exited with code 1.\n"
        "\tat io.joern.console.cpgcreation.JsSrcCpgGenerator.generate(JsSrcCpgGenerator.scala:20)\n"
        "\t... 12 more\n"
    )
    assert jr._error_summary("", stderr).startswith("AstGenRunner")
    assert "astgen binary not found" in jr._error_summary("", stderr)
    assert "JOERN_JAVA_OPTS" in jr._error_summary("", "java.lang.OutOfMemoryError: Java heap space")
    assert jr._error_summary("", "a\nb\nc\nd") == "b | c | d"


def test_joern_java_home_is_exported_as_java_home(jr, monkeypatch):
    # An earlier test's `agent` fixture loads agent_bridge, whose
    # _sync_env_from_settings() does os.environ.setdefault("JOERN_JAVA_HOME", ...)
    # from the real .env value — that's a plain os.environ write, not a
    # monkeypatch one, so it outlives that test. Clear it so this test's own
    # "unset" case is genuinely unset regardless of run order.
    monkeypatch.delenv("JOERN_JAVA_HOME", raising=False)
    monkeypatch.setenv("JAVA_HOME", "/intel/jdk")
    assert jr._env()["JAVA_HOME"] == "/intel/jdk"
    monkeypatch.setenv("JOERN_JAVA_HOME", "/arm/jdk")
    assert jr._env()["JAVA_HOME"] == "/arm/jdk"


def test_languages_for_scan_ranks_and_caps(jr):
    paths = (["a.java"] * 10 + ["b.py"] * 5 + ["c.ts", "d.tsx", "e.js"]
             + ["f.go"] * 2 + ["README.md"] * 50)
    # Go has 2 files (< MIN_FILES_PER_LANGUAGE); JS/TS share one frontend.
    assert jr.languages_for_scan(paths) == ["javasrc", "pythonsrc", "jssrc"]
    assert jr.languages_for_scan(paths, max_languages=1) == ["javasrc"]


# ---------------------------------------------------------------------------
# joern_flows
# ---------------------------------------------------------------------------

def test_flows_from_joern_builds_hops_and_taint_path(agent, tmp_path):
    jf = sys.modules["pipeline.joern_flows"]
    _sqli_repo(tmp_path)
    flows, total = jf.flows_from_joern([_fixture("flows_java_sqli.json")], tmp_path, cap=30)
    assert total == 1
    flow = flows[0]
    assert flow.entry_tier == "joern"
    assert flow.sink_kind == "sql"
    assert [h.method for h in flow.hops] == ["UserController.get", "UserDao.find"]
    assert [h.role for h in flow.hops] == ["source", "sink"]
    assert flow.files == ["src/main/java/com/x/UserController.java", "src/main/java/com/x/UserDao.java"]
    sink = flow.hops[-1]
    assert sink.line == 8 and "executeQuery" in sink.body
    assert (sink.start_line, sink.end_line) == (5, 11)
    assert flow.hops[0].body.strip().startswith("@GetMapping") or "public String get" in flow.hops[0].body
    assert flow.taint_path[0]["code"] == "@RequestParam String id"
    assert any("executeQuery" in s["code"] or "select" in s["code"] for s in flow.taint_path)


def test_flows_carry_guards_sanitizers_and_auth(agent, tmp_path):
    jf = sys.modules["pipeline.joern_flows"]
    _extra_repo(tmp_path)
    flows, total = jf.flows_from_joern([_fixture("flows_java_extra.json")], tmp_path, cap=30)
    assert total == 6
    by_line = {(f.sink_kind, f.hops[-1].line): f for f in flows}

    guarded = by_line[("sql", 32)]
    assert [g["code"] for g in guarded.guards] == ['!id.matches("\\\\d+")']
    assert guarded.guards[0]["line"] == 28 and guarded.sanitizers == []
    assert guarded.authenticated is True  # @PreAuthorize on the source method

    parsed = by_line[("sql", 38)]
    assert [s["code"] for s in parsed.sanitizers] == ["Integer.parseInt(id)"]
    assert parsed.authenticated is False
    assert [s["code"] for s in by_line[("xss", 22)].sanitizers] == ["htmlEscape(name)"]
    assert {f.sink_kind for f in flows} == {"sql", "xss", "header", "response_body", "log"}


def test_rank_puts_unsanitized_injection_flows_first(agent, tmp_path):
    jf = sys.modules["pipeline.joern_flows"]
    _extra_repo(tmp_path)
    flows, _ = jf.flows_from_joern([_fixture("flows_java_extra.json")], tmp_path, cap=30)
    order = [(f.sink_kind, bool(f.sanitizers)) for f in flows]
    # Clean SQL first; then the high-volume Joern-only kinds; sanitized last.
    assert order[0] == ("sql", False)
    assert order[-2:] == [("sql", True), ("xss", True)] or order[-2:] == [("xss", True), ("sql", True)]
    assert {k for k, _ in order[1:4]} == {"header", "response_body", "log"}
    capped, _ = jf.flows_from_joern([_fixture("flows_java_extra.json")], tmp_path, cap=1)
    assert capped[0].hops[-1].line == 32


def test_taint_note_lists_guards_and_sanitizers(agent, tmp_path):
    jf = sys.modules["pipeline.joern_flows"]
    fv = sys.modules["pipeline.flow_verify"]
    cg = sys.modules["pipeline.call_graph"]
    _extra_repo(tmp_path)
    flows, _ = jf.flows_from_joern([_fixture("flows_java_extra.json")], tmp_path, cap=30)
    by_line = {(f.sink_kind, f.hops[-1].line): f for f in flows}

    note = fv.build_taint_path_note(by_line[("sql", 32)])
    assert "control-dependent" in note
    assert 'ExtraController.java:L28  !id.matches(' in note
    assert "sanitizer" not in note.lower()
    note = fv.build_taint_path_note(by_line[("sql", 38)])
    assert "Known sanitizer calls" in note and "L37  Integer.parseInt(id)" in note
    assert "control-dependent" not in note
    as_dict = cg.flow_to_dict(by_line[("sql", 38)])
    assert as_dict["sanitizers"] and as_dict["guards"] == []


def test_taint_spec_kinds_are_ranked_and_ordered(agent):
    # flows.sc runs kinds in kind_order and a timeout keeps the finished
    # prefix, so that order must follow the severity flows are ranked by.
    cg = sys.modules["pipeline.call_graph"]
    spec = json.loads((_ENGINE_DIR / "joern" / "taint_spec.json").read_text(encoding="utf-8"))
    order = spec["kind_order"]
    kinds = {s["kind"] for s in spec["sinks"]}
    assert kinds <= set(order) and set(order) <= set(cg._SINK_SEVERITY)
    assert [cg._SINK_SEVERITY[k] for k in order] == sorted(cg._SINK_SEVERITY[k] for k in order)
    sanitized = {k for s in spec["sanitizers"] for k in s.get("kinds", [])}
    assert sanitized <= kinds


def test_single_file_flow_dropped_when_file_was_deep_scanned(agent, tmp_path):
    jf = sys.modules["pipeline.joern_flows"]
    _sqli_repo(tmp_path)
    raw = _fixture("flows_java_sqli.json")
    one_file = {"flows": [{
        **raw["flows"][0],
        "elements": [e for e in raw["flows"][0]["elements"] if e["file"].endswith("UserDao.java")],
    }]}
    kept, _ = jf.flows_from_joern([one_file], tmp_path, cap=30)
    assert len(kept) == 1 and len(kept[0].hops) == 1 and kept[0].hops[0].role == "sink"
    dropped, total = jf.flows_from_joern(
        [one_file], tmp_path, cap=30, deep_scanned_paths={"src/main/java/com/x/UserDao.java"},
    )
    assert dropped == [] and total == 0


def test_taint_path_reaches_flow_verify_prompt(agent, tmp_path):
    jf = sys.modules["pipeline.joern_flows"]
    fv = sys.modules["pipeline.flow_verify"]
    cg = sys.modules["pipeline.call_graph"]
    _sqli_repo(tmp_path)
    flows, _ = jf.flows_from_joern([_fixture("flows_java_sqli.json")], tmp_path, cap=30)
    prompt = fv.build_flow_user_prompt(flows[0], fv.build_flow_slice(flows[0]))
    assert "Dataflow path (Joern" in prompt
    assert "UserController.java:L7  @RequestParam String id" in prompt
    assert cg.flow_to_dict(flows[0])["taint_path"]

    captured = {}

    def fake_llm(system, user, **kwargs):
        captured["user"] = user
        return json.dumps([{
            "verdict": "true_positive", "severity": "HIGH", "cwe": "CWE-89",
            "owasp_category": "A03:2021-Injection", "rule_id": "llm-extra",
            "title": "SQL injection", "line": 8, "verdict_reason": "concatenated",
            "confidence": 0.9,
        }])

    result = fv.verify_flows(flows, call_llm_fn=fake_llm)
    assert result["tp_count"] == 1
    assert "Dataflow path (Joern" in captured["user"]
    finding = result["files"][0]["findings"][0]
    assert finding["kind"] == "flow" and finding["file_path"].endswith("UserDao.java")


def test_tree_sitter_flows_have_no_taint_note(agent):
    cg = sys.modules["pipeline.call_graph"]
    fv = sys.modules["pipeline.flow_verify"]
    hop = cg.FlowHop(file="a.java", method="A.m", fqcn="A", name="m", line=1,
                     start_line=1, end_line=1, body="x", role="sink", label="x")
    flow = cg.Flow(hops=[hop], entry_tier="framework", sink_kind="sql", authenticated=False, files=["a.java"])
    assert fv.build_taint_path_note(flow) == ""


# ---------------------------------------------------------------------------
# joern_findings
# ---------------------------------------------------------------------------

def test_query_hits_become_unverified_joern_findings(agent, tmp_path):
    jfind = sys.modules["pipeline.joern_findings"]
    _write(tmp_path, "src/com/x/Bad.java", BAD_JAVA)
    raw = _fixture("queries_javasrc.json")
    file_results, skipped = jfind.file_results_from_hits([raw], tmp_path)
    assert skipped == {"generated": 0, "vendored": 0, "unreadable": 0}
    findings = file_results[0]["findings"]
    by_rule = {f["rule_id"]: f for f in findings}
    assert set(by_rule) == {
        "joern-java-xxe-unhardened-parser", "joern-java-trust-all-certificates",
        "joern-java-weak-hash", "joern-java-weak-cipher",
        "joern-java-cookie-missing-flags", "joern-hardcoded-credential",
    }
    xxe = by_rule["joern-java-xxe-unhardened-parser"]
    assert xxe["line"] == 15  # parse(), not the hardened parseSafe() at L19
    assert xxe["kind"] == "joern" and xxe["verdict"] == "unverified"
    assert xxe["severity"] == "HIGH" and xxe["cwe"] == "CWE-611"
    assert xxe["matched_text"] == "DocumentBuilderFactory.newInstance()"
    assert by_rule["joern-java-trust-all-certificates"]["severity"] == "CRITICAL"
    assert by_rule["joern-java-weak-hash"]["severity"] == "MEDIUM"
    assert "15:" in xxe["snippet"] or "15 " in xxe["snippet"] or "DocumentBuilderFactory" in xxe["snippet"]

    rules = {r.id: r for r in jfind.rules_for_hits([raw])}
    assert rules["joern-java-xxe-unhardened-parser"].cwe == "CWE-611"
    assert rules["joern-java-xxe-unhardened-parser"].regex.search(BAD_JAVA) is None


def test_query_hits_in_generated_files_are_skipped(agent, tmp_path):
    jfind = sys.modules["pipeline.joern_findings"]
    _write(tmp_path, "src/com/x/Bad.java", "// DO NOT EDIT - generated\n" + BAD_JAVA)
    file_results, skipped = jfind.file_results_from_hits([_fixture("queries_javasrc.json")], tmp_path)
    assert file_results == [] and skipped["generated"] == 1


def test_joern_findings_group_with_existing_grouping(agent, tmp_path):
    jfind = sys.modules["pipeline.joern_findings"]
    lfs = sys.modules["pipeline.llm_file_scan"]
    _write(tmp_path, "app.py", 'import subprocess\nfrom flask import Flask\napp = Flask(__name__)\n'
                               'api_key = "AKIAZZZZZZZZZZZZ1234"\ndef go(x):\n'
                               '    subprocess.run("ls " + x, shell=True)\napp.run(debug=True)\n')
    file_results, _ = jfind.file_results_from_hits([_fixture("queries_pythonsrc.json")], tmp_path)
    grouping = lfs.group_unverified_findings(file_results)
    assert grouping["group_count"] == 3


# ---------------------------------------------------------------------------
# graph nodes
# ---------------------------------------------------------------------------

def _state(agent, root: Path, **extra) -> dict:
    state = {
        "local_path": str(root), "scope": None, "use_llm": True, "inter_file_flow": True,
        "_tracer": agent.AgentTrace(verbose=False), "usage": agent.init_usage(None, None),
    }
    state.update(extra)
    return state


def _fake_session(jr, tmp_path, languages=("javasrc",)):
    builds = []
    for lang in languages:
        p = tmp_path / f"cpg_{lang}.bin"
        p.write_text("cpg")
        builds.append(jr.CpgBuild(lang, p, 0.1))
    return jr.JoernSession(work_dir=tmp_path / "work", builds=builds)


def test_build_joern_cpg_skips_cleanly_when_unavailable(agent, tmp_path):
    _sqli_repo(tmp_path)
    state = _state(agent, tmp_path)
    state.update(agent.node_scan_directory(state))
    assert agent.node_build_joern_cpg(state)["joern"]["status"] == "unavailable"
    state["joern_dataflow"] = False
    state["joern_scan_queries"] = False
    assert agent.node_build_joern_cpg(state)["joern"]["status"] == "disabled"


def test_discover_flows_uses_joern_for_non_java_python_stack(agent, jr, tmp_path, monkeypatch):
    # The tree-sitter graph doesn't run here (no call_graph), so every flow
    # must come from Joern — what lets JS/C/Go repos get flow verification.
    _sqli_repo(tmp_path)
    monkeypatch.setattr(jr, "run_flows", lambda cpg, **kw: _fixture("flows_java_sqli.json"))
    state = _state(agent, tmp_path, joern={"status": "ready", "_session": _fake_session(jr, tmp_path)})
    assert agent._inter_file_enabled(state) is True
    out = agent.node_discover_flows(state)
    assert len(out["flow_candidates"]) == 1
    assert out["flow_candidates"][0]["entry_tier"] == "joern"
    assert out["joern"]["flows_found"] == 1

    state["joern_dataflow"] = False
    assert agent._joern_dataflow_enabled(state) is False
    assert agent.node_discover_flows(state)["flow_candidates"] == []


def test_merge_flows_reserves_room_for_tree_sitter(agent, tmp_path):
    cg = sys.modules["pipeline.call_graph"]

    def flow(tier, line):
        hop = cg.FlowHop(file="a.java", method="A.m", fqcn="A", name="m", line=line,
                         start_line=1, end_line=99, body="", role="sink", label="")
        return cg.Flow(hops=[hop], entry_tier=tier, sink_kind="sql", authenticated=False, files=["a.java"])

    joern = [flow("joern", i) for i in range(1, 31)]
    ts = [flow("framework", 1)] + [flow("framework", 100 + i) for i in range(20)]
    merged = agent._merge_flows(joern, ts, 30)
    assert len(merged) == 30
    ts_kept = [f for f in merged if f.entry_tier == "framework"]
    assert len(ts_kept) == 10  # cap // 3, and the duplicate sink at line 1 is not among them
    assert all(f.hops[-1].line >= 100 for f in ts_kept)
    assert agent._merge_flows([], ts, 30) == ts


def test_joern_scan_node_writes_findings_and_reports(agent, jr, tmp_path, monkeypatch):
    _write(tmp_path, "src/com/x/Bad.java", BAD_JAVA)
    monkeypatch.setattr(jr, "run_queries", lambda cpg, **kw: _fixture("queries_javasrc.json"))
    written = []
    session = _fake_session(jr, tmp_path)
    state = _state(agent, tmp_path, joern={"status": "ready", "_session": session},
                   findings_writer=lambda p, f: written.append((p, f)))
    out = agent.node_joern_scan(state)
    results = out["joern_scan_results"]
    assert results["hit_count"] == 6 and results["unverified_count"] == 6
    assert written and written[0][0] == "src/com/x/Bad.java"
    assert all(f["kind"] == "joern" for f in written[0][1])

    state.update(out)
    report = agent.node_generate_report(state)["report"]
    assert report["unverified_count"] == 6
    assert report["joern"]["query_hits"] == 6
    assert "_session" not in report["joern"]

    state["joern_scan_queries"] = False
    assert agent.node_joern_scan(state)["joern_scan_results"]["files"] == []


def test_build_graph_wires_joern_nodes(agent):
    g = agent.build_graph().get_graph()
    edges = {(e.source, e.target) for e in g.edges}
    assert ("map_modules_and_risk", "build_joern_cpg") in edges
    assert ("build_joern_cpg", "build_call_graph") in edges
    assert ("scan_triage_files", "joern_scan") in edges
    assert ("joern_scan", "group_triage_findings") in edges


# ---------------------------------------------------------------------------
# live — real Joern install
# ---------------------------------------------------------------------------

def _real_joern_home() -> str:
    for candidate in (os.environ.get("REAL_JOERN_HOME"), Path.home() / ".local/opt/joern-cli"):
        if candidate and (Path(candidate) / "joern").exists():
            return str(candidate)
    return ""


@pytest.mark.live
def test_live_joern_end_to_end(agent, jr, tmp_path, monkeypatch):
    home = _real_joern_home()
    if not home:
        pytest.skip("no Joern install (set REAL_JOERN_HOME)")
    monkeypatch.setenv("JOERN_HOME", home)
    repo = tmp_path / "repo"
    _sqli_repo(repo)
    _extra_repo(repo)
    _write(repo, "src/main/java/com/x/Bad.java", BAD_JAVA)
    monkeypatch.chdir(tmp_path)
    session = jr.start_session(repo, ["javasrc"], work_dir=tmp_path / "work")
    assert session.cpgs, session.summary()
    jf = sys.modules["pipeline.joern_flows"]
    raw = jr.run_flows(session.cpgs[0].cpg_path)
    assert raw["complete"] is True
    flows, _ = jf.flows_from_joern([raw], repo, cap=30)
    assert any(f.sink_kind == "sql" and f.hops[-1].file.endswith("UserDao.java") for f in flows)
    assert {"log", "response_body", "header"} <= {f.sink_kind for f in flows}
    guarded = [f for f in flows if f.sink_kind == "sql" and f.hops[-1].line == 32]
    assert guarded and guarded[0].guards and guarded[0].authenticated
    escaped = [f for f in flows if f.sink_kind == "xss" and f.hops[0].file.endswith("ExtraController.java")]
    assert escaped and escaped[0].taint_path[0]["code"] == "@RequestParam String name"
    assert escaped[0].sanitizers
    # HttpServletResponse is framework-injected, not a source.
    assert not any("HttpServletResponse" in s["code"] for f in flows for s in f.taint_path[:1])
    hits = jr.run_queries(session.cpgs[0].cpg_path)["hits"]
    assert {"java-xxe-unhardened-parser", "java-trust-all-certificates"} <= {h["query"] for h in hits}
    assert (tmp_path / "work" / "workspace").is_dir() and not (tmp_path / "workspace").exists()
    session.cleanup()

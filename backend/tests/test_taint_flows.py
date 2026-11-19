"""Argument-level taint along Java call-graph flows (pipeline/taint_flows.py).
Offline: tree-sitter only, no LLM."""

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_java")
pytest.importorskip("langgraph")

from app.config import settings  # noqa: E402
from app.services.agent_bridge import _load_agent_module  # noqa: E402

_ENGINE_DIR = Path(__file__).resolve().parents[1] / "sast_engine"
_PKG = "src/main/java/com/example"

CONTROLLER = """
package com.example;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class FooController {
    private FooService svc;

    @GetMapping("/foo")
    public String handle(@RequestParam("id") String id) {
        return svc.%s;
    }

    @GetMapping("/foo/{n}")
    public String byNumber(@PathVariable("n") Long n) {
        return svc.find(String.valueOf(n));
    }
}
"""

SERVICE = """
package com.example;

import java.util.List;
import org.springframework.web.util.HtmlUtils;

public class FooService {
    private FooDao dao;
    private String table;

    public String find(String id) {
        String trimmed = id.trim();
        return dao.query(trimmed);
    }

    public String fixed(String id) {
        return dao.query("constant");
    }

    public String numeric(String id) {
        long n = Long.parseLong(id);
        return dao.query("" + n);
    }

    public String escaped(String id) {
        return dao.query(HtmlUtils.htmlEscape(id));
    }

    public String fromField(String id) {
        return dao.query(table);
    }

    public String built(String id) {
        StringBuilder b = new StringBuilder("x");
        b.append(id).append("y");
        return dao.query(b.toString());
    }

    public String bound(String id) {
        return dao.bound(id);
    }

    public String each(List<String> ids) {
        ids.forEach(i -> dao.query(i));
        return "";
    }
}
"""

DAO = """
package com.example;

import java.sql.Connection;
import java.sql.PreparedStatement;

public class FooDao {
    private Connection conn;

    public String query(String id) throws Exception {
        String sql = "SELECT * FROM foo WHERE id = '" + id + "'";
        PreparedStatement stmt = conn.prepareStatement(sql);
        stmt.executeQuery();
        return "";
    }

    public String bound(String id) throws Exception {
        try (PreparedStatement ps = conn.prepareStatement("SELECT * FROM foo WHERE id = ?")) {
            ps.setString(1, id);
            ps.executeQuery();
        }
        return "";
    }
}
"""

SERVLET = """
package com.example;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SearchServlet extends HttpServlet {
    private Repo repo;

    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        String term = request.getParameter("q");
        repo.search(term, 10);
    }
}
"""

REPO = """
package com.example;

import org.springframework.jdbc.core.JdbcTemplate;

public class Repo {
    private JdbcTemplate jdbcTemplate;

    public void search(String term, int limit) {
        jdbcTemplate.execute("DELETE FROM t WHERE name = '" + term + "'");
    }

    public void bound(String term) {
        jdbcTemplate.query("SELECT * FROM t WHERE name = ?", (rs, i) -> rs.getString(1), term);
    }
}
"""

ECHO_SERVLET = """
package com.example;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class EchoServlet extends HttpServlet {
    private Renderer renderer;

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        renderer.%s(response, request.getParameter("q"));
    }
}
"""

RENDERER = """
package com.example;

import javax.servlet.http.HttpServletResponse;
import org.springframework.web.util.HtmlUtils;

public class Renderer {
    public void escaped(HttpServletResponse response, String text) throws Exception {
        response.getWriter().print(HtmlUtils.htmlEscape(text));
    }

    public void raw(HttpServletResponse response, String text) throws Exception {
        response.getWriter().print(text);
    }
}
"""


@pytest.fixture()
def engine(monkeypatch):
    monkeypatch.setattr(settings, "sast_framework_path", str(_ENGINE_DIR))
    sys.modules.pop("sast_scan_agent", None)
    agent = _load_agent_module()
    return SimpleNamespace(
        agent=agent,
        cg=sys.modules["pipeline.call_graph"],
        tf=sys.modules["pipeline.taint_flows"],
        reach=sys.modules["pipeline.reachability"],
        fv=sys.modules["pipeline.flow_verify"],
    )


def _repo(root: Path, files: dict) -> list:
    paths = []
    for name, text in files.items():
        rel = f"{_PKG}/{name}"
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text.strip() + "\n", encoding="utf-8")
        paths.append(rel)
    return paths


def _flows(engine, tmp_path, call: str, entry: str = "handle"):
    paths = _repo(tmp_path, {
        "FooController.java": CONTROLLER % call, "FooService.java": SERVICE, "FooDao.java": DAO,
    })
    graph = engine.cg.build_call_graph(tmp_path, paths)
    flows = [f for f in engine.cg.discover_flows(graph) if f.hops[0].name == entry]
    engine.tf.annotate_flows(graph, flows)
    return graph, flows


def _only(flows):
    assert len(flows) == 1, [(f.hops[1].name, f.taint) for f in flows]
    return flows[0]


def test_concatenated_input_is_a_path(engine, tmp_path):
    flow = _only(_flows(engine, tmp_path, "find(id)")[1])
    taint = flow.taint
    assert taint["status"] == "path"
    assert taint["sink_position"] == "receiver"  # stmt.executeQuery() on a statement built from sql
    codes = [s["code"] for s in taint["steps"]]
    assert codes[0] == '@RequestParam("id") String id'
    assert codes[1:] == ["svc.find(id)", "dao.query(trimmed)", "stmt.executeQuery()"]
    assert taint["steps"][-1]["line"] == flow.hops[-1].line
    assert taint["sanitizers"] == []


@pytest.mark.parametrize("call", ["fixed(id)", "numeric(id)", "bound(id)"])
def test_sink_without_input_is_no_path(engine, tmp_path, call):
    flow = _only(_flows(engine, tmp_path, call)[1])
    assert flow.taint["status"] == "no_path", flow.taint


def test_numeric_entry_parameter_carries_nothing(engine, tmp_path):
    flow = _only(_flows(engine, tmp_path, "fixed(id)", entry="byNumber")[1])
    assert flow.taint["status"] == "no_path"


def _echo_flow(engine, tmp_path, method: str):
    paths = _repo(tmp_path, {"EchoServlet.java": ECHO_SERVLET % method, "Renderer.java": RENDERER})
    graph = engine.cg.build_call_graph(tmp_path, paths)
    flows = engine.cg.discover_flows(graph)
    engine.tf.annotate_flows(graph, flows)
    return _only(flows)


def test_encoder_for_the_sink_gives_sanitized_path(engine, tmp_path):
    flow = _echo_flow(engine, tmp_path, "escaped")
    assert flow.sink_kind == "xss"
    assert flow.taint["status"] == "sanitized_path"
    [sanitizer] = flow.taint["sanitizers"]
    assert sanitizer["code"] == "HtmlUtils.htmlEscape(text)"
    assert sanitizer["file"].endswith("Renderer.java")
    assert flow.taint["steps"][0]["code"] == 'request.getParameter("q")'
    assert "judge whether it fits this sink" in engine.tf.prompt_note(flow)


def test_unencoded_response_write_is_a_path(engine, tmp_path):
    assert _echo_flow(engine, tmp_path, "raw").taint["status"] == "path"


def test_encoder_for_another_sink_does_not_sanitize(engine, tmp_path):
    # HTML escaping before a SQL query is no SQL defence.
    flow = _only(_flows(engine, tmp_path, "escaped(id)")[1])
    assert flow.sink_kind == "sql"
    assert flow.taint["status"] == "path"
    assert flow.taint["sanitizers"] == []


def test_field_value_is_unknown_never_no_path(engine, tmp_path):
    flow = _only(_flows(engine, tmp_path, "fromField(id)")[1])
    assert flow.taint["status"] == "unknown"
    assert flow.taint["unknown"] == ["field `table`"]


def test_builder_mutation_carries_taint(engine, tmp_path):
    assert _only(_flows(engine, tmp_path, "built(id)")[1]).taint["status"] == "path"


def test_lambda_parameter_takes_the_collection(engine, tmp_path):
    flow = _only(_flows(engine, tmp_path, "each(java.util.List.of(id))")[1])
    assert flow.taint["status"] == "path"


def test_try_with_resources_statement_is_a_sink(engine, tmp_path):
    graph, _ = _flows(engine, tmp_path, "bound(id)")
    bound = {s.line for s in graph.sinks if graph.methods[s.caller_key].name == "bound"}
    assert bound, "ps.executeQuery() inside try-with-resources must resolve to a sql sink"


def test_request_accessor_source_and_dangerous_argument_only(engine, tmp_path):
    paths = _repo(tmp_path, {"SearchServlet.java": SERVLET, "Repo.java": REPO})
    graph = engine.cg.build_call_graph(tmp_path, paths)
    flows = engine.cg.discover_flows(graph)
    engine.tf.annotate_flows(graph, flows)
    flow = _only(flows)
    assert flow.taint["status"] == "path"
    assert flow.taint["sink_position"] == "argument 1"
    assert flow.taint["steps"][0]["code"] in ('request.getParameter("q")', "HttpServletRequest request")


def test_jdbc_template_bound_argument_is_not_the_sql(engine, tmp_path):
    servlet = SERVLET.replace("repo.search(term, 10);", "repo.bound(term);")
    paths = _repo(tmp_path, {"SearchServlet.java": servlet, "Repo.java": REPO})
    graph = engine.cg.build_call_graph(tmp_path, paths)
    flows = engine.cg.discover_flows(graph)
    engine.tf.annotate_flows(graph, flows)
    assert [f.taint["status"] for f in flows] == ["no_path"]


def test_analysis_error_makes_the_flow_unknown(engine, tmp_path, monkeypatch):
    graph, flows = _flows(engine, tmp_path, "find(id)")
    monkeypatch.setattr(engine.tf.TaintAnalyzer, "trace", lambda self, flow: 1 / 0)
    counts = engine.tf.annotate_flows(graph, flows)
    assert counts["unknown"] == 1
    assert flows[0].taint["unknown"] == ["analysis error: ZeroDivisionError"]


def test_path_becomes_reachability_evidence(engine, tmp_path):
    flow = _only(_flows(engine, tmp_path, "find(id)")[1])
    index = engine.reach.build_sink_index([flow])
    sink = flow.hops[-1]
    finding = {"cwe": "CWE-89", "line": sink.line, "file_path": sink.file, "verdict": "true_positive",
               "confidence": 0.6}
    evidence = engine.reach.match(finding, index)
    assert evidence["status"] == "path"
    assert evidence["source"]["code"] == '@RequestParam("id") String id'
    finding["reachability"] = evidence
    assert engine.reach.apply_confidence(finding) is True
    assert finding["confidence"] == engine.reach.REACHABLE_CONFIDENCE_FLOOR
    assert "Dataflow evidence" in engine.reach.render_evidence(evidence)


def test_sanitized_and_untraced_evidence(engine, tmp_path):
    flow = _echo_flow(engine, tmp_path, "escaped")
    evidence = engine.reach.evidence_from_call_graph_flow(flow)
    assert evidence["status"] == "sanitized_path"
    assert evidence["sanitizers"][0]["code"] == "HtmlUtils.htmlEscape(text)"
    flow.taint = {"status": "no_path"}
    assert engine.reach.evidence_from_call_graph_flow(flow)["status"] == "entry_reachable"
    flow.taint = None
    assert engine.reach.evidence_from_call_graph_flow(flow)["status"] == "entry_reachable"


def test_prompt_carries_the_trace_only_when_traced(engine, tmp_path):
    flow = _only(_flows(engine, tmp_path, "find(id)")[1])
    traced = engine.fv.build_flow_user_prompt(flow, "SLICE")
    assert "Taint analysis (deterministic and best effort" in traced
    assert "`svc.find(id)`" in traced
    flow.taint = None
    plain = engine.fv.build_flow_user_prompt(flow, "SLICE")
    assert "Taint analysis" not in plain
    assert "(HTTP, listener, or main).\n\nSLICE" in plain  # byte-identical to before


def _discover(engine, tmp_path, taint_flows: bool):
    paths = _repo(tmp_path, {
        "FooController.java": CONTROLLER % "fixed(id) + svc.find(id)",
        "FooService.java": SERVICE, "FooDao.java": DAO,
    })
    graph = engine.cg.build_call_graph(tmp_path, paths)
    state = {
        "_tracer": engine.agent.AgentTrace(verbose=False),
        "call_graph": {"_graph": graph, "_graph_lang": "java"},
        "taint_flows": taint_flows,
    }
    return engine.agent.node_discover_flows(state)


def test_node_drops_no_path_flows_from_verification_only(engine, tmp_path):
    out = _discover(engine, tmp_path, taint_flows=True)
    verified = {c["hops"][1]["name"] for c in out["flow_candidates"]}
    assert "fixed" not in verified
    assert "find" in verified
    counts = out["call_graph"]["taint_status_counts"]
    # handle -> fixed, and byNumber -> find (a Long path variable carries no text).
    assert counts["no_path"] == 2 and counts["path"] == 1
    statuses = [c["taint"]["status"] for c in out["flow_candidates"]]
    assert statuses == sorted(statuses, key=lambda s: {"path": 0, "sanitized_path": 1, "unknown": 2}[s])
    # The dropped flow's call chain is still evidence at its sink.
    evidence = [ev for evs in out["reachability_index"].values() for ev in evs]
    assert any(ev["status"] == "entry_reachable" and ev["source"]["code"] == "handle(...)" for ev in evidence)


def test_node_without_taint_verifies_every_flow(engine, tmp_path):
    out = _discover(engine, tmp_path, taint_flows=False)
    assert "fixed" in {c["hops"][1]["name"] for c in out["flow_candidates"]}
    assert all(c["taint"] is None for c in out["flow_candidates"])
    assert "taint_status_counts" not in out["call_graph"]


def _verify_with_answer(engine, flow, line, snippet="stmt.executeQuery();"):
    import json

    answer = {"findings": [{
        "rule_id": "llm-extra", "title": "SQL injection", "cwe": "CWE-89", "severity": "HIGH",
        "verdict": "true_positive", "confidence": 0.6, "line": line,
        "snippet": snippet, "verdict_reason": "The id is concatenated into the SQL text.",
    }]}
    result = engine.fv.verify_flows([flow], call_llm_fn=lambda *a, **k: json.dumps(answer))
    [finding] = result["findings"]
    return finding


def test_flow_finding_at_the_sink_carries_the_traced_path(engine, tmp_path):
    flow = _only(_flows(engine, tmp_path, "find(id)")[1])
    finding = _verify_with_answer(engine, flow, flow.hops[-1].line)
    assert finding["line"] == flow.hops[-1].line  # a file line, not a line inside the method
    assert finding["reachability"]["status"] == "path"
    assert finding["reachability"]["source"]["code"] == '@RequestParam("id") String id'
    assert finding["confidence"] == engine.reach.REACHABLE_CONFIDENCE_FLOOR


def test_flow_finding_away_from_the_sink_or_untraced_gets_no_path(engine, tmp_path):
    flow = _only(_flows(engine, tmp_path, "find(id)")[1])
    away = _verify_with_answer(engine, flow, flow.hops[-1].start_line, snippet="public String query(String id)")
    assert away["line"] == flow.hops[-1].start_line
    assert "reachability" not in away
    flow.taint = None
    assert "reachability" not in _verify_with_answer(engine, flow, flow.hops[-1].line)

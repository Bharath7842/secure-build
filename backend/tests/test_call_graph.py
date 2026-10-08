"""Offline coverage for pipeline/call_graph.py — Java typed sinks, overloads,
tiered entries, and multi-file flow discovery. No LLM.
"""

from pathlib import Path

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_java")
pytest.importorskip("langgraph")

from app.config import settings  # noqa: E402
from app.services.agent_bridge import _load_agent_module  # noqa: E402

_ENGINE_DIR = Path(__file__).resolve().parents[1] / "sast_engine"

FOO_CONTROLLER = """
package com.example;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class FooController {
    private FooService svc;

    @GetMapping("/foo")
    public String create(@RequestParam("id") String id) {
        return svc.find(id);
    }
}
"""

FOO_SERVICE = """
package com.example;

public class FooService {
    private FooDao dao;

    public String find(String id) {
        return dao.query(id);
    }
}
"""

FOO_DAO = """
package com.example;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class FooDao {
    private Connection conn;

    public ResultSet query(String id) throws Exception {
        String sql = "SELECT * FROM foo WHERE id = '" + id + "'";
        PreparedStatement stmt = conn.prepareStatement(sql);
        return stmt.executeQuery();
    }
}
"""

USER_SERVICE = """
package com.example;

public class UserService {
    private UserDao dao;

    public String find(String id) {
        return dao.query(id);
    }
}
"""

USER_DAO = """
package com.example;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class UserDao {
    private Connection conn;

    public ResultSet query(String id) throws Exception {
        String sql = "SELECT * FROM users WHERE id = '" + id + "'";
        PreparedStatement stmt = conn.prepareStatement(sql);
        return stmt.executeQuery();
    }
}
"""

ALL_IN_ONE = """
package com.example;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class AllController {
    private AllService svc;

    @GetMapping("/foo")
    public String create(@RequestParam("id") String id) {
        return svc.find(id);
    }
}

class AllService {
    private AllDao dao;

    public String find(String id) {
        return dao.query(id);
    }
}

class AllDao {
    private Connection conn;

    public ResultSet query(String id) throws Exception {
        PreparedStatement stmt = conn.prepareStatement("SELECT * FROM t WHERE id='" + id + "'");
        return stmt.executeQuery();
    }
}
"""

TWO_IMPL = """
package com.example;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

interface Repo {
    ResultSet query(String id) throws Exception;
}

class RepoA implements Repo {
    private Connection conn;
    public ResultSet query(String id) throws Exception {
        PreparedStatement stmt = conn.prepareStatement(id);
        return stmt.executeQuery();
    }
}

class RepoB implements Repo {
    private Connection conn;
    public ResultSet query(String id) throws Exception {
        PreparedStatement stmt = conn.prepareStatement(id);
        return stmt.executeQuery();
    }
}

@RestController
class TwoImplController {
    private Repo repo;

    @GetMapping("/x")
    public ResultSet go(String id) throws Exception {
        return repo.query(id);
    }
}
"""

EXECUTOR = """
package com.example;

import java.util.concurrent.ExecutorService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ExecController {
    private ExecutorService pool;

    @GetMapping("/run")
    public void go() {
        pool.execute(() -> {});
    }
}
"""

OVERLOAD_AMBIG = """
package com.example;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class OverloadCtrl {
    private OverloadSvc svc;

    @GetMapping("/o")
    public void go(String id) {
        svc.find(id);
    }
}

class OverloadSvc {
    void find(String id) { }
    void find(Integer id) { }
}
"""

OVERLOAD_ARITY = """
package com.example;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class ArityCtrl {
    private AritySvc svc;

    @GetMapping("/a")
    public ResultSet go(String id) throws Exception {
        return svc.find(id);
    }
}

class AritySvc {
    private ArityDao dao;

    public ResultSet find(String id) throws Exception {
        return dao.query(id);
    }

    public ResultSet find(String id, int n) throws Exception {
        return dao.query(id);
    }
}

class ArityDao {
    private Connection conn;

    public ResultSet query(String id) throws Exception {
        PreparedStatement stmt = conn.prepareStatement(id);
        return stmt.executeQuery();
    }
}
"""


@pytest.fixture()
def agent(monkeypatch):
    import sys

    monkeypatch.setattr(settings, "sast_framework_path", str(_ENGINE_DIR))
    sys.modules.pop("sast_scan_agent", None)
    return _load_agent_module()


@pytest.fixture()
def cg(agent):
    import sys
    return sys.modules["pipeline.call_graph"]


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.strip() + "\n", encoding="utf-8")


def _http_tree(tmp_path: Path) -> list[str]:
    _write(tmp_path, "src/main/java/com/example/FooController.java", FOO_CONTROLLER)
    _write(tmp_path, "src/main/java/com/example/FooService.java", FOO_SERVICE)
    _write(tmp_path, "src/main/java/com/example/FooDao.java", FOO_DAO)
    return [
        "src/main/java/com/example/FooController.java",
        "src/main/java/com/example/FooService.java",
        "src/main/java/com/example/FooDao.java",
    ]


def test_http_fixture_discovers_one_multi_file_flow(cg, tmp_path):
    paths = _http_tree(tmp_path)
    graph = cg.build_call_graph(tmp_path, paths)
    names = {(m.fqcn.rsplit(".", 1)[-1], m.name) for m in graph.methods.values()}
    assert ("FooController", "create") in names
    assert ("FooService", "find") in names
    assert ("FooDao", "query") in names
    callee_names = {
        (graph.methods[e.caller_key].name, graph.methods[e.callee_key].name)
        for e in graph.edges
    }
    assert ("create", "find") in callee_names
    assert ("find", "query") in callee_names
    assert graph.sinks
    assert all(s.kind == "sql" for s in graph.sinks)
    flows = cg.discover_flows(graph)
    assert graph.entry_tier == "framework"
    assert len(flows) == 1
    files = set(flows[0].files)
    assert len(files) == 3
    hop_methods = [h.method for h in flows[0].hops]
    assert hop_methods[0].endswith(".create")
    assert hop_methods[-1].endswith(".query")
    # Middle hop line is the call inside FooService, not the line in
    # FooController that entered it (off-by-one on the BFS `lines` list).
    middle = flows[0].hops[1]
    assert middle.role == "hop"
    assert middle.file.endswith("FooService.java")
    assert middle.start_line <= middle.line <= middle.end_line
    find_key = next(
        k for k, m in graph.methods.items()
        if m.name == "find" and m.fqcn.endswith("FooService")
    )
    assert middle.line in {
        e.call_line for e in graph.edges if e.caller_key == find_key
    }


def test_standalone_fixture_uses_public_api_tier(cg, tmp_path):
    _write(tmp_path, "src/main/java/com/example/UserService.java", USER_SERVICE)
    _write(tmp_path, "src/main/java/com/example/UserDao.java", USER_DAO)
    paths = [
        "src/main/java/com/example/UserService.java",
        "src/main/java/com/example/UserDao.java",
    ]
    graph = cg.build_call_graph(tmp_path, paths)
    flows = cg.discover_flows(graph)
    assert graph.entry_tier == "public_api"
    assert len(flows) == 1
    assert set(flows[0].files) == set(paths)
    assert flows[0].hops[0].method.endswith(".find")
    assert flows[0].hops[-1].method.endswith(".query")


def test_same_file_flow_skipped(cg, tmp_path):
    _write(tmp_path, "src/main/java/com/example/AllInOne.java", ALL_IN_ONE)
    graph = cg.build_call_graph(tmp_path, ["src/main/java/com/example/AllInOne.java"])
    flows = cg.discover_flows(graph)
    assert flows == []


def test_two_impl_interface_does_not_flow_through_call(cg, tmp_path):
    _write(tmp_path, "src/main/java/com/example/TwoImpl.java", TWO_IMPL)
    graph = cg.build_call_graph(tmp_path, ["src/main/java/com/example/TwoImpl.java"])
    assert "unresolved_interface" in graph.unresolved
    # Single file anyway; even if impls were followed, same-file would drop.
    # Guard: no edge from controller into a concrete query.
    ctrl_edges = [
        e for e in graph.edges
        if graph.methods[e.caller_key].name == "go"
    ]
    assert ctrl_edges == []


def test_executor_execute_is_not_a_sink(cg, tmp_path):
    _write(tmp_path, "src/main/java/com/example/ExecController.java", EXECUTOR)
    graph = cg.build_call_graph(tmp_path, ["src/main/java/com/example/ExecController.java"])
    assert graph.sinks == []
    flows = cg.discover_flows(graph)
    assert flows == []


def test_prepared_statement_execute_query_is_a_sink(cg, tmp_path):
    _write(tmp_path, "src/main/java/com/example/FooDao.java", FOO_DAO)
    graph = cg.build_call_graph(tmp_path, ["src/main/java/com/example/FooDao.java"])
    assert any(s.kind == "sql" and s.method_name == "executeQuery" for s in graph.sinks)


def test_overload_same_argc_stops_branch(cg, tmp_path):
    _write(tmp_path, "src/main/java/com/example/Overload.java", OVERLOAD_AMBIG)
    graph = cg.build_call_graph(tmp_path, ["src/main/java/com/example/Overload.java"])
    assert "unresolved_overload" in graph.unresolved
    edges_from_go = [
        e for e in graph.edges if graph.methods[e.caller_key].name == "go"
    ]
    assert edges_from_go == []


def test_overload_different_argc_picks_matching(cg, tmp_path):
    # Same three types as OVERLOAD_ARITY, split across files so discover_flows
    # keeps the path (same-file flows are dropped).
    ctrl, rest = OVERLOAD_ARITY.split("class AritySvc", 1)
    svc, dao = rest.split("class ArityDao", 1)
    _write(tmp_path, "src/main/java/com/example/ArityCtrl.java", ctrl)
    _write(
        tmp_path,
        "src/main/java/com/example/AritySvc.java",
        "package com.example;\n\nclass AritySvc" + svc,
    )
    _write(
        tmp_path,
        "src/main/java/com/example/ArityDao.java",
        "package com.example;\n\nimport java.sql.Connection;\n"
        "import java.sql.PreparedStatement;\nimport java.sql.ResultSet;\n\n"
        "class ArityDao" + dao,
    )
    paths = [
        "src/main/java/com/example/ArityCtrl.java",
        "src/main/java/com/example/AritySvc.java",
        "src/main/java/com/example/ArityDao.java",
    ]
    graph = cg.build_call_graph(tmp_path, paths)
    edges = [
        (graph.methods[e.caller_key].name, graph.methods[e.callee_key].name,
         graph.methods[e.callee_key].argc)
        for e in graph.edges
    ]
    assert ("go", "find", 1) in edges
    assert ("go", "find", 2) not in edges
    flows = cg.discover_flows(graph)
    assert len(flows) == 1
    assert [h.method.split(".")[-1] for h in flows[0].hops] == ["go", "find", "query"]


def test_nodes_noop_when_not_java_or_python(agent, tmp_path):
    # Neither maven-java nor python — inter-file call-graph tracing supports
    # only those two stacks, so this must stay a no-op.
    (tmp_path / "package.json").write_text('{"name": "x", "version": "1.0.0"}\n', encoding="utf-8")
    (tmp_path / "index.js").write_text("console.log(1);\n", encoding="utf-8")
    state = {
        "local_path": str(tmp_path),
        "scope": None,
        "use_llm": True,
        "inter_file_flow": True,
        "_tracer": agent.AgentTrace(verbose=False),
        "usage": agent.init_usage(None, None),
    }
    state.update(agent.node_scan_directory(state))
    state.update(agent.node_analyze_tech_stack(state))
    state.update(agent.node_categorize_files(state))
    state.update(agent.node_map_modules_and_risk(state))
    built = agent.node_build_call_graph(state)
    assert built["call_graph"]["files_parsed"] == 0
    state.update(built)
    discovered = agent.node_discover_flows(state)
    assert discovered["flow_candidates"] == []
    state.update(discovered)
    verified = agent.node_verify_flow_slices(state)
    assert verified["flow_scan_results"]["files_scanned"] == 0


def test_nodes_noop_when_flag_off(agent, tmp_path):
    _http_tree(tmp_path)
    (tmp_path / "pom.xml").write_text("<project/>\n", encoding="utf-8")
    state = {
        "local_path": str(tmp_path),
        "scope": None,
        "use_llm": True,
        "inter_file_flow": False,
        "_tracer": agent.AgentTrace(verbose=False),
        "usage": agent.init_usage(None, None),
    }
    state.update(agent.node_scan_directory(state))
    state.update(agent.node_analyze_tech_stack(state))
    result = agent.node_build_call_graph(state)
    assert result["call_graph"]["files_parsed"] == 0


def test_build_graph_inserts_flow_nodes_before_deep_scan(agent):
    graph = agent.build_graph()
    nodes = set(graph.get_graph().nodes)
    assert "build_call_graph" in nodes
    assert "discover_flows" in nodes
    assert "verify_flow_slices" in nodes
    assert "derive_runtime_rules" in nodes
    assert "scan_deep_files" in nodes

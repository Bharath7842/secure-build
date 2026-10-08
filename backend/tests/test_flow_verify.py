"""Offline coverage for pipeline/flow_verify.py — mocked LLM, no Bedrock."""

import json
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_java")
pytest.importorskip("langgraph")

from app.config import settings  # noqa: E402
from app.services.agent_bridge import _load_agent_module  # noqa: E402

_ENGINE_DIR = Path(__file__).resolve().parents[1] / "sast_engine"

CONTROLLER = """
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

SERVICE = """
package com.example;

public class FooService {
    private FooDao dao;

    public String find(String id) {
        return dao.query(id);
    }
}
"""

DAO = """
package com.example;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class FooDao {
    private Connection conn;

    public ResultSet query(String id) throws Exception {
        PreparedStatement stmt = conn.prepareStatement("SELECT * FROM t WHERE id='" + id + "'");
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


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.strip() + "\n", encoding="utf-8")


def test_verify_flow_writes_kind_flow_and_affected_files(agent, tmp_path):
    import sys

    cg = sys.modules["pipeline.call_graph"]
    fv = sys.modules["pipeline.flow_verify"]

    _write(tmp_path, "src/main/java/com/example/FooController.java", CONTROLLER)
    _write(tmp_path, "src/main/java/com/example/FooService.java", SERVICE)
    _write(tmp_path, "src/main/java/com/example/FooDao.java", DAO)
    graph = cg.build_call_graph(tmp_path, [
        "src/main/java/com/example/FooController.java",
        "src/main/java/com/example/FooService.java",
        "src/main/java/com/example/FooDao.java",
    ])
    flows = cg.discover_flows(graph)
    assert len(flows) == 1

    payload = [{
        "verdict": "true_positive",
        "severity": "HIGH",
        "cwe": "CWE-89",
        "owasp_category": "A03:2021-Injection",
        "rule_id": "llm-extra",
        "title": "SQL injection in query",
        "line": flows[0].hops[-1].line,
        "source": "id",
        "sink": "executeQuery",
        "data_flow": "id -> query -> executeQuery",
        "snippet": "stmt.executeQuery()",
        "verdict_reason": "concatenated SQL",
        "confidence": 0.9,
        "ai_fix": "use a bind parameter",
    }]

    def fake_llm(system, user, **kwargs):
        assert "FULL method body" in system or "complete" in system.lower() or "FULL" in system
        assert "FooController" in user and "FooDao" in user
        return json.dumps(payload)

    writer_calls = []
    result = fv.verify_flows(
        flows,
        call_llm_fn=fake_llm,
        findings_writer=lambda p, f: writer_calls.append((p, f)),
        suppress_no_cwe=True,
    )
    assert result["tp_count"] == 1
    assert writer_calls
    path, findings = writer_calls[0]
    assert findings[0]["kind"] == "flow"
    assert "FooDao.java" in path
    assert len(findings[0]["affected_files"]) == 3
    assert findings[0]["flow_path"][0]["file"].endswith("FooController.java")
    assert findings[0]["flow_path"][-1]["role"] == "sink"
    hop = findings[0]["flow_path"][1]
    assert hop["file"].endswith("FooService.java")
    assert hop["role"] == "hop"
    assert hop["start_line"] <= hop["line"]
    assert findings[0]["flow_path"][0]["snippet"].lstrip()[:1].isdigit()
    assert "executeQuery" in findings[0]["snippet"]


def test_node_verify_flow_slices_threads_findings_writer(agent, tmp_path, monkeypatch):
    _write(tmp_path, "pom.xml", "<project/>\n")
    _write(tmp_path, "src/main/java/com/example/FooController.java", CONTROLLER)
    _write(tmp_path, "src/main/java/com/example/FooService.java", SERVICE)
    _write(tmp_path, "src/main/java/com/example/FooDao.java", DAO)

    captured = []

    def fake_verify_flows(*args, findings_writer=None, **kwargs):
        captured.append(findings_writer)
        return {
            "files_scanned": 0, "tp_count": 0, "fp_count": 0, "files": [],
            "flows_verified": 0, "flows_skipped_large": 0, "findings": [],
        }

    monkeypatch.setattr(agent.flow_verify, "verify_flows", fake_verify_flows)

    state = {
        "local_path": str(tmp_path),
        "scope": None,
        "use_llm": True,
        "inter_file_flow": True,
        "_tracer": agent.AgentTrace(verbose=False),
        "usage": agent.init_usage(None, None),
        "findings_writer": object(),
    }
    state.update(agent.node_scan_directory(state))
    state.update(agent.node_analyze_tech_stack(state))
    state.update(agent.node_categorize_files(state))
    state.update(agent.node_map_modules_and_risk(state))
    state.update(agent.node_build_call_graph(state))
    state.update(agent.node_discover_flows(state))
    marker = object()
    state["findings_writer"] = marker
    agent.node_verify_flow_slices(state)
    assert captured == [marker]

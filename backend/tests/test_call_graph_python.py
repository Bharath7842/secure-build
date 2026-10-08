"""Offline coverage for pipeline/call_graph_python.py — Python typed sinks,
import-alias resolution, cross-file ambiguity, and multi-file flow discovery.
No LLM. Mirrors tests/test_call_graph.py's fixture pattern for the Java module.
"""

from pathlib import Path

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_python")
pytest.importorskip("langgraph")

from app.config import settings  # noqa: E402
from app.services.agent_bridge import _load_agent_module  # noqa: E402

_ENGINE_DIR = Path(__file__).resolve().parents[1] / "sast_engine"


@pytest.fixture()
def agent(monkeypatch):
    import sys

    monkeypatch.setattr(settings, "sast_framework_path", str(_ENGINE_DIR))
    sys.modules.pop("sast_scan_agent", None)
    return _load_agent_module()


@pytest.fixture()
def cgp(agent):
    import sys
    return sys.modules["pipeline.call_graph_python"]


@pytest.fixture()
def derive_rules(agent):
    import sys
    return sys.modules["pipeline.derive_rules"]


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.strip() + "\n", encoding="utf-8")


APP_PY = """
from flask import Flask
import db

app = Flask(__name__)


@app.route("/user/<id>")
def show_user(id):
    return db.get_user(id)
"""

DB_PY = """
def get_user(id):
    cursor.execute(f"SELECT * FROM users WHERE id={id}")
    return cursor.fetchone()
"""


def _flask_sql_tree(tmp_path: Path) -> list[str]:
    _write(tmp_path, "app.py", APP_PY)
    _write(tmp_path, "db.py", DB_PY)
    return ["app.py", "db.py"]


def test_flask_route_to_sql_flow(cgp, tmp_path):
    paths = _flask_sql_tree(tmp_path)
    graph = cgp.build_call_graph(tmp_path, paths)

    assert any(s.kind == "sql" for s in graph.sinks)

    flows = cgp.discover_flows(graph)
    assert flows
    flow = flows[0]
    assert flow.entry_tier == "framework"
    assert flow.sink_kind == "sql"
    assert set(flow.files) == {"app.py", "db.py"}


def test_import_alias_resolution_subprocess_run_as_r(cgp, tmp_path):
    src = """
from subprocess import run as r


def handler(cmd):
    r(cmd, shell=True)
"""
    _write(tmp_path, "runner.py", src)
    graph = cgp.build_call_graph(tmp_path, ["runner.py"])
    assert any(s.kind == "command" for s in graph.sinks)


def test_ambiguous_cross_file_name_is_unresolved(cgp, tmp_path):
    _write(tmp_path, "mod_a.py", "def get_user(x):\n    return x\n")
    _write(tmp_path, "mod_b.py", "def get_user(y):\n    return y\n")
    _write(tmp_path, "caller.py", "def handler():\n    return get_user(1)\n")
    graph = cgp.build_call_graph(tmp_path, ["mod_a.py", "mod_b.py", "caller.py"])
    assert "unresolved_ambiguous_name" in graph.unresolved


def test_literal_cursor_execute_is_still_a_sink(cgp, tmp_path):
    src = """
def run_query():
    cursor.execute("SELECT 1")
"""
    _write(tmp_path, "q.py", src)
    graph = cgp.build_call_graph(tmp_path, ["q.py"])
    assert any(s.kind == "sql" for s in graph.sinks)


def test_flow_to_dict_populates_every_flow_verify_field(cgp, tmp_path):
    paths = _flask_sql_tree(tmp_path)
    graph = cgp.build_call_graph(tmp_path, paths)
    flows = cgp.discover_flows(graph)
    assert flows
    flow = flows[0]

    # Every field flow_verify.py actually reads off Flow/FlowHop.
    assert flow.entry_tier
    assert flow.sink_kind
    assert flow.files
    for hop in flow.hops:
        assert hop.file
        assert hop.method
        assert hop.start_line > 0
        assert hop.end_line >= hop.start_line
        assert hop.body
        assert hop.role in ("source", "hop", "sink")
        assert hop.label
        assert hop.line > 0

    as_dict = cgp.flow_to_dict(flow)
    assert as_dict["entry_tier"] == flow.entry_tier
    assert as_dict["sink_kind"] == flow.sink_kind
    assert as_dict["files"] == flow.files
    assert len(as_dict["hops"]) == len(flow.hops)
    for hop_dict in as_dict["hops"]:
        for key in ("file", "method", "fqcn", "name", "line", "start_line", "end_line", "body", "role", "label"):
            assert key in hop_dict


def test_derive_rules_wrappers_from_python_adapter(cgp, derive_rules, tmp_path):
    src = """
def get(id):
    cursor.execute(f"SELECT * FROM users WHERE id={id}")


def get_user(id):
    cursor.execute(f"SELECT * FROM users WHERE id={id}")
"""
    _write(tmp_path, "db2.py", src)
    graph = cgp.build_call_graph(tmp_path, ["db2.py"])
    adapter = cgp.PythonGraphAdapter(graph)

    raw = derive_rules.wrappers_from_graph(adapter)
    ids = {r["id"] for r in raw}

    assert "runtime-sink-sql-get_user" in ids
    assert "runtime-sink-sql-get" not in ids
    by_id = {r["id"]: r for r in raw}
    assert by_id["runtime-sink-sql-get_user"]["languages"] == ["python"]

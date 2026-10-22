"""Runtime-derived regex: Pass A wrappers, Pass B LLM, catalog-preserving merge."""

from pathlib import Path

import pytest

pytest.importorskip("langgraph")

from app.config import settings  # noqa: E402
from app.services.agent_bridge import _load_agent_module  # noqa: E402

_ENGINE_DIR = Path(__file__).resolve().parents[1] / "sast_engine"

DAO = """
package com.example;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class FooDao {
    private Connection conn;

    public ResultSet runNativeQuery(String id) throws Exception {
        PreparedStatement stmt = conn.prepareStatement(
            "SELECT * FROM t WHERE id='" + id + "'");
        return stmt.executeQuery();
    }

    public ResultSet find(String id) throws Exception {
        PreparedStatement stmt = conn.prepareStatement("SELECT 1");
        return stmt.executeQuery();
    }
}
"""

CALLER = """
package com.example;

public class FooService {
    private FooDao dao;

    public ResultSet go(String id) throws Exception {
        return dao.runNativeQuery(id);
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
def derive_rules(agent):
    import sys

    return sys.modules["pipeline.derive_rules"]


@pytest.fixture()
def regex_scan(agent):
    import sys

    return sys.modules["pipeline.regex_scan"]


@pytest.fixture()
def call_graph(agent):
    import sys

    pytest.importorskip("tree_sitter")
    pytest.importorskip("tree_sitter_java")
    return sys.modules["pipeline.call_graph"]


def _write_java(tmp_path):
    src = tmp_path / "src" / "main" / "java" / "com" / "example"
    src.mkdir(parents=True)
    (src / "FooDao.java").write_text(DAO, encoding="utf-8")
    (src / "FooService.java").write_text(CALLER, encoding="utf-8")
    return ["src/main/java/com/example/FooDao.java",
            "src/main/java/com/example/FooService.java"]


def _raw(rule_id, pattern, *, derived=True):
    return {
        "id": rule_id,
        "title": rule_id,
        "description": "test",
        "cwe": "CWE-89",
        "severity": "HIGH",
        "owasp": "A03:2021-Injection",
        "languages": ["java"],
        "frameworks": [],
        "pattern": pattern,
        "derived": derived,
    }


WRAPPER = "runtime-sink-sql-runNativeQuery-"  # + 8 hex of owner and signature


def _only(ids, prefix=WRAPPER):
    (match,) = [i for i in ids if i.startswith(prefix)]
    return match


def test_pass_a_emits_wrapper_not_find(tmp_path, call_graph, derive_rules, regex_scan):
    paths = _write_java(tmp_path)
    graph = call_graph.build_call_graph(tmp_path, paths)
    raw = derive_rules.wrappers_from_graph(call_graph.JavaGraphAdapter(graph))
    ids = {r["id"] for r in raw}
    rule_id = _only(ids)
    assert len(rule_id) == len(WRAPPER) + 8
    assert not any("find" in r["id"].lower() for r in raw)

    static = regex_scan.load_rules(_ENGINE_DIR / "rules")
    compiled = derive_rules.compile_derived_rules(raw, static, cap=20)
    by_id = {r.id: r for r in compiled}
    rule = by_id[rule_id]
    assert rule.derived is True
    assert rule.group_by_rule is True
    assert rule.wrapper == {"owner": "com.example.FooDao", "signature": "runNativeQuery(String)",
                            "name": "runNativeQuery", "arity": 1, "tainted_params": [0]}
    hits = regex_scan.scan_text(CALLER, [rule], file_lang="java")
    assert hits
    assert hits[0]["rule"] == rule_id


def test_compile_drops_duplicate_id_and_pattern(derive_rules, regex_scan):
    catalog = [
        regex_scan.RegexRule(_raw("java-runtime-exec", r"\bexec\s*\(", derived=False)),
        regex_scan.RegexRule(_raw("catalog-same-pat", r"\brunNativeQuery\s*\(", derived=False)),
    ]
    raw = [
        _raw("java-runtime-exec", r"\bsomethingElse\s*\("),
        _raw("runtime-llm-clone", r"\brunNativeQuery\s*\("),
        _raw("runtime-llm-ok", r"\bcustomSink\s*\("),
    ]
    out = derive_rules.compile_derived_rules(raw, catalog, cap=20)
    assert [r.id for r in out] == ["runtime-llm-ok"]


def test_compile_drops_redos_and_invalid(derive_rules):
    raw = [
        _raw("runtime-llm-redos", r".*.*foo"),
        _raw("runtime-llm-nested", r"(a+)+"),
        _raw("runtime-llm-bad", r"[unclosed"),
        _raw("runtime-llm-ok", r"\bcustomSink\s*\("),
    ]
    out = derive_rules.compile_derived_rules(raw, [], cap=20)
    assert [r.id for r in out] == ["runtime-llm-ok"]


def test_compile_tracks_dropped_reasons(derive_rules, regex_scan):
    catalog = [regex_scan.RegexRule(_raw("catalog-same-pat", r"\bsame\s*\(", derived=False))]
    raw = [
        _raw("catalog-same-pat", r"\bsomethingElse\s*\("),  # duplicate_id
        _raw("runtime-llm-dup-pattern", r"\bsame\s*\("),  # duplicate_pattern
        _raw("runtime-llm-redos", r".*.*foo"),  # unsafe_pattern:redos
        _raw("runtime-llm-bad", r"[unclosed"),  # compile_error
        _raw("runtime-llm-ok", r"\bcustomSink\s*\("),  # survives
    ]
    dropped: list = []
    out = derive_rules.compile_derived_rules(raw, catalog, cap=20, dropped=dropped)
    assert [r.id for r in out] == ["runtime-llm-ok"]
    assert dropped == ["duplicate_id", "duplicate_pattern", "unsafe_pattern:redos", "compile_error"]


def test_cap_prefers_pass_a_order(derive_rules):
    raw = [_raw(f"runtime-sink-sql-wrap{i:02d}", rf"\bwrap{i:02d}\s*\(") for i in range(25)]
    dropped: list = []
    out = derive_rules.compile_derived_rules(raw, [], cap=20, dropped=dropped)
    assert len(out) == 20
    assert out[0].id == "runtime-sink-sql-wrap00"
    assert out[-1].id == "runtime-sink-sql-wrap19"
    assert dropped == ["over_cap"] * 5


def test_pass_a_ranks_wrappers_by_sink_severity(derive_rules):
    """A capped derive keeps SQL/command wrappers over file/deser ones,
    whatever order the graph lists them in."""
    from types import SimpleNamespace

    hits = [("readConfigFile", "files"), ("loadState", "deser"), ("runScript", "command"),
            ("selectCount", "sql"), ("fetchRows", "jpa")]

    class FakeGraph:
        language = "java"

        def sink_hits(self):
            return [SimpleNamespace(caller_key=name, kind=kind) for name, kind in hits]

        def caller_info(self, key):
            return SimpleNamespace(name=key, is_constructor=False, file=f"src/main/java/{key}.java", display=key)

        def is_test_path(self, path):
            return False

    raw = derive_rules.wrappers_from_graph(FakeGraph())
    assert [r["wrapper_name"] for r in raw] == ["fetchRows", "selectCount", "runScript", "loadState", "readConfigFile"]
    kept = derive_rules.compile_derived_rules(raw, [], cap=3)
    assert [r.id for r in kept] == [
        "runtime-sink-jpa-fetchRows", "runtime-sink-sql-selectCount", "runtime-sink-command-runScript",
    ]


def test_pass_b_mocked_merges(tmp_path, call_graph, derive_rules, regex_scan):
    paths = _write_java(tmp_path)
    graph = call_graph.build_call_graph(tmp_path, paths)
    static = regex_scan.load_rules(_ENGINE_DIR / "rules")

    def fake_llm(*_args, **_kwargs):
        return (
            '[{"id": "extra-sink", "title": "Custom", "description": "x", '
            '"cwe": "CWE-78", "severity": "HIGH", "owasp": "A03:2021-Injection", '
            '"languages": ["java"], "frameworks": [], "pattern": "\\\\bcustomSink\\\\s*\\\\("}]'
        )

    out = derive_rules.derive_runtime_rules(
        graph=call_graph.JavaGraphAdapter(graph), static_rules=static, use_llm=True,
        call_llm_fn=fake_llm, max_rules=20,
    )
    ids = {r.id for r in out}
    assert _only(ids)
    assert "runtime-llm-extra-sink" in ids
    assert all(r.derived for r in out)


def test_pass_b_failed_json_keeps_pass_a(tmp_path, call_graph, derive_rules, regex_scan):
    paths = _write_java(tmp_path)
    graph = call_graph.build_call_graph(tmp_path, paths)
    static = regex_scan.load_rules(_ENGINE_DIR / "rules")
    calls = []

    def fake_llm(*_args, **_kwargs):
        calls.append(1)
        return "this is not json"

    out = derive_rules.derive_runtime_rules(
        graph=call_graph.JavaGraphAdapter(graph), static_rules=static, use_llm=True,
        call_llm_fn=fake_llm, max_rules=20,
    )
    assert len(calls) == 2
    assert {r.id for r in out} == {_only(r.id for r in out)}


def test_use_llm_false_skips_pass_b(tmp_path, call_graph, derive_rules, regex_scan):
    paths = _write_java(tmp_path)
    graph = call_graph.build_call_graph(tmp_path, paths)
    static = regex_scan.load_rules(_ENGINE_DIR / "rules")
    calls = []

    def spy(*_args, **_kwargs):
        calls.append(1)
        return "[]"

    out = derive_rules.derive_runtime_rules(
        graph=call_graph.JavaGraphAdapter(graph), static_rules=static, use_llm=False,
        call_llm_fn=spy, max_rules=20,
    )
    assert calls == []
    assert {r.id for r in out} == {_only(r.id for r in out)}


def test_node_skips_when_disabled(agent, tmp_path):
    state = {
        "local_path": str(tmp_path),
        "derive_runtime_rules": False,
        "_tracer": agent.AgentTrace(verbose=False),
    }
    result = agent.node_derive_runtime_rules(state)
    assert result["derived_rules"] == []


def test_scan_context_merges_derived(agent, derive_rules, regex_scan, tmp_path):
    (tmp_path / "pom.xml").write_text("<project/>\n", encoding="utf-8")
    (tmp_path / "src" / "main" / "java").mkdir(parents=True)
    (tmp_path / "src" / "main" / "java" / "A.java").write_text("class A {}\n", encoding="utf-8")
    extra = derive_rules.compile_derived_rules(
        [_raw("runtime-llm-ok", r"\bcustomSink\s*\(")], [], cap=20,
    )
    state = {
        "local_path": str(tmp_path),
        "derived_rules": extra,
        "llm_analysis": {"tech_stack": "Java", "dependency_summary": {}},
        "_tracer": agent.AgentTrace(verbose=False),
    }
    state.update(agent.node_scan_directory(state))
    state.update(agent.node_analyze_tech_stack(state))
    _root, rules, *_rest = agent._scan_context(state)
    ids = {r.id for r in rules}
    assert "runtime-llm-ok" in ids
    assert "java-runtime-exec" in ids


def test_findings_from_hits_copies_derived(agent, derive_rules):
    import sys

    llm_file_scan = sys.modules["pipeline.llm_file_scan"]
    rules = derive_rules.compile_derived_rules(
        [_raw("runtime-llm-ok", r"\bcustomSink\s*\(")], [], cap=20,
    )
    rules_by_id = {r.id: r for r in rules}
    out = llm_file_scan.findings_from_hits(
        file_path="a.java",
        source_text="customSink(x);\n",
        hits=[{"line": 1, "rule": "runtime-llm-ok", "matched_text": "customSink("}],
        rules_by_id=rules_by_id,
    )
    assert out[0]["derived"] is True
    assert out[0]["kind"] == "regex"
    assert out[0]["group_by_rule"] is False


# --- SAST-02-060: wrapper rules keyed by method identity ------------------------------

IDENTITY_FILES = {
    "OrderDao.java": """
package com.example;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

public class OrderDao {
    private Connection conn;

    public ResultSet runFilter(String where) throws Exception {
        Statement st = conn.createStatement();
        return st.executeQuery("SELECT * FROM orders WHERE " + where);
    }

    public ResultSet loadOrder(long orderId) throws Exception {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM orders WHERE id = ?");
        ps.setLong(1, orderId);
        return ps.executeQuery();
    }

    public ResultSet loadEverything() throws Exception {
        Statement st = conn.createStatement();
        return st.executeQuery("SELECT * FROM orders");
    }
}
""",
    "ArchiveDao.java": """
package com.example;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class ArchiveDao {
    private Connection conn;

    public ResultSet runFilter(String where) throws Exception {
        Statement st = conn.createStatement();
        return st.executeQuery("SELECT * FROM archive WHERE " + where);
    }
}
""",
}


def _identity_graph(tmp_path, call_graph):
    src = tmp_path / "src" / "main" / "java" / "com" / "example"
    src.mkdir(parents=True)
    paths = []
    for name, text in IDENTITY_FILES.items():
        (src / name).write_text(text, encoding="utf-8")
        paths.append(f"src/main/java/com/example/{name}")
    return call_graph.build_call_graph(tmp_path, paths)


def test_only_wrappers_whose_parameter_reaches_sql_text_derive_a_rule(tmp_path, call_graph, derive_rules):
    graph = _identity_graph(tmp_path, call_graph)
    stats = {}
    raw = derive_rules.wrappers_from_graph(call_graph.JavaGraphAdapter(graph), stats=stats)
    names = sorted((r["wrapper_owner"], r["wrapper_name"]) for r in raw)
    # loadOrder binds its value; loadEverything takes no argument.
    assert names == [("com.example.ArchiveDao", "runFilter"), ("com.example.OrderDao", "runFilter")]
    assert stats == {"candidates": 4, "derived": 2}
    assert all(r["tainted_params"] == [0] for r in raw)


def test_same_named_wrappers_of_different_owners_are_two_compiled_rules(tmp_path, call_graph, derive_rules, regex_scan):
    graph = _identity_graph(tmp_path, call_graph)
    raw = derive_rules.wrappers_from_graph(call_graph.JavaGraphAdapter(graph))
    static = regex_scan.load_rules(_ENGINE_DIR / "rules")
    compiled = derive_rules.compile_derived_rules(raw, static, cap=20)
    assert len(compiled) == 2 and len({r.id for r in compiled}) == 2
    assert {r.wrapper["owner"] for r in compiled} == {"com.example.OrderDao", "com.example.ArchiveDao"}


def test_derivation_is_byte_stable_across_runs(tmp_path, call_graph, derive_rules, regex_scan, agent):
    import sys

    lfs = sys.modules["pipeline.llm_file_scan"]
    static = regex_scan.load_rules(_ENGINE_DIR / "rules")

    def derive_and_prompt():
        graph = _identity_graph(tmp_path / str(len(list(tmp_path.iterdir()))), call_graph)
        rules = derive_rules.derive_runtime_rules(graph=call_graph.JavaGraphAdapter(graph), static_rules=static)
        catalog = [{"id": r.id, "title": r.title, "cwe": r.cwe, "severity": r.severity,
                    "description": r.description} for r in rules]
        return [r.id for r in rules], lfs.build_system_prompt(catalog, "maven-java")

    first, second = derive_and_prompt(), derive_and_prompt()
    assert first[0] == second[0] and first[1] == second[1]

"""pipeline/reachability.py — Joern paths as evidence for other tiers' findings,
the corroborate_flows node, grouped-confirmation prompts and the DB writer.

Uses the real flows.sc fixtures from tests/fixtures/joern/ (see test_joern.py
for the sources they were captured from; line numbers matter)."""

import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("langgraph")

from app.config import settings  # noqa: E402
from app.db import init_db  # noqa: E402
from app.models import Finding, Project, Scan  # noqa: E402
from app.services.agent_bridge import _load_agent_module  # noqa: E402
from app.services.scan_runner import _make_findings_writer, _make_reachability_updates_writer  # noqa: E402

_ENGINE_DIR = Path(__file__).resolve().parents[1] / "sast_engine"
_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "joern"

DAO = "src/main/java/com/x/UserDao.java"
EXTRA = "src/main/java/com/x/ExtraController.java"


@pytest.fixture()
def agent(monkeypatch):
    monkeypatch.setattr(settings, "sast_framework_path", str(_ENGINE_DIR))
    sys.modules.pop("sast_scan_agent", None)
    return _load_agent_module()


@pytest.fixture()
def rc(agent):
    return sys.modules["pipeline.reachability"]


def _fixture(name: str) -> dict:
    return json.loads((_FIXTURES / name).read_text(encoding="utf-8"))


def _index(rc):
    return rc.build_sink_index([_fixture("flows_java_sqli.json"), _fixture("flows_java_extra.json"), None])


def test_every_taint_spec_kind_maps_to_cwes(rc):
    spec = json.loads((_ENGINE_DIR / "joern" / "taint_spec.json").read_text(encoding="utf-8"))
    assert set(spec["kind_order"]) <= set(rc.SINK_KIND_CWES)


def test_index_keys_on_sink_line_and_marks_sanitized_paths(rc):
    index = _index(rc)
    (ev,) = index[(DAO, 8)]
    assert ev["status"] == rc.STATUS_PATH and ev["sink_kind"] == "sql"
    assert ev["source"] == {"file": "src/main/java/com/x/UserController.java", "line": 7,
                            "code": "@RequestParam String id"}
    assert ev["taint_path"][0]["code"] == "@RequestParam String id"
    assert index[(EXTRA, 38)][0]["status"] == rc.STATUS_SANITIZED
    assert index[(EXTRA, 32)][0]["status"] == rc.STATUS_PATH
    assert index[(EXTRA, 32)][0]["guards"]


def test_long_paths_keep_source_and_sink(rc):
    elements = [{"file": "a.py", "line": i, "method": "m", "code": f"v{i}"} for i in range(1, 31)]
    ev = rc.evidence_from_raw({"sink_kind": "sql", "elements": elements})
    assert len(ev["taint_path"]) == rc.MAX_PATH_STEPS and ev["steps_total"] == 30
    assert ev["taint_path"][0]["code"] == "v1" and ev["taint_path"][-1]["code"] == "v30"
    assert "18 intermediate step(s) omitted" in rc.render_evidence(ev)


def test_match_needs_same_file_nearby_line_and_fitting_cwe(rc):
    index = _index(rc)
    base = {"file_path": DAO, "line": 8, "cwe": "CWE-89"}
    assert rc.match(base, index)["sink_kind"] == "sql"
    assert rc.match({**base, "line": 10}, index) is not None  # within ±2
    assert rc.match({**base, "line": 11}, index) is None
    assert rc.match({**base, "cwe": "CWE-79"}, index) is None  # wrong sink kind
    assert rc.match({**base, "cwe": ""}, index) is None
    assert rc.match({**base, "file_path": "./" + DAO}, index) is not None
    # Log injection at L16 must not vouch for the response-body finding at L17
    # and vice versa: kinds are matched through the CWE.
    assert rc.match({"file_path": EXTRA, "line": 16, "cwe": "CWE-117"}, index)["sink_kind"] == "log"
    assert rc.match({"file_path": EXTRA, "line": 16, "cwe": "CWE-209"}, index)["sink_kind"] == "response_body"


def test_unsanitized_evidence_wins(rc):
    def ev(status, steps):
        return {"status": status, "sink_kind": "sql", "steps_total": steps}
    index = {("a.java", 5): [ev(rc.STATUS_SANITIZED, 2), ev(rc.STATUS_PATH, 9), ev(rc.STATUS_PATH, 3)]}
    best = rc.match({"file_path": "a.java", "line": 5, "cwe": "89"}, index)
    assert best["status"] == rc.STATUS_PATH and best["steps_total"] == 3


def test_confidence_only_ever_rises_for_true_positives_with_a_clean_path(rc):
    path = {"status": rc.STATUS_PATH}
    tp = {"verdict": "true_positive", "confidence": 0.6, "reachability": path}
    assert rc.apply_confidence(tp) and tp["confidence"] == rc.REACHABLE_CONFIDENCE_FLOOR
    high = {"verdict": "true_positive", "confidence": 0.97, "reachability": path}
    assert not rc.apply_confidence(high) and high["confidence"] == 0.97
    for verdict in ("false_positive", "unverified"):
        f = {"verdict": verdict, "confidence": 0.2, "reachability": path}
        assert not rc.apply_confidence(f) and f["confidence"] == 0.2
    sanitized = {"verdict": "true_positive", "confidence": 0.6, "reachability": {"status": rc.STATUS_SANITIZED}}
    assert not rc.apply_confidence(sanitized) and sanitized["confidence"] == 0.6
    bare = {"verdict": "true_positive", "confidence": 0.6}
    assert not rc.apply_confidence(bare) and bare["confidence"] == 0.6


def test_corroborate_node_annotates_tiers_and_persists(agent, rc):
    deep = {"file_path": DAO, "rule_id": "llm-extra", "line": 8, "cwe": "CWE-89",
            "verdict": "true_positive", "confidence": 0.7, "kind": "llm"}
    unmatched = {"file_path": DAO, "rule_id": "weak-hash", "line": 8, "cwe": "CWE-328",
                 "verdict": "true_positive", "confidence": 0.7, "kind": "llm"}
    # Regex findings carry no file_path of their own.
    regex = {"rule_id": "sqli-concat", "line": 32, "cwe": "CWE-89",
             "verdict": "unverified", "confidence": None, "kind": "regex"}
    writes = []
    state = {
        "_tracer": agent.AgentTrace(verbose=False),
        "reachability_index": _index(rc),
        "scan_results": {"files": [{"file_path": DAO, "findings": [deep, unmatched]}]},
        "triage_scan_results": {"files": [{"file_path": EXTRA, "findings": [regex]}]},
        "reachability_updates_writer": lambda path, items: writes.append((path, items)),
    }
    out = agent.node_corroborate_flows(state)

    assert deep["reachability"]["status"] == rc.STATUS_PATH
    assert deep["confidence"] == rc.REACHABLE_CONFIDENCE_FLOOR
    assert "reachability" not in unmatched and unmatched["confidence"] == 0.7
    assert regex["reachability"]["sink_kind"] == "sql" and regex["confidence"] is None
    assert set(out) == {"scan_results", "triage_scan_results"}
    assert sorted(p for p, _ in writes) == sorted([DAO, EXTRA])
    assert writes[0][1][0]["rule_id"] in {"llm-extra", "sqli-concat"}

    report_counts = agent._reachability_counts(
        state["scan_results"]["files"] + state["triage_scan_results"]["files"]
    )
    assert report_counts == {"corroborated": 2, "sanitized": 0, "entry_reachable": 0,
                             "by_kind": {"llm": 1, "regex": 1}}


def _call_graph_flow(cg, sink_file="src/main/java/com/x/FooDao.java", sink_line=14):
    def hop(file, method, line, role, label):
        return cg.FlowHop(file=file, method=method, fqcn="com.x." + method, name=method.split(".")[-1],
                          line=line, start_line=1, end_line=40, body="", role=role, label=label)
    return cg.Flow(
        hops=[hop("src/main/java/com/x/FooController.java", "FooController.get", 9, "source", "get(...)"),
              hop("src/main/java/com/x/FooService.java", "FooService.load", 12, "hop", "load(...)"),
              hop(sink_file, "FooDao.find", sink_line, "sink", "stmt.executeQuery(sql)")],
        entry_tier="spring", sink_kind="sql", authenticated=False,
        files=["src/main/java/com/x/FooController.java", "src/main/java/com/x/FooService.java", sink_file],
    )


def test_call_graph_flows_are_weaker_evidence_that_never_boosts(agent, rc):
    cg = sys.modules["pipeline.call_graph"]
    index = rc.build_sink_index([], [_call_graph_flow(cg)])
    finding = {"file_path": "src/main/java/com/x/FooDao.java", "line": 14, "cwe": "CWE-89",
               "verdict": "true_positive", "confidence": 0.6}
    ev = rc.match(finding, index)
    assert ev["status"] == rc.STATUS_ENTRY_REACHABLE
    assert [s["method"] for s in ev["taint_path"]] == ["FooController.get", "FooService.load", "FooDao.find"]
    finding["reachability"] = ev
    assert not rc.apply_confidence(finding) and finding["confidence"] == 0.6
    text = rc.render_evidence(ev)
    assert text.startswith("Call-graph evidence (sql sink, no auth annotation seen)")
    assert "Method level only" in text and "FooDao.find -> stmt.executeQuery(sql)" in text


def test_joern_path_beats_call_graph_chain_at_the_same_sink(agent, rc):
    cg = sys.modules["pipeline.call_graph"]
    index = rc.build_sink_index([_fixture("flows_java_sqli.json")], [_call_graph_flow(cg, DAO, 8)])
    assert {e["status"] for e in index[(DAO, 8)]} == {rc.STATUS_PATH, rc.STATUS_ENTRY_REACHABLE}
    assert rc.match({"file_path": DAO, "line": 8, "cwe": "CWE-89"}, index)["status"] == rc.STATUS_PATH
    assert rc.evidence_rank(None) > rc.evidence_rank({"status": rc.STATUS_ENTRY_REACHABLE}) \
        > rc.evidence_rank({"status": rc.STATUS_SANITIZED}) > rc.evidence_rank({"status": rc.STATUS_PATH})


def test_corroborate_works_without_joern_from_the_call_graph_alone(agent, rc):
    cg = sys.modules["pipeline.call_graph"]
    regex = {"rule_id": "sqli-concat", "line": 15, "cwe": "CWE-89", "verdict": "unverified", "kind": "regex"}
    state = {
        "_tracer": agent.AgentTrace(verbose=False),
        "reachability_index": rc.build_sink_index([], [_call_graph_flow(cg)]),
        "triage_scan_results": {"files": [{"file_path": "src/main/java/com/x/FooDao.java", "findings": [regex]}]},
    }
    agent.node_corroborate_flows(state)
    assert regex["reachability"]["status"] == rc.STATUS_ENTRY_REACHABLE
    counts = agent._reachability_counts(state["triage_scan_results"]["files"])
    assert counts["entry_reachable"] == 1 and counts["corroborated"] == 0


def test_corroborate_node_is_a_noop_without_an_index(agent):
    assert agent.node_corroborate_flows({"_tracer": agent.AgentTrace(verbose=False)}) == {}


@pytest.mark.parametrize("parallel", [True, False])
def test_graph_routes_through_corroborate(agent, parallel):
    graph = agent.build_graph(parallel=parallel).get_graph()
    edges = {(e.source, e.target) for e in graph.edges}
    assert ("corroborate_flows", "group_triage_findings") in edges
    assert any(t == "corroborate_flows" for _, t in edges)


def test_group_confirm_prompt_carries_evidence_and_floor(agent, rc, tmp_path):
    lfs = sys.modules["pipeline.llm_file_scan"]
    (tmp_path / "A.java").write_text("a\nb\nc\n", encoding="utf-8")
    (tmp_path / "B.java").write_text("a\nb\nc\n", encoding="utf-8")
    ev = _index(rc)[(DAO, 8)][0]
    plain = {"rule_id": "sqli-concat", "line": 2, "cwe": "CWE-89", "severity": "HIGH",
             "matched_text": "b", "verdict": "unverified", "kind": "regex"}
    reached = {**plain, "reachability": ev}
    prompts = []

    def fake_llm(system, user, **kwargs):
        prompts.append(user)
        return json.dumps({"decisions": [{"verdict": "true_positive", "confidence": 0.5,
                                          "verdict_reason": "concatenated"}]})

    writes = []
    lfs.group_confirm_unverified_findings(
        file_results=[{"file_path": "A.java", "findings": [plain]},
                      {"file_path": "B.java", "findings": [reached]}],
        repo_root=tmp_path, rules=[], call_llm_fn=fake_llm,
        verdict_updates_writer=lambda p, u: writes.append((p, u)),
    )
    (user,) = prompts
    # The occurrence with a path is the representative, and its path is shown.
    assert "Representative occurrence — B.java" in user
    assert "Dataflow evidence (Joern, sql sink)" in user and "@RequestParam String id" in user
    # Group verdict applies to both; only the reached one gets the floor.
    assert plain["confidence"] == 0.5
    assert reached["confidence"] == rc.REACHABLE_CONFIDENCE_FLOOR
    # file_path is stamped from the file result, so the writer gets real paths.
    assert sorted(p for p, _ in writes) == ["A.java", "B.java"]

    system, user = lfs.build_group_confirm_prompt(
        representative=plain, occurrence_paths=["A.java"], source_text="a\nb\n", rule=None,
    )
    assert "Dataflow evidence" not in user


def test_joern_flow_findings_carry_their_path(agent, rc, tmp_path):
    jf = sys.modules["pipeline.joern_flows"]
    fv = sys.modules["pipeline.flow_verify"]
    controller = tmp_path / "src/main/java/com/x/UserController.java"
    controller.parent.mkdir(parents=True)
    controller.write_text("\n".join(f"// {i}" for i in range(1, 12)), encoding="utf-8")
    (tmp_path / DAO).write_text("\n".join(f"// {i}" for i in range(1, 12)), encoding="utf-8")
    flows, _ = jf.flows_from_joern([_fixture("flows_java_sqli.json")], tmp_path, cap=5)
    (flow,) = flows

    findings = fv._findings_for_flow(
        flow,
        [{"verdict": "true_positive", "cwe": "CWE-89", "title": "SQLi", "confidence": 0.6,
          "line": 8, "verdict_reason": "concat", "severity": "HIGH"}],
        suppress_no_cwe=True, suppress_http_findings=False,
        suppress_low_confidence_false_positives=False,
    )
    (finding,) = findings
    assert finding["reachability"]["status"] == rc.STATUS_PATH
    assert finding["reachability"]["taint_path"][0]["code"] == "@RequestParam String id"
    assert finding["confidence"] == rc.REACHABLE_CONFIDENCE_FLOOR


def test_reachability_writer_updates_rows_in_place(tmp_path):
    SessionLocal = init_db(f"sqlite:///{(tmp_path / 'reach.db').as_posix()}")
    with SessionLocal() as db:
        project = Project(name="reach", default_git_url="https://github.com/org/repo.git")
        db.add(project)
        db.commit()
        scan = Scan(project_id=project.id, git_url=project.default_git_url)
        db.add(scan)
        db.commit()
        scan_id = scan.id
    base = {"severity": "HIGH", "cwe": "CWE-89", "rule_id": "llm-extra", "title": "SQLi",
            "file_path": DAO, "snippet": "x", "kind": "llm", "verdict": "true_positive",
            "confidence": 0.6}
    _make_findings_writer(scan_id)(DAO, [{**base, "line": 8}, {**base, "line": 20}])

    evidence = {"status": "path", "sink_kind": "sql", "taint_path": [{"file": DAO, "line": 8, "code": "q"}]}
    _make_reachability_updates_writer(scan_id)(DAO, [
        {"rule_id": "llm-extra", "line": 8, "reachability": evidence, "confidence": 0.9},
    ])

    with SessionLocal() as db:
        rows = {r.line: r for r in db.query(Finding).filter(Finding.scan_id == scan_id).all()}
    assert len(rows) == 2
    assert rows[8].reachability == evidence and rows[8].confidence == 0.9
    assert rows[20].reachability is None and rows[20].confidence == 0.6


def test_discover_flows_indexes_call_graph_flows_past_the_verify_cap(agent, rc, monkeypatch):
    cg = sys.modules["pipeline.call_graph"]
    flows = [_call_graph_flow(cg, sink_line=line) for line in (14, 20, 30)]
    seen_caps = []

    class FakeGraph:
        entry_tier = "spring"
        flows_discovered_total = 3

    def fake_discover(graph, *, cap, max_hop_depth):
        seen_caps.append(cap)
        return flows[:cap]

    monkeypatch.setattr(cg, "discover_flows", fake_discover)
    out = agent.node_discover_flows({
        "_tracer": agent.AgentTrace(verbose=False),
        "call_graph": {"_graph": FakeGraph(), "_graph_lang": "java"},
        "flow_verify_cap": 1,
        "joern_dataflow": False,
    })
    assert len(out["flow_candidates"]) == 1  # the LLM still gets only the cap
    assert seen_caps == [sys.maxsize]
    dao = "src/main/java/com/x/FooDao.java"
    assert {line for (path, line) in out["reachability_index"] if path == dao} == {14, 20, 30}

"""Entry points and proof of inactive code (SAST-02-070): "no callers" is a
claim the call graph proves from a complete model of entry points —
annotations, deployment descriptors, EJB business interfaces, JMS and
reflection — with full parse coverage, or it is `unknown`."""

import shutil
import sys
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_java")
pytest.importorskip("boto3", reason="pipeline modules import llm_client")

_ENGINE = Path(__file__).resolve().parents[1] / "sast_engine"
if str(_ENGINE) not in sys.path:
    sys.path.insert(0, str(_ENGINE))

from pipeline import call_graph as cg  # noqa: E402
from pipeline import entry_points as ep  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).parent / "fixtures" / "entry_points"


def _build(root=ROOT):
    java = sorted(str(p.relative_to(root)) for p in root.rglob("*.java"))
    xml = sorted(str(p.relative_to(root)) for p in root.rglob("*.xml"))
    return cg.build_call_graph(root, java, descriptor_paths=xml)


def _key(graph, owner, name):
    return next(k for k, m in graph.methods.items() if m.fqcn.endswith(owner) and m.name == name)


@pytest.fixture(scope="module")
def graph():
    return _build()


def test_descriptor_parsing():
    entries = ep.parse_descriptor("WEB-INF/web.xml", (ROOT / "src/main/webapp/WEB-INF/web.xml").read_text())
    assert entries.classes == {"com.acme.web.LegacyEndpoint": "web.xml"}
    ejb = ep.parse_descriptor("META-INF/ejb-jar.xml", (ROOT / "src/main/resources/META-INF/ejb-jar.xml").read_text())
    assert ejb.interfaces == {"com.acme.ejb.OrderRemote": {"com.acme.ejb.OrderBean"}}
    spring = ep.parse_descriptor("spring-context.xml", (ROOT / "src/main/resources/spring-context.xml").read_text())
    assert ("com.acme.dao.Cleaner", "warmUp") in spring.methods


def test_an_entity_declaring_descriptor_is_a_parse_failure():
    evil = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e "boom">]><web-app>&e;</web-app>'
    assert ep.parse_descriptor("WEB-INF/web.xml", evil).failed == ["WEB-INF/web.xml"]


@pytest.mark.parametrize("owner, name, source", [
    ("LegacyEndpoint", "process", "descriptor"),   # a servlet in web.xml only
    ("OrderBean", "place", "descriptor"),          # ejb-jar.xml bean
    ("InventoryBean", "count", "interface"),       # implements a @Remote interface
    ("OrderListener", "onMessage", "jms"),
    ("Plugin", "run", "reflection"),               # Class.forName("...Plugin")
    ("Cleaner", "warmUp", "descriptor"),           # Spring XML init-method
    ("Loader", "main", "annotation"),
])
def test_entry_point_sources(graph, owner, name, source):
    assert graph.entry_points[_key(graph, owner, name)] == source


def test_an_ejb_remote_interface_resolves_to_its_bean(graph):
    assert graph.impls_of["com.acme.ejb.OrderRemote"] == ["com.acme.ejb.OrderBean"]


def test_entry_points_are_counted_by_source(graph):
    counts = cg.entry_point_counts(graph)
    assert counts["descriptor"] >= 3 and counts["jms"] == 1 and counts["reflection"] >= 1


def test_a_private_method_nothing_calls_is_unreferenced(graph):
    status, checked = cg.reachability_status(graph, _key(graph, "LegacyDao", "unusedQuery"))
    assert status == "unreferenced"
    assert any("parsed" in c for c in checked)


def test_a_method_called_from_a_field_initializer_is_not_unreferenced(graph):
    status, reasons = cg.reachability_status(graph, _key(graph, "LegacyDao", "initQuery"))
    assert status == "unknown" and "initQuery(" in reasons[0]


def test_a_method_with_a_caller_is_not_unreferenced(graph):
    assert cg.reachability_status(graph, _key(graph, "LegacyDao", "usedQuery"))[0] != "unreferenced"


def test_a_remote_interface_implementation_is_reachable(graph):
    assert cg.reachability_status(graph, _key(graph, "InventoryBean", "count"))[0] == "reachable"


def test_one_file_failing_to_parse_makes_it_unknown(tmp_path):
    root = tmp_path / "repo"
    shutil.copytree(ROOT, root)
    (root / "src/main/java/com/acme/dao/Broken.java").write_text("package com.acme.dao; class Broken { void x( }")
    broken = _build(root)
    status, reasons = cg.reachability_status(broken, _key(broken, "LegacyDao", "unusedQuery"))
    assert status == "unknown" and "failed to parse" in reasons[0]


def test_a_partial_graph_proves_nothing(graph):
    from pipeline import sql_semantics as sq

    text = (ROOT / "src/main/java/com/acme/dao/LegacyDao.java").read_text()
    single = sq.SqlSummaries.for_file("src/main/java/com/acme/dao/LegacyDao.java", text).graph
    assert cg.reachability_status(single, _key(single, "LegacyDao", "unusedQuery"))[0] == "unknown"


# --- inactive code through the SQL check --------------------------------------------

def _sql_finding(graph, line, **over):
    from pipeline import sql_semantics as sq
    from pipeline.validators import ValidatorContext
    from pipeline.validators import sql_binding as sb

    rel = "src/main/java/com/acme/dao/LegacyDao.java"
    text = (ROOT / rel).read_text()
    finding = {"file_path": rel, "line": line, "rule_id": "java-jdbc-statement-exec-variable",
               "cwe": "CWE-89", "verdict": "true_positive", **over}
    summaries = sq.SqlSummaries(graph, lambda p: (ROOT / p).read_text())
    facts = {}
    result = sb.sql_binding(finding, facts, ValidatorContext(file_text={rel: text}, call_graph=graph, sql=summaries))
    return result, facts


def test_unsafe_sql_in_an_unreferenced_method_is_inactive_not_dismissed(graph):
    result, facts = _sql_finding(graph, 12)  # unusedQuery's executeQuery
    assert result.outcome == "positive_fact" and result.issue_class == "inactive"
    assert "nothing calls it" in result.proof
    assert facts["reachability_status"] == "unreferenced"


def test_unsafe_sql_in_a_referenced_method_keeps_its_class(graph):
    result, facts = _sql_finding(graph, 17)  # usedQuery's executeQuery
    assert result.outcome == "positive_fact" and result.issue_class is None
    assert facts["reachability_status"] != "unreferenced"


def test_the_no_callers_check_stands_down_only_on_a_proof():
    from pipeline import explanation_check as ec

    finding = {"verdict": "true_positive", "verdict_reason": "Concatenated, though the method has no callers.",
               "line": 1, "sink": ""}
    assert any(c["check"] == ec.CHECK_CALLERS for c in ec.check_explanation(finding, {}, "x"))
    assert not any(c["check"] == ec.CHECK_CALLERS
                   for c in ec.check_explanation(finding, {"reachability_status": "unreferenced"}, "x"))


def test_a_public_method_nobody_calls_is_never_proven_unreferenced(tmp_path):
    # It may be called from a JSP, an EL expression, a framework config or
    # another module: callers this graph cannot see.
    (tmp_path / "Lone.java").write_text("package a; public class Lone { public void unused() {} }")
    graph = cg.build_call_graph(tmp_path, ["Lone.java"])
    status, reasons = cg.reachability_status(graph, next(iter(graph.methods)))
    assert status == "unknown" and "private" in reasons[0]

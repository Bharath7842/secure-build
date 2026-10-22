"""Semantic group keys (SAST-01-060): the engine's grouping key and the app's
report key must agree, and members whose resolved facts differ must not share
one group."""

import sys
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_java")
pytest.importorskip("boto3", reason="pipeline modules import llm_client")

_ENGINE = Path(__file__).resolve().parents[1] / "sast_engine"
if str(_ENGINE) not in sys.path:
    sys.path.insert(0, str(_ENGINE))

from pipeline import finding_facts, llm_file_scan as lfs, occurrence_facts as of  # noqa: E402

from app.models import Finding  # noqa: E402
from app.services import occurrence as app_occurrence  # noqa: E402
from app.services.scan_export import _finding_group_key  # noqa: E402

pytestmark = pytest.mark.unit


def _lines(text, needle):
    return next(i for i, line in enumerate(text.splitlines(), 1) if needle in line)


def _regex_finding(path, text, needle, rule_id, **extra):
    line = _lines(text, needle)
    col = text.splitlines()[line - 1].index(needle.strip().split("(")[0].split(".")[-1])
    f = {
        "rule_id": rule_id, "file_path": path, "line": line, "verdict": "unverified",
        "severity": "MEDIUM", "cwe": "CWE-89", "title": "t", "matched_text": needle.strip()[:60],
        "kind": "regex", "col_start": col, "col_end": col + 3, **extra,
    }
    finding_facts.attach_facts(f, text, file_path=path)
    return f


def _orm(f):
    return Finding(
        verdict=f["verdict"], rule_id=f["rule_id"], kind=f.get("kind"), group_by_rule=f.get("group_by_rule"),
        matched_text=f.get("matched_text"), title=f.get("title"), cwe=f.get("cwe"), facts=f.get("facts"),
    )


# --- the two key functions agree -----------------------------------------------------

JAVA = """\
package com.acme;

public class Q {
    void run(java.sql.Statement stmt, String s, int n, Exception ex, java.util.Calendar cal) throws Exception {
        stmt.executeQuery("a" + s);
        stmt.executeQuery("a" + n);
        log.error("x", ex.toString());
    }
}
"""


@pytest.mark.parametrize("group_by_rule", [False, True])
@pytest.mark.parametrize("rule_id", ["java-jdbc-statement-exec-variable", "llm-extra", ""])
@pytest.mark.parametrize("needle", ['stmt.executeQuery("a" + s);', 'stmt.executeQuery("a" + n);'])
@pytest.mark.parametrize("with_facts", [True, False])
def test_engine_and_report_keys_share_everything_after_the_verdict(group_by_rule, rule_id, needle, with_facts):
    f = _regex_finding("Q.java", JAVA, needle, rule_id, group_by_rule=group_by_rule)
    if not with_facts:
        f.pop("facts", None)
    assert _finding_group_key(_orm(f))[1:] == lfs.group_key_for_finding(f)


@pytest.mark.parametrize("path, needle", [("Q.java", 'stmt.executeQuery("a" + s);'), ("Q.java", "log.error")])
def test_the_two_signature_functions_are_the_same(path, needle):
    f = _regex_finding(path, JAVA, needle, "r")
    assert of.semantic_signature(f["facts"]) == app_occurrence.semantic_signature(f["facts"])
    for facts in (None, {}, {"in_comment": True}, {"is_declaration": True, "is_stub": True,
                                                   "enclosing": {"method": "m", "arity": 1}}):
        assert of.semantic_signature(facts) == app_occurrence.semantic_signature(facts)


# --- the required splits --------------------------------------------------------------

def _groups(findings):
    return lfs.group_unverified_findings([{"file_path": f["file_path"], "findings": [f]} for f in findings])


def test_62_a_dao_call_and_a_dto_call_with_one_name_are_two_groups():
    text = """\
package com.acme;
public class Port {
    void a(PortDao dao, XmlPortMsg xmlPortMsg) {
        long x = dao.getPortID(5L);
        long y = xmlPortMsg.getPortID();
    }
}
"""
    rule = "runtime-sink-sql-getPortID"
    a = _regex_finding("Port.java", text, "dao.getPortID(5L)", rule, group_by_rule=True, matched_text="getPortID(")
    b = _regex_finding("Port.java", text, "xmlPortMsg.getPortID()", rule, group_by_rule=True, matched_text="getPortID(")
    assert _groups([a, b])["group_count"] == 2


def test_78_numeric_and_concatenated_arguments_are_two_groups():
    a = _regex_finding("Q.java", JAVA, 'stmt.executeQuery("a" + s);', "r", matched_text="executeQuery(")
    b = _regex_finding("Q.java", JAVA, 'stmt.executeQuery("a" + n);', "r", matched_text="executeQuery(")
    summary = _groups([a, b])
    assert summary["group_count"] == 2 and summary["construct_count"] == 1
    assert {g["signature"] for g in summary["groups"]} == {
        of.semantic_signature(a["facts"]), of.semantic_signature(b["facts"]),
    }


def test_284_a_calendar_receiver_and_a_throwable_receiver_are_two_groups():
    text = """\
package com.acme;
public class T {
    void run(Exception ex, java.util.Calendar cal) {
        log.error("x", ex.toString());
        log.error("x", cal.toString());
    }
}
"""
    a = _regex_finding("T.java", text, 'ex.toString()', "logger-exception-tostring", group_by_rule=True, matched_text="toString")
    b = _regex_finding("T.java", text, 'cal.toString()', "logger-exception-tostring", group_by_rule=True, matched_text="toString")
    assert _groups([a, b])["group_count"] == 2


def test_39_a_stub_and_a_real_implementation_are_two_groups():
    stub = "package a;\npublic class S implements Api {\n    public boolean isOk(String n) { return false; }\n}\n"
    impl = "package a;\npublic class I implements Api {\n    public boolean isOk(String n) {\n        return dao.find(n);\n    }\n}\n"
    rule = "runtime-sink-sql-isOk"
    a = _regex_finding("S.java", stub, "isOk(String n)", rule, group_by_rule=True, matched_text="isOk(")
    b = _regex_finding("I.java", impl, "isOk(String n)", rule, group_by_rule=True, matched_text="isOk(")
    assert _groups([a, b])["group_count"] == 2


# --- what must not split ---------------------------------------------------------------

def test_the_same_construct_in_100_files_is_one_group():
    findings = []
    for i in range(100):
        f = _regex_finding(f"F{i}.java", JAVA, 'stmt.executeQuery("a" + s);', "r", matched_text="executeQuery(")
        findings.append(f)
    assert _groups(findings)["group_count"] == 1


def test_members_without_facts_group_together_but_never_with_resolved_ones():
    resolved = [_regex_finding(f"F{i}.java", JAVA, 'stmt.executeQuery("a" + s);', "r", matched_text="executeQuery(")
                for i in range(3)]
    bare = []
    for i in range(3):
        f = _regex_finding(f"G{i}.java", JAVA, 'stmt.executeQuery("a" + s);', "r", matched_text="executeQuery(")
        f.pop("facts")
        bare.append(f)
    summary = _groups(resolved + bare)
    assert summary["group_count"] == 2
    assert sorted(g["occurrence_count"] for g in summary["groups"]) == [3, 3]
    assert "unresolved" in {g["signature"] for g in summary["groups"]}

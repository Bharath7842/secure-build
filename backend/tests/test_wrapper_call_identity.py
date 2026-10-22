"""The `wrapper_call_identity` validator (SAST-02-060): a derived
`runtime-sink-*` rule's regex matches every same-named call; only a call that
resolves to the wrapper's owner and arity, with a non-constant argument at a
tainted parameter, can carry its taint."""

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
from pipeline import occurrence_facts as of  # noqa: E402
from pipeline.validators import ValidatorContext  # noqa: E402
from pipeline.validators.wrapper_call_identity import wrapper_call_identity  # noqa: E402

pytestmark = pytest.mark.unit

WRAPPER = {"owner": "com.acme.PortDao", "signature": "getPortID(String)", "name": "getPortID",
           "arity": 1, "tainted_params": [0]}

FILES = {
    "PortDao.java": """package com.acme;
public class PortDao implements PortLookup {
    public String getPortID(String number) { return number; }
}
""",
    "PortLookup.java": """package com.acme;
public interface PortLookup {
    String getPortID(String number);
}
""",
    "XmlPortMsg.java": """package com.acme;
public class XmlPortMsg {
    private String portId;
    public String getPortID() { return portId; }
}
""",
    "Callers.java": """package com.acme;
public class Callers {
    private PortDao dao;
    private PortLookup lookup;
    private XmlPortMsg xmlPortMsg;
    private Unknown mystery;

    public Object fromMessage() { return xmlPortMsg.getPortID(); }
    public Object constant() { return dao.getPortID("5"); }
    public Object tainted(String number) { return dao.getPortID(number); }
    public Object viaInterface(String number) { return lookup.getPortID(number); }
    public Object unresolved(String number) { return mystery.getPortID(number); }
}
""",
}


@pytest.fixture()
def ctx(tmp_path):
    for name, text in FILES.items():
        (tmp_path / name).write_text(text)
    graph = cg.build_call_graph(tmp_path, list(FILES))
    return ValidatorContext(repo_root=tmp_path, call_graph=graph)


def _decide(ctx, needle):
    text = FILES["Callers.java"]
    line = next(n for n, c in enumerate(text.splitlines(), 1) if needle in c)
    start = text.splitlines()[line - 1].index("getPortID")
    facts = of.facts_for("Callers.java", text, line, (start, start + len("getPortID(")))
    finding = {"rule_id": "runtime-sink-sql-getPortID-1a2b3c4d", "file_path": "Callers.java", "line": line,
               "wrapper": WRAPPER}
    return wrapper_call_identity(finding, facts, ctx)


@pytest.mark.parametrize("needle, outcome, tag", [
    ("fromMessage", "negative_proof", "wrapper_identity_mismatch"),  # #62: same name, other owner
    ("constant()", "negative_proof", "wrapper_arg_constant"),
    ("tainted(", "no_opinion", None),
    ("viaInterface", "no_opinion", None),  # an interface the wrapper's class implements
    ("unresolved", "no_opinion", None),
])
def test_identity(ctx, needle, outcome, tag):
    result = _decide(ctx, needle)
    assert (result.outcome, result.reason_tag) == (outcome, tag), result


def test_a_finding_without_a_wrapper_identity_is_left_alone(ctx):
    finding = {"rule_id": "runtime-sink-sql-getPortID", "file_path": "Callers.java", "line": 8}
    assert wrapper_call_identity(finding, {"call": {"callee": "getPortID"}}, ctx).outcome == "no_opinion"

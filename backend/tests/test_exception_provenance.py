"""Exception-message provenance (SAST-03-040): what text can a logged exception carry?

A mini project with a handful of exception classes and throw sites; each test
logs from a catch and asks the validator for its answer. Nothing in the answer
may depend on the logger overload or on `{}` placeholders.
"""

import sys
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_java")
pytest.importorskip("boto3", reason="pipeline modules import llm_client")

_ENGINE = Path(__file__).resolve().parents[1] / "sast_engine"
if str(_ENGINE) not in sys.path:
    sys.path.insert(0, str(_ENGINE))

from pipeline import call_graph, exception_provenance as ep, finding_facts  # noqa: E402
from pipeline.validators import VALIDATOR_CONTEXT_USAGE_KEY, ValidatorContext  # noqa: E402

pytestmark = pytest.mark.unit

FILES = {
    "com/acme/FixedException.java": """package com.acme;

public class FixedException extends Exception {
    public FixedException(String message) { super(message); }
}
""",
    "com/acme/ReqException.java": """package com.acme;

public class ReqException extends Exception {
    public ReqException(String message) { super(message); }
}
""",
    "com/acme/WrapException.java": """package com.acme;

public class WrapException extends Exception {
    public WrapException(String message) { super(message); }
}
""",
    "com/acme/NeverBuilt.java": """package com.acme;

public class NeverBuilt extends Exception {
}
""",
    "com/acme/Thrower.java": """package com.acme;

import javax.servlet.http.HttpServletRequest;
import java.sql.SQLException;

public class Thrower {
    static final String CODE = "E42";

    void fixed(boolean b) throws FixedException {
        if (b) {
            throw new FixedException("job failed");
        }
        throw new FixedException(CODE);
    }

    void fromRequest(HttpServletRequest req) throws ReqException {
        throw new ReqException(req.getParameter("reason"));
    }

    void rethrow() throws WrapException {
        try {
            query();
        } catch (SQLException e) {
            throw new WrapException(e.getMessage());
        }
    }

    void query() throws SQLException {
    }
}
""",
}

SVC_HEAD = """package com.acme;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.servlet.http.HttpServletRequest;

public class Svc {
    private static final Logger log = LoggerFactory.getLogger(Svc.class);

"""


@pytest.fixture()
def project(tmp_path):
    for rel, text in FILES.items():
        f = tmp_path / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
    return tmp_path


def _decide(project, method_body, needle):
    text = SVC_HEAD + method_body + "\n}\n"
    (project / "com/acme/Svc.java").write_text(text)
    paths = sorted(str(p.relative_to(project)) for p in project.rglob("*.java"))
    graph = call_graph.build_call_graph(project, paths)
    ctx = ValidatorContext(repo_root=project, call_graph=graph, usage={})
    line = next(i for i, l in enumerate(text.splitlines(), 1) if needle in l)
    f = {"file_path": "com/acme/Svc.java", "line": line, "rule_id": "java-log-injection-unsanitized-input",
         "cwe": "CWE-117", "kind": "llm", "verdict": "true_positive", "verdict_reason": "The model says so.",
         "issue_class": "security", "confidence": 0.8}
    usage = {VALIDATOR_CONTEXT_USAGE_KEY: ctx}
    ctx.usage = usage
    finding_facts.prepare_findings([f], text, file_path=f["file_path"], usage=usage)
    mine = [(o["outcome"], o.get("reason_tag")) for o in (f.get("facts") or {}).get("validators", [])
            if o["validator"] == "log_exception_provenance"]
    return f, mine, ctx


def _method(catch_type, try_body, log_call, params=""):
    return f"""    void run({params}) {{
        try {{
            {try_body}
        }} catch ({catch_type} e) {{
            {log_call}
        }}
    }}"""


NEG = [("negative_proof", "exception_message_constrained")]
POS = [("positive_fact", "external_text_possible")]


@pytest.mark.parametrize("catch_type, try_body, expected", [
    ("FixedException", "new Thrower().fixed(true);", NEG),            # every site passes a literal or a constant
    ("ReqException", "new Thrower().fromRequest(null);", POS),         # one site passes request data
    ("InterruptedException", "Thread.sleep(5);", NEG),                 # VM-written, no message
    ("Exception", "new Thrower().fixed(true);", POS),                  # a generic catch widens to anything
    ("org.xml.sax.SAXParseException", "new Thrower().fixed(true);", POS),  # parser text echoes the document
    ("java.sql.SQLException", "new Thrower().query();", POS),
    ("NullPointerException", "new Thrower().fixed(true);", NEG),       # VM-generated
    ("WrapException", "new Thrower().rethrow();", POS),                # carries the SQLException's message
])
@pytest.mark.parametrize("log_call", [
    'log.warn("failed {}", e.getMessage());',
    'log.warn("failed", e);',
    'log.warn("failed: " + e.getMessage());',
])
def test_decision_does_not_depend_on_the_overload(project, catch_type, try_body, log_call, expected):
    f, mine, _ = _decide(project, _method(catch_type, try_body, log_call), "log.warn")
    assert mine == expected, (catch_type, log_call)


def test_an_explicit_npe_with_request_text_is_a_positive_candidate(project):
    body = _method("NullPointerException",
                   'throw new NullPointerException(req.getParameter("n"));',
                   'log.warn("failed {}", e.getMessage());', params="HttpServletRequest req")
    f, mine, _ = _decide(project, body, "log.warn")
    assert mine == POS


def test_a_class_nobody_constructs_is_an_evidence_gap_naming_it(project):
    f, mine, _ = _decide(project, _method("NeverBuilt", "new Thrower().fixed(true);", 'log.warn("x {}", e.getMessage());'),
                         "log.warn")
    assert mine == [("evidence_gap", None)]
    assert "NeverBuilt" in f["verdict_reason"] or "NeverBuilt" in str(f["facts"]["validators"])


def test_a_parameter_exception_is_not_summarised(project):
    body = """    void handle(Exception e) {
        log.warn("failed {}", e.getMessage());
    }"""
    f, mine, _ = _decide(project, body, "log.warn")
    assert mine == [("evidence_gap", None)]


def test_something_else_non_constant_in_the_call_keeps_the_proof_from_forming(project):
    body = _method("FixedException", "new Thrower().fixed(true);",
                   'log.warn("failed {} {}", e.getMessage(), name);', params="String name")
    f, mine, _ = _decide(project, body, "log.warn")
    assert mine == []  # the exception is fixed text, `name` is not: no proof, no opinion


def test_summaries_are_memoised_per_scan(project):
    _, _, ctx = _decide(project, _method("FixedException", "new Thrower().fixed(true);",
                                         'log.warn("failed {}", e.getMessage());'), "log.warn")
    summaries = ctx.exception_summaries()
    before = summaries.stats.get("classes", 0)
    summaries.class_domain("FixedException")
    assert summaries.stats.get("classes", 0) == before
    assert summaries.stats.get("cache_hits", 0) >= 1


def test_the_jdk_table_entries_cite_their_source():
    for name, why in ep.JDK_NO_EXTERNAL_TEXT.items():
        assert why and ("VM" in why or "JDK" in why or "JLS" in why or "JVMS" in why), name

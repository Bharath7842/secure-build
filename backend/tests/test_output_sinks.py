"""Sink classification (SAST-03-010): what a print or log call writes to.

Table-driven over small sources; needs tree-sitter and the engine's pipeline
modules, skipped cleanly when they are absent.
"""

import sys
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_java")
pytest.importorskip("tree_sitter_typescript")
pytest.importorskip("boto3", reason="pipeline modules import llm_client")

_ENGINE = Path(__file__).resolve().parents[1] / "sast_engine"
if str(_ENGINE) not in sys.path:
    sys.path.insert(0, str(_ENGINE))

from pipeline import jsp_scriptlets, occurrence_facts as of, output_sinks as sinks  # noqa: E402

pytestmark = pytest.mark.unit

FIXTURES = Path(__file__).parent / "fixtures" / "output_sinks"

IMPORTS = """package com.acme;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.*;
import javax.servlet.http.*;
import java.util.Properties;
"""


def _java(body: str, needle: str, *, fields: str = "", path: str = "Foo.java"):
    text = (
        IMPORTS
        + "public class Foo {\n" + fields + "\n"
        + "  void run(HttpServletRequest request, HttpServletResponse response, String x, PrintWriter param) throws Exception {\n"
        + "    " + body + "\n  }\n}\n"
    )
    line = next(i for i, l in enumerate(text.splitlines(), 1) if needle in l)
    facts = of.facts_for(path, text, line)
    return sinks.sink_class(facts, file_path=path)


AUDIT = "private static final Logger AUDIT = LoggerFactory.getLogger(Foo.class);"


@pytest.mark.parametrize("fields,body,needle,expected", [
    (AUDIT, "AUDIT.info(x);", "AUDIT.info", sinks.LOGGER),
    ("", "LoggerFactory.getLogger(Foo.class).warn(x);", "getLogger(Foo", sinks.LOGGER),
    ("", 'System.out.println(x);', "System.out", sinks.PROCESS_STREAM),
    ("", 'System.err.println(x);', "System.err", sinks.PROCESS_STREAM),
    ("", "try {\n      run(null, null, x, null);\n    } catch (Exception e) {\n      e.printStackTrace();\n    }", "printStackTrace", sinks.PROCESS_STREAM),
    ("", "response.getWriter().println(x);", "getWriter()", sinks.HTTP_RESPONSE),
    ("", "response.getOutputStream().write(1);", "getOutputStream()", sinks.HTTP_RESPONSE),
    ("", "PrintWriter w = response.getWriter();\n    w.write(x);", "w.write", sinks.HTTP_RESPONSE),
    ("", "new PrintWriter(response.getWriter()).println(x);", "new PrintWriter", sinks.HTTP_RESPONSE),
    ("", "new PrintWriter(new FileWriter(\"f\")).println(x);", "new PrintWriter", sinks.OTHER),
    ("", "PrintWriter w = new PrintWriter(new FileWriter(\"f\"));\n    w.println(x);", "w.println", sinks.OTHER),
    ("", "Properties catalog = new Properties();\n    catalog.setProperty(x, x);", "catalog.setProperty", sinks.OTHER),
    # A writer handed in as a parameter may be the response's: no proof either way.
    ("", "param.println(x);", "param.println", sinks.UNKNOWN),
    # Nothing is known about this receiver.
    ("", "out.println(x);", "out.println", sinks.UNKNOWN),
])
def test_java_sink_classes(fields, body, needle, expected):
    result = _java(body, needle, fields=fields)
    assert result.kind == expected, result


def test_exposure_follows_the_class():
    assert _java("System.out.println(x);", "System.out").exposure == sinks.EXPOSURE_PROCESS
    assert _java("response.getWriter().println(x);", "getWriter").exposure == sinks.EXPOSURE_HTTP
    assert _java("AUDIT.info(x);", "AUDIT.info", fields=AUDIT).exposure == sinks.EXPOSURE_LOG
    assert _java("out.println(x);", "out.println").exposure is None


def test_any_variable_name_is_a_logger_by_type():
    result = _java("banana.error(x);", "banana.error",
                   fields="private static final Logger banana = LoggerFactory.getLogger(Foo.class);")
    assert result.kind == sinks.LOGGER


def test_a_project_class_named_like_a_logger_is_unknown_not_other():
    result = _java("log.info(x);", "log.info", fields="private final AppLogger log = null;")
    assert result.kind == sinks.UNKNOWN


def test_no_call_at_the_anchor_is_unknown():
    assert sinks.sink_class(None).kind == sinks.UNKNOWN
    assert sinks.sink_class({"call": None}).kind == sinks.UNKNOWN


def test_is_logger_helper():
    text = IMPORTS + "class Foo {\n  Logger log;\n  void a(String x) {\n    log.info(x);\n  }\n}\n"
    line = next(i for i, l in enumerate(text.splitlines(), 1) if "log.info" in l)
    assert sinks.is_logger(of.facts_for("Foo.java", text, line))


# --- JSP -----------------------------------------------------------------------

def _jsp_facts(line: int):
    text = (FIXTURES / "page.jsp").read_text()
    return of.facts_for("page.jsp", text, line)


def test_jsp_rewrite_keeps_line_numbers():
    text = (FIXTURES / "page.jsp").read_text()
    rewritten = jsp_scriptlets.rewrite(text)
    assert rewritten is not None
    assert rewritten.count("\n") >= text.count("\n")
    assert rewritten.splitlines()[4].strip().startswith("out.println(q);")


def test_a_jsp_without_scriptlets_has_no_facts():
    assert jsp_scriptlets.rewrite("<html><p>hello ${name}</p></html>") is None
    assert of.facts_for("x.jsp", "<html><p>hello ${name}</p></html>", 1) is None


def test_jsp_scriptlet_out_is_the_response_writer():
    assert sinks.sink_class(_jsp_facts(5), file_path="page.jsp").kind == sinks.HTTP_RESPONSE


def test_jsp_expression_is_a_response_write():
    facts = _jsp_facts(6)
    assert facts is not None and facts.call["callee"] == "print"
    assert sinks.sink_class(facts, file_path="page.jsp").kind == sinks.HTTP_RESPONSE


def test_jsp_request_is_resolved_for_later_stories():
    facts = _jsp_facts(4)
    assert facts.call["receiver_type"] == "HttpServletRequest"


# --- TypeScript ----------------------------------------------------------------

TS = """import { NGXLogger } from 'ngx-logger';
import { Wrapper } from './wrapper.service';
import { Plain } from './plain.service';
export class C {
  constructor(private logger: NGXLogger, private wrapper: Wrapper, private plain: Plain) {}
  go(x: string) {
    this.logger.error(x);
    console.log(x);
    this.wrapper.say(x);
    this.plain.say(x);
  }
}
"""


def _ts(line, read_text=None):
    facts = of.facts_for("src/c.ts", TS, line)
    return sinks.sink_class(facts, file_path="src/c.ts", read_text=read_text)


def test_typescript_loggers():
    assert _ts(7).kind == sinks.LOGGER
    assert _ts(8).kind == sinks.LOGGER


def test_typescript_wrapper_service_is_a_logger_only_when_its_file_wraps_one():
    files = {"src/wrapper.service.ts": "export class Wrapper { say(x){ console.log(x); } }",
             "src/plain.service.ts": "export class Plain { say(x){ return x; } }"}
    assert _ts(9).kind == sinks.UNKNOWN  # no way to look inside
    assert _ts(9, files.get and (lambda p: files.get(p, ""))).kind == sinks.LOGGER
    assert _ts(10, lambda p: files.get(p, "")).kind == sinks.UNKNOWN

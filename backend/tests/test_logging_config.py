"""Logging configuration model (SAST-03-050) and the `log_layout` validator."""

import sys
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_java")
pytest.importorskip("boto3", reason="pipeline modules import llm_client")

_ENGINE = Path(__file__).resolve().parents[1] / "sast_engine"
if str(_ENGINE) not in sys.path:
    sys.path.insert(0, str(_ENGINE))

from pipeline import finding_facts, logging_config as lc  # noqa: E402
from pipeline.validators import VALIDATOR_CONTEXT_USAGE_KEY, ValidatorContext  # noqa: E402

pytestmark = pytest.mark.unit

LOGBACK_RAW = """<configuration>
  <appender name="STDOUT" class="ch.qos.logback.core.ConsoleAppender">
    <encoder><pattern>%d %msg%n</pattern></encoder>
  </appender>
  <root level="INFO"><appender-ref ref="STDOUT"/></root>
</configuration>
"""
LOGBACK_REPLACE = """<configuration>
  <appender name="STDOUT" class="ch.qos.logback.core.ConsoleAppender">
    <encoder><pattern>%d %replace(%msg){'[\\r\\n]','_'}%n</pattern></encoder>
  </appender>
  <root level="INFO"><appender-ref ref="STDOUT"/></root>
</configuration>
"""
LOG4J2_JSON = """<Configuration>
  <Appenders>
    <Console name="Out"><JsonTemplateLayout eventTemplateUri="classpath:EcsLayout.json"/></Console>
  </Appenders>
  <Loggers><Root level="info"><AppenderRef ref="Out"/></Root></Loggers>
</Configuration>
"""
LOGBACK_MAPPED = """<configuration>
  <appender name="RAWAPP" class="ch.qos.logback.core.ConsoleAppender">
    <encoder><pattern>%d %msg%n</pattern></encoder>
  </appender>
  <appender name="SAFE" class="ch.qos.logback.core.ConsoleAppender">
    <encoder class="net.logstash.logback.encoder.LogstashEncoder"/>
  </appender>
  <logger name="com.acme" level="INFO" additivity="false"><appender-ref ref="RAWAPP"/></logger>
  <root level="INFO"><appender-ref ref="SAFE"/></root>
</configuration>
"""


def _write(tmp_path, rel, text):
    f = tmp_path / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(text)


# --- pattern analysis -----------------------------------------------------------

@pytest.mark.parametrize("pattern, message, throwable", [
    ("%d %msg%n", lc.RAW, lc.RAW),
    ("%d %replace(%msg){'[\\r\\n]','_'}%n", lc.NEUTRALISED, lc.RAW),
    ("%d %replace(%msg){'[\\r\\n]','_'} %replace(%ex){'[\\r\\n]','_'}", lc.NEUTRALISED, lc.NEUTRALISED),
    ("%d %enc{%m}{CRLF}%n", lc.NEUTRALISED, lc.RAW),
    ("%d %enc{%m}%n", lc.RAW, lc.RAW),  # the default encoding is HTML, which keeps a line break
    ("%replace{%m}{[\\r\\n]}{_}%n%xEx", lc.NEUTRALISED, lc.RAW),
    ("%d %m %nopex", lc.RAW, lc.NEUTRALISED),
    ("", lc.UNKNOWN, lc.UNKNOWN),
])
def test_pattern_analysis(pattern, message, throwable):
    layout = lc.analyze_pattern(pattern)
    assert (layout.message_crlf, layout.throwable_crlf) == (message, throwable), pattern


def test_a_replace_that_does_not_match_line_breaks_neutralises_nothing():
    assert lc.analyze_pattern("%replace(%msg){'x','_'}%n").message_crlf == lc.RAW


# --- loading and category resolution ---------------------------------------------

def test_logback_pattern_is_raw_and_json_layouts_neutralise(tmp_path):
    _write(tmp_path, "src/main/resources/logback.xml", LOGBACK_RAW)
    cfg = lc.load(tmp_path)
    assert cfg.found
    assert cfg.resolve("com.acme.Foo").part("message_crlf") == lc.RAW

    _write(tmp_path, "src/main/resources/logback.xml", LOGBACK_REPLACE)
    r = lc.load(tmp_path).resolve("com.acme.Foo")
    assert (r.part("message_crlf"), r.part("throwable_crlf")) == (lc.NEUTRALISED, lc.RAW)

    _write(tmp_path, "src/main/resources/logback.xml", LOGBACK_MAPPED)
    cfg = lc.load(tmp_path)
    assert cfg.resolve("com.acme.Foo").part("message_crlf") == lc.RAW      # mapped by <logger name="com.acme">
    assert cfg.resolve("org.other.Bar").part("message_crlf") == lc.NEUTRALISED  # root -> JSON


def test_log4j2_json_template_layout_neutralises_both(tmp_path):
    _write(tmp_path, "src/main/resources/log4j2.xml", LOG4J2_JSON)
    r = lc.load(tmp_path).resolve("com.acme.Foo")
    assert (r.part("message_crlf"), r.part("throwable_crlf")) == (lc.NEUTRALISED, lc.NEUTRALISED)


def test_log4j1_and_jul_properties(tmp_path):
    _write(tmp_path, "src/main/resources/log4j.properties",
           "log4j.rootLogger=INFO, A\nlog4j.appender.A=org.apache.log4j.ConsoleAppender\n"
           "log4j.appender.A.layout=org.apache.log4j.PatternLayout\n"
           "log4j.appender.A.layout.ConversionPattern=%d %m%n\n")
    assert lc.load(tmp_path).resolve("x.Y").part("message_crlf") == lc.RAW
    _write(tmp_path, "logging.properties",
           "handlers=java.util.logging.ConsoleHandler\n"
           "java.util.logging.ConsoleHandler.formatter=java.util.logging.SimpleFormatter\n")
    assert lc.load(tmp_path).resolve("x.Y").part("message_crlf") == lc.RAW


def test_two_profiles_the_least_safe_wins(tmp_path):
    _write(tmp_path, "src/main/resources/logback-spring.xml", LOGBACK_REPLACE)
    _write(tmp_path, "src/main/resources/logback-dev.xml", LOGBACK_RAW)
    assert lc.load(tmp_path).resolve("com.acme.Foo").part("message_crlf") == lc.RAW


def test_test_resources_and_entity_files_are_ignored(tmp_path):
    _write(tmp_path, "src/test/resources/logback.xml", LOGBACK_RAW)
    _write(tmp_path, "logback.xml", '<!DOCTYPE x [<!ENTITY a "b">]><configuration/>')
    assert not lc.load(tmp_path).found


def test_no_configuration_is_not_found(tmp_path):
    assert not lc.load(tmp_path).found
    assert lc.load(None).files == []


# --- the validator ---------------------------------------------------------------

SVC = """package com.acme.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Svc {
    private static final Logger log = LoggerFactory.getLogger(Svc.class);

    void run(Exception ex) {
        log.warn("failed {}", ex.getMessage());
    }

    void trace(Exception ex) {
        log.warn("failed", ex);
    }
}
"""


def _decide(tmp_path, needle):
    ctx = ValidatorContext(repo_root=tmp_path)
    line = next(i for i, l in enumerate(SVC.splitlines(), 1) if needle in l)
    f = {"file_path": "com/acme/service/Svc.java", "line": line, "rule_id": "java-log-injection-unsanitized-input",
         "cwe": "CWE-117", "kind": "llm", "verdict": "true_positive", "verdict_reason": "The model says so.",
         "issue_class": "security", "confidence": 0.8}
    finding_facts.prepare_findings([f], SVC, file_path=f["file_path"], usage={VALIDATOR_CONTEXT_USAGE_KEY: ctx})
    mine = [(o["outcome"], o.get("reason_tag")) for o in (f.get("facts") or {}).get("validators", [])
            if o["validator"] == "log_layout"]
    return f, mine


def test_no_configuration_is_a_gap_that_does_not_lower_a_confirmed_finding(tmp_path):
    f, mine = _decide(tmp_path, "ex.getMessage()")
    assert mine == [("note", "log_layout_unknown")]
    # The unknown layout is only recorded: a finding other evidence supports keeps its verdict.
    assert f["verdict"] == "true_positive"


def test_a_note_never_changes_an_undecided_finding_either(tmp_path):
    f = {"file_path": "com/acme/service/Svc.java", "line": 14, "rule_id": "java-log-injection-unsanitized-input",
         "cwe": "CWE-117", "kind": "regex", "verdict": "unverified", "verdict_reason": "Regex hit.",
         "issue_class": "security", "unresolved_reason": "not_reviewed_regex"}
    finding_facts.prepare_findings([f], SVC, file_path=f["file_path"],
                                   usage={VALIDATOR_CONTEXT_USAGE_KEY: ValidatorContext(repo_root=tmp_path)})
    assert f["verdict"] == "unverified" and f["unresolved_reason"] == "not_reviewed_regex"


def test_a_raw_layout_is_a_positive_fact(tmp_path):
    _write(tmp_path, "src/main/resources/logback.xml", LOGBACK_RAW)
    f, mine = _decide(tmp_path, "ex.getMessage()")
    assert mine == [("positive_fact", "log_layout_raw")]
    assert f["verdict"] == "true_positive"


def test_a_json_layout_is_a_proof_the_message_cannot_forge(tmp_path):
    _write(tmp_path, "src/main/resources/log4j2.xml", LOG4J2_JSON)
    f, mine = _decide(tmp_path, "ex.getMessage()")
    assert mine == [("negative_proof", "log_layout_neutralises")]
    assert f["verdict"] == "false_positive" and f["reason_tag"] == "log_layout_neutralises"


def test_the_stack_trace_is_judged_by_the_throwable_part(tmp_path):
    _write(tmp_path, "src/main/resources/logback.xml", LOGBACK_REPLACE)  # message encoded, %ex implicit and raw
    f, mine = _decide(tmp_path, 'log.warn("failed", ex)')
    assert mine == [("positive_fact", "log_layout_raw")]
    f, mine = _decide(tmp_path, "ex.getMessage()")
    assert mine == [("negative_proof", "log_layout_neutralises")]


def test_a_logger_mapped_to_a_raw_appender_by_name(tmp_path):
    _write(tmp_path, "src/main/resources/logback.xml", LOGBACK_MAPPED)
    f, mine = _decide(tmp_path, "ex.getMessage()")
    assert mine == [("positive_fact", "log_layout_raw")]  # com.acme.service.Svc -> <logger name="com.acme">

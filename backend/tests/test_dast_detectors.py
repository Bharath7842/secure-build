"""DAST-04-020 / -030: the detector library. Pure functions over response pairs."""

from __future__ import annotations

import itertools

import pytest

from app.dast.domain import detectors as D
from app.dast.domain.entities import DetectorSignal, ResponseSnapshot

pytestmark = pytest.mark.unit


def r(body="", status=200, length=None, headers=None, elapsed=0.0) -> ResponseSnapshot:
    return ResponseSnapshot(status=status, length=len(body) if length is None else length, body_excerpt=body, headers=headers or {}, elapsed_ms=elapsed)


def names(signals):
    return [s.name for s in signals]


OK = r('{"items": []}')

# (detector, baseline, test, ctx, expected_fires)
DB_ERRORS = [
    "You have an error in your SQL syntax; check the manual",
    "ORA-00933: SQL command not properly ended",
    "Unclosed quotation mark after the character string 'x'",
    "ERROR: syntax error at or near \"'\"",
    "SQLSTATE[42000]: Syntax error or access violation",
    "java.sql.SQLSyntaxErrorException: bad grammar",
]
STACKS = [
    "Traceback (most recent call last):\n  File \"app.py\", line 3",
    "java.lang.NullPointerException\n\tat com.acme.Svc.run(Svc.java:42)",
    "Exception in thread \"main\" java.lang.Error",
    "   at Acme.Web.Handler.Run() in C:\\src\\Handler.cs:line 88",
    "Error: boom\n    at Object.<anonymous> (/srv/app/index.js:10:5)",
    "Whitelabel Error Page",
]
COMMANDS = [
    "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
    "root:x:0:0:root:/root:/bin/bash",
    " Volume Serial Number is 1234-ABCD",
    "Linux version 5.15.0-91-generic (buildd@lcy02)",
    "Windows IP Configuration\n  Host Name . . . : srv",
]


@pytest.mark.parametrize("body", DB_ERRORS)
def test_db_error_fires_when_new(body):
    assert names(D.db_error_surfaced(OK, r(body))) == ["db_error_surfaced"]


@pytest.mark.parametrize("body", DB_ERRORS[:5])
def test_db_error_ignored_when_already_in_baseline(body):
    assert D.db_error_surfaced(r(body), r(body + " again")) == []


@pytest.mark.parametrize("body", ["all good", '{"error":"bad request"}', "SQL is a language", "", "select a drink"])
def test_db_error_negatives(body):
    assert D.db_error_surfaced(OK, r(body)) == []


@pytest.mark.parametrize("body", STACKS)
def test_stack_trace_fires(body):
    assert names(D.stack_trace_leaked(OK, r(body))) == ["stack_trace_leaked"]


@pytest.mark.parametrize("body", STACKS[:4])
def test_stack_trace_ignored_when_in_baseline(body):
    assert D.stack_trace_leaked(r(body), r(body)) == []


@pytest.mark.parametrize("body", ["not found", '{"message":"oops"}', "at the end of the day", "trace this", "error"])
def test_stack_trace_negatives(body):
    assert D.stack_trace_leaked(OK, r(body)) == []


@pytest.mark.parametrize("body", COMMANDS)
def test_command_output_fires(body):
    assert names(D.command_output_marker(OK, r(body))) == ["command_output_marker"]


@pytest.mark.parametrize("body", COMMANDS[:4])
def test_command_output_ignored_when_in_baseline(body):
    assert D.command_output_marker(r(body), r(body)) == []


@pytest.mark.parametrize("body", ["hello", "uid is a word", "root directory", "windows are open", "total"])
def test_command_output_negatives(body):
    assert D.command_output_marker(OK, r(body)) == []


PAYLOAD = "<b>probe-7</b>"


@pytest.mark.parametrize(
    "body",
    [f"<p>{PAYLOAD}</p>", f"you searched: {PAYLOAD}", PAYLOAD, f'{{"html":"{PAYLOAD}"}}', f"x{PAYLOAD}y{PAYLOAD}"],
)
def test_reflection_fires_for_raw_payload(body):
    assert names(D.input_reflected_unescaped(OK, r(body), D.DetectionContext(payload=PAYLOAD))) == ["input_reflected_unescaped"]


@pytest.mark.parametrize(
    "body",
    [
        "&lt;b&gt;probe-7&lt;/b&gt;",  # HTML-escaped
        "\\u003cb\\u003eprobe-7\\u003c/b\\u003e",  # JSON-escaped
        "nothing here",
        "",
        "<b>other</b>",
    ],
)
def test_reflection_negatives(body):
    assert D.input_reflected_unescaped(OK, r(body), D.DetectionContext(payload=PAYLOAD)) == []


def test_reflection_needs_markup_payload_and_new_in_test():
    assert D.input_reflected_unescaped(OK, r("probe"), D.DetectionContext(payload="probe")) == []
    assert D.input_reflected_unescaped(r(PAYLOAD), r(PAYLOAD), D.DetectionContext(payload=PAYLOAD)) == []
    assert D.input_reflected_unescaped(OK, r(PAYLOAD)) == []  # no payload in the context


def test_detectors_tolerate_hostile_input():
    binary = r("\x00\x01\x02 ORA-00933")
    broken = ResponseSnapshot(status=None, length=0, body_excerpt=None, headers=None)  # type: ignore[arg-type]
    weird = ResponseSnapshot(status=200, length=-5, body_excerpt=b"bytes ORA-00933 body", headers={"x": 1})  # type: ignore[arg-type]
    for baseline, test in itertools.product([OK, binary, broken, weird], repeat=2):
        for name, fn in D.DETECTORS.items():
            assert isinstance(fn(baseline, test, D.DetectionContext(payload="<x>")), list), name
    assert D.db_error_surfaced(OK, binary) == []  # binary body: text patterns are meaningless
    assert names(D.db_error_surfaced(OK, weird)) == ["db_error_surfaced"]  # bytes decoded
    assert D.run_detectors(broken, broken) == []


# ---- DAST-04-030 --------------------------------------------------------------------------------


def test_status_length_divergence():
    assert names(D.status_length_divergence(r("a" * 100), r("a" * 100, status=500))) == ["status_length_divergence"]
    assert names(D.status_length_divergence(r("a" * 1000), r("a" * 100))) == ["status_length_divergence"]
    assert D.status_length_divergence(r("a" * 1000), r("a" * 1050)) == []  # within tolerance
    assert D.status_length_divergence(r("a" * 10), r("a" * 30)) == []  # below the absolute floor
    assert D.status_length_divergence(r("x", status=200), r("y", status=204)) == []  # same class
    assert D.status_length_divergence(ResponseSnapshot(None, 0, ""), OK) == []


def test_boolean_divergence_needs_a_control_that_differs():
    base = r('{"rows":[1,2,3]}' + " " * 400)
    true_variant = r('{"rows":[1,2,3]}' + " " * 410)
    false_variant = r('{"rows":[]}')
    ctx = D.DetectionContext(control=false_variant)
    assert names(D.boolean_divergence(base, true_variant, ctx)) == ["boolean_divergence"]
    assert D.boolean_divergence(base, true_variant) == []  # no control: no signal
    assert D.boolean_divergence(base, true_variant, D.DetectionContext(control=true_variant)) == []  # control identical
    assert D.boolean_divergence(base, false_variant, ctx) == []  # true variant itself diverged


def test_time_delta_requires_threshold_and_two_samples():
    ctx = lambda b, t, thr=1000: D.DetectionContext(baseline_ms=b, test_ms=t, time_threshold_ms=thr)  # noqa: E731
    assert names(D.time_delta(OK, OK, ctx([100, 110], [2200, 2400]))) == ["time_delta"]
    assert D.time_delta(OK, OK, ctx([100, 110], [2200])) == []  # single sample is noise
    assert D.time_delta(OK, OK, ctx([100], [2200, 2400])) == []
    assert D.time_delta(OK, OK, ctx([100, 110], [400, 500])) == []  # below threshold
    assert D.time_delta(OK, OK, ctx([100, 110], [100, 5000])) == []  # one outlier does not carry it
    assert D.time_delta(OK, OK, ctx([100, 110], [1200, 1300], thr=5000)) == []  # configurable threshold
    assert D.time_delta(OK, OK, D.DetectionContext()) == []
    assert D.time_delta(OK, OK, ctx([100, "x", True], [2200, 2400])) == []  # junk samples ignored


ADMIN = r('{"users":[{"id":1,"email":"a@x"}],"total":1}')


def test_auth_boundary_crossed_on_equivalent_success():
    assert names(D.auth_boundary_crossed(ADMIN, r('{"users":[{"id":1,"email":"a@x"}],"total":1}'))) == ["auth_boundary_crossed"]


@pytest.mark.parametrize("status", [401, 403, 404, 302, 500])
def test_auth_boundary_never_fires_on_denied_or_non_success(status):
    assert D.auth_boundary_crossed(ADMIN, r('{"error":"nope"}', status=status)) == []
    assert D.auth_boundary_crossed(r("x", status=status), ADMIN) == []


def test_auth_boundary_requires_material_equivalence():
    assert D.auth_boundary_crossed(ADMIN, r('{"users":[{"id":1,"email":"a@x"}],"total":1,' + '"x":"' + "y" * 400 + '"}')) == []
    assert D.auth_boundary_crossed(ADMIN, r('{"message":"welcome","profile":{}}')) == []  # different shape


def test_auth_boundary_empty_body_edge_case():
    """Documented: an empty 200 on both sides proves nothing about what either caller may see."""
    assert D.auth_boundary_crossed(r("", status=200), r("", status=200)) == []
    assert D.auth_boundary_crossed(ADMIN, r("", status=200)) == []
    assert D.auth_boundary_crossed(r("", status=200), ADMIN) == []


FILES_DISCLOSED = [
    "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
    "[extensions]\nMAPI=1\n[mci extensions]\n3g2=MPEGVideo",
    "; for 16-bit app support\n[386Enh]",
    "[boot loader]\ntimeout=30\ndefault=multi(0)disk(0)",
    "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK...",
    "<?php\n// config.php leaked unexecuted\n$db_password = 'x';",
]


@pytest.mark.parametrize("body", FILES_DISCLOSED)
def test_file_disclosure_fires(body):
    assert names(D.file_disclosure_marker(OK, r(body))) == ["file_disclosure_marker"]


@pytest.mark.parametrize("body", FILES_DISCLOSED[:4])
def test_file_disclosure_ignored_when_in_baseline(body):
    assert D.file_disclosure_marker(r(body), r(body)) == []


@pytest.mark.parametrize("body", ["hello world", "root cause analysis", "boot camp starts monday"])
def test_file_disclosure_negatives(body):
    assert D.file_disclosure_marker(OK, r(body)) == []


NOSQL_ERRORS = [
    "MongoError: $where is not allowed",
    "com.mongodb.MongoQueryException: query failed",
    "TypeError: Cannot convert undefined or null to object",
    "redis.exceptions.ResponseError: WRONGTYPE Operation against a key",
]


@pytest.mark.parametrize("body", NOSQL_ERRORS)
def test_nosql_error_fires(body):
    assert names(D.nosql_error_surfaced(OK, r(body))) == ["nosql_error_surfaced"]


def test_nosql_error_negatives():
    assert D.nosql_error_surfaced(OK, r("no rows found")) == []


LDAP_ERRORS = [
    "javax.naming.directory.InvalidSearchFilterException: bad filter",
    "LDAPException: invalid DN syntax",
    "System.DirectoryServices.DirectoryServicesCOMException: 0x8007203A",
    "LDAP: error code 34 - invalid DN syntax",
]


@pytest.mark.parametrize("body", LDAP_ERRORS)
def test_ldap_error_fires(body):
    assert names(D.ldap_error_surfaced(OK, r(body))) == ["ldap_error_surfaced"]


def test_ldap_error_negatives():
    assert D.ldap_error_surfaced(OK, r("user not found")) == []


XPATH_ERRORS = [
    "XPathException: invalid expression '//user[1'",
    "System.Xml.XPath.XPathException: Expected token */",
    "org.w3c.dom.DOMException: INVALID_CHARACTER_ERR",
]


@pytest.mark.parametrize("body", XPATH_ERRORS)
def test_xpath_error_fires(body):
    assert names(D.xpath_error_surfaced(OK, r(body))) == ["xpath_error_surfaced"]


def test_xpath_error_negatives():
    assert D.xpath_error_surfaced(OK, r("no match")) == []


@pytest.mark.parametrize(
    "payload, body",
    [
        ("{{7*7}}", "result: 49"),
        ("${7*7}", "result: 49"),
        ("#{7*7}", "result: 49"),
        ("<%= 7*7 %>", "result: 49"),
        ("@(7*7)", "result: 49"),
        ("{{ 12 * 3 }}", "value=36"),
    ],
)
def test_template_expression_evaluated_fires_when_the_product_appears(payload, body):
    assert names(D.template_expression_evaluated(OK, r(body), D.DetectionContext(payload=payload))) == ["template_expression_evaluated"]


def test_template_expression_negatives():
    # markup survived unevaluated: reflection, not execution
    assert D.template_expression_evaluated(OK, r("echo: {{7*7}}"), D.DetectionContext(payload="{{7*7}}")) == []
    # product already present in the baseline by coincidence
    assert D.template_expression_evaluated(r("49 things"), r("49 things"), D.DetectionContext(payload="{{7*7}}")) == []
    # not a template expression at all
    assert D.template_expression_evaluated(OK, r("49"), D.DetectionContext(payload="just text")) == []
    # numbers too large to be a harmless probe
    assert D.template_expression_evaluated(OK, r("250000"), D.DetectionContext(payload="{{5000*50}}")) == []
    assert D.template_expression_evaluated(OK, r("49")) == []  # no payload in context


def test_open_redirect_location_fires_when_location_matches_the_payload():
    ctx = D.DetectionContext(payload="https://evil.example.com/phish")
    assert names(D.open_redirect_location(OK, r("", status=302, headers={"Location": "https://evil.example.com/phish"}), ctx)) == ["open_redirect_location"]
    ctx2 = D.DetectionContext(payload="//evil.example.com")
    assert names(D.open_redirect_location(OK, r("", status=303, headers={"Location": "//evil.example.com"}), ctx2)) == ["open_redirect_location"]


def test_open_redirect_location_negatives():
    ctx = D.DetectionContext(payload="https://evil.example.com")
    assert D.open_redirect_location(OK, r("", status=302, headers={"Location": "/local/path"}), ctx) == []  # redirected elsewhere
    assert D.open_redirect_location(OK, r("ok", status=200), ctx) == []  # not even a redirect
    assert D.open_redirect_location(OK, r("", status=302, headers={"Location": "https://evil.example.com"}), D.DetectionContext(payload="/relative")) == []  # payload not off-origin
    assert D.open_redirect_location(OK, r("", status=302), ctx) == []  # no Location header at all


CSRF_BASE = r('{"status":"ok","id":42}')


def test_csrf_not_enforced_fires_when_missing_token_still_succeeds():
    assert names(D.csrf_not_enforced(CSRF_BASE, r('{"status":"ok","id":42}'))) == ["csrf_not_enforced"]


@pytest.mark.parametrize("status", [401, 403, 400, 302])
def test_csrf_not_enforced_never_fires_when_the_test_was_rejected(status):
    assert D.csrf_not_enforced(CSRF_BASE, r('{"error":"invalid csrf token"}', status=status)) == []


def test_csrf_not_enforced_requires_a_successful_baseline_too():
    assert D.csrf_not_enforced(r('{"error":"nope"}', status=403), CSRF_BASE) == []


def test_csrf_not_enforced_empty_body_edge_case():
    assert D.csrf_not_enforced(r("", status=200), r("", status=200)) == []


def test_registry_and_signal_names():
    assert set(D.DETECTORS) == {
        "db_error_surfaced", "input_reflected_unescaped", "command_output_marker", "stack_trace_leaked",
        "boolean_divergence", "time_delta", "status_length_divergence", "auth_boundary_crossed",
        "file_disclosure_marker", "nosql_error_surfaced", "ldap_error_surfaced", "xpath_error_surfaced",
        "template_expression_evaluated", "open_redirect_location", "csrf_not_enforced",
        "xxe_entity_resolved", "parameter_pollution_selected", "prototype_pollution_applied",
        "marker_executed_in_browser", "marker_reaches_dom_sink", "marker_persisted_unescaped",
    }
    assert set(D.DETECTORS) <= D.signal_names()
    assert "header_absent" in D.signal_names()
    assert "made_up" not in D.signal_names()


def test_run_detectors_is_deterministic_and_never_judges():
    ctx = D.DetectionContext(payload="<x>")
    out1 = D.run_detectors(OK, r("<x> ORA-00933"), ctx)
    out2 = D.run_detectors(OK, r("<x> ORA-00933"), ctx)
    assert out1 == out2 and all(isinstance(s, DetectorSignal) for s in out1)
    assert {"db_error_surfaced", "input_reflected_unescaped"} <= set(names(out1))
    assert names(D.run_detectors(OK, r("<x> ORA-00933"), ctx, names=["db_error_surfaced"])) == ["db_error_surfaced"]

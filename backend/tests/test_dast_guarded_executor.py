"""DAST-01-030: the guarded request executor, against the in-process fake target."""

from __future__ import annotations

import json

import httpx
import pytest

from app.dast.domain.interfaces import GuardDecision, RequestExecutor, RequestSpec
from app.dast.domain.policy import CANCELLED, METHOD_NOT_PERMITTED, OFF_SCOPE, MethodPolicy, Scope
from app.services.guarded_executor import GuardedExecutor
from app.services.request_audit import MemoryAuditSink
from app.services.safety_guard import SafetyGuard, registrable_domain

pytestmark = pytest.mark.integration

BASE = "http://target.test"
PASSWORD = "s3cr3t-pw-value"


def make_executor(
    transport,
    *,
    policy: MethodPolicy | None = None,
    mode: str = "exact",
    target: str = BASE,
    cancelled=lambda: False,
    **kwargs,
):
    audit = MemoryAuditSink()
    guard = SafetyGuard(
        Scope.for_target(target, mode, registrable_domain),  # type: ignore[arg-type]
        policy or MethodPolicy(),
        rate_limit_per_sec=100_000.0,
        max_concurrent=4,
        is_cancelled=cancelled,
    )
    return GuardedExecutor(guard, audit, transport=transport, **kwargs), audit


def test_executor_satisfies_the_domain_interface(fake_target):
    executor, _ = make_executor(fake_target.transport)
    assert isinstance(executor, RequestExecutor)


# ---- allowed ----------------------------------------------------------------------------------


def test_allowed_request_is_sent_once_audited_once_and_returned(fake_target):
    fake_target.add_page("/", "<h1>Home</h1>", headers={"X-Frame-Options": "DENY"})
    executor, audit = make_executor(fake_target.transport)

    decision = executor.execute(RequestSpec("GET", f"{BASE}/", identity_label="admin", check_id="chk-1"))

    assert decision.allowed and decision.deny_reason is None and decision.error is None
    assert decision.response.status == 200
    assert decision.response.body_excerpt == "<h1>Home</h1>"
    assert decision.response.headers["x-frame-options"] == "DENY"
    assert decision.response.elapsed_ms >= 0
    assert len(fake_target.requests) == 1
    assert len(audit.records) == 1
    row = audit.records[0]
    assert (row.method, row.url, row.allowed, row.response_status) == ("GET", f"{BASE}/", True, 200)
    assert row.check_id == "chk-1" and decision.audit_seq == 1


def test_identity_label_is_recorded_and_falls_back_to_the_identity_id(fake_target):
    fake_target.add_page("/", "x")
    executor, audit = make_executor(fake_target.transport)
    executor.execute(RequestSpec("GET", f"{BASE}/", identity_id="id-7", identity_label="viewer"))
    executor.execute(RequestSpec("GET", f"{BASE}/", identity_id="id-9"))
    executor.execute(RequestSpec("GET", f"{BASE}/"))
    assert [r.identity_label for r in audit.records] == ["viewer", "id-9", None]


def test_body_headers_and_json_are_sent(fake_target):
    fake_target.route("POST", "/echo", lambda r: httpx.Response(200, json={"got": r.content.decode(), "ct": r.headers.get("content-type")}))
    executor, _ = make_executor(fake_target.transport, policy=MethodPolicy(safe_mode=False))
    decision = executor.execute(RequestSpec("POST", f"{BASE}/echo", headers={"X-Probe": "1"}, body={"a": 1}))
    assert decision.allowed
    echoed = json.loads(decision.response.body_excerpt)
    assert json.loads(echoed["got"]) == {"a": 1} and echoed["ct"] == "application/json"
    assert fake_target.requests[0].headers["x-probe"] == "1"


def test_response_body_is_truncated_to_the_configured_size(fake_target):
    fake_target.add_page("/big", "A" * 10_000)
    executor, _ = make_executor(fake_target.transport, max_body_bytes=100)
    response = executor.execute(RequestSpec("GET", f"{BASE}/big")).response
    assert len(response.body_excerpt) == 100
    assert response.length == 10_000  # the real size is still reported


def test_unknown_charset_does_not_break_the_response(fake_target):
    fake_target.route("GET", "/odd", lambda r: httpx.Response(200, content=b"caf\xc3\xa9", headers={"content-type": "text/plain; charset=nonsense-9"}))
    executor, _ = make_executor(fake_target.transport)
    assert executor.execute(RequestSpec("GET", f"{BASE}/odd")).response.body_excerpt == "café"


# ---- denied -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "spec, reason",
    [
        (RequestSpec("GET", "http://evil.test/x"), OFF_SCOPE),
        (RequestSpec("GET", "http://target.test.evil.test/"), OFF_SCOPE),
        (RequestSpec("GET", "http://target.test@evil.test/"), OFF_SCOPE),
        (RequestSpec("GET", "not a url"), OFF_SCOPE),
        (RequestSpec("POST", f"{BASE}/login", body={"a": 1}), METHOD_NOT_PERMITTED),
        (RequestSpec("DELETE", f"{BASE}/users/1"), METHOD_NOT_PERMITTED),
    ],
)
def test_denied_request_never_reaches_the_transport_and_is_audited(fake_target, spec, reason):
    executor, audit = make_executor(fake_target.transport)
    decision = executor.execute(spec)

    assert isinstance(decision, GuardDecision)  # a structured denial, not an exception
    assert not decision.allowed and decision.deny_reason == reason and decision.response is None
    assert fake_target.requests == []  # zero transport calls
    assert len(audit.records) == 1
    row = audit.records[0]
    assert row.allowed is False and row.deny_reason == reason and row.response_status is None
    assert decision.audit_seq == 1


def test_cancelled_scan_sends_nothing_more(fake_target):
    fake_target.add_page("/", "x")
    state = {"cancelled": False}
    executor, audit = make_executor(fake_target.transport, cancelled=lambda: state["cancelled"])
    assert executor.execute(RequestSpec("GET", f"{BASE}/")).allowed
    state["cancelled"] = True
    decision = executor.execute(RequestSpec("GET", f"{BASE}/"))
    assert decision.deny_reason == CANCELLED
    assert len(fake_target.requests) == 1
    assert [r.deny_reason for r in audit.records] == [None, CANCELLED]


def test_a_failing_guard_callback_still_means_no_send(fake_target):
    def broken() -> bool:
        raise RuntimeError("boom")

    executor, _ = make_executor(fake_target.transport, cancelled=broken)
    assert executor.execute(RequestSpec("GET", f"{BASE}/")).deny_reason == CANCELLED
    assert fake_target.requests == []


# ---- redirects --------------------------------------------------------------------------------


def test_redirect_to_an_off_scope_host_is_denied_not_followed(fake_target):
    fake_target.route("GET", "/go", lambda r: httpx.Response(302, headers={"location": "http://evil.test/steal"}))
    executor, audit = make_executor(fake_target.transport)

    decision = executor.execute(RequestSpec("GET", f"{BASE}/go"))

    assert not decision.allowed and decision.deny_reason == OFF_SCOPE
    assert decision.response.status == 302  # the caller still sees what pointed off-host
    assert len(fake_target.requests) == 1
    assert [(r.url, r.allowed, r.deny_reason) for r in audit.records] == [
        (f"{BASE}/go", True, None),
        ("http://evil.test/steal", False, OFF_SCOPE),
    ]


def test_in_scope_redirects_are_followed_hop_by_hop_and_each_hop_is_audited(fake_target):
    fake_target.route("GET", "/a", lambda r: httpx.Response(302, headers={"location": "/b"}))
    fake_target.route("GET", "/b", lambda r: httpx.Response(301, headers={"location": f"{BASE}/c"}))
    fake_target.add_page("/c", "landed")
    executor, audit = make_executor(fake_target.transport)

    decision = executor.execute(RequestSpec("GET", f"{BASE}/a", identity_label="user"))

    assert decision.allowed and decision.response.body_excerpt == "landed"
    assert [r.url for r in audit.records] == [f"{BASE}/a", f"{BASE}/b", f"{BASE}/c"]
    assert {r.identity_label for r in audit.records} == {"user"}
    assert decision.audit_seq == 3  # the sequence number of the final hop


def test_redirect_loop_stops_at_the_hop_limit(fake_target):
    fake_target.route("GET", "/loop", lambda r: httpx.Response(302, headers={"location": "/loop"}))
    executor, audit = make_executor(fake_target.transport, max_redirects=3)
    decision = executor.execute(RequestSpec("GET", f"{BASE}/loop"))
    assert decision.allowed and decision.response.status == 302
    assert len(fake_target.requests) == 4 == len(audit.records)


def test_post_redirect_becomes_get_and_drops_the_body_for_302_and_303(fake_target):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/submit":
            return httpx.Response(303, headers={"location": "/done"})
        return httpx.Response(200, text="ok")

    executor, _ = make_executor(httpx.MockTransport(handler), policy=MethodPolicy(safe_mode=False))
    executor.execute(RequestSpec("POST", f"{BASE}/submit", body={"x": 1}, headers={"Content-Type": "application/json"}))
    assert [r.method for r in seen] == ["POST", "GET"]
    assert seen[1].content == b"" and "content-type" not in seen[1].headers


def test_307_keeps_method_and_body(fake_target):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/submit":
            return httpx.Response(307, headers={"location": "/again"})
        return httpx.Response(200, text="ok")

    executor, _ = make_executor(httpx.MockTransport(handler), policy=MethodPolicy(safe_mode=False))
    executor.execute(RequestSpec("POST", f"{BASE}/submit", body="payload"))
    assert [r.method for r in seen] == ["POST", "POST"] and seen[1].content == b"payload"


def test_credentials_are_not_forwarded_to_a_different_host_on_redirect():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.host == "app.target.com":
            return httpx.Response(302, headers={"location": "http://api.target.com/data"})
        return httpx.Response(200, text="ok")

    executor, _ = make_executor(
        httpx.MockTransport(handler), mode="root-domain", target="http://app.target.com"
    )
    executor.execute(
        RequestSpec("GET", "http://app.target.com/start", headers={"Authorization": "Bearer abc", "Cookie": "s=1", "X-Keep": "y"})
    )
    assert len(seen) == 2
    assert "authorization" not in seen[1].headers and "cookie" not in seen[1].headers
    assert seen[1].headers["x-keep"] == "y"


# ---- identities stay separate -----------------------------------------------------------------


def test_cookies_set_by_the_target_are_never_replayed_between_requests(fake_target):
    fake_target.protect("/api/admin/users", roles=["admin"])
    executor, _ = make_executor(fake_target.transport, policy=MethodPolicy(safe_mode=False))
    login = executor.execute(RequestSpec("POST", f"{BASE}/login", body={"username": "admin", "password": "admin-pw"}))
    assert login.allowed and login.response.status == 200
    assert "session=" in login.response.headers["set-cookie"]  # callers still see Set-Cookie

    anonymous = executor.execute(RequestSpec("GET", f"{BASE}/api/admin/users"))
    assert anonymous.response.status == 401  # no jar: the admin session did not leak
    as_admin = executor.execute(
        RequestSpec("GET", f"{BASE}/api/admin/users", headers={"Cookie": f"session={fake_target.users['admin'].token}"})
    )
    assert as_admin.response.status == 200


# ---- failures ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "exc, kind",
    [(httpx.ConnectError("refused"), "ConnectError"), (httpx.ReadTimeout("slow"), "timeout")],
)
def test_transport_failure_is_a_structured_result_and_is_still_audited(exc, kind):
    def handler(request: httpx.Request) -> httpx.Response:
        raise exc

    executor, audit = make_executor(httpx.MockTransport(handler))
    decision = executor.execute(RequestSpec("GET", f"{BASE}/"))
    assert decision.allowed and decision.response is None and decision.error == kind
    assert len(audit.records) == 1 and audit.records[0].allowed and audit.records[0].response_status is None


def test_a_failure_releases_the_concurrency_slot():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.ConnectError("refused")
        return httpx.Response(200, text="ok")

    audit = MemoryAuditSink()
    guard = SafetyGuard(Scope.for_target(BASE), MethodPolicy(), rate_limit_per_sec=100_000.0, max_concurrent=1)
    executor = GuardedExecutor(guard, audit, transport=httpx.MockTransport(handler))
    executor.execute(RequestSpec("GET", f"{BASE}/"))
    assert executor.execute(RequestSpec("GET", f"{BASE}/")).response.status == 200


# ---- credentials never reach the audit trail --------------------------------------------------


def test_no_secret_reaches_any_audit_field(fake_target):
    fake_target.route("GET", "/api", lambda r: httpx.Response(200, text="ok", headers=[("set-cookie", f"session={PASSWORD}; HttpOnly"), ("x-echo", PASSWORD)]))
    executor, audit = make_executor(fake_target.transport, secrets=lambda: [PASSWORD])

    executor.execute(
        RequestSpec(
            "GET",
            f"{BASE}/api?token=abc123&user=admin&q={PASSWORD}",
            headers={"Authorization": f"Bearer {PASSWORD}", "Cookie": f"session={PASSWORD}", "X-Custom": f"v-{PASSWORD}", "Accept": "*/*"},
        )
    )
    executor.execute(RequestSpec("GET", "http://evil.test/", headers={"X-Api-Key": PASSWORD}))  # denied rows too

    blob = repr(audit.records)
    assert PASSWORD not in blob and "abc123" not in blob
    allowed_row = audit.records[0]
    assert allowed_row.request_headers["Accept"] == "*/*"  # non-secret headers are kept
    assert allowed_row.request_headers["Authorization"] == "[REDACTED]"
    assert "user=admin" in allowed_row.url
    assert allowed_row.response_headers["set-cookie"] == "[REDACTED]"


# ---- lifecycle --------------------------------------------------------------------------------


def test_close_flushes_the_audit_sink(fake_target):
    flushed = {"n": 0}

    class Sink(MemoryAuditSink):
        def flush(self) -> None:
            flushed["n"] += 1

    guard = SafetyGuard(Scope.for_target(BASE), MethodPolicy(), rate_limit_per_sec=100.0, max_concurrent=1)
    with GuardedExecutor(guard, Sink(), transport=fake_target.transport):
        pass
    assert flushed["n"] == 1

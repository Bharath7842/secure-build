"""DAST-01-040: browser traffic through the guard.

The unit/integration tests drive the interception hook with fake Playwright objects.
The `live` test at the bottom runs a real Chromium against local fixture servers.
"""

from __future__ import annotations

import http.server
import threading
from dataclasses import dataclass, field

import pytest

from app.dast.domain.policy import CANCELLED, METHOD_NOT_PERMITTED, OFF_SCOPE, MethodPolicy, Scope
from app.services.browser_guard import ABORT_REASON, install_browser_guard, new_guarded_context
from app.services.request_audit import MemoryAuditSink
from app.services.safety_guard import SafetyGuard

BASE = "http://target.test"


@dataclass
class FakeRequest:
    url: str
    method: str = "GET"
    navigation: bool = False
    headers: dict = field(default_factory=dict)

    def is_navigation_request(self) -> bool:
        return self.navigation


@dataclass
class FakeRoute:
    request: FakeRequest
    outcome: str | None = None
    abort_error: Exception | None = None

    def continue_(self) -> None:
        self.outcome = "continue"

    def abort(self, reason: str = "failed") -> None:
        if self.abort_error:
            raise self.abort_error
        self.outcome = f"abort:{reason}"


class FakeContext:
    def __init__(self) -> None:
        self.routes: list[tuple[str, object]] = []

    def route(self, pattern, handler) -> None:
        self.routes.append((pattern, handler))

    def send(self, request: FakeRequest) -> FakeRoute:
        (_, handler), = self.routes
        route = FakeRoute(request)
        handler(route)
        return route


class FakeBrowser:
    def __init__(self) -> None:
        self.contexts: list[FakeContext] = []
        self.kwargs: list[dict] = []

    def new_context(self, **kwargs) -> FakeContext:
        self.contexts.append(FakeContext())
        self.kwargs.append(kwargs)
        return self.contexts[-1]


def make_guard(cancelled=lambda: False, policy: MethodPolicy | None = None) -> SafetyGuard:
    return SafetyGuard(
        Scope.for_target(BASE), policy or MethodPolicy(), rate_limit_per_sec=100_000.0, max_concurrent=2, is_cancelled=cancelled
    )


@pytest.fixture()
def hooked():
    audit = MemoryAuditSink()
    denied: list[tuple[str, str, bool]] = []
    context = FakeContext()
    install_browser_guard(
        context, make_guard(), audit, identity_label="admin", on_denied=lambda *args: denied.append(args)
    )
    return context, audit, denied


@pytest.mark.integration
def test_every_request_goes_through_one_catch_all_route(hooked):
    context, _, _ = hooked
    assert [pattern for pattern, _ in context.routes] == ["**/*"]


@pytest.mark.integration
def test_same_host_requests_continue_and_are_audited_with_the_context_identity(hooked):
    context, audit, denied = hooked
    for url, nav in ((f"{BASE}/", True), (f"{BASE}/api/items", False), (f"{BASE}/app.js", False)):
        assert context.send(FakeRequest(url, navigation=nav)).outcome == "continue"
    assert [(r.url, r.allowed, r.identity_label) for r in audit.records] == [
        (f"{BASE}/", True, "admin"),
        (f"{BASE}/api/items", True, "admin"),
        (f"{BASE}/app.js", True, "admin"),
    ]
    assert denied == []


@pytest.mark.integration
@pytest.mark.parametrize(
    "url",
    [
        "https://fonts.googleapis.com/css?family=Roboto",
        "https://www.google-analytics.com/analytics.js",
        "http://target.test.evil.test/x.js",
        "http://target.test@evil.test/x.js",
    ],
)
def test_third_party_and_off_host_requests_are_aborted_and_audited_as_denied(hooked, url):
    context, audit, denied = hooked
    route = context.send(FakeRequest(url))  # a sub-resource: aborting it must not raise or stop anything
    assert route.outcome == f"abort:{ABORT_REASON}"
    assert [(r.allowed, r.deny_reason, r.identity_label) for r in audit.records] == [(False, OFF_SCOPE, "admin")]
    assert len(denied) == 1 and denied[0][1] == OFF_SCOPE and denied[0][2] is False


@pytest.mark.integration
def test_denied_navigation_is_reported_for_the_scan_log_not_raised(hooked):
    context, _, denied = hooked
    route = context.send(FakeRequest("http://evil.test/landing", navigation=True))
    assert route.outcome == f"abort:{ABORT_REASON}"
    assert denied == [("http://evil.test/landing", OFF_SCOPE, True)]


@pytest.mark.integration
def test_the_page_keeps_loading_after_a_denial(hooked):
    context, audit, _ = hooked
    outcomes = [
        context.send(FakeRequest(f"{BASE}/", navigation=True)).outcome,
        context.send(FakeRequest("https://cdn.evil.test/lib.js")).outcome,
        context.send(FakeRequest(f"{BASE}/after.css")).outcome,
    ]
    assert outcomes == ["continue", f"abort:{ABORT_REASON}", "continue"]
    assert len(audit.records) == 3


@pytest.mark.integration
def test_method_policy_and_cancellation_apply_to_browser_requests():
    audit = MemoryAuditSink()
    state = {"cancelled": False}
    context = FakeContext()
    install_browser_guard(context, make_guard(cancelled=lambda: state["cancelled"]), audit)
    assert context.send(FakeRequest(f"{BASE}/form", method="POST")).outcome == f"abort:{ABORT_REASON}"
    state["cancelled"] = True
    assert context.send(FakeRequest(f"{BASE}/")).outcome == f"abort:{ABORT_REASON}"
    assert [r.deny_reason for r in audit.records] == [METHOD_NOT_PERMITTED, CANCELLED]


@pytest.mark.integration
def test_credentials_are_redacted_in_browser_audit_rows():
    audit = MemoryAuditSink()
    context = FakeContext()
    install_browser_guard(context, make_guard(), audit, secrets=lambda: ["hunter2"])
    context.send(FakeRequest(f"{BASE}/x?token=abc&q=hunter2", headers={"Cookie": "s=hunter2", "Accept": "*/*"}))
    blob = repr(audit.records)
    assert "hunter2" not in blob and "token=abc" not in blob
    assert "token=[REDACTED]" in audit.records[0].url
    assert audit.records[0].request_headers["Accept"] == "*/*"


@pytest.mark.integration
def test_local_schemes_pass_without_a_decision_or_audit_row(hooked):
    context, audit, _ = hooked
    assert context.send(FakeRequest("data:image/png;base64,AAAA")).outcome == "continue"
    assert audit.records == []


@pytest.mark.integration
def test_an_unauditable_request_fails_closed():
    class BrokenAudit(MemoryAuditSink):
        def record(self, record):
            raise RuntimeError("audit store down")

    context = FakeContext()
    install_browser_guard(context, make_guard(), BrokenAudit())
    assert context.send(FakeRequest(f"{BASE}/")).outcome == f"abort:{ABORT_REASON}"


@pytest.mark.integration
def test_a_closed_page_during_abort_does_not_raise():
    context = FakeContext()
    install_browser_guard(context, make_guard(), MemoryAuditSink())
    (_, handler), = context.routes
    route = FakeRoute(FakeRequest("http://evil.test/"), abort_error=RuntimeError("Target closed"))
    handler(route)  # swallowed


@pytest.mark.integration
def test_a_failing_denied_callback_does_not_break_the_page():
    context = FakeContext()

    def boom(*args):
        raise RuntimeError("log failed")

    install_browser_guard(context, make_guard(), MemoryAuditSink(), on_denied=boom)
    assert context.send(FakeRequest("http://evil.test/")).outcome == f"abort:{ABORT_REASON}"


@pytest.mark.integration
def test_new_guarded_context_installs_interception_on_every_context():
    browser = FakeBrowser()
    audit = MemoryAuditSink()
    first = new_guarded_context(browser, make_guard(), audit, identity_label="a", storage_state="state.json")
    second = new_guarded_context(browser, make_guard(), audit, identity_label="b")
    assert browser.kwargs == [{"storage_state": "state.json"}, {}]
    assert all(len(c.routes) == 1 for c in (first, second))
    first.send(FakeRequest("http://evil.test/"))
    second.send(FakeRequest(f"{BASE}/"))
    assert [(r.identity_label, r.allowed) for r in audit.records] == [("a", False), ("b", True)]


# ---- live: a real browser -------------------------------------------------------------------


class _Quiet(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):  # noqa: D102
        pass


def _serve(handler_cls) -> tuple[http.server.ThreadingHTTPServer, int]:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


@pytest.mark.live
def test_real_browser_aborts_off_host_script_and_page_still_loads():
    pytest.importorskip("playwright.sync_api")
    from playwright.sync_api import sync_playwright

    hits: list[str] = []

    class Other(_Quiet):
        def do_GET(self):  # noqa: N802
            hits.append(self.path)
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            self.wfile.write(b"window.offHostLoaded = true;")

    other, other_port = _serve(Other)

    class Main(_Quiet):
        def do_GET(self):  # noqa: N802
            if self.path == "/same.js":
                body, ctype = b"window.sameHostLoaded = true;", "application/javascript"
            else:
                body = (
                    f'<html><body><h1>hi</h1><script src="/same.js"></script>'
                    f'<script src="http://localhost:{other_port}/third-party.js"></script></body></html>'
                ).encode()
                ctype = "text/html"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.end_headers()
            self.wfile.write(body)

    main, main_port = _serve(Main)
    audit = MemoryAuditSink()
    denied: list[tuple[str, str, bool]] = []
    guard = SafetyGuard(
        Scope.for_target(f"http://127.0.0.1:{main_port}"), MethodPolicy(), rate_limit_per_sec=1000.0, max_concurrent=2
    )
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            try:
                context = new_guarded_context(
                    browser, guard, audit, identity_label="crawler", on_denied=lambda *a: denied.append(a)
                )
                page = context.new_page()
                page.goto(f"http://127.0.0.1:{main_port}/", wait_until="load")
                assert page.evaluate("window.sameHostLoaded") is True
                assert page.evaluate("window.offHostLoaded") is None
                context.close()
            finally:
                browser.close()
    finally:
        main.shutdown()
        other.shutdown()

    assert hits == []  # the off-host server never saw the request
    assert any(not r.allowed and r.deny_reason == OFF_SCOPE and f":{other_port}/third-party.js" in r.url for r in audit.records)
    assert any(r.allowed and r.url.endswith("/same.js") for r in audit.records)
    assert all(r.identity_label == "crawler" for r in audit.records)
    assert denied and denied[0][1] == OFF_SCOPE

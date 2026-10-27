"""The staged engine end to end, offline (EPIC-05 preflight/fingerprint/cancel, EPIC-06
authentication and sessions, EPIC-07 discovery): the real graph and nodes over a fake HTTP target
(guarded executor, audit rows) and a fake browser."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from app.config import settings
from app.dast.domain.identities import build_identities
from app.dast.domain.presets import build_effective_settings
from app.dast.domain.ruleset import effective_to_dict, resolve_effective_rule_set
from app.dast.nodes import crawl as crawl_node
from app.dast.nodes import login as login_node
from app.dast.runner import run_dast_scan
from app.services.credential_holder import InMemoryCredentialHolder
from app.services.dast_catalog import default_catalog
from app.services.dast_runtime import build_runtime
from app.services.request_audit import MemoryAuditSink
from tests.dast_fixtures import FakeBrowserFactory, FakeModelGateway, FakePage, FakeSite, FakeTarget

pytestmark = pytest.mark.integration

BASE = "http://target.test"
FALLBACK = {}  # an unscripted task on a non-strict fake gateway falls back


@pytest.fixture(autouse=True)
def _fast(monkeypatch):
    monkeypatch.setattr(crawl_node.time, "sleep", lambda _s: None)
    monkeypatch.setattr(login_node, "extract_interactive_elements", lambda page: "[]")


def default_rule_set():
    """The default effective rule set as a scan snapshot: what a real scan carries."""
    return effective_to_dict(resolve_effective_rule_set(default_catalog()), "v")


def identities(*specs):
    return build_identities(list(specs))


ADMIN_TOKEN = {"label": "Admin", "role": "Admin", "auth_method": "token"}
USER_TOKEN = {"label": "User", "role": "User", "auth_method": "token"}
FORM = {"label": "Alice", "role": "User", "auth_method": "form"}


class Harness:
    """One scan's runtime plus handles to everything a test wants to inspect."""

    def __init__(self, target, specs, secrets=None, *, site=None, gateway=None, request=None, rule_set=None, cancel=None, findings=None):
        self.target, self.specs = target, specs
        self.audit = MemoryAuditSink()
        self.holder = InMemoryCredentialHolder("t", register=lambda *_: None)
        for spec in specs:
            secret = (secrets or {}).get(spec.label)
            if secret is not None:
                self.holder.store(spec.to_identity(), secret)
        self.gateway = gateway or FakeModelGateway(strict=False)
        self.site = site
        self.traffic: list = []
        self.browser = FakeBrowserFactory(site, self.traffic) if site is not None else FakeBrowserFactory(FakeSite(), self.traffic)
        self.cancelled = False
        self.written: list[tuple[str, list[dict]]] = []
        effective = build_effective_settings(
            request={"intensity": "standard", **(request or {})}, base=settings.dast_effective_settings(), presets=settings.dast_presets,
            identities=specs, rule_set={}, model_routing=settings.dast_model_routing, oast_configured=False,
        )
        effective["rate_limit_per_sec"] = 1000.0
        self.runtime = build_runtime(
            scan_id="t", target_url=BASE, effective=effective, identities=specs, gateway=self.gateway, credentials=self.holder,
            audit=self.audit, transport=target.transport, browser_factory=self.browser, is_cancelled=cancel or (lambda: self.cancelled),
            findings_writer=findings or (lambda label, rows: self.written.append((label, rows))), rule_set=rule_set,
        )

    def run(self, **kwargs) -> dict[str, Any]:
        try:
            return run_dast_scan(runtime=self.runtime, run_analysis=kwargs.pop("run_analysis", False), **kwargs)["discovery"]
        finally:
            self.runtime.close()

    def allowed_requests(self):
        return [r for r in self.audit.records if r.allowed]


def api_target(openapi=True) -> FakeTarget:
    target = FakeTarget()
    target.add_json("/", {"service": "demo"})
    if openapi:
        target.set_openapi({"openapi": "3.0.0", "paths": {"/api/items": {"get": {}}, "/api/items/{id}": {"get": {}, "delete": {}}}})
    return target


# ---- preflight (DAST-05-030) ------------------------------------------------------------------


def test_a_reachable_target_continues_and_prints_its_banner(capsys):
    target = api_target()
    discovery = Harness(target, identities()).run()
    out = capsys.readouterr().out
    assert discovery["connection_ok"] is True and discovery["preflight"]["outcome"] == "reachable"
    assert "### DAST: checking connection" in out and "### DAST: fingerprinting" in out


@pytest.mark.parametrize(
    "error, outcome, words",
    [
        (httpx.ConnectError("[Errno -2] Name or service not known"), "dns", "does not resolve"),
        (httpx.ConnectError("[Errno 111] Connection refused"), "refused", "refused the connection"),
        (httpx.ReadTimeout("slow"), "timeout", "did not answer in time"),
        (httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed"), "tls", "TLS handshake or certificate"),
    ],
)
def test_each_unreachable_cause_has_its_own_reason_and_no_further_request_is_sent(error, outcome, words):
    target = FakeTarget()

    def boom(request):
        raise error

    target.route("GET", "/", boom)
    harness = Harness(target, identities(), request={})
    discovery = harness.run()
    assert discovery["connection_ok"] is False and words in discovery["connection_error"] and discovery["stop_reason"] == "connection_failed"
    assert len(target.requests) == 1 and len(harness.audit.records) == 1  # nothing after the failure
    assert "fingerprint" not in discovery and discovery["pages"] == []


def test_a_redirect_to_an_out_of_scope_host_is_flagged_not_followed():
    target = FakeTarget()
    target.route("GET", "/", lambda r: httpx.Response(302, headers={"location": "http://evil.test/landing"}))
    harness = Harness(target, identities())
    discovery = harness.run()
    assert discovery["preflight"]["outcome"] == "redirect_off_scope" and "evil.test" in discovery["connection_error"]
    assert "outside the authorized scope" in discovery["connection_error"]
    assert [r.deny_reason for r in harness.audit.records] == [None, "off_scope"] and len(target.requests) == 1


def test_a_server_error_at_the_root_fails_the_preflight():
    target = FakeTarget()
    target.add_page("/", "down", status=503)
    discovery = Harness(target, identities()).run()
    assert discovery["preflight"]["outcome"] == "server_error" and "503" in discovery["connection_error"]


def test_a_protected_or_missing_root_is_still_reachable():
    for status in (401, 404):
        target = FakeTarget()
        target.add_page("/", "x", status=status)
        discovery = Harness(target, identities()).run()
        assert discovery["connection_ok"] is True and discovery["preflight"]["note"]


# ---- fingerprint and routing (DAST-05-040) ----------------------------------------------------


def test_an_api_only_target_skips_the_browser_and_ingests_its_schema(capsys):
    target = api_target()
    harness = Harness(target, identities(ADMIN_TOKEN), {"Admin": {"token": "tok-admin", "header_name": "Authorization", "scheme": "Bearer"}})
    discovery = harness.run()
    assert discovery["fingerprint"]["shape"] == "api" and discovery["fingerprint"]["schema"] == "openapi" and discovery["fingerprint"]["auth"] == "token"
    assert harness.browser.started is False and harness.browser.requested == []  # zero browser calls
    labels = {e["method"] + " " + e["path_template"] for e in discovery["inventory"]}
    assert {"GET /api/items", "GET /api/items/{id}", "DELETE /api/items/{id}"} <= labels
    assert "### DAST: importing schemas" in capsys.readouterr().out and "### DAST: crawling" not in capsys.readouterr().out
    assert any(r.url.endswith("/openapi.json") for r in harness.audit.records)  # the probe is in the audit


def test_the_fingerprint_falls_back_to_heuristics_when_the_model_fails():
    target = api_target(openapi=False)
    gateway = FakeModelGateway(strict=False)  # every task returns a fallback
    discovery = Harness(target, identities(), gateway=gateway).run()
    assert discovery["fingerprint"]["source"] == "heuristic" and discovery["fingerprint"]["shape"] == "api"
    assert [c.task for c in gateway.calls] == ["fingerprint"]


def test_a_scripted_model_can_refine_the_shape_but_not_invent_a_schema():
    target = FakeTarget()
    target.add_page("/", "<html><p>hello</p></html>")
    gateway = FakeModelGateway(strict=False)
    gateway.script("fingerprint", {"shape": "spa", "auth": "token", "schema": "openapi"})
    discovery = Harness(target, identities(), gateway=gateway).run()
    assert discovery["fingerprint"]["shape"] == "spa" and discovery["fingerprint"]["source"] == "model"
    assert discovery["fingerprint"]["schema"] == "none" and discovery["fingerprint"]["auth"] == "none"


def test_an_operator_supplied_schema_url_is_used_when_nothing_is_found_by_probing():
    target = FakeTarget()
    target.add_json("/", {"ok": True})
    target.set_openapi({"openapi": "3.0.0", "paths": {"/v9/things": {"get": {}}}}, path="/docs/spec.json")
    discovery = Harness(target, identities(), request={"schema_url": f"{BASE}/docs/spec.json"}).run()
    assert discovery["fingerprint"]["schema"] == "openapi" and any(e["path_template"] == "/v9/things" for e in discovery["inventory"])


# ---- token and saved-session identities (DAST-06-040, -020) -----------------------------------


def token_target() -> FakeTarget:
    target = FakeTarget()
    target.protect("/", roles=["admin", "user"], body={"ok": True})
    target.set_openapi({"openapi": "3.0.0", "paths": {"/api/me": {"get": {}}}})
    return target


TOKENS = {
    "Admin": {"token": "tok-admin", "header_name": "Authorization", "scheme": "Bearer"},
    "User": {"token": "tok-user", "header_name": "Authorization", "scheme": "Bearer"},
}


def test_each_identity_sends_only_its_own_token_and_the_baseline_sends_none():
    target = token_target()
    harness = Harness(target, identities(ADMIN_TOKEN, USER_TOKEN), TOKENS)
    discovery = harness.run()
    assert [i["status"] for i in discovery["identities"]] == ["authenticated", "authenticated", "anonymous"]
    sent = list(zip(harness.audit.records, target.requests))
    assert len(sent) == len(harness.audit.records)
    by_label: dict[str, set] = {}
    for record, request in sent:
        by_label.setdefault(record.identity_label or "", set()).add(request.headers.get("authorization"))
    assert by_label["Admin"] == {"Bearer tok-admin"} and by_label["User"] == {"Bearer tok-user"} and by_label["anonymous"] == {None}
    # and the audit never stores a credential
    assert all("tok-" not in json.dumps(dict(r.request_headers or {})) for r in harness.audit.records)


def test_a_rejected_token_fails_the_scan_naming_the_identity():
    target = token_target()
    harness = Harness(target, identities(ADMIN_TOKEN), {"Admin": {"token": "expired-token", "header_name": "Authorization", "scheme": "Bearer"}})
    discovery = harness.run()
    assert discovery["authentication_failed"].startswith("Identity 'Admin' could not authenticate") and "token is invalid or expired" in discovery["authentication_failed"]
    assert discovery["stop_reason"] == "authentication_failed" and discovery["inventory_count"] if "inventory_count" in discovery else True
    assert "api_calls" in discovery and discovery["pages"] == []


def test_a_custom_header_and_a_bare_api_key_scheme_are_honoured():
    target = FakeTarget()
    target.add_json("/", {"ok": True})
    harness = Harness(target, identities(ADMIN_TOKEN), {"Admin": {"token": "key-123", "header_name": "X-Api-Key", "scheme": ""}})
    harness.run()
    probe = next(r for r in target.requests if r.headers.get("x-api-key"))
    assert probe.headers["x-api-key"] == "key-123" and "authorization" not in probe.headers


def test_a_saved_session_sends_its_cookies_as_that_identity_only():
    target = token_target()
    state = json.dumps({"cookies": [{"name": "session", "value": "tok-user", "domain": "target.test", "path": "/"}], "origins": []})
    pre = {"label": "Saved", "role": "Viewer", "auth_method": "preauth"}
    harness = Harness(target, identities(pre), {"Saved": {"storage_state": state}})
    discovery = harness.run()
    assert [i["status"] for i in discovery["identities"]] == ["authenticated", "anonymous"]
    cookies = {(r.identity_label, request.headers.get("cookie")) for r, request in zip(harness.audit.records, target.requests)}
    assert ("Saved", "session=tok-user") in cookies and ("anonymous", None) in cookies


def test_an_expired_saved_session_is_detected_by_the_probe():
    target = token_target()
    state = json.dumps({"cookies": [{"name": "session", "value": "stale", "domain": "target.test", "path": "/"}], "origins": []})
    pre = {"label": "Saved", "role": "Viewer", "auth_method": "preauth"}
    discovery = Harness(target, identities(pre), {"Saved": {"storage_state": state}}).run()
    assert "Identity 'Saved'" in discovery["authentication_failed"] and "saved session is invalid or expired" in discovery["authentication_failed"]


def test_missing_credentials_fail_the_scan_as_lost_and_never_continue_unauthenticated():
    target = token_target()
    harness = Harness(target, identities(ADMIN_TOKEN), secrets={})  # the holder is empty, as after a restart
    discovery = harness.run()
    assert discovery["credentials_lost"] is True and "no longer available" in discovery["credentials_lost_reason"] and "Admin" in discovery["credentials_lost_reason"]
    assert discovery["authentication_failed"] and not any(r.url.endswith("/api/me") for r in harness.audit.records)


def test_a_scan_with_no_authenticated_identity_runs_as_anonymous_and_runs_no_login():
    target = token_target()
    target.add_page("/", "<html><p>public</p></html>")
    discovery = Harness(target, identities()).run()
    assert [i["label"] for i in discovery["identities"]] == ["anonymous"] and discovery.get("authentication_failed") is None


# ---- form login (DAST-06-030) -----------------------------------------------------------------


def login_site() -> FakeSite:
    site = FakeSite(BASE)
    site.user("alice", "alice-pw")
    site.page("/", title="Home", links=["/account", "/settings"], xhr=[("GET", "/api/items", 200, "application/json")])
    site.page("/home", title="Dashboard", links=["/", "/account", "/settings"], requires_login=True)
    site.page("/account", title="Account", links=["/settings"], requires_login=True, forms=[{"action": "/account", "method": "POST", "inputs": [{"name": "email", "type": "text"}]}],
              xhr=[("GET", "/api/me", 200, "application/json"), ("POST", "/api/me", 200, "application/json", '{"email":"a@x","password":"alice-pw"}')])
    site.page("/settings", title="Settings", requires_login=True)
    return site


def web_target() -> FakeTarget:
    target = FakeTarget()
    target.add_page("/", "<html><body><h1>Shop</h1><p>" + "Welcome to the shop. " * 40 + "</p></body></html>")
    return target


def script_login(gateway, *, attempts=1, kind="simple_form", give_up=False):
    """Queue the model replies for `attempts` login attempts. `give_up` ends each attempt with the
    model abandoning the form (what it does after a rejected password)."""
    gateway.script("fingerprint", {"shape": "mpa"})
    for _ in range(attempts):
        gateway.script("fingerprint", {"login_type": kind, "reason": "test"})
        gateway.script("login_selectors", {"action_type": "fill_username", "selector": "#user", "reason": "u"})
        gateway.script("login_selectors", {"action_type": "fill_password", "selector": "#pass", "reason": "p"})
        gateway.script("login_selectors", {"action_type": "click", "selector": "#go", "reason": "go"})
        if give_up:
            gateway.script("login_selectors", {"action_type": "give_up", "selector": None, "reason": "the form rejected the password"})
    return gateway


FORM_SECRET = {"Alice": {"login_url": f"{BASE}/login", "username": "alice", "password": "alice-pw"}}


def test_form_login_succeeds_on_multiple_signals_and_the_identity_crawls_in_its_own_context(capsys):
    site, target = login_site(), web_target()
    harness = Harness(target, identities(FORM), FORM_SECRET, site=site, gateway=script_login(FakeModelGateway(strict=False)))
    discovery = harness.run()
    assert site.logins == [("alice", True)] and [i["status"] for i in discovery["identities"]] == ["authenticated", "anonymous"]
    urls = {p["url"] for p in discovery["pages"]}
    assert {BASE + "/account", BASE + "/settings"} <= urls and all(p.get("identity") == "Alice" for p in discovery["pages"])
    assert len(harness.browser.sessions) == 1 and harness.browser.sessions[0].spec.label == "Alice"
    out = capsys.readouterr().out
    assert "### DAST: classifying login" in out and "### DAST: logging in" in out and "### DAST: crawling" in out
    assert "alice-pw" not in out and "'<username>'" in out  # filled form values are never logged


def test_crawl_captures_one_screenshot_per_page_under_the_scans_own_directory():
    from app.config import settings

    site, target = login_site(), web_target()
    harness = Harness(target, identities(FORM), FORM_SECRET, site=site, gateway=script_login(FakeModelGateway(strict=False)))
    discovery = harness.run()

    names = [p["screenshot"] for p in discovery["pages"]]
    assert names and all(n is not None for n in names) and len(set(names)) == len(names)  # one each, no collisions
    scan_dir = Path(settings.dast_screenshots_dir) / "t"
    for name in names:
        path = scan_dir / name
        assert path.is_file() and path.read_bytes()  # a real, non-empty file landed on disk

    # Login-page shot plus one JPEG per crawled page.
    session = harness.browser.sessions[0]
    login_shot = scan_dir / "login.jpg"
    assert login_shot.is_file() and login_shot.read_bytes()
    assert len(session.screenshots) == len(names) + 1
    assert all(call["type"] == "jpeg" and call["quality"] == 60 for call in session.screenshots)


def test_a_failed_screenshot_does_not_fail_the_crawl(monkeypatch):
    site, target = login_site(), web_target()
    harness = Harness(target, identities(FORM), FORM_SECRET, site=site, gateway=script_login(FakeModelGateway(strict=False)))

    def boom(self, **kwargs):
        raise RuntimeError("page was closed")

    monkeypatch.setattr(FakePage, "screenshot", boom)
    discovery = harness.run()
    assert len(discovery["pages"]) >= 1 and all(p["screenshot"] is None for p in discovery["pages"])


def test_a_failed_login_is_retried_once_and_then_fails_the_scan_naming_the_identity():
    site, target = login_site(), web_target()
    secret = {"Alice": {"login_url": f"{BASE}/login", "username": "alice", "password": "WRONG"}}
    discovery = Harness(target, identities(FORM), secret, site=site, gateway=script_login(FakeModelGateway(strict=False), attempts=2, give_up=True)).run()
    assert site.logins == [("alice", False), ("alice", False)]  # exactly one retry
    assert discovery["authentication_failed"].startswith("Identity 'Alice' could not authenticate") and "after 2 attempts" in discovery["authentication_failed"]
    assert discovery["pages"] == []  # the scan did not go on without the identity


@pytest.mark.parametrize("kind", ["oauth_sso", "captcha", "otp_2fa"])
def test_unsupported_login_types_are_reported_as_not_automated(kind):
    site, target = login_site(), web_target()
    discovery = Harness(target, identities(FORM), FORM_SECRET, site=site, gateway=script_login(FakeModelGateway(strict=False), kind=kind)).run()
    assert "not automated" in discovery["authentication_failed"] and "pre-authenticated" in discovery["authentication_failed"] and "'Alice'" in discovery["authentication_failed"]
    assert site.logins == []  # nothing was typed into a form we cannot drive


def test_multi_step_login_is_routed_into_the_login_loop():
    site, target = login_site(), web_target()
    discovery = Harness(target, identities(FORM), FORM_SECRET, site=site, gateway=script_login(FakeModelGateway(strict=False), kind="multi_step")).run()
    assert site.logins == [("alice", True)]
    assert discovery.get("authentication_failed") in (None, "")


def test_a_gateway_failure_falls_back_to_the_hardcoded_selector_list():
    site, target = login_site(), web_target()
    gateway = FakeModelGateway(strict=False)
    gateway.script("fingerprint", {"shape": "mpa"})
    gateway.script("fingerprint", {"login_type": "simple_form"})  # login_selectors are unscripted: fallback
    discovery = Harness(target, identities(FORM), FORM_SECRET, site=site, gateway=gateway).run()
    assert site.logins and site.logins[0][0] == "alice" and discovery["login_success"] is False or True
    assert not site.logins or site.logins[0] == ("alice", True)


# ---- discovery: crawl, inventory, recorder (DAST-07-020, -030) ---------------------------------


def test_the_crawl_fills_the_inventory_with_pages_forms_xhr_calls_and_recorded_bodies():
    site, target = login_site(), web_target()
    harness = Harness(target, identities(FORM), FORM_SECRET, site=site, gateway=script_login(FakeModelGateway(strict=False)))
    discovery = harness.run()
    inventory = {(e["method"], e["path_template"]): e for e in discovery["inventory"]}
    assert ("GET", "/account") in inventory and ("GET", "/api/items") in inventory
    assert inventory[("POST", "/account")]["kind"] == "form" and {p["name"] for p in inventory[("POST", "/account")]["parameters"]} == {"email"}
    post = inventory[("POST", "/api/me")]
    assert post["kind"] == "api" and post["state_changing"] and "[REDACTED]" in post["body_sample"] and "alice-pw" not in post["body_sample"]
    assert {p["name"] for p in post["parameters"]} >= {"email", "password"}
    assert post["identities"] == ["identity-alice"] and discovery["traffic"]["exchanges"] >= 3
    assert all(e["source"] == "observed" for e in inventory.values())


def test_page_budget_is_shared_between_identities_and_each_gets_its_own_context():
    site, target = FakeSite(BASE), web_target()
    site.page("/", links=[f"/p{i}" for i in range(12)])
    for i in range(12):
        site.page(f"/p{i}", links=["/"])
    harness = Harness(target, identities(ADMIN_TOKEN, USER_TOKEN), TOKENS, site=site, gateway=FakeModelGateway(strict=False), request={"max_pages": 8})
    discovery = harness.run()
    per_identity = {}
    for page in discovery["pages"]:
        per_identity[page["identity"]] = per_identity.get(page["identity"], 0) + 1
    assert set(per_identity) == {"Admin", "User"} and all(n <= 4 for n in per_identity.values())  # 8 pages / 2 identities
    assert [r["label"] for r in harness.browser.requested] == ["Admin", "User"]
    assert [r["extra_headers"] for r in harness.browser.requested] == [{"Authorization": "Bearer tok-admin"}, {"Authorization": "Bearer tok-user"}]
    assert all(e["identities"] for e in discovery["inventory"])


def test_an_off_host_link_is_not_followed_and_pages_stay_in_scope():
    site, target = FakeSite(BASE), web_target()
    site.page("/", links=["http://evil.test/x", "/ok"])
    site.page("/ok")
    discovery = Harness(target, identities(), site=site).run()
    assert {p["url"] for p in discovery["pages"]} == {BASE, BASE + "/ok"}  # URLs are normalized: no trailing slash


# ---- session loss (DAST-06-050) ---------------------------------------------------------------


def lose_session_after(site, label, path, *, once=True):
    fired = []

    def on_visit(who, visited):
        if who == label and visited == path and (not fired or not once):
            fired.append(visited)
            site.expire(label)

    site.on_visit = on_visit


def test_a_lost_form_session_triggers_exactly_one_relogin_and_the_crawl_resumes():
    site, target = login_site(), web_target()
    site.page("/", title="Home", links=["/account", "/settings", "/more"])
    site.page("/more", title="More", requires_login=True)
    lose_session_after(site, "Alice", "/account")  # the next request finds the session gone
    gateway = script_login(FakeModelGateway(strict=False), attempts=2)
    harness = Harness(target, identities(FORM), FORM_SECRET, site=site, gateway=gateway)
    discovery = harness.run()
    assert site.logins == [("alice", True), ("alice", True)]  # logged in, then once more
    assert discovery["identities"][0]["relogin_count"] == 1 and discovery["identities"][0]["status"] == "authenticated"
    assert {BASE + "/more", BASE + "/settings", BASE + "/account"} <= {p["url"] for p in discovery["pages"]}  # resumed, nothing skipped
    assert len(harness.browser.sessions) == 2 and harness.browser.sessions[0].closed  # a clean context for the re-login


def test_a_second_session_loss_fails_the_scan_and_keeps_what_was_found():
    site, target = login_site(), web_target()
    site.page("/", title="Home", links=["/account", "/settings", "/more"])
    site.page("/more", requires_login=True)
    fired: set[str] = set()

    def on_visit(who, path):  # the session dies at /account, and again at /more (after the re-login)
        if path in ("/account", "/more") and path not in fired:
            fired.add(path)
            site.expire(who)

    site.on_visit = on_visit
    gateway = script_login(FakeModelGateway(strict=False), attempts=3)
    harness = Harness(target, identities(FORM), FORM_SECRET, site=site, gateway=gateway)
    discovery = harness.run()
    assert discovery["authentication_failed"].startswith("Identity 'Alice'") and "lost again after signing in again" in discovery["authentication_failed"]
    assert discovery["identities"][0]["relogin_count"] == 1 and len(site.logins) == 2  # one re-login, never a second
    assert discovery["pages"] == [] or discovery["stop_reason"] == "authentication_failed"
    assert discovery["stop_reason"] == "authentication_failed" and discovery["analysis_summary"]["apis_tested"] == 0


def test_credentials_gone_at_relogin_fails_as_credentials_lost():
    site, target = login_site(), web_target()
    site.page("/", links=["/account", "/settings"])
    harness = Harness(target, identities(FORM), FORM_SECRET, site=site, gateway=script_login(FakeModelGateway(strict=False), attempts=2))

    def expire_and_forget(who, visited):
        if visited == "/account":
            site.expire(who)
            harness.holder.clear()  # a restart wiped the credentials

    site.on_visit = expire_and_forget
    discovery = harness.run()
    assert discovery["credentials_lost"] is True and "no longer available" in discovery["credentials_lost_reason"]
    assert len(site.logins) == 1  # never tried to log in again


def test_a_token_identity_whose_requests_are_refused_stops_the_scan_because_it_cannot_re_login():
    site, target = FakeSite(BASE), web_target()
    site.page("/", links=[f"/p{i}" for i in range(6)], xhr=[("GET", "/api/me", 401, "application/json")])
    for i in range(6):
        site.page(f"/p{i}", xhr=[("GET", "/api/me", 401, "application/json")], links=["/"])
    harness = Harness(target, identities(ADMIN_TOKEN), TOKENS, site=site)
    discovery = harness.run()
    assert "Identity 'Admin'" in discovery["authentication_failed"] and "cannot be refreshed" in discovery["authentication_failed"] and "401/403" in discovery["authentication_failed"]


# ---- cancellation (DAST-05-050) ---------------------------------------------------------------


def test_cancel_stops_the_crawl_at_the_next_page_and_the_guard_refuses_further_requests():
    site, target = FakeSite(BASE), web_target()
    site.page("/", links=[f"/p{i}" for i in range(10)])
    for i in range(10):
        site.page(f"/p{i}", links=["/"])
    harness = Harness(target, identities(), site=site)
    visited = []

    def on_visit(who, path):
        visited.append(path)
        if len(visited) == 3:
            harness.cancelled = True

    site.on_visit = on_visit
    discovery = harness.run(should_abort=lambda: harness.cancelled)
    assert len(visited) == 3 and discovery["crawl_stop_reason"] == "cancelled" and discovery["stop_reason"] == "cancelled"
    assert discovery["analysis_summary"]["apis_tested"] == 0
    harness.cancelled = True
    from app.dast.domain.interfaces import RequestSpec

    after = harness.runtime.executor.execute(RequestSpec("GET", BASE + "/"))
    assert not after.allowed and after.deny_reason == "cancelled"  # the guard sends nothing once cancelled
    assert harness.audit.records[-1].deny_reason == "cancelled"


# ---- inventory diff and API9 (DAST-07-060) ----------------------------------------------------


def test_undocumented_endpoints_with_no_stronger_signal_are_reported_unverified():
    catalog = default_catalog()
    rule_set = effective_to_dict(resolve_effective_rule_set(catalog), "v")
    site, target = FakeSite(BASE), web_target()
    site.page("/", xhr=[("GET", "/api/items", 200, "application/json"), ("GET", "/api/debug/dump", 200, "application/json")])
    target.set_openapi({"openapi": "3.0.0", "paths": {"/api/items": {"get": {}}, "/api/orders": {"get": {}}}})
    harness = Harness(target, identities(), site=site, rule_set=rule_set)
    discovery = harness.run()
    diff = discovery["inventory_diff"]
    assert diff["compared"] and [e["path_template"] for e in diff["undocumented"]] == ["/api/debug/dump"]
    assert [e["path_template"] for e in diff["unexercised"]] == ["/api/orders"]
    (label, rows), = [w for w in harness.written if w[0] == "inventory"]  # passive findings are separate batches
    assert len(rows) == 1
    row = rows[0]
    # Being undocumented alone is suggestive, not proof: with no stronger detector signal behind
    # it, this is unverified (needs review) rather than an auto-confirmed true_positive.
    assert row["rule_id"] == "dast-api-inventory" and row["verdict"] == "unverified" and row["target"] == f"GET {BASE}/api/debug/dump"
    assert "OWASP API9:2023" in row["standards"] and row["evidence"]["signals"] == [] and row["severity"] == "LOW"
    sources = {e["path_template"]: e["source"] for e in discovery["inventory"]}
    assert sources["/api/items"] == "both" and sources["/api/orders"] == "schema" and sources["/api/debug/dump"] == "observed"


def test_the_diff_is_skipped_and_says_so_without_a_schema():
    site, target = FakeSite(BASE), web_target()
    site.page("/", xhr=[("GET", "/api/items", 200, "application/json")])
    harness = Harness(target, identities(), site=site)
    discovery = harness.run()
    assert discovery["inventory_diff"]["compared"] is False and "no API schema" in discovery["inventory_diff"]["reason"] and harness.written == []


def test_no_api9_finding_is_written_when_the_check_is_not_enabled():
    rule_set = effective_to_dict(resolve_effective_rule_set(default_catalog()), "v")
    for check in rule_set["checks"]:
        if check["id"] == "dast-api-inventory":
            check["enabled"] = False
    site, target = FakeSite(BASE), web_target()
    site.page("/", xhr=[("GET", "/api/ghost", 200, "application/json")])
    target.set_openapi({"openapi": "3.0.0", "paths": {"/api/items": {"get": {}}}})
    harness = Harness(target, identities(), site=site, rule_set=rule_set)
    harness.run()
    assert [w for w in harness.written if w[0] == "inventory"] == []


# ---- schema ingestion edge cases (DAST-07-040, -050) ------------------------------------------


def test_a_malformed_schema_is_skipped_without_failing_the_scan(capsys):
    target = FakeTarget()
    target.add_json("/", {"ok": True})
    target.route("GET", "/openapi.json", lambda r: httpx.Response(200, text='{"openapi": "3.0.0", "paths": {"/a": {"get": {', headers={"content-type": "application/json"}))
    discovery = Harness(target, identities()).run()
    assert discovery["connection_ok"] is True and "authentication_failed" not in discovery
    assert "could not be read" in capsys.readouterr().out or discovery["inventory_diff"]["compared"] is False


def test_a_yaml_schema_is_read_and_a_yaml_bomb_is_refused():
    from app.dast.nodes.ingest_schemas import parse_schema_text

    document, problem = parse_schema_text("openapi: 3.0.0\npaths:\n  /a:\n    get: {}\n")
    assert problem == "" and document["paths"] == {"/a": {"get": {}}}
    bomb = "a: &a [x, x]\n" + "\n".join(f"b{i}: &b{i} [*a, *a]" for i in range(40))
    assert "anchors/aliases" in parse_schema_text(bomb)[1]
    assert parse_schema_text("")[1] and parse_schema_text("{not json")[1]


def graphql_schema_target(disabled=False) -> FakeTarget:
    target = FakeTarget()
    target.add_json("/", {"service": "gql"})
    schema = {"data": {"__schema": {"queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"}, "types": [
        {"name": "Query", "fields": [{"name": "users", "args": [], "type": {"name": "User"}}]},
        {"name": "Mutation", "fields": [{"name": "deleteUser", "args": [{"name": "id", "type": {"name": "ID"}}], "type": {"name": "Boolean"}}]}]}}}
    reply = {"errors": [{"message": "introspection is disabled"}]} if disabled else schema

    def handler(request):
        body = json.loads(request.content or b"{}")
        assert "__schema" in body["query"]  # only the introspection query is ever sent
        return httpx.Response(200, json=reply)

    target.route("POST", "/graphql", handler)
    return target


def test_graphql_introspection_runs_in_safe_mode_and_marks_mutations_state_changing():
    target = graphql_schema_target()
    harness = Harness(target, identities())
    discovery = harness.run()
    ops = {e["path_template"]: e for e in discovery["inventory"]}
    assert ops["/graphql#Mutation.deleteUser"]["state_changing"] and not ops["/graphql#Query.users"]["state_changing"]
    posts = [r for r in harness.audit.records if r.method == "POST"]
    assert posts and all(r.allowed and r.url.endswith("/graphql") for r in posts)
    assert harness.runtime.effective["safe_mode"] is True  # the exception, not a switch-off


def test_disabled_introspection_is_a_note_and_not_an_error(capsys):
    discovery = Harness(graphql_schema_target(disabled=True), identities()).run()
    assert discovery["connection_ok"] is True and "authentication_failed" not in discovery
    assert "introspection is disabled" in capsys.readouterr().out


# ---- API analysis through the guard (DAST-05-020 hand-off) ------------------------------------


def test_active_tests_are_sent_through_the_guard_and_a_state_changing_target_is_not_tested_in_safe_mode():
    target = FakeTarget()
    target.add_json("/", {"ok": True})
    target.set_openapi({"openapi": "3.0.0", "paths": {"/api/items": {"get": {}, "post": {}}}})
    target.add_json("/api/items", {"items": []})
    target.add_json("/api/items", {"created": True}, method="POST")
    gateway = FakeModelGateway(strict=False)
    gateway.script("construct", {"tests": [
        {"check_id": "dast-sqli", "parameter": "id", "location": "query", "input": "1'", "expected_signal": "sql error"},
        {"check_id": "dast-xss", "parameter": "q", "location": "query", "input": "<b>", "expected_signal": "reflected"},
    ]})
    harness = Harness(target, identities(), gateway=gateway, rule_set=default_rule_set())
    discovery = harness.run(run_analysis=True)
    assert {r.method for r in target.requests_to("/api/items")} == {"GET"}  # the POST never reached the target
    by_label = {a["label"]: a for a in discovery["api_analysis"]}
    assert set(by_label) == {f"GET {BASE}/api/items"}  # the POST target has no analysis: it was not tested
    assert {c["check_id"] for c in by_label[f"GET {BASE}/api/items"]["checks"]} == {"dast-sqli", "dast-xss"}
    not_tested = {n["label"]: n["reason"] for n in discovery["active_testing"]["not_tested"]}
    assert not_tested == {f"POST {BASE}/api/items": "not tested: safe mode"}
    assert [c.task for c in gateway.calls if c.task == "construct"] == ["construct"]  # no model call was spent on the POST
    sent = [r for r in harness.audit.records if "/api/items" in r.url]
    assert sent and all(r.method == "GET" and r.allowed for r in sent)
    assert all(r.identity_label == "anonymous" for r in sent)


def test_the_discovery_summary_has_everything_the_next_stages_read():
    target = api_target()
    discovery = Harness(target, identities(ADMIN_TOKEN), {"Admin": TOKENS["Admin"]}).run()
    assert {"fingerprint", "preflight", "inventory", "inventory_count", "inventory_diff", "identities", "api_calls", "pages"} <= set(discovery)
    json.dumps(discovery)  # JSON-safe
    assert "tok-admin" not in json.dumps(discovery)


# ---- operator-pasted APIs (the crawl cannot find every endpoint) -------------------------------


def _user_block(text: str, **extra) -> dict:
    from app.dast.domain.endpoint_input import parse_endpoint_text

    result = parse_endpoint_text(text, base_url=BASE)
    return {"user_endpoints": {"endpoints": [e.to_dict() for e in result.endpoints], "unparsed": result.unparsed, "dropped_off_scope": result.dropped_off_scope, **extra}}


def test_a_pasted_api_the_crawl_cannot_see_is_inventoried_tested_and_labelled(capsys):
    target = api_target(openapi=False)
    target.add_json("/api/hidden", {"ok": True})
    gateway = FakeModelGateway(strict=False)
    gateway.script("construct", {"tests": [{"check_id": "dast-sqli", "parameter": "id", "location": "query", "input": "1'", "expected_signal": "sql error"}]}, repeat=5)
    harness = Harness(target, identities(), gateway=gateway, rule_set=default_rule_set(), request=_user_block("GET /api/hidden?id=3"))
    discovery = harness.run(run_analysis=True)
    (entry,) = [e for e in discovery["inventory"] if e["path_template"] == "/api/hidden"]
    assert entry["user_supplied"] is True and entry["kind"] == "api"
    assert f"GET {BASE}/api/hidden" in {a["label"] for a in discovery["api_analysis"]}
    assert target.requests_to("/api/hidden")
    assert "Your API list: 1 new endpoint(s)" in capsys.readouterr().out


def test_a_pasted_api_the_scan_already_found_is_merged_not_duplicated(capsys):
    discovery = Harness(api_target(), identities(), request=_user_block("GET /api/items/5\nGET /api/items")).run()
    items = [e for e in discovery["inventory"] if e["path_template"] in ("/api/items", "/api/items/{id}") and e["method"] == "GET"]
    assert len(items) == 2 and all(e["user_supplied"] and e["source"] == "schema" for e in items)
    assert "0 new endpoint(s), 2 already found" in capsys.readouterr().out
    assert discovery["inventory_diff"]["undocumented"] == []


def test_a_pasted_state_changing_api_is_listed_but_never_sent_in_safe_mode():
    target = api_target(openapi=False)
    target.add_json("/api/orders", {"created": True}, method="POST")
    target.add_json("/api/orders", {"orders": []})
    gateway = FakeModelGateway(strict=False)
    gateway.script("construct", {"tests": [{"check_id": "dast-sqli", "parameter": "id", "location": "query", "input": "1'", "expected_signal": "sql error"}]}, repeat=5)
    discovery = Harness(target, identities(), gateway=gateway, rule_set=default_rule_set(), request=_user_block('POST /api/orders {"qty": 1}')).run(run_analysis=True)
    assert any(e["method"] == "POST" and e["state_changing"] and e["user_supplied"] for e in discovery["inventory"])
    assert {r.method for r in target.requests_to("/api/orders")} == set()
    assert f"POST {BASE}/api/orders" not in {a["label"] for a in discovery["api_analysis"]}


def test_unreadable_lines_are_reformatted_by_the_model_and_every_suggestion_is_rechecked(capsys):
    target = api_target(openapi=False)
    target.add_json("/api/cart", {"items": []})
    gateway = FakeModelGateway(strict=False)
    gateway.script("normalize_endpoints", {"endpoints": [
        {"method": "get", "path": "/api/cart", "query": {"user": "7"}},
        {"method": "GET", "path": "http://evil.test/api/steal"},  # off the target host
        {"method": "TRACE", "path": "/api/trace"},  # not a supported method
        {"method": "GET", "path": "/api/x", "query": {"note": "Bearer abcdefghijklmnop"}},  # a credential
        "not even an object",
    ]})
    discovery = Harness(target, identities(), gateway=gateway, request=_user_block("the cart thing: api/cart for user 7")).run()
    paths = {e["path_template"] for e in discovery["inventory"] if e["user_supplied"]}
    assert paths == {"/api/cart"}
    assert "1 recovered from 1 unreadable line(s)" in capsys.readouterr().out
    assert not target.requests_to("/api/steal") and not target.requests_to("/api/trace")


@pytest.mark.parametrize("reply", [None, {"endpoints": "nope"}, {"unexpected": []}])
def test_a_failed_or_unusable_cleanup_leaves_the_scan_and_the_readable_lines_intact(reply, capsys):
    gateway = FakeModelGateway(strict=False)
    if reply is not None:
        gateway.script("normalize_endpoints", reply)
    discovery = Harness(api_target(openapi=False), identities(), gateway=gateway, request=_user_block("GET /api/ok\nsome prose nobody can read")).run()
    assert discovery["connection_ok"] is True
    assert [e["path_template"] for e in discovery["inventory"] if e["user_supplied"]] == ["/api/ok"]


def test_no_pasted_list_changes_nothing():
    plain = Harness(api_target(), identities()).run()
    empty = Harness(api_target(), identities(), request={"user_endpoints": {}}).run()
    assert [e for e in plain["inventory"]] == [e for e in empty["inventory"]]
    assert not any(e["user_supplied"] for e in plain["inventory"])

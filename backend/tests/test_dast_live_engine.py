"""Live tests: the real engine over a real local site and real headless Chromium.

Only the model is faked (scripted replies), because Ollama is not assumed to be running. These close
the acceptance criteria that need a browser: DAST-01-040 (browser traffic through the guard),
DAST-06-030 (form login), DAST-07-020 (crawl on the browser driver) and DAST-07-030 (the network
recorder). Run with `pytest -m live`; skipped otherwise.
"""

from __future__ import annotations

import json

import pytest

from app.config import settings
from app.dast.domain.identities import build_identities
from app.dast.domain.presets import build_effective_settings
from app.dast.nodes import crawl as crawl_node
from app.dast.runner import run_dast_scan
from app.services.credential_holder import InMemoryCredentialHolder
from app.services.dast_runtime import build_runtime
from app.services.request_audit import MemoryAuditSink
from tests.dast_fixtures import FakeModelGateway
from tests.dast_fixtures.live_site import PASSWORD, USER, LiveSite

pytestmark = pytest.mark.live


@pytest.fixture(autouse=True)
def _no_politeness_delay(monkeypatch):
    monkeypatch.setattr(crawl_node.time, "sleep", lambda _s: None)


def script_login(gateway):
    gateway.script("fingerprint", {"shape": "mpa"})
    gateway.script("fingerprint", {"login_type": "simple_form"})
    gateway.script("login_selectors", {"action_type": "fill_username", "selector": "#u", "reason": "u"})
    gateway.script("login_selectors", {"action_type": "fill_password", "selector": "#p", "reason": "p"})
    gateway.script("login_selectors", {"action_type": "click", "selector": "#go", "reason": "go"})
    return gateway


def run(site, *, password=PASSWORD, request=None, identity_raw=None, secret=None):
    specs = build_identities(identity_raw if identity_raw is not None else [{"label": "Alice", "role": "User", "auth_method": "form"}])
    holder = InMemoryCredentialHolder("live", register=lambda *_: None)
    for spec in specs:
        if spec.authenticated:
            holder.store(spec.to_identity(), secret or {"login_url": f"{site.base}/login", "username": USER, "password": password})
    effective = build_effective_settings(
        request={"intensity": "standard", "max_pages": 12, "max_runtime_minutes": 2, **(request or {})}, base=settings.dast_effective_settings(),
        presets=settings.dast_presets, identities=specs, rule_set={}, model_routing=settings.dast_model_routing, oast_configured=False,
    )
    effective["rate_limit_per_sec"] = 200.0
    audit = MemoryAuditSink()
    gateway = script_login(FakeModelGateway(strict=False))
    runtime = build_runtime(scan_id="live", target_url=site.base, effective=effective, identities=specs, gateway=gateway, credentials=holder, audit=audit)
    try:
        discovery = run_dast_scan(runtime=runtime, run_analysis=False)["discovery"]
    finally:
        runtime.close()
    return discovery, audit, runtime


def test_form_login_crawl_and_recorder_against_a_real_site_in_safe_mode():
    with LiveSite() as site:
        discovery, audit, runtime = run(site)
        assert discovery["identities"][0]["status"] == "authenticated", discovery.get("authentication_failed")
        urls = {p["url"] for p in discovery["pages"]}
        assert f"{site.base}/account" in urls and all(p["url"].startswith(site.base) for p in discovery["pages"])

        # the login POST went through (the guard's login window); safe mode still forbids every other POST
        assert [(m, p) for m, p, _ in site.requests if m == "POST" and p.startswith("/login")]
        account_posts = [r for r in audit.records if r.method == "POST" and "/api/me" in r.url]
        assert account_posts and not any(r.allowed for r in account_posts)  # the page's XHR write was aborted
        assert not [1 for m, p, _ in site.requests if m == "POST" and p == "/api/me"]  # and never reached the server

        # off-host links and destructive-looking links were never requested
        assert not any(r.allowed and "other.invalid" in r.url for r in audit.records)
        assert "/delete-all" not in site.paths() and "/logout" not in site.paths()

        # every browser request is attributed to the identity that made it
        labels = {r.identity_label for r in audit.records}
        assert labels == {"Alice", "anonymous"}  # the preflight, fingerprint probes and schema probes ran as the baseline

        # the recorder: XHR/fetch with bodies where allowed; assets by URL and status only
        inventory = {(e["method"], e["path_template"]): e for e in discovery["inventory"]}
        assert ("GET", "/api/me") in inventory and inventory[("GET", "/api/me")]["kind"] == "api"
        assert discovery["traffic"]["assets"] >= 1 and discovery["traffic"]["api_exchanges"] >= 1
        assert not any(t.asset and (t.response_body or t.request_body) for t in runtime.traffic)
        assert discovery["inventory_diff"]["compared"] is True  # /openapi.json exists on the site
        assert "/api/orders" in [e["path_template"] for e in discovery["inventory_diff"]["unexercised"]]


def test_a_wrong_password_fails_with_the_identity_named_and_posts_only_to_the_login_form():
    with LiveSite() as site:
        gateway_runs = 0
        discovery, audit, _ = run(site, password="not-the-password")
        assert "Identity 'Alice' could not authenticate" in discovery["authentication_failed"]
        assert discovery["pages"] == []
        posts = [p for m, p, _ in site.requests if m == "POST"]
        assert posts and all(p == "/login" for p in posts)  # nothing else was ever written


def test_a_saved_session_skips_login_and_the_browser_context_carries_it():
    with LiveSite() as site:
        host = "127.0.0.1"
        state = json.dumps({"cookies": [{"name": "session", "value": "live-session-abc123", "domain": host, "path": "/"}], "origins": []})
        discovery, audit, _ = run(
            site, identity_raw=[{"label": "Saved", "role": "Viewer", "auth_method": "preauth"}], secret={"storage_state": state}
        )
        assert discovery["identities"][0]["status"] == "authenticated"
        assert not [1 for m, p, _ in site.requests if m == "POST" and p == "/login"]  # no login stage ran
        assert f"{site.base}/account" in {p["url"] for p in discovery["pages"]}  # the cookie opened the protected pages
        cookies_sent = [h.get("Cookie") for m, p, h in site.requests if p == "/account"]
        assert cookies_sent and all("live-session-abc123" in (c or "") for c in cookies_sent)


def test_an_anonymous_scan_crawls_the_public_pages_in_a_real_browser():
    with LiveSite() as site:
        discovery, audit, _ = run(site, identity_raw=[])
        assert discovery["fingerprint"]["schema"] == "openapi"
        urls = {p["url"] for p in discovery["pages"]}
        assert f"{site.base}/about" in urls and f"{site.base}/account" not in urls  # protected pages stay out of reach
        assert {p["identity"] for p in discovery["pages"]} == {"anonymous"}
        # (the API-only case, where no browser is launched at all, is covered offline in test_dast_engine.py)

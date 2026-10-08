"""SSRF with out-of-band confirmation (DAST-09-060): a received callback is the only proof; every
callback address is unique to its test; waiting is bounded; the OAST poll is the audited scope
exception; and without an OAST address nothing is tested."""

from __future__ import annotations

import json
import threading

import httpx
import pytest

from app.dast import ssrf
from app.dast.domain import oast as O
from app.dast.domain.entities import Location, Parameter
from app.dast.domain.inventory import observed
from app.dast.domain.ruleset import parse_rule_config, resolve_effective_rule_set
from app.services.oast import OAST_AUDIT_CHECK, HttpOastCollaborator
from app.services.request_audit import MemoryAuditSink
from tests.dast_fixtures import FakeModelGateway, FakeTarget
from tests.test_dast_active import CATALOG, harness_steps
from tests.test_dast_engine import BASE, Harness, default_rule_set, identities

pytestmark = pytest.mark.integration


class FakeOast:
    """An in-memory collaborator: the fake target 'calls back' by telling it which URL it fetched."""

    host = "oast.test"

    def __init__(self):
        self.tokens: list[O.OastToken] = []
        self.received: set[str] = set()
        self.poll_calls: list[float] = []
        self._n = 0

    def new_token(self, test_key):
        self._n += 1
        token = f"tok{self._n:04d}"
        issued = O.OastToken(token, f"https://oast.test/c/{token}", test_key)
        self.tokens.append(issued)
        return issued

    def poll(self, token, *, wait_s, interval_s=1.0):
        self.poll_calls.append(wait_s)
        return [O.OastCallback(token.token, "203.0.113.9")] if token.token in self.received else []

    def callback_for(self, url: str):
        for issued in self.tokens:
            if issued.url in url:
                self.received.add(issued.token)


def ssrf_target(oast: FakeOast, vulnerable: tuple[str, ...] = ("/api/fetch",)) -> FakeTarget:
    t = FakeTarget()
    t.add_json("/", {"ok": True})
    for path in ("/api/fetch", "/api/preview"):
        def handler(request, path=path):
            url = request.url.params.get("url", "")
            if path in vulnerable:
                oast.callback_for(url)  # the vulnerable server requests whatever address it was given
            return httpx.Response(200, json={"fetched": path in vulnerable})

        t.route("GET", path, handler)
    return t


FETCH = observed("GET", f"{BASE}/api/fetch?url=http://example.org/", kind="api")
PREVIEW = observed("GET", f"{BASE}/api/preview?url=http://example.org/", kind="api")
NO_URL = observed("GET", f"{BASE}/api/plain?q=1", kind="api")


def run(oast, endpoints, *, vulnerable=("/api/fetch",), max_tests=10, wait_s=3.0, cancelled=lambda: False):
    target = ssrf_target(oast, vulnerable)
    steps, harness = harness_steps(target, FakeModelGateway(strict=False))
    check = ssrf.ssrf_check(resolve_effective_rule_set(CATALOG))
    return ssrf.run_ssrf(endpoints, oast=oast, check=check, steps=steps, max_tests=max_tests, wait_s=wait_s, cancelled=cancelled, log=lambda *_: None), target, harness


def test_a_received_callback_is_a_true_positive_with_the_oast_signal():
    oast = FakeOast()
    result, target, _ = run(oast, [FETCH])
    (row,) = result.rows
    assert row["rule_id"] == "dast-ssrf" and row["verdict"] == "true_positive" and row["target"] == f"GET {BASE}/api/fetch" and row["param"] == "url"
    assert row["evidence"]["signals"][0]["name"] == "oast_callback_received" and "203.0.113.9" in row["evidence"]["signals"][0]["detail"]
    assert row["severity"] == "HIGH" and "CWE-918" in row["standards"]
    assert result.confirmed == 1 and result.tests == 1
    assert oast.tokens[0].url in str(target.requests_to("/api/fetch")[0].url) or "oast.test" in str(target.requests_to("/api/fetch")[0].url)


def test_no_callback_means_no_finding():
    result, *_ = run(FakeOast(), [PREVIEW], vulnerable=())
    assert result.rows == [] and result.confirmed == 0 and result.tests == 1


def test_each_callback_address_is_unique_and_one_callback_cannot_confirm_another_test():
    oast = FakeOast()
    result, *_ = run(oast, [FETCH, PREVIEW], vulnerable=("/api/fetch",))
    assert len({t.token for t in oast.tokens}) == 2 and len({t.url for t in oast.tokens}) == 2
    assert [r["target"] for r in result.rows] == [f"GET {BASE}/api/fetch"]  # the preview test was not confirmed by fetch's callback
    token = oast.tokens[0]
    assert O.confirms(token, [O.OastCallback("someone-else"), O.OastCallback(token.token)]) == [O.OastCallback(token.token)]
    assert O.confirms(token, [O.OastCallback("someone-else")]) == []


def test_tokens_are_unguessable_without_the_nonce_and_unique_per_counter():
    a = O.make_token("scan", "GET /x|url", 1, "nonce-1")
    assert a == O.make_token("scan", "GET /x|url", 1, "nonce-1") and a != O.make_token("scan", "GET /x|url", 2, "nonce-1") and a != O.make_token("scan", "GET /x|url", 1, "nonce-2")
    assert len(a) == O.TOKEN_CHARS


def test_only_url_taking_parameters_are_tested_and_the_cap_and_cancel_are_honoured():
    oast = FakeOast()
    result, target, _ = run(oast, [NO_URL, FETCH, PREVIEW], vulnerable=(), max_tests=1)
    assert result.tests == 1 and len(oast.tokens) == 1
    result, *_ = run(FakeOast(), [FETCH, PREVIEW], vulnerable=(), cancelled=lambda: True)
    assert result.tests == 0 and result.cancelled


def test_the_wait_for_a_callback_is_bounded():
    oast = FakeOast()
    run(oast, [FETCH], vulnerable=(), wait_s=1.5)
    assert oast.poll_calls == [1.5]


def test_ssrf_never_runs_without_an_oast_address_or_when_downgraded():
    rs = resolve_effective_rule_set(CATALOG)
    assert ssrf.ssrf_check(rs) is not None
    assert ssrf.ssrf_check(rs, [{"check_id": "dast-ssrf", "status": "degraded", "effective_mode": "assist-only"}]) is None
    assert ssrf.ssrf_check(rs, [{"check_id": "dast-ssrf", "status": "skipped"}]) is None
    off = resolve_effective_rule_set(CATALOG, scan_config=parse_rule_config({"checks": {"dast-ssrf": {"enabled": False}}}, CATALOG))
    assert ssrf.ssrf_check(off) is None and ssrf.ssrf_check(None) is None


def test_the_stage_runs_ssrf_only_with_a_collaborator_and_otherwise_says_why():
    oast = FakeOast()
    target = ssrf_target(oast)
    target.set_openapi({"openapi": "3.0.0", "paths": {"/api/fetch": {"get": {"parameters": [{"name": "url", "in": "query", "schema": {"type": "string"}}]}}}})
    harness = Harness(target, identities(), rule_set=default_rule_set())
    harness.runtime.oast = oast
    discovery = harness.run(run_analysis=True)
    assert discovery["active_testing"]["ssrf"] == {"tests": 1, "confirmed": 1}
    batches = {label: rows for label, rows in harness.written}
    assert [r["rule_id"] for r in batches["ssrf"]] == ["dast-ssrf"]

    target2 = ssrf_target(FakeOast())
    target2.set_openapi({"openapi": "3.0.0", "paths": {"/api/fetch": {"get": {"parameters": [{"name": "url", "in": "query", "schema": {"type": "string"}}]}}}})
    harness2 = Harness(target2, identities(), rule_set=default_rule_set())
    discovery2 = harness2.run(run_analysis=True)
    assert discovery2["active_testing"]["ssrf"]["tests"] == 0 and "no OAST address" in discovery2["active_testing"]["ssrf"]["reason"]
    assert not [r for r in target2.requests_to("/api/fetch") if "oast" in str(r.url)]


# ---- the HTTP collaborator: its own client, audited polls ---------------------------------------------


def make_collaborator(handler, audit=None, clock=None, sleep=None):
    ticks = {"t": 0.0}
    return HttpOastCollaborator(
        "scan-1", "https://oast.example/", audit=audit, transport=httpx.MockTransport(handler),
        clock=clock or (lambda: ticks["t"]), sleep=sleep or (lambda s: ticks.__setitem__("t", ticks["t"] + s)),
    )


def test_the_http_collaborator_issues_unique_addresses_and_returns_only_matching_callbacks():
    seen = []

    def handler(request):
        seen.append(str(request.url))
        token = request.url.params["token"]
        return httpx.Response(200, json={"callbacks": [{"token": token, "remote": "198.51.100.7", "at": "now"}, {"token": "other", "remote": "x"}]})

    oast = make_collaborator(handler)
    a, b = oast.new_token("k1"), oast.new_token("k2")
    assert a.url.startswith("https://oast.example/c/") and a.url != b.url and a.token != b.token
    got = oast.poll(a, wait_s=2)
    assert [c.token for c in got] == [a.token] and got[0].source == "198.51.100.7"
    assert seen[0].startswith("https://oast.example/poll?token=")


def test_polling_is_bounded_and_every_poll_is_audited_under_its_own_category():
    audit = MemoryAuditSink()
    oast = make_collaborator(lambda r: httpx.Response(200, json={"callbacks": []}), audit=audit)
    token = oast.new_token("k")
    assert oast.poll(token, wait_s=3, interval_s=1) == []
    assert 3 <= oast.polls <= 5  # bounded by the wait, not unbounded
    assert len(audit.records) == oast.polls
    assert all(r.check_id == OAST_AUDIT_CHECK and r.identity_label == "oast" and token.token not in r.url for r in audit.records)


def test_a_failing_poll_is_not_an_error_and_never_confirms():
    def boom(request):
        raise httpx.ConnectError("down")

    oast = make_collaborator(boom)
    assert oast.poll(oast.new_token("k"), wait_s=1) == []


def test_the_collaborator_is_not_subject_to_the_target_scope_guard():
    """The scope guard refuses the OAST host as off-scope; the collaborator's own client reaches it."""
    audit = MemoryAuditSink()
    harness = Harness(FakeTarget(), identities())
    refused = harness.runtime.executor.execute(__import__("app.dast.domain.interfaces", fromlist=["RequestSpec"]).RequestSpec("GET", "https://oast.example/poll?token=x"))
    assert not refused.allowed and refused.deny_reason == "off_scope"
    oast = make_collaborator(lambda r: httpx.Response(200, json={"callbacks": []}), audit=audit)
    oast.poll(oast.new_token("k"), wait_s=0)
    assert audit.records and audit.records[0].allowed

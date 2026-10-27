"""JWT structural checks and guarded replay proof, with no live model or external target."""

import base64
import hashlib
import hmac
import json
from dataclasses import replace

import httpx
import pytest

from app.dast.active import loop_checks
from app.dast.domain.jwt_check import accepts_weak_hmac_secret, alg_is_none, decode_token, missing_required_claims, modified_token
from app.dast.domain.inventory import observed
from app.dast.domain.ruleset import parse_rule_config, resolve_effective_rule_set
from app.dast.jwt_probe import CHECKS, jwt_checks, run_jwt
from app.dast.sessions import SessionStore
from app.services.dast_catalog import default_catalog
from tests.dast_fixtures import FakeTarget
from tests.test_dast_engine import ADMIN_TOKEN, BASE, Harness, identities


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def token(secret=b"secret", alg="HS256"):
    # Deliberately non-canonical JSON: verification must use the original encoded segments.
    head = b64(json.dumps({"typ": "JWT", "alg": alg}, indent=2).encode())
    body = b64(json.dumps({"sub": "alice", "exp": 4102444800, "iss": "test-issuer", "aud": "test-api"}, indent=2).encode())
    signature = b64(hmac.new(secret, f"{head}.{body}".encode(), hashlib.sha256).digest())
    return f"{head}.{body}.{signature}"


def rules(weak=False):
    catalog = default_catalog()
    cfg = parse_rule_config({"checks": {"dast-jwt-weak-secret": {"enabled": True}}}, catalog) if weak else None
    return resolve_effective_rule_set(catalog, scan_config=cfg)


def test_decode_and_exact_signature_match_with_bounded_public_examples():
    decoded = decode_token(token())
    assert decoded is not None and accepts_weak_hmac_secret(*decoded.segments)
    assert missing_required_claims(decoded.payload) == ()
    assert missing_required_claims({"exp": 1}) == ("iss", "aud")
    assert alg_is_none({"alg": "none"})
    assert not accepts_weak_hmac_secret(*decode_token(token(b"unlisted-random-material")).segments)
    assert not accepts_weak_hmac_secret(*decode_token(token(alg="RS256")).segments)


@pytest.mark.parametrize("raw", ["plain", "x.y.z", "W10.e30.", "e30.W10.", "a" * 20000, "eyJhbGciOiJIUzI1NiJ9.e30.!bad"])
def test_malformed_tokens_fail_closed(raw):
    assert decode_token(raw) is None


def test_mutations_leave_identity_and_privileges_unchanged():
    decoded = decode_token(token())
    none = decode_token(modified_token(decoded, "alg-none"))
    assert alg_is_none(none.header) and not none.segments[2] and none.payload["sub"] == "alice"
    claims = decode_token(modified_token(decoded, "missing-claims"))
    assert missing_required_claims(claims.payload) == ("exp", "iss", "aud")
    assert modified_token(decoded, "weak-secret") is None


def test_jwt_catalog_is_resolvable_and_weak_secret_is_opt_in():
    catalog = default_catalog()
    assert set(CHECKS) <= {c.check_id for c in catalog.checks}
    for cid in CHECKS:
        check = catalog.get(cid)
        assert check.remediation_ref == cid.replace("dast-", "rem-") and check.detector_signals
        assert not check.flags
    assert "dast-jwt-weak-secret" not in jwt_checks(rules())
    assert set(jwt_checks(rules(True))) == set(CHECKS)
    assert not set(loop_checks(rules(True))) & set(CHECKS)
    assert "dast-jwt-alg-none" not in jwt_checks(rules(), [{"check_id": "dast-jwt-alg-none", "status": "skipped"}])


def setup_probe(*, vulnerable=True, weak=False, public=False, cookie=False):
    original = token()
    target = FakeTarget()

    def read(request):
        auth = request.headers.get("authorization", "").removeprefix("Bearer ")
        if cookie:
            auth = request.headers.get("cookie", "").removeprefix("session=")
        accepted = public or auth == original or (vulnerable and decode_token(auth) is not None)
        return httpx.Response(200, json={"account": "alice", "private_notes": "protected account contents"}) if accepted else httpx.Response(401, json={"error": "unauthorized"})

    target.route("GET", "/api/account", read)
    specs = identities(ADMIN_TOKEN)
    harness = Harness(target, specs, {"Admin": {"token": original, "header_name": "Authorization", "scheme": "Bearer"}})
    store = SessionStore(specs)
    spec = specs[0]
    store.mark_authenticated(spec.identity_id)
    if cookie:
        store.update_cookies(spec.identity_id, [{"name": "session", "value": original, "domain": "target.test", "path": "/"}])
    else:
        store.set_token(spec.identity_id, "Authorization", "Bearer", original)
        # This unrelated cookie must never get into the probe's isolated credentials.
        store.update_cookies(spec.identity_id, [{"name": "admin_session", "value": "other-secret", "domain": "target.test", "path": "/"}])
    endpoint = observed("GET", BASE + "/api/account", identity_id=spec.identity_id, kind="api", status=200)
    return harness, store, endpoint, jwt_checks(rules(weak)), original


def probe(harness, store, endpoints, checks, **kwargs):
    return run_jwt(endpoints, store=store, executor=harness.runtime.executor, credentials=harness.holder, checks=checks, **kwargs)


@pytest.mark.parametrize("cookie", [False, True])
def test_accepted_modified_tokens_prove_findings_and_no_secrets_leave_memory(cookie):
    harness, store, endpoint, checks, original = setup_probe(weak=True, cookie=cookie)
    try:
        run = probe(harness, store, [endpoint], checks)
        assert run.confirmed == 3 and run.tests == 3
        assert {row["rule_id"] for row in run.rows} == set(CHECKS)
        assert all(row["verdict"] == "true_positive" for row in run.rows)
        assert len(harness.target.requests) == 5  # baseline, anonymous control, one per weakness
        findings = json.dumps(run.rows)
        shown = findings + str(harness.audit.records)
        assert original not in shown
        for value in harness.holder.read("identity-admin").values():
            if decode_token(value) is not None:
                assert value not in shown  # generated JWTs are registered before audit, too
        assert "protected account contents" not in findings  # ordinary request audit keeps a redacted excerpt
        assert not any("other-secret" in str(r.headers) for r in harness.target.requests)
        if not cookie:
            assert store.get("identity-admin").token_header == ("Authorization", f"Bearer {original}")
        assert not harness.gateway.calls
    finally:
        harness.runtime.close()


@pytest.mark.parametrize("public,vulnerable", [(False, False), (True, True)])
def test_rejected_tokens_and_public_endpoints_never_confirm(public, vulnerable):
    harness, store, endpoint, checks, _ = setup_probe(public=public, vulnerable=vulnerable)
    try:
        run = probe(harness, store, [endpoint], checks)
        assert run.rows == [] and run.confirmed == 0
        assert run.tests == (0 if public else 2)
    finally:
        harness.runtime.close()


def test_no_unobserved_mutating_off_scope_or_cancelled_probe():
    harness, store, endpoint, checks, _ = setup_probe()
    try:
        assert probe(harness, store, [replace(endpoint, seen_as=())], checks).tests == 0
        assert probe(harness, store, [replace(endpoint, method="POST", state_changing=True)], checks).tests == 0
        assert probe(harness, store, [endpoint], checks, cancelled=lambda: True).cancelled
        assert not harness.target.requests
        assert probe(harness, store, [replace(endpoint, url="http://evil.test/api/account")], checks).tests == 0
        assert not harness.target.requests
        assert harness.audit.records[-1].deny_reason == "off_scope"
    finally:
        harness.runtime.close()

"""Passive analysis (DAST-08-010 .. -030): header/cookie, CORS/disclosure and error/sensitive-data
checks over recorded responses, deduplication, redaction, and the stage's "no request, no model call"
guarantee."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from app.dast import passive as engine_passive
from app.dast.domain import passive as P
from app.dast.domain.entities import ResponseSnapshot
from app.dast.domain.ruleset import resolve_effective_rule_set, RuleConfig, parse_rule_config
from app.dast.domain.traffic import RecordedExchange
from app.dast.runtime import LiveCounters
from app.dast.nodes.passive_analysis import has_active_work, passive_analysis, route_after_passive
from app.services.dast_catalog import default_catalog

pytestmark = pytest.mark.unit

CATALOG = default_catalog()
PATTERNS = engine_passive.default_patterns()
ALL = frozenset(P.PASSIVE_CHECK_IDS)


def ex(url="https://app.test/", status=200, headers=None, body="", content_type="text/html", method="GET", request_headers=None, asset=False):
    headers = {"Content-Type": content_type, **(headers or {})}
    return RecordedExchange(method, url, status, "document", content_type=content_type, response_headers=headers, response_body=body, request_headers=request_headers, asset=asset)


GOOD = {
    "Content-Security-Policy": "default-src 'self'", "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
    "Strict-Transport-Security": "max-age=31536000", "Referrer-Policy": "no-referrer",
}


def hits_for(exchange, wanted=ALL):
    return P.analyze_exchange(exchange, frozenset(wanted), PATTERNS)


def by_check(hits):
    return {(h.check_id, h.param): h for h in hits}


# ---- security headers ---------------------------------------------------------------------------


def test_a_well_configured_html_response_has_no_header_findings():
    assert hits_for(ex(headers=GOOD)) == []


def test_every_missing_header_is_reported_with_the_response_it_was_seen_on():
    found = by_check(hits_for(ex(url="https://app.test/home", headers={})))
    assert {k[1] for k in found} == {"Content-Security-Policy", "X-Frame-Options", "Referrer-Policy", "X-Content-Type-Options", "Strict-Transport-Security"}
    csp = found[(P.CSP, "Content-Security-Policy")]
    assert csp.signal == "header_absent" and csp.url == "https://app.test/home" and csp.status == 200 and csp.verdict == "true_positive"


def test_weak_header_values_are_misconfigured_not_absent():
    weak = {
        **GOOD,
        "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'",
        "X-Content-Type-Options": "sniff",
        "Strict-Transport-Security": "max-age=60",
        "X-Frame-Options": "ALLOW-FROM https://x.test",
        "Referrer-Policy": "unsafe-url",
    }
    found = by_check(hits_for(ex(headers=weak)))
    assert {h.signal for h in found.values()} == {"header_misconfigured"}
    assert len(found) == 5
    assert "unsafe-inline" in found[(P.CSP, "Content-Security-Policy")].detail
    assert "max-age 60" in found[(P.HSTS, "Strict-Transport-Security")].detail


def test_csp_with_frame_ancestors_covers_framing_and_a_report_only_policy_is_not_enforced():
    csp = {**GOOD, "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"}
    csp.pop("X-Frame-Options")
    assert not [h for h in hits_for(ex(headers=csp)) if h.check_id == P.CLICKJACKING]
    report_only = {k: v for k, v in GOOD.items() if k != "Content-Security-Policy"} | {"Content-Security-Policy-Report-Only": "default-src 'self'"}
    found = [h for h in hits_for(ex(headers=report_only)) if h.check_id == P.CSP]
    assert found and "not enforced" in found[0].detail


def test_transport_security_applies_only_to_https_responses():
    http = hits_for(ex(url="http://app.test/", headers={k: v for k, v in GOOD.items() if k != "Strict-Transport-Security"}))
    assert not [h for h in http if h.check_id == P.HSTS]
    https = hits_for(ex(url="https://app.test/", headers={k: v for k, v in GOOD.items() if k != "Strict-Transport-Security"}))
    assert [h.check_id for h in https if h.check_id == P.HSTS] == [P.HSTS]


def test_html_only_headers_are_not_demanded_of_json_and_errors_and_assets_are_skipped():
    json_hits = hits_for(ex(content_type="application/json", headers={}))
    assert {h.check_id for h in json_hits} == {P.XCTO, P.HSTS}  # CSP, framing and referrer are page concerns
    assert hits_for(ex(status=404, headers={})) == [] and hits_for(ex(status=302, headers={})) == []
    assert hits_for(ex(asset=True, headers={})) == []


def test_only_enabled_checks_run():
    assert {h.check_id for h in hits_for(ex(headers={}), wanted={P.XCTO})} == {P.XCTO}
    assert hits_for(ex(headers={}), wanted=set()) == []


# ---- cookies ------------------------------------------------------------------------------------


def cookie_ex(value, url="https://app.test/login"):
    return ex(url=url, headers={**GOOD, "Set-Cookie": value})


@pytest.mark.parametrize(
    "header, missing",
    [
        ("sid=[REDACTED]; Path=/", ["HttpOnly", "SameSite", "Secure"]),
        ("sid=[REDACTED]; Path=/; Secure; HttpOnly", ["SameSite"]),
        ("sid=[REDACTED]; Path=/; HttpOnly; SameSite=Lax", ["Secure"]),
        ("sid=[REDACTED]; Path=/; Secure; HttpOnly; SameSite=Strict", []),
    ],
)
def test_cookie_flag_combinations(header, missing):
    found = [h for h in hits_for(cookie_ex(header)) if h.check_id == P.COOKIES]
    if not missing:
        assert found == []
        return
    assert len(found) == 1 and found[0].param == "sid" and found[0].signal == "cookie_flag_missing"
    assert all(flag in found[0].detail for flag in missing)
    assert "[REDACTED]" in found[0].excerpt  # the cookie value is never in evidence


def test_secure_flag_is_only_judged_on_https_and_several_cookies_are_each_judged():
    http = [h for h in hits_for(cookie_ex("a=[REDACTED]; HttpOnly; SameSite=Lax", url="http://app.test/")) if h.check_id == P.COOKIES]
    assert http == []
    two = [h for h in hits_for(cookie_ex("a=[REDACTED]; HttpOnly\nb=[REDACTED]; Secure; HttpOnly; SameSite=Lax")) if h.check_id == P.COOKIES]
    assert [h.param for h in two] == ["a"]


# ---- CORS ---------------------------------------------------------------------------------------


def cors(acao, creds=False, origin=None, url="https://api.test/data"):
    headers = {"Access-Control-Allow-Origin": acao, **({"Access-Control-Allow-Credentials": "true"} if creds else {})}
    return ex(url=url, content_type="application/json", headers={**GOOD, **headers}, request_headers={"Origin": origin} if origin else None)


def test_wildcard_with_credentials_and_null_origin_are_reported_with_the_observed_values():
    hits = P.check_cors([cors("*", creds=True), cors("null", url="https://api.test/other")])
    assert [h.detail for h in hits] == ["wildcard origin combined with credentials", "the null origin is allowed"]
    assert "Access-Control-Allow-Credentials: true" in hits[0].excerpt and hits[0].severity_shift == 1 and hits[1].severity_shift == 0


def test_a_plain_wildcard_without_credentials_is_not_reported():
    assert P.check_cors([cors("*")]) == []


def test_reflection_needs_two_origins_to_be_confirmed_and_one_is_unverified():
    one = P.check_cors([cors("https://a.example", origin="https://a.example")])
    assert len(one) == 1 and one[0].verdict == "false_positive" and "single allowed origin" in one[0].note
    two = P.check_cors([cors("https://a.example", origin="https://a.example"), cors("https://b.example", origin="https://b.example")])
    assert len(two) == 1 and two[0].verdict == "true_positive" and "reflects any request origin" in two[0].detail


def test_the_apps_own_origin_is_not_a_reflection_and_assessability_is_reported():
    own = cors("https://api.test", origin="https://api.test")
    assert P.check_cors([own]) == []
    assert not P.cors_assessment([cors("*")]).assessable and "not assessable" in P.cors_assessment([cors("*")]).note
    assert P.cors_assessment([own]).assessable


# ---- disclosure ---------------------------------------------------------------------------------


def test_server_version_powered_by_and_generator_meta_are_disclosures():
    page = ex(headers={**GOOD, "Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4.3"}, body='<html><meta name="generator" content="WordPress 6.1"></html>')
    found = {h.param: h for h in hits_for(page) if h.check_id == P.TECH}
    assert set(found) == {"server", "x-powered-by", "meta-generator"}
    assert "nginx/1.18.0" in found["server"].excerpt


def test_a_server_header_without_a_version_is_not_a_finding():
    assert not [h for h in hits_for(ex(headers={**GOOD, "Server": "nginx"})) if h.check_id == P.TECH]


# ---- verbose errors and sensitive data -----------------------------------------------------------


def body_hits(body, status=200, **kw):
    return [h for h in hits_for(ex(status=status, body=body, content_type="text/plain", headers=GOOD, **kw)) if h.check_id in (P.VERBOSE, P.SENSITIVE)]


def test_stack_traces_and_database_errors_reuse_the_active_detectors():
    trace = body_hits('Traceback (most recent call last):\n  File "/app/x.py", line 3, in <module>', status=500)
    assert {(h.check_id, h.param) for h in trace} >= {(P.VERBOSE, "stack_trace")}
    db = body_hits("You have an error in your SQL syntax near 'x'", status=500)
    assert (P.VERBOSE, "database_error") in {(h.check_id, h.param) for h in db}
    assert all(h.verdict == "true_positive" for h in trace + db)
    assert P.SHARED_LEAK_PATTERNS["stack_trace"] is not None


def test_internal_paths_only_count_in_error_responses_and_private_addresses_are_unverified():
    ok = body_hits("see /var/www/html/app/index.php", status=200)
    assert not [h for h in ok if h.param == "internal_path"]
    err = body_hits("Error in /var/www/html/app/index.php", status=500)
    assert [h for h in err if h.param == "internal_path" and h.verdict == "true_positive"]
    addr = body_hits("connect to 10.1.2.3 failed")
    assert [h.verdict for h in addr if h.param == "internal_address"] == ["false_positive"]


SECRET = "AKIAIOSFODNN7EXAMPLE"


def test_a_secret_is_detected_but_never_quoted_in_evidence():
    found = body_hits(f'{{"key": "{SECRET}"}}')
    assert [h.param for h in found] == ["aws_access_key_id"] and found[0].verdict == "true_positive"
    blob = json.dumps([found[0].excerpt, found[0].detail])
    assert SECRET not in blob and "value not recorded" in found[0].excerpt


@pytest.mark.parametrize(
    "body, family",
    [
        ("-----BEGIN RSA PRIVATE KEY-----\nMIIE", "private_key_block"),
        ("token ghp_" + "a" * 36, "github_token"),
        ("sk_live_" + "b" * 24, "stripe_live_key"),
        ("AIza" + "c" * 35, "google_api_key"),
        ("xoxb-1234567890-abcdef", "slack_token"),
    ],
)
def test_definite_secret_families(body, family):
    assert [h.param for h in body_hits(body)] == [family]


def test_ambiguous_personal_data_is_unverified_and_luhn_filters_random_digits():
    card = body_hits('{"card": "4111 1111 1111 1111"}')
    assert [(h.param, h.verdict) for h in card] == [("payment_card_number", "false_positive")]
    assert "4111" not in card[0].excerpt
    assert body_hits("order 1234 5678 9012 3456") == []  # fails the Luhn check
    ssn = body_hits("ssn 123-45-6789")
    assert [(h.param, h.verdict) for h in ssn] == [("us_ssn", "false_positive")]
    assert body_hits("ssn 000-12-3456") == []


def test_jwt_lookalikes_do_not_trip_but_a_real_token_is_unverified():
    import base64

    def b64(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    real = f"{b64({'alg': 'HS256', 'typ': 'JWT'})}.{b64({'sub': '1'})}.{'s' * 20}"
    assert [(h.param, h.verdict) for h in body_hits(f"token={real}")] == [("jwt_in_response", "false_positive")]
    noise = "eyJ" + "A" * 12 + "." + "B" * 12 + "." + "C" * 12  # right shape, header is not JSON
    assert body_hits(noise) == []
    assert body_hits("U29tZSBsb25nIGJhc2U2NCBub2lzZSB0aGF0IGlzIG5vdCBhIHRva2VuIGF0IGFsbA==") == []


def test_pattern_files_are_data_and_a_bad_edit_fails_loudly():
    custom = P.parse_pattern_set({"schema_version": 1, "families": [{"id": "x", "check": "sensitive", "pattern": "SECRET-[0-9]{4}"}]})
    hits = P.check_errors_and_data(ex(body="SECRET-1234", content_type="text/plain"), custom, frozenset({P.SENSITIVE}))
    assert [h.param for h in hits] == ["x"]
    with pytest.raises(ValueError):
        P.parse_pattern_set({"schema_version": 1, "families": [{"id": "x", "check": "sensitive", "pattern": "("}]})
    with pytest.raises(ValueError):
        P.parse_pattern_set({"schema_version": 2})


# ---- dedupe ---------------------------------------------------------------------------------------


def test_fifty_identical_responses_make_one_finding_listing_where_it_was_seen():
    traffic = [ex(url=f"https://app.test/page{i}", headers={k: v for k, v in GOOD.items() if k != "Content-Security-Policy"}) for i in range(50)]
    hits, _ = P.analyze_traffic(traffic, {P.CSP}, PATTERNS)
    assert len(hits) == 50
    deduped = P.dedupe_hits(hits)
    assert len(deduped) == 1 and deduped[0].occurrences == 50 and len(deduped[0].affected) == 25  # capped
    assert deduped[0].hit.url == "https://app.test/page0"


def test_dedupe_prefers_a_confirmed_hit_as_the_representative():
    a = P.PassiveHit(P.CORS, "ACAO", "cors_permissive", "d", "GET", "https://x/a", 200, verdict="false_positive")
    b = P.PassiveHit(P.CORS, "ACAO", "cors_permissive", "d", "GET", "https://x/b", 200, verdict="true_positive")
    assert P.dedupe_hits([a, b])[0].hit is b


# ---- severity -------------------------------------------------------------------------------------


def test_cors_severity_follows_credentials_and_an_explicit_override_wins():
    rule_set = resolve_effective_rule_set(CATALOG)
    rows, _ = engine_passive.run_passive([cors("*", creds=True)], rule_set)
    assert [r["severity"] for r in rows if r["rule_id"] == P.CORS] == ["HIGH"]  # MEDIUM raised one step
    override = resolve_effective_rule_set(CATALOG, scan_config=parse_rule_config({"checks": {P.CORS: {"severity": "LOW"}}}, CATALOG))
    rows, _ = engine_passive.run_passive([cors("*", creds=True)], override)
    assert [r["severity"] for r in rows if r["rule_id"] == P.CORS] == ["LOW"]


# ---- rows -----------------------------------------------------------------------------------------


def test_rows_carry_standards_remediation_signal_and_a_deterministic_order():
    rule_set = resolve_effective_rule_set(CATALOG)
    traffic = [ex(url="https://app.test/a", headers={})]
    rows, summary = engine_passive.run_passive(traffic, rule_set)
    assert rows == engine_passive.run_passive(traffic, rule_set)[0]
    assert [r["rule_id"] for r in rows] == sorted(r["rule_id"] for r in rows)
    csp = next(r for r in rows if r["rule_id"] == P.CSP)
    assert csp["verdict"] == "true_positive" and csp["confidence_label"] == "HIGH" and csp["source"] == "passive analysis"
    assert csp["evidence"]["signals"][0]["name"] == "header_absent" and csp["remediation_ref"] == "rem-csp" and "CWE-693" in csp["standards"]
    assert summary["findings"] == len(rows) and summary["unverified"] == 0


# ---- the stage ------------------------------------------------------------------------------------


class Boom:
    """An executor, gateway or browser that fails the test if anything uses it."""

    def __getattr__(self, name):
        raise AssertionError(f"passive analysis touched {name!r}")


def stage_state(traffic, rule_set, skipped=(), root=None, cancelled=False):
    written = []
    runtime = SimpleNamespace(
        traffic=traffic, rule_set=rule_set, skipped_degraded=list(skipped), target_url="https://app.test/", executor=Boom(), gateway=Boom(),
        browser=Boom(), counters=LiveCounters(), cancelled=lambda: cancelled, findings_writer=lambda label, rows: written.append((label, rows)),
    )
    return {"runtime": runtime, "root_response": root}, written


def test_the_stage_makes_no_request_and_no_model_call_and_writes_through_the_writer(capsys):
    state, written = stage_state([ex(url="https://app.test/a", headers={})], resolve_effective_rule_set(CATALOG))
    passive_analysis(state)
    (label, rows), = written
    assert label == "passive analysis" and rows and state["passive_analysis"]["findings"] == len(rows)
    assert "no requests sent" in capsys.readouterr().out


def test_the_root_response_is_analysed_when_no_browser_traffic_exists():
    root = ResponseSnapshot(200, 10, "<html></html>", {"Content-Type": "text/html"})
    state, written = stage_state([], resolve_effective_rule_set(CATALOG), root=root)
    passive_analysis(state)
    assert {r["target"] for r in written[0][1]} == {"GET https://app.test/"}


def test_disabled_and_skipped_checks_do_not_run():
    cfg = parse_rule_config({"checks": {P.CSP: {"enabled": False}}}, CATALOG)
    state, written = stage_state([ex(headers={})], resolve_effective_rule_set(CATALOG, scan_config=cfg), skipped=[{"check_id": P.XCTO, "status": "skipped"}])
    passive_analysis(state)
    ids = {r["rule_id"] for _, rows in written for r in rows}
    assert P.CSP not in ids and P.XCTO not in ids and P.HSTS in ids


def test_a_cancelled_scan_stops_before_analysing():
    state, written = stage_state([ex(headers={})], resolve_effective_rule_set(CATALOG), cancelled=True)
    passive_analysis(state)
    assert written == [] and state["stop_reason"] == "cancelled"


def test_the_passive_only_pack_ends_the_scan_after_the_stage():
    only = parse_rule_config({"packs": {"owasp-api-top10-2023": False, "owasp-web-top10": False, "passive-only": True}}, CATALOG)
    rule_set = resolve_effective_rule_set(CATALOG, scan_config=only)
    assert not has_active_work(rule_set, [])
    state, _ = stage_state([], rule_set)
    assert route_after_passive(state) == "end"
    full, _ = stage_state([], resolve_effective_rule_set(CATALOG))
    assert route_after_passive(full) == "analyze_apis"
    assert has_active_work(None, [])  # no rule set says nothing: do not stop

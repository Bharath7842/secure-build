"""DAST-01-010: scope and method policy (pure decision function, table-driven)."""

from __future__ import annotations

import pytest

from app.dast.domain.policy import (
    METHOD_NOT_PERMITTED,
    OFF_SCOPE,
    MethodPolicy,
    RequestDescription,
    Scope,
    evaluate_redirect,
    evaluate_request,
    normalize_host,
    resolve_method_policy,
)
from app.services.safety_guard import registrable_domain

pytestmark = pytest.mark.unit

SAFE = MethodPolicy(safe_mode=True, allow_state_changing=False)
UNSAFE = MethodPolicy(safe_mode=False)
OPTED_IN = MethodPolicy(safe_mode=True, allow_state_changing=True)


def scope(target: str = "http://target.com", mode: str = "exact") -> Scope:
    return Scope.for_target(target, mode, registrable_domain)  # type: ignore[arg-type]


def decide(url: str, method: str = "GET", *, sc: Scope | None = None, policy: MethodPolicy = SAFE):
    return evaluate_request(RequestDescription(method, url), sc or scope(), policy)


# ---- scope: exact mode ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://target.com/",
        "https://target.com/a/b?c=d#e",
        "https://TARGET.com:8443/x",  # case, non-default port
        "http://target.com:80/",  # default port
        "http://target.com./",  # trailing dot (fully-qualified form)
        "http://target.com",
    ],
)
def test_in_scope_urls_are_allowed(url):
    assert decide(url).allowed


@pytest.mark.parametrize(
    "url",
    [
        "http://app.target.com/",  # sibling/sub domain in exact mode
        "http://target.com.evil.com/",  # look-alike suffix
        "http://eviltarget.com/",  # look-alike prefix
        "http://evil.com/",
        "http://target.com@evil.com/",  # userinfo trick: real host is evil.com
        "http://evil.com@target.com/",  # userinfo at all is refused, even toward the real host
        "http://target.com:pw@target.com/",
        "http://target.com\\@evil.com/",  # a browser reads the backslash as '/', i.e. host target.com
        "http://evil.com\\.target.com/",
        "http://target.com%2eevil.com/",  # encoded dot inside the host
        "http://target.com /x",  # whitespace
        "http://target.com/\r\nHost: evil.com",  # control characters
        "http://target.com:notaport/",
        "http://target.com:99999/",
        "ftp://target.com/",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "//target.com/x",  # scheme-relative: no scheme to trust
        "/relative/path",
        "",
        "http://",
        "http:///x",
    ],
)
def test_out_of_scope_or_untrustworthy_urls_are_denied_before_anything_is_sent(url):
    decision = decide(url)
    assert not decision.allowed and decision.reason == OFF_SCOPE
    assert decision.detail


# ---- scope: root-domain mode ----------------------------------------------------------------


def test_sibling_subdomain_is_denied_in_exact_and_allowed_in_root_domain():
    exact = scope("http://app.target.com", "exact")
    root = scope("http://app.target.com", "root-domain")
    for url in ("http://api.target.com/", "http://target.com/", "http://deep.api.target.com/"):
        assert decide(url, sc=exact).reason == OFF_SCOPE
        assert decide(url, sc=root).allowed
    assert decide("http://app.target.com/", sc=exact).allowed


@pytest.mark.parametrize(
    "url",
    [
        "http://target.com.evil.com/",
        "http://eviltarget.com/",
        "http://evil.com/",
        "http://api.target.com@evil.com/",
        "http://target.org/",
    ],
)
def test_root_domain_mode_still_rejects_lookalikes(url):
    assert decide(url, sc=scope("http://app.target.com", "root-domain")).reason == OFF_SCOPE


def test_root_domain_is_public_suffix_aware():
    root = scope("https://app.company.co.uk", "root-domain")
    assert decide("https://portal.company.co.uk/", sc=root).allowed
    # A different registrant under the same public suffix is not the same domain.
    assert decide("https://evil.co.uk/", sc=root).reason == OFF_SCOPE
    assert decide("https://company.com/", sc=root).reason == OFF_SCOPE


def test_root_domain_mode_never_widens_for_a_single_label_or_ip_target():
    for target, sibling in (("http://localhost:3000", "http://other.localhost/"), ("http://10.0.0.5", "http://10.0.0.6/")):
        sc = scope(target, "root-domain")
        assert decide(target + "/", sc=sc).allowed
        assert decide(sibling, sc=sc).reason == OFF_SCOPE


# ---- host normalization ---------------------------------------------------------------------


def test_idn_hosts_compare_by_their_punycode_form():
    sc = scope("http://bücher.example")
    assert decide("http://xn--bcher-kva.example/", sc=sc).allowed
    assert decide("http://BÜCHER.example/", sc=sc).allowed
    assert decide("http://bucher.example/", sc=sc).reason == OFF_SCOPE


def test_ip_literals_are_canonicalized():
    sc = scope("http://127.0.0.1:3000")
    assert decide("http://127.0.0.1/", sc=sc).allowed
    assert decide("http://[::ffff:127.0.0.1]/", sc=sc).allowed  # IPv4-mapped IPv6
    assert decide("http://127.0.0.2/", sc=sc).reason == OFF_SCOPE
    assert decide("http://2130706433/", sc=sc).reason == OFF_SCOPE  # decimal form is not trusted
    assert decide("http://0x7f.0.0.1/", sc=sc).reason == OFF_SCOPE
    v6 = scope("http://[::1]:8080")
    assert decide("http://[0:0:0:0:0:0:0:1]/", sc=v6).allowed
    assert decide("http://[::2]/", sc=v6).reason == OFF_SCOPE


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("Example.COM.", "example.com"),
        ("[::1]", "::1"),
        ("::ffff:10.0.0.1", "10.0.0.1"),
        ("", ""),
        (".", ""),
    ],
)
def test_normalize_host(raw, expected):
    assert normalize_host(raw) == expected


def test_scope_rejects_a_target_it_cannot_parse():
    for bad in ("", "not a url", "ftp://x.com", "http://user:pw@x.com"):
        with pytest.raises(ValueError):
            Scope.for_target(bad)
    with pytest.raises(ValueError):
        Scope.for_target("http://x.com", "subtree")  # type: ignore[arg-type]


# ---- method policy --------------------------------------------------------------------------


@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS", "get", " Head "])
def test_safe_methods_are_always_allowed(method):
    assert decide("http://target.com/", method).allowed


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "post", "Delete"])
def test_state_changing_methods_are_denied_in_safe_mode(method):
    decision = decide("http://target.com/", method)
    assert not decision.allowed and decision.reason == METHOD_NOT_PERMITTED


@pytest.mark.parametrize("policy", [UNSAFE, OPTED_IN])
@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_state_changing_methods_are_allowed_after_opt_in(policy, method):
    assert decide("http://target.com/", method, policy=policy).allowed


@pytest.mark.parametrize("method", ["TRACE", "CONNECT", "PROPFIND", "", "G ET"])
def test_unsupported_methods_are_denied_even_with_safe_mode_off(method):
    decision = decide("http://target.com/", method, policy=UNSAFE)
    assert not decision.allowed and decision.reason == METHOD_NOT_PERMITTED


def test_off_scope_wins_over_method_so_the_reason_is_accurate():
    assert decide("http://evil.com/", "POST").reason == OFF_SCOPE


def test_non_disposable_target_forces_safe_mode():
    forced = resolve_method_policy(safe_mode=False, allow_state_changing=True, target_disposable=False)
    assert forced == MethodPolicy(safe_mode=True, allow_state_changing=False)
    assert decide("http://target.com/", "POST", policy=forced).reason == METHOD_NOT_PERMITTED
    # Defaults are safe too.
    assert resolve_method_policy() == MethodPolicy(True, False)
    # A disposable target honours the scan's choices.
    assert resolve_method_policy(safe_mode=False, target_disposable=True) == MethodPolicy(False, False)
    assert resolve_method_policy(allow_state_changing=True, target_disposable=True) == MethodPolicy(True, True)
    assert resolve_method_policy(target_disposable=True) == MethodPolicy(True, False)


# ---- redirects ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "location, allowed",
    [
        ("/login", True),
        ("next", True),
        ("http://target.com/elsewhere", True),
        ("https://target.com/secure", True),
        ("http://evil.com/", False),
        ("//evil.com/x", False),  # scheme-relative off-host
        ("https://target.com.evil.com/", False),
        ("http://target.com@evil.com/", False),
        ("javascript:alert(1)", False),
        ("ftp://target.com/", False),
    ],
)
def test_redirect_hops_are_decided_like_requests(location, allowed):
    decision = evaluate_redirect("http://target.com/start", location, "GET", scope(), SAFE)
    assert decision.allowed is allowed
    if not allowed:
        assert decision.reason == OFF_SCOPE


def test_redirect_inherits_the_method_policy():
    decision = evaluate_redirect("http://target.com/a", "/b", "POST", scope(), SAFE)
    assert decision.reason == METHOD_NOT_PERMITTED


# ---- purity ---------------------------------------------------------------------------------


@pytest.mark.parametrize("garbage", [None, 5, b"http://target.com", "\x00", "http://[::1", "http://[xyz]/", "http://a b/", "http://%00/", "x" * 10_000])
def test_garbage_never_raises_and_is_denied(garbage):
    decision = evaluate_request(RequestDescription("GET", garbage), scope(), SAFE)  # type: ignore[arg-type]
    assert not decision.allowed

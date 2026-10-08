"""Redaction helpers shared by the request audit (DAST-01-050; DAST-06-010 extends them)."""

from __future__ import annotations

import pytest

from app.dast.domain.redaction import REDACTED, redact_headers, redact_url

pytestmark = pytest.mark.unit


def test_sensitive_header_values_are_masked_but_names_are_kept():
    out = redact_headers(
        {"Authorization": "Bearer x", "cookie": "a=b", "Set-Cookie": "s=1", "X-Api-Key": "k", "X-Session-Id": "z", "Accept": "*/*"}
    )
    assert out["Accept"] == "*/*"
    assert all(out[name] == REDACTED for name in out if name != "Accept")
    assert set(out) == {"Authorization", "cookie", "Set-Cookie", "X-Api-Key", "X-Session-Id", "Accept"}


def test_known_secret_values_are_scrubbed_from_innocent_looking_headers():
    out = redact_headers({"X-Trace": "id-hunter2-9", "User-Agent": "ua"}, secrets=["hunter2", ""])
    assert out == {"X-Trace": f"id-{REDACTED}-9", "User-Agent": "ua"}


def test_redact_headers_handles_none_and_does_not_mutate():
    assert redact_headers(None) == {}
    original = {"Authorization": "Bearer x"}
    redact_headers(original)
    assert original == {"Authorization": "Bearer x"}


@pytest.mark.parametrize(
    "url, expected_fragments, forbidden",
    [
        ("http://t.test/a?token=abc&user=bob", ["user=bob", "token=[REDACTED]"], ["abc"]),
        ("http://t.test/a?password=pw&api_key=k", ["password=[REDACTED]", "api_key=[REDACTED]"], ["=pw", "=k&"]),
        ("http://u:pw@t.test/a", [f"{REDACTED}@t.test"], ["u:pw"]),
        ("http://t.test/a", ["http://t.test/a"], []),
        ("http://t.test/a?flag", ["flag="], []),
    ],
)
def test_redact_url(url, expected_fragments, forbidden):
    out = redact_url(url)
    assert all(fragment in out for fragment in expected_fragments), out
    assert not any(bad in out for bad in forbidden), out


def test_redact_url_scrubs_known_secrets_in_path_and_fragment():
    out = redact_url("http://t.test/users/hunter2/x?q=hunter2#hunter2", secrets=["hunter2"])
    assert "hunter2" not in out


def test_redact_url_survives_garbage():
    assert redact_url("http://[::1", secrets=["s"]) == "http://[::1"

"""The DAST test fixtures themselves (DAST-00-060)."""

import socket
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

from app.dast.domain.interfaces import ModelGateway, ModelReply
from tests.dast_fixtures import FakeModelGateway, FakeTarget, ModelGatewayError

pytestmark = pytest.mark.unit

BACKEND = Path(__file__).resolve().parents[1]


# ---- fake HTTP target ---------------------------------------------------------------------


def test_target_serves_scripted_pages_headers_and_cookies(fake_target):
    fake_target.add_page(
        "/", "<h1>Home</h1>", headers={"X-Frame-Options": "DENY"}, cookies={"theme": "dark"}
    )
    response = fake_target.client().get("/")

    assert response.status_code == 200
    assert "<h1>Home</h1>" in response.text
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["content-type"].startswith("text/html")
    assert response.cookies.get("theme") == "dark"


def test_target_unknown_path_is_404_and_requests_are_recorded(fake_target):
    client = fake_target.client()
    assert client.get("/missing").status_code == 404
    client.post("/missing", json={"a": 1})
    assert [(r.method, r.url.path) for r in fake_target.requests] == [("GET", "/missing"), ("POST", "/missing")]
    assert len(fake_target.requests_to("/missing")) == 2


def test_target_serves_an_openapi_document(fake_target):
    document = {"openapi": "3.0.0", "paths": {"/api/items": {"get": {"summary": "list"}}}}
    fake_target.set_openapi(document)
    response = fake_target.client().get("/openapi.json")
    assert response.json() == document


def test_target_has_two_users_who_can_log_in(fake_target):
    assert {u.role for u in fake_target.users.values()} == {"admin", "user"}
    client = fake_target.client()

    ok = client.post("/login", json={"username": "admin", "password": "admin-pw"})
    assert ok.status_code == 200 and ok.json()["role"] == "admin"
    assert "session=" in ok.headers["set-cookie"]

    assert client.post("/login", json={"username": "admin", "password": "wrong"}).status_code == 401
    assert client.post("/login", content=b"not json").status_code == 400


def test_protected_route_distinguishes_anonymous_wrong_role_and_right_role(fake_target):
    fake_target.protect("/api/admin/users", roles=["admin"])

    anonymous = fake_target.client()
    assert anonymous.get("/api/admin/users").status_code == 401

    as_user = fake_target.client(headers={"Authorization": f"Bearer {fake_target.users['user'].token}"})
    assert as_user.get("/api/admin/users").status_code == 403

    as_admin = fake_target.client(headers={"Authorization": f"Bearer {fake_target.users['admin'].token}"})
    assert as_admin.get("/api/admin/users").status_code == 200

    with_cookie = fake_target.client(cookies={"session": fake_target.users["admin"].token})
    assert with_cookie.get("/api/admin/users").status_code == 200


def test_target_uses_no_sockets(fake_target, monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("fake target must not open sockets")

    monkeypatch.setattr(socket, "socket", refuse)
    fake_target.add_page("/", "ok")
    assert fake_target.client().get("/").text == "ok"


@pytest.mark.asyncio
async def test_target_works_with_the_async_client(fake_target):
    fake_target.add_json("/api/ping", {"pong": True})
    async with fake_target.async_client() as client:
        assert (await client.get("/api/ping")).json() == {"pong": True}


def test_custom_route_handler_and_base_url():
    target = FakeTarget(base_url="http://other.test")
    target.route("GET", "/echo", lambda request: httpx.Response(200, text=str(request.url.params.get("q"))))
    assert target.client().get("/echo", params={"q": "hello"}).text == "hello"
    assert str(target.client().base_url).startswith("http://other.test")


# ---- fake model gateway -------------------------------------------------------------------


def test_gateway_satisfies_the_domain_contract(fake_gateway):
    assert isinstance(fake_gateway, ModelGateway)


def test_gateway_returns_scripted_replies_in_order_and_records_calls(fake_gateway):
    fake_gateway.script("construct", {"tests": [1]})
    fake_gateway.script("construct", {"tests": [2]})
    fake_gateway.script("rule", {"verdict": "FAIL"})

    first = fake_gateway.complete("construct", "sys", "prompt one", {"type": "object"}, max_tokens=100, temperature=0.1)
    second = fake_gateway.complete("construct", "sys", "prompt two", {"type": "object"})
    ruling = fake_gateway.complete("rule", "sys", "judge", {"type": "object"})

    assert [first.data, second.data, ruling.data] == [{"tests": [1]}, {"tests": [2]}, {"verdict": "FAIL"}]
    assert [c.task for c in fake_gateway.calls] == ["construct", "construct", "rule"]
    assert fake_gateway.calls[0].prompt == "prompt one"
    assert fake_gateway.calls[0].max_tokens == 100 and fake_gateway.calls[0].temperature == 0.1
    assert len(fake_gateway.calls_for("construct")) == 2
    assert fake_gateway.pending("construct") == 0


def test_gateway_can_simulate_failure_and_malformed_output(fake_gateway):
    fake_gateway.script_failure("construct")
    fake_gateway.script_failure("rule", TimeoutError("model timed out"))
    fake_gateway.script_malformed("narrate", "oops {")

    with pytest.raises(ModelGatewayError):
        fake_gateway.complete("construct", "s", "p", {})
    with pytest.raises(TimeoutError):
        fake_gateway.complete("rule", "s", "p", {})
    with pytest.raises(ValueError, match="malformed"):
        fake_gateway.complete("narrate", "s", "p", {})
    assert len(fake_gateway.calls) == 3  # failed calls are still recorded


def test_strict_gateway_fails_on_an_unscripted_call(fake_gateway):
    with pytest.raises(AssertionError, match="unscripted"):
        fake_gateway.complete("fingerprint", "s", "p", {})


def test_lenient_gateway_reports_a_fallback_instead():
    reply = FakeModelGateway(strict=False).complete("fingerprint", "s", "p", {})
    assert reply.fallback_used is True


def test_gateway_passes_through_a_full_model_reply(fake_gateway):
    scripted = ModelReply(data={"x": 1}, input_tokens=7, output_tokens=3, cost_usd=0.01)
    fake_gateway.script("rule", scripted)
    assert fake_gateway.complete("rule", "s", "p", {}) is scripted


# ---- markers: live tests are skipped unless selected ---------------------------------------


def _pytest(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-q", "-rs", *args],
        cwd=BACKEND, capture_output=True, text=True, timeout=120,
    )


def test_live_tests_are_skipped_by_default():
    result = _pytest("tests/test_dast_live_example.py")
    assert result.returncode == 0, result.stdout
    assert "1 skipped" in result.stdout
    assert "passed" not in result.stdout


def test_live_tests_run_when_explicitly_selected():
    result = _pytest("tests/test_dast_live_example.py", "-m", "live")
    assert result.returncode == 0, result.stdout
    assert "1 passed" in result.stdout


def test_not_live_deselects_live_tests():
    result = _pytest("tests/test_dast_live_example.py", "-m", "not live")
    assert "1 deselected" in result.stdout

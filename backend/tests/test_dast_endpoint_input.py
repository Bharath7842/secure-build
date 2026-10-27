"""Operator-pasted REST endpoints: the pure parser, the gate shared with the model cleanup, and the
inventory merge. No network, model or database."""

from __future__ import annotations

import json

import pytest

from app.dast.domain import endpoint_input as ei
from app.dast.domain import inventory as inv
from app.dast.domain.entities import EndpointSource, Location
from app.dast.domain.policy import Scope

pytestmark = pytest.mark.unit

BASE = "http://t.test"
SCOPE = Scope.for_target(BASE, "exact")


def parse(text: str) -> ei.ParseResult:
    return ei.parse_endpoint_text(text, base_url=BASE)


def keys(result: ei.ParseResult) -> list[tuple[str, str]]:
    return [(e.method, e.path) for e in result.endpoints]


def test_methods_paths_urls_bullets_and_comments_are_read():
    result = parse(
        """
        # users api
        GET /api/users/1
        - post /api/orders {"qty": 2, "note": "hi"}
        1. `DELETE /api/orders/9`
        /api/health
        http://t.test/api/ping?verbose=1
        PUT api/items/{id}
        GET /api/files/<name>
        """
    )
    assert keys(result) == [
        ("GET", "/api/users/1"), ("POST", "/api/orders"), ("DELETE", "/api/orders/9"), ("GET", "/api/health"),
        ("GET", "/api/ping"), ("PUT", "/api/items/{id}"), ("GET", "/api/files/{name}"),
    ]
    assert result.endpoints[1].body == '{"qty":2,"note":"hi"}'
    assert result.endpoints[4].query == (("verbose", "1"),)
    assert not result.unparsed and not result.rejected


def test_multiline_json_body_is_joined():
    result = parse('POST /api/orders {\n  "qty": 1,\n  "sku": "a"\n}\nGET /api/after')
    assert keys(result) == [("POST", "/api/orders"), ("GET", "/api/after")]
    assert json.loads(result.endpoints[0].body) == {"qty": 1, "sku": "a"}


def test_curl_commands_with_continuations_and_data():
    result = parse(
        "curl -X PATCH 'http://t.test/api/users/4?x=1' \\\n  -H 'Content-Type: application/json' \\\n  -d '{\"name\":\"a\"}'\n"
        "curl http://t.test/api/ping\n"
        "curl -d 'a=1&b=2' http://t.test/api/form"
    )
    assert keys(result) == [("PATCH", "/api/users/4"), ("GET", "/api/ping"), ("POST", "/api/form")]
    assert result.endpoints[0].query == (("x", "1"),)
    assert result.endpoints[0].body == '{"name":"a"}'
    assert result.endpoints[2].body == "a=1&b=2"


@pytest.mark.parametrize(
    "line",
    [
        "curl -H 'Authorization: Bearer abcdefghijklmnop' http://t.test/api/x",
        "curl -H 'Cookie: sid=1' http://t.test/api/x",
        "curl -H 'X-API-Key: k' http://t.test/api/x",
        "curl -u admin:pw http://t.test/api/x",
        "curl -b 'a=b' http://t.test/api/x",
        "Authorization: Bearer abcdefghijklmnop",
        "Authorization: whatever",
        "GET /api/x?token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig",
        "POST /api/x {\"k\": \"AKIAABCDEFGHIJKLMNOP\"}",
    ],
)
def test_credentials_reject_the_paste_with_a_line_number(line):
    result = parse("GET /api/ok\n" + line)
    assert result.rejected and result.rejected[0][0] == 2
    assert "Identities" in result.rejected[0][1]
    assert all(line not in str(e) for e in result.endpoints)


def test_harmless_headers_are_ignored_not_stored():
    result = parse("GET /api/x\nAccept: application/json\nX-Request-Id: 12")
    assert keys(result) == [("GET", "/api/x")]
    assert not result.rejected and len(result.warnings) == 2


def test_sensitive_parameter_and_body_values_are_blanked():
    result = parse('POST /api/login?api_key=zzz {"user": "bob", "password": "hunter2", "nested": {"token": "t"}}')
    (endpoint,) = result.endpoints
    assert endpoint.query == (("api_key", ""),)
    body = json.loads(endpoint.body)
    assert body["user"] == "bob" and body["password"] == "" and body["nested"]["token"] == ""
    assert "hunter2" not in json.dumps(endpoint.to_dict())


def test_other_hosts_are_dropped_and_counted_not_reported():
    result = parse("GET http://evil.test/api/x\nGET http://t.test/api/y\nGET //evil.test/z\nGET ftp://t.test/f")
    assert keys(result) == [("GET", "/api/y")]
    assert result.dropped_off_scope == 1
    assert len(result.unparsed) == 2  # protocol-relative and ftp are malformed, not off-scope


def test_unreadable_lines_are_kept_for_the_model_and_capped():
    result = parse("please also test the cart thing\nGET /api/ok\n" + "\n".join(f"mystery line {i}" for i in range(80)))
    assert keys(result) == [("GET", "/api/ok")]
    assert result.unparsed[0] == "please also test the cart thing"
    assert len(result.unparsed) == ei.MAX_UNPARSED


def test_an_openapi_paste_is_handed_back_unparsed():
    assert parse('{"openapi": "3.0.0", "paths": {}}').openapi_text
    assert parse("openapi: 3.0.0\npaths: {}\n").openapi_text
    assert parse("swagger: '2.0'\n").openapi_text


def test_size_and_count_caps():
    many = "\n".join(f"GET /api/item{i}x" for i in range(ei.MAX_ENDPOINTS + 25))
    result = parse(many)
    assert len(result.endpoints) == ei.MAX_ENDPOINTS and result.truncated
    assert parse("GET /a\n" + "x" * (ei.MAX_TEXT_CHARS + 10)).truncated


def test_empty_and_whitespace_input():
    for text in ("", "   \n\n", None):
        result = ei.parse_endpoint_text(text, base_url=BASE)
        assert not result.endpoints and not result.unparsed and not result.rejected


def test_build_endpoint_is_the_gate_for_model_output_too():
    ok, _ = ei.build_endpoint("get", "/api/x", scope=SCOPE, origin="model")
    assert ok and ok.method == "GET" and ok.origin == "model"
    assert ei.build_endpoint("TRACE", "/api/x", scope=SCOPE)[0] is None
    assert ei.build_endpoint("GET", "http://evil.test/x", scope=SCOPE)[1] == "off_scope"
    assert ei.build_endpoint("GET", "/x", query=[("a", "Bearer abcdefghijklmnop")], scope=SCOPE)[1] == "credential"
    assert ei.build_endpoint("GET", "/x y", scope=SCOPE)[0] is None
    assert ei.build_endpoint("GET", "/a" * 400, scope=SCOPE)[0] is None


def test_stored_records_round_trip_and_reject_tampering():
    (endpoint,) = parse('POST /api/o?x=1 {"a": 1}').endpoints
    assert ei.UserEndpoint.from_dict(endpoint.to_dict()) == endpoint
    assert ei.UserEndpoint.from_dict({"method": "TRACE", "path": "/x"}) is None
    assert ei.UserEndpoint.from_dict({"method": "GET", "path": "http://evil.test/x"}) is None
    assert ei.UserEndpoint.from_dict({"method": "GET"}) is None


# ---- inventory ---------------------------------------------------------------------------------


def test_a_pasted_endpoint_merges_with_a_crawled_one_instead_of_duplicating():
    inventory = inv.Inventory([inv.observed("GET", BASE + "/api/users/5", identity_id="u1", status=200, kind="api")])
    (user,) = parse("GET /api/users/7\nGET /api/users/{id}").endpoints[:1]
    merged = inventory.add(ei.to_inventory_endpoint(user, BASE))
    assert len(inventory) == 1
    assert merged.source is EndpointSource.BOTH and merged.user_supplied and merged.seen_as == ("u1",)
    assert merged.last_status == 200
    (param,) = [p for p in merged.parameters if p.location is Location.PATH]
    assert set(param.observed_values) == {"5", "7"}


def test_a_new_pasted_endpoint_is_testable_and_not_reported_as_undocumented():
    inventory = inv.Inventory([inv.observed("GET", BASE + "/api/known", status=200, kind="api")])
    for user in parse("POST /api/hidden {\"a\": 1}\nGET /api/things/{id}").endpoints:
        inventory.add(ei.to_inventory_endpoint(user, BASE))
    hidden = inventory.get("POST", "/api/hidden")
    assert hidden.user_supplied and hidden.state_changing and hidden.url == BASE + "/api/hidden"
    assert hidden.body_sample == '{"a":1}' and any(p.location is Location.BODY and p.name == "a" for p in hidden.parameters)
    assert inventory.get("GET", "/api/things/{id}").url == BASE + "/api/things/{id}"
    diff = inv.compare_observed_vs_documented(inventory, schema_found=True)
    assert [e.path_template for e in diff.undocumented] == ["/api/known"]
    assert not any(e.user_supplied for e in diff.unexercised)
    assert all(e["user_supplied"] in (True, False) for e in inventory.to_summary())


def test_state_changing_comes_from_the_method_only():
    for line, expected in (("GET /a", False), ("HEAD /a", False), ("POST /a", True), ("PUT /a", True), ("PATCH /a", True), ("DELETE /a", True)):
        (user,) = parse(line).endpoints
        assert ei.to_inventory_endpoint(user, BASE).state_changing is expected

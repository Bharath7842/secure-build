"""Pure discovery logic: fingerprint heuristics, session rules, OpenAPI and GraphQL parsing,
the introspection exception in the method policy, and the observed-vs-documented diff."""

from __future__ import annotations

import json

import pytest

from app.dast.domain import fingerprint as fp
from app.dast.domain import inventory as inv
from app.dast.domain import openapi, session
from app.dast.domain.entities import EndpointSource, Location, ResponseSnapshot
from app.dast.domain.graphql import INTROSPECTION_BODY, endpoints_from_introspection
from app.dast.domain.identities import build_identities
from app.dast.domain.introspection import is_introspection_request
from app.dast.domain.policy import INTROSPECTION_INTENT, MethodPolicy, RequestDescription, Scope, evaluate_request

pytestmark = pytest.mark.unit


def resp(body="", status=200, ctype="text/html; charset=utf-8", **headers):
    return ResponseSnapshot(status=status, length=len(body), body_excerpt=body, headers={"content-type": ctype, **headers})


IDS = lambda *specs: build_identities(list(specs))  # noqa: E731
FORM = {"label": "a", "role": "User", "auth_method": "form"}
TOKEN = {"label": "t", "role": "Admin", "auth_method": "token"}
PRE = {"label": "p", "role": "Viewer", "auth_method": "preauth"}


# ---- fingerprint ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "root, shape",
    [
        (resp('{"status":"ok"}', ctype="application/json"), "api"),
        (resp('<?xml version="1.0"?><r/>', ctype="application/xml"), "api"),
        (resp("<html><body><div id='root'></div><script src='/main.js'></script></body></html>"), "spa"),
        (resp("<html><app-root></app-root></html>"), "spa"),
        (resp("<html><script src='/a.js'></script><script src='/b.js'></script><script src='/c.js'></script></html>"), "spa"),
        (resp("<html><body><h1>Shop</h1><p>" + "Welcome to our catalog. " * 40 + "</p><a href='/p'>x</a></body></html>"), "mpa"),
        (None, "mpa"),
    ],
)
def test_shape_detection(root, shape):
    assert fp.detect_shape(root)[0] == shape


def test_schema_document_recognition():
    assert fp.classify_schema_document('{"openapi": "3.0.1", "paths": {}, "info": {}}') == "openapi"
    assert fp.classify_schema_document('{"swagger": "2.0", "paths": {}}') == "openapi"
    assert fp.classify_schema_document("openapi: 3.0.0\ninfo:\n  title: x\n") == "openapi"
    assert fp.classify_schema_document('{"openapi": "3.0.1", "paths": {"/a": {"get": {') == "openapi"  # truncated
    assert fp.classify_schema_document('{"hello": "world"}') == "" and fp.classify_schema_document("<html>") == "" and fp.classify_schema_document("") == ""


def test_heuristic_fingerprint_finds_schema_auth_and_shape():
    probes = [fp.SchemaProbe("http://t/openapi.json", resp("<html>", 404)), fp.SchemaProbe("http://t/swagger.json", resp('{"swagger":"2.0","paths":{}}', ctype="application/json"))]
    result = fp.heuristic_fingerprint(resp("{}", ctype="application/json"), probes, IDS(FORM))
    assert (result.shape, result.auth, result.schema, result.schema_url, result.source) == ("api", "form", "openapi", "http://t/swagger.json", "heuristic")
    none = fp.heuristic_fingerprint(resp("<html><p>hi</p></html>"), [], IDS())
    assert (none.shape, none.auth, none.schema) == ("mpa", "none", "none")


def test_auth_comes_from_the_supplied_identities_only():
    assert fp.auth_from_identities(IDS(TOKEN)) == "token"
    assert fp.auth_from_identities(IDS(PRE)) == "preauth"
    assert fp.auth_from_identities(IDS(PRE, TOKEN, FORM)) == "form"
    assert fp.auth_from_identities(IDS()) == "none"


def test_operator_supplied_schema_url_and_graphql_hint():
    s = fp.heuristic_fingerprint(resp("<p>x</p>"), [], IDS(), schema_url_supplied="http://t/docs.json")
    assert (s.schema, s.schema_url) == ("openapi", "http://t/docs.json")
    g = fp.heuristic_fingerprint(resp("<p>x</p>"), [], IDS(), graphql_url="http://t/graphql")
    assert g.schema == "graphql"


def test_reconcile_lets_the_model_change_shape_but_not_facts():
    base = fp.heuristic_fingerprint(resp("<html><p>hi</p></html>"), [], IDS(FORM))
    out = fp.reconcile({"shape": "spa", "auth": "token", "schema": "openapi"}, base)
    assert (out.shape, out.auth, out.schema, out.source) == ("spa", "form", "none", "model") and "model classified" in out.evidence[-1]
    assert fp.reconcile({"shape": "bogus"}, base) is base and fp.reconcile(None, base) is base and fp.reconcile({"shape": "mpa"}, base) is base


def test_routing_plan_per_shape_and_auth():
    api = fp.Fingerprint("api", "token", "openapi")
    plan = fp.routing_plan(api, IDS(TOKEN))
    assert plan["browser_crawl"] is False and plan["schema_ingestion"] is True and plan["form_login"] is False
    site = fp.routing_plan(fp.Fingerprint("mpa", "form", "none"), IDS(FORM, PRE))
    assert site["browser_crawl"] and site["form_login"] and site["preauth_identity_ids"] == ["identity-p"]
    assert fp.routing_plan(fp.Fingerprint("spa", "none", "none"), IDS())["schema_ingestion"] is False


# ---- session rules ----------------------------------------------------------------------------


def test_hash_routed_login_urls_count_as_login_pages():
    assert session.looks_like_login_url("http://127.0.0.1:3001/#/login")
    assert session.looks_like_login_url("http://t.test/signin")
    assert not session.looks_like_login_url("http://127.0.0.1:3001/#/search")
    from app.dast.nodes.login import _url_left_login
    assert _url_left_login("http://127.0.0.1:3001/#/search", "http://127.0.0.1:3001/#/login")
    assert not _url_left_login("http://127.0.0.1:3001/#/login", "http://127.0.0.1:3001/#/login")
    assert not _url_left_login("http://t.test/login?error=1", "http://t.test/login")


def test_login_needs_two_independent_signals():
    assert not session.login_verified([])
    assert not session.login_verified(["url_changed"])
    assert not session.login_verified(["url_changed", "url_changed"])
    assert not session.login_verified(["bogus", "other"])
    assert session.login_verified(["url_changed", "credential_field_gone"])
    assert session.login_verified(["post_login_indicator", "url_changed", "credential_field_gone"])


@pytest.mark.parametrize("kind", ["multi_step", "oauth_sso", "captcha", "otp_2fa", "unknown"])
def test_unsupported_login_message_points_to_a_preauthenticated_session(kind):
    message = session.unsupported_login_message(kind, "Admin A")
    assert "Admin A" in message and "not automated" in message and "pre-authenticated" in message


@pytest.mark.parametrize(
    "kwargs, ok",
    [
        ({"status": 200}, True), ({"status": 404}, True), ({"status": 500}, True),
        ({"status": 401}, False), ({"status": 403}, False),
        ({"status": 302, "location": "/login?next=/a"}, False), ({"status": 302, "location": "/signin"}, False),
        ({"status": 302, "location": "/dashboard"}, True),
        ({"status": 200, "final_url": "http://t/auth"}, False),
        ({"status": 200, "login_form_present": True}, False),
        ({"status": 200, "post_login_indicator_missing": True}, False),
        ({"status": 200, "final_url": "http://t/app/login", "login_url": "http://t/app/login"}, False),
    ],
)
def test_session_verdict(kwargs, ok):
    verdict = session.session_verdict(**kwargs)
    assert verdict.ok is ok and (verdict.reason == "") is ok


def test_probe_verdict_names_what_failed():
    assert session.probe_verdict(200).ok and session.probe_verdict(204, kind="session").ok
    bad = session.probe_verdict(401)
    assert not bad.ok and "token is invalid or expired" in bad.reason
    assert "saved session is invalid or expired" in session.probe_verdict(403, kind="session").reason
    assert "could not be checked" in session.probe_verdict(None, error="timeout").reason


def test_relogin_is_bounded_per_identity():
    assert session.may_relogin({}, "a") and not session.may_relogin({"a": 1}, "a") and session.may_relogin({"a": 1}, "b")


def exchange(status, identity_id="a", asset=False):
    from app.dast.domain.traffic import RecordedExchange

    return RecordedExchange("GET", "http://t/x", status, "xhr", identity_id=identity_id, asset=asset)


def test_new_denials_resumes_from_where_it_left_off_and_skips_other_identities_and_assets():
    tracker = session.DenialTracker()  # default threshold=3
    traffic = [exchange(403, "a"), exchange(401, "b"), exchange(200, "a")]
    reason, cursor = session.new_denials(traffic, "a", 0, tracker)
    assert reason == "" and cursor == 3  # one 403 for "a" (score 1), well under threshold, then the 200 resets it
    traffic.append(exchange(401, "a"))  # score 2
    traffic.append(exchange(403, "a", asset=True))  # an asset never counts
    traffic.append(exchange(401, "a"))  # score 4, crosses the threshold
    reason, cursor = session.new_denials(traffic, "a", cursor, tracker)
    assert reason and cursor == len(traffic)
    reason, cursor = session.new_denials(traffic, "a", cursor, tracker)
    assert reason == "" and cursor == len(traffic)  # nothing new since the last call


# ---- OpenAPI ----------------------------------------------------------------------------------

OAS3 = {
    "openapi": "3.0.3", "servers": [{"url": "http://t.test/api/v1"}],
    "paths": {
        "/users/{userId}": {
            "parameters": [{"name": "userId", "in": "path", "required": True, "schema": {"type": "integer"}}],
            "get": {"summary": "Get user", "parameters": [{"name": "expand", "in": "query", "schema": {"type": "string"}}]},
            "delete": {},
        },
        "/users": {"post": {"requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/NewUser"}}}}}},
        "/health": {"get": {}},
    },
    "components": {"schemas": {
        "NewUser": {"type": "object", "required": ["email"], "properties": {"email": {"type": "string"}, "address": {"$ref": "#/components/schemas/Address"}}},
        "Address": {"type": "object", "properties": {"city": {"type": "string"}, "owner": {"$ref": "#/components/schemas/NewUser"}}},
    }},
}
SWAGGER2 = {
    "swagger": "2.0", "basePath": "/v2",
    "paths": {"/pets/{id}": {"get": {"parameters": [{"name": "id", "in": "path", "required": True, "type": "string"}]},
                             "put": {"parameters": [{"name": "body", "in": "body", "schema": {"type": "object", "properties": {"name": {"type": "string"}}}}]}}},
}


def test_openapi3_endpoints_parameters_and_body_schema():
    result = openapi.endpoints_from_openapi(OAS3, base_url="http://t.test")
    by_label = {e.label: e for e in result.endpoints}
    assert set(by_label) == {"GET /api/v1/users/{userId}", "DELETE /api/v1/users/{userId}", "POST /api/v1/users", "GET /api/v1/health"}
    get = by_label["GET /api/v1/users/{userId}"]
    assert {(p.name, p.location, p.schema_type) for p in get.parameters} == {("userId", Location.PATH, "integer"), ("expand", Location.QUERY, "string")}
    assert get.source is EndpointSource.SCHEMA and get.note == "Get user" and get.url == "http://t.test/api/v1/users/{userId}"
    body = by_label["POST /api/v1/users"].body_schema
    assert body["required"] == ["email"] and body["properties"]["address"]["properties"]["city"] == {"type": "string"}
    assert by_label["DELETE /api/v1/users/{userId}"].state_changing and not get.state_changing
    assert result.version == "3.0.3" and not result.truncated


def test_recursive_refs_are_bounded():
    body = {e.label: e for e in openapi.endpoints_from_openapi(OAS3).endpoints}["POST /api/v1/users"].body_schema
    owner = body["properties"]["address"]["properties"]["owner"]
    assert owner == {"type": "object", "x-recursive": "NewUser"}


def test_a_ref_bomb_is_bounded():
    schemas = {f"S{i}": {"type": "object", "properties": {"a": {"$ref": f"#/components/schemas/S{i + 1}"}, "b": {"$ref": f"#/components/schemas/S{i + 1}"}}} for i in range(40)}
    schemas["S40"] = {"type": "string"}
    doc = {"openapi": "3.0.0", "paths": {f"/p{i}": {"post": {"requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/S0"}}}}}} for i in range(120)}, "components": {"schemas": schemas}}
    result = openapi.endpoints_from_openapi(doc)
    assert len(result.endpoints) == 120 and result.endpoints[-1].body_schema == {"x-truncated": True, "type": "object"} and result.truncated and any("reference expansion limit" in w for w in result.warnings)


def test_swagger2_basepath_and_body_parameter():
    by_label = {e.label: e for e in openapi.endpoints_from_openapi(SWAGGER2).endpoints}
    assert set(by_label) == {"GET /v2/pets/{id}", "PUT /v2/pets/{id}"}
    assert by_label["PUT /v2/pets/{id}"].body_schema == {"type": "object", "properties": {"name": {"type": "string"}}}
    assert by_label["GET /v2/pets/{id}"].parameters[0].schema_type == "string"


@pytest.mark.parametrize("doc", [None, [], "text", {}, {"openapi": "3.0.0"}, {"paths": []}])
def test_unusable_documents_give_a_warning_not_an_exception(doc):
    result = openapi.endpoints_from_openapi(doc)
    assert result.endpoints == [] and result.warnings


def test_external_refs_are_never_followed_and_odd_operations_do_not_stop_the_rest():
    doc = {"openapi": "3.0.0", "paths": {"/a": {"get": {"parameters": [{"$ref": "http://evil.test/p.json"}, "garbage", {"name": "q", "in": "query"}]}},
                                          "bad": {"get": {}}, "/b": 5, "/c": {"post": {"requestBody": {"$ref": "#/components/requestBodies/Missing"}}}}}
    result = openapi.endpoints_from_openapi(doc)
    assert [e.label for e in result.endpoints] == ["GET /a", "POST /c"]
    assert [p.name for p in result.endpoints[0].parameters] == ["q"]


def test_endpoint_cap():
    doc = {"openapi": "3.0.0", "paths": {f"/p{i}": {"get": {}} for i in range(20)}}
    result = openapi.endpoints_from_openapi(doc, max_endpoints=5)
    assert len(result.endpoints) == 5 and result.truncated


def test_openapi_endpoints_merge_into_the_inventory_with_observed_ones():
    inventory = inv.Inventory([inv.observed("GET", "http://t.test/api/v1/users/9", kind="api")])
    for e in openapi.endpoints_from_openapi(OAS3, base_url="http://t.test").endpoints:
        inventory.add(e)
    merged = inventory.get("GET", "/api/v1/users/{userId}")
    assert merged.source is EndpointSource.BOTH and len(inventory) == 4


# ---- GraphQL ----------------------------------------------------------------------------------

SCHEMA_RESPONSE = {"data": {"__schema": {
    "queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"},
    "types": [
        {"kind": "OBJECT", "name": "Query", "fields": [
            {"name": "users", "args": [{"name": "limit", "type": {"kind": "SCALAR", "name": "Int", "ofType": None}}], "type": {"kind": "LIST", "name": None, "ofType": {"kind": "OBJECT", "name": "User"}}},
            {"name": "__typename", "args": [], "type": {"name": "String"}}]},
        {"kind": "OBJECT", "name": "Mutation", "fields": [
            {"name": "deleteUser", "args": [{"name": "id", "type": {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "ID"}}}], "type": {"kind": "OBJECT", "name": "Result", "ofType": None}}]},
    ]}}}


def test_introspection_result_becomes_inventory_entries_with_mutations_state_changing():
    result = endpoints_from_introspection(SCHEMA_RESPONSE, path="/graphql", base_url="http://t.test")
    by_label = {e.path_template: e for e in result.endpoints}
    assert set(by_label) == {"/graphql#Query.users", "/graphql#Mutation.deleteUser"}
    assert by_label["/graphql#Mutation.deleteUser"].state_changing and not by_label["/graphql#Query.users"].state_changing
    assert [(p.name, p.schema_type) for p in by_label["/graphql#Mutation.deleteUser"].parameters] == [("id", "ID")]
    assert by_label["/graphql#Query.users"].url == "http://t.test/graphql" and "returning User" in by_label["/graphql#Query.users"].note


@pytest.mark.parametrize("response", [{"errors": [{"message": "GraphQL introspection is not allowed"}]}, {"data": None}, {"data": {}}])
def test_disabled_introspection_is_a_note_not_an_error(response):
    result = endpoints_from_introspection(response)
    assert result.endpoints == [] and result.introspection_disabled and "disabled" in result.notes[0]
    assert endpoints_from_introspection("nope").notes


@pytest.mark.parametrize(
    "query, expected",
    [
        ("{ __schema { types { name } } }", True), ('query { __type(name:"User"){ name } }', True),
        ("query Q { __schema { queryType { name } } }", True),
        ("{ users { id } }", False), ("mutation { deleteUser(id: 1) { id } }", False),
        ("{ __schema { types { name } } users { id } }", False), ("{ a: __schema { types { name } } }", False),
        ("query A { __schema { types { name } } } mutation B { x }", False), ("subscription { __schema { types { name } } }", False),
        ("fragment F on Query { __schema { types { name } } } query { ...F }", False), ("", False), ("{", False),
    ],
)
def test_is_introspection_request(query, expected):
    assert is_introspection_request({"query": query}) is expected


def test_introspection_request_must_be_a_json_object_with_only_query_fields():
    assert is_introspection_request(INTROSPECTION_BODY) and is_introspection_request(json.dumps(INTROSPECTION_BODY))
    assert not is_introspection_request({"query": "{ __schema { types { name } } }", "extra": 1})
    assert not is_introspection_request("not json") and not is_introspection_request(None) and not is_introspection_request([1])
    assert not is_introspection_request({"query": "{ __schema { types { name } } }" + " " * 30000})


# ---- the method policy exception --------------------------------------------------------------

SCOPE = Scope.for_target("http://t.test")
SAFE = MethodPolicy(safe_mode=True, allow_state_changing=False)


def decide(method="POST", body=None, intent="", policy=SAFE, url="http://t.test/graphql"):
    return evaluate_request(RequestDescription(method, url, intent, body), SCOPE, policy)


def test_safe_mode_allows_only_a_verified_introspection_post():
    assert decide(intent=INTROSPECTION_INTENT, body=INTROSPECTION_BODY).allowed
    assert not decide(body=INTROSPECTION_BODY).allowed  # no declared intent: still a plain POST
    denied = decide(intent=INTROSPECTION_INTENT, body={"query": "mutation { drop }"})
    assert not denied.allowed and denied.reason == "method_not_permitted" and "introspection" in denied.detail
    assert not decide(intent=INTROSPECTION_INTENT, body=None).allowed
    assert not decide(method="PUT", intent=INTROSPECTION_INTENT, body=INTROSPECTION_BODY).allowed
    assert not decide(method="DELETE", intent=INTROSPECTION_INTENT, body=INTROSPECTION_BODY).allowed
    assert not decide(intent="something_else", body=INTROSPECTION_BODY).allowed


def test_the_exception_does_not_bypass_scope():
    assert decide(intent=INTROSPECTION_INTENT, body=INTROSPECTION_BODY, url="http://evil.test/graphql").reason == "off_scope"


# ---- observed vs documented -------------------------------------------------------------------


def build_inventory():
    base = "http://t.test"
    inventory = inv.Inventory()
    inventory.add(inv.observed("GET", f"{base}/api/users/5", kind="api"))  # documented below
    inventory.add(inv.observed("GET", f"{base}/api/debug/dump", content_type="application/json"))  # shadow endpoint
    inventory.add(inv.observed("GET", f"{base}/about"))  # a page: never "undocumented"
    inventory.add(inv.observed("GET", f"{base}/static/app.js"))  # an asset
    inventory.add(inv.from_schema("GET", "/api/users/{id}"))
    inventory.add(inv.from_schema("DELETE", "/api/users/{id}"))  # never exercised
    return inventory


def test_diff_lists_undocumented_and_unexercised():
    diff = inv.compare_observed_vs_documented(build_inventory(), schema_found=True)
    assert diff.compared
    assert [e.label for e in diff.undocumented] == ["GET /api/debug/dump"]
    assert [e.label for e in diff.unexercised] == ["DELETE /api/users/{id}"]


def test_diff_is_skipped_without_a_schema_and_says_so():
    diff = inv.compare_observed_vs_documented(build_inventory(), schema_found=False)
    assert not diff.compared and diff.undocumented == () and diff.unexercised == () and "no API schema" in diff.reason
    assert json.dumps(diff.to_dict())


def test_kind_guessing():
    assert inv.guess_kind("http://t/a.css") == "asset" and inv.guess_kind("http://t/x", "application/json") == "api"
    assert inv.guess_kind("http://t/api/x") == "api" and inv.guess_kind("http://t/page", "text/html") == "page"
    assert inv.guess_kind("http://t/graphql") == "api" and inv.guess_kind("http://t/submit", "", "POST") == "api"

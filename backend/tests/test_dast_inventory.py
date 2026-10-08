"""DAST-07-010: the endpoint inventory model (pure)."""

from __future__ import annotations

import json

import pytest

from app.dast.domain import inventory as inv
from app.dast.domain.entities import EndpointSource, Location, Parameter

pytestmark = pytest.mark.unit

BASE = "http://t.test"


def seen(method, path, **kw):
    return inv.observed(method, BASE + path, **kw)


def test_numeric_uuid_and_slug_segments_are_templated_and_merge():
    inventory = inv.Inventory()
    for path in ("/users/1", "/users/2", "/users/3?x=1"):
        inventory.add(seen("GET", path))
    (e,) = inventory.endpoints()
    assert e.path_template == "/users/{id}" and len(inventory) == 1
    assert inv.normalize_path_template("/o/550e8400-e29b-41d4-a716-446655440000") == "/o/{uuid}"
    assert inv.normalize_path_template("/post/my-post-2024-05") == "/post/{slug}"
    assert inv.normalize_path_template("/users/:id/orders") == "/users/{id}/orders"
    assert inv.normalize_path_template("/plain/path/") == "/plain/path"


def test_same_path_with_a_different_method_stays_separate():
    inventory = inv.Inventory([seen("GET", "/items/5"), seen("POST", "/items/5"), seen("delete", "/items/6")])
    assert [(e.method, e.path_template) for e in inventory.endpoints()] == [
        ("DELETE", "/items/{id}"), ("GET", "/items/{id}"), ("POST", "/items/{id}"),
    ]
    assert [e.state_changing for e in inventory.endpoints()] == [True, False, True]


def test_observed_and_schema_merge_to_both_and_prefer_the_schema_names():
    inventory = inv.Inventory([seen("GET", "/users/42?expand=orders", identity_id="u1", status=200, content_type="application/json")])
    inventory.add(inv.from_schema("get", "/users/{userId}", base_url=BASE, parameters=[Parameter("expand", Location.QUERY, schema_type="string")]))
    (e,) = inventory.endpoints()
    assert e.source is EndpointSource.BOTH and e.path_template == "/users/{userId}"
    assert e.seen_as == ("u1",) and e.last_status == 200 and e.content_type == "application/json"
    expand = next(p for p in e.parameters if p.name == "expand")
    assert expand.observed_values == ("orders",) and expand.schema_type == "string"
    assert any(p.location is Location.PATH for p in e.parameters)
    assert e.params == {p.name: p.location for p in e.parameters}


def test_parameter_union_accumulates_values_up_to_a_cap():
    inventory = inv.Inventory()
    for i in range(20):
        inventory.add(seen("GET", f"/search?q=term{i}&page=1"))
    (e,) = inventory.endpoints()
    q = next(p for p in e.parameters if p.name == "q")
    assert len(q.observed_values) == inv.MAX_OBSERVED_VALUES and q.observed_values[0] == "term0"
    assert {p.name for p in e.parameters} == {"q", "page"}
    inventory.add(seen("GET", "/search?other=x"))
    assert {p.name for p in inventory.endpoints()[0].parameters} == {"q", "page", "other"}


def test_identities_are_unioned_in_first_seen_order():
    inventory = inv.Inventory([seen("GET", "/a", identity_id="admin"), seen("GET", "/a", identity_id="user"), seen("GET", "/a", identity_id="admin")])
    assert inventory.endpoints()[0].seen_as == ("admin", "user")


def test_body_sample_is_capped_and_first_one_kept():
    e = inv.observed("POST", BASE + "/x", body_sample="b" * 5000)
    assert len(e.body_sample) == inv.MAX_BODY_SAMPLE_CHARS
    merged = inv.Inventory([seen("POST", "/x", body_sample="first"), seen("POST", "/x", body_sample="second")]).endpoints()[0]
    assert merged.body_sample == "first"


def test_source_views_distinguish_observed_only_schema_only_and_both():
    inventory = inv.Inventory([seen("GET", "/seen-only"), seen("GET", "/both/1")])
    inventory.add(inv.from_schema("GET", "/both/{id}"))
    inventory.add(inv.from_schema("GET", "/documented-only"))
    assert [e.path_template for e in inventory.only(EndpointSource.OBSERVED)] == ["/seen-only"]
    assert [e.path_template for e in inventory.only(EndpointSource.SCHEMA)] == ["/documented-only"]
    assert [e.path_template for e in inventory.endpoints(EndpointSource.SCHEMA)] == ["/both/{id}", "/documented-only"]


def test_lookup_by_url_or_template_and_deterministic_order():
    inventory = inv.Inventory([seen("GET", "/b"), seen("GET", "/a"), seen("POST", "/a")])
    assert [e.label for e in inventory.endpoints()] == ["GET /a", "POST /a", "GET /b"]
    assert inventory.get("get", BASE + "/b?x=1") is not None and inventory.get("GET", "/zzz") is None
    again = inv.Inventory(reversed(inventory.endpoints()))
    assert [e.label for e in again.endpoints()] == [e.label for e in inventory.endpoints()]


def test_merge_does_not_mutate_its_inputs():
    a, b = seen("GET", "/a?x=1"), seen("GET", "/a?y=2")
    before = (a.parameters, b.parameters)
    inv.merge_endpoints(a, b)
    assert (a.parameters, b.parameters) == before


def test_schema_endpoint_state_changing_override_for_graphql_mutations():
    mutation = inv.from_schema("POST", "/graphql", operation="Mutation.createUser", state_changing=True)
    query = inv.from_schema("POST", "/graphql", operation="Query.users", state_changing=False)
    assert mutation.state_changing and not query.state_changing
    inventory = inv.Inventory([mutation, query])
    assert [e.path_template for e in inventory.endpoints()] == ["/graphql#Mutation.createUser", "/graphql#Query.users"]
    assert inventory.get("POST", "/graphql#Query.users") is query and mutation.url == ""


def test_summary_is_json_safe_and_carries_the_legacy_api_call_keys():
    inventory = inv.Inventory([seen("GET", "/api/products?id=7", status=200, content_type="application/json", identity_id="u")])
    (entry,) = inventory.to_summary()
    json.dumps(entry)
    assert {"method", "url", "status_code", "content_type"} <= set(entry)
    assert entry["path_template"] == "/api/products" and entry["source"] == "observed" and entry["parameters"][0]["values"] == ["7"]


def test_empty_inventory():
    assert inv.Inventory().endpoints() == [] and inv.Inventory().to_summary() == []

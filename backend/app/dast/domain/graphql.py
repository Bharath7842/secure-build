"""GraphQL introspection results (DAST-07-050): parse a schema into inventory endpoints. Pure.

The introspection request itself, and the check that a request is nothing but one, live in
`introspection.py` (the method policy depends on it)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Mapping

from .entities import Endpoint, Location, Parameter
from .inventory import from_schema

from .introspection import INTROSPECTION_BODY, INTROSPECTION_QUERY, is_introspection_request  # noqa: F401

MAX_TYPES = 400
MAX_FIELDS_PER_ROOT = 200


@dataclass
class GraphQLResult:
    endpoints: list[Endpoint] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    introspection_disabled: bool = False


def _type_name(ref: Mapping[str, Any] | None) -> str:
    """`[String!]!`-style rendering collapsed to the named type."""
    while isinstance(ref, Mapping):
        if ref.get("name"):
            return str(ref["name"])
        ref = ref.get("ofType")
    return ""


def introspection_was_enabled(result: GraphQLResult) -> bool:
    """The endpoint returned a schema. Disabled introspection yields notes, not operations."""
    return bool(result.endpoints) and not result.introspection_disabled


def batch_accepted(body: str) -> bool:
    """A GraphQL server that answers a JSON array of operations with a JSON array of results."""
    try:
        parsed = json.loads(body or "")
    except ValueError:
        return False
    return isinstance(parsed, list) and len(parsed) >= 2 and all(isinstance(item, dict) for item in parsed[:2])


def batch_payload() -> list[dict[str, str]]:
    """Two cheap read-only operations. Not an introspection document and not a mutation."""
    one = {"query": "{__typename}"}
    return [one, dict(one)]


def endpoints_from_introspection(response: Any, *, path: str = "/graphql", base_url: str = "") -> GraphQLResult:
    """Inventory endpoints for every query and mutation field. A mutation is marked
    state-changing so the method gate applies to it; a target that has introspection turned
    off yields a note, not an error."""
    result = GraphQLResult()
    if not isinstance(response, Mapping):
        result.notes.append("the GraphQL endpoint did not return JSON; nothing was ingested")
        return result
    schema = (response.get("data") or {}).get("__schema") if isinstance(response.get("data"), Mapping) else None
    if not isinstance(schema, Mapping):
        errors = response.get("errors") or []
        text = " ".join(str(e.get("message", "")) if isinstance(e, Mapping) else str(e) for e in errors)[:300]
        result.introspection_disabled = True
        result.notes.append("GraphQL introspection is disabled on the target" + (f" ({text})" if text else ""))
        return result
    types = {t.get("name"): t for t in (schema.get("types") or [])[:MAX_TYPES] if isinstance(t, Mapping)}
    for root_key, kind, state_changing in (("queryType", "Query", False), ("mutationType", "Mutation", True)):
        root = schema.get(root_key)
        root_type = types.get((root or {}).get("name")) if isinstance(root, Mapping) else None
        for fld in ((root_type or {}).get("fields") or [])[:MAX_FIELDS_PER_ROOT]:
            if not isinstance(fld, Mapping) or not fld.get("name") or str(fld["name"]).startswith("__"):
                continue
            params = [
                Parameter(str(a.get("name")), Location.BODY, schema_type=_type_name(a.get("type")))
                for a in (fld.get("args") or [])
                if isinstance(a, Mapping) and a.get("name")
            ]
            result.endpoints.append(
                from_schema(
                    "POST", path, base_url=base_url, parameters=params, state_changing=state_changing,
                    note=f"GraphQL {kind.lower()} returning {_type_name(fld.get('type')) or 'unknown'}",
                    operation=f"{kind}.{fld['name']}",
                )
            )
    if not result.endpoints:
        result.notes.append("the GraphQL schema declares no queries or mutations")
    return result

"""The GraphQL introspection request (DAST-07-050): the query itself and the check that a request
really is nothing but a schema query. No other domain imports, so the method policy can use it
without a cycle. See `graphql.py` for turning the result into inventory endpoints.

Introspection is a POST, which safe mode forbids. The method policy therefore carries one
explicit, narrow exception (`policy.INTROSPECTION_INTENT`): a POST declared as an introspection
request is allowed in safe mode, but only if `is_introspection_request` confirms the body is
nothing but a schema query. It is not a general allowance for POST.
"""

from __future__ import annotations

import json
import re
from typing import Any, Mapping

_TYPE_REF = "kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } }"
INTROSPECTION_QUERY = (
    "query IntrospectionQuery { __schema { queryType { name } mutationType { name } "
    "types { kind name fields(includeDeprecated: true) { name args { name type { " + _TYPE_REF + " } } type { " + _TYPE_REF + " } } } } }"
)
INTROSPECTION_BODY = {"query": INTROSPECTION_QUERY, "operationName": "IntrospectionQuery"}
_STRINGS = re.compile(r'"""(?:.|\n)*?"""|"(?:\\.|[^"\\\n])*"')
_COMMENT = re.compile(r"#[^\n]*")
_TOKEN = re.compile(r"\.\.\.|[A-Za-z_]\w*|[{}()\[\]:@!=$]|\S")
_ROOT_FIELDS = frozenset({"__schema", "__type"})


def _is_pure_schema_query(query: str) -> bool:
    """Does this GraphQL document consist of exactly one `query` whose selection set holds only
    `__schema` / `__type` fields? Anything else (a mutation or subscription, a fragment, an alias
    or directive, a second operation, an ordinary field) is not an introspection request."""
    text = _COMMENT.sub("", _STRINGS.sub('""', query))
    brace = paren = 0
    seen_selection = False
    header: list[str] = []
    for token in _TOKEN.findall(text):
        if token == "{":
            brace += 1
            seen_selection = seen_selection or brace == 1
            continue
        if token == "}":
            brace -= 1
            if brace < 0:
                return False
            continue
        if token == "(":
            paren += 1
            continue
        if token == ")":
            paren -= 1
            if paren < 0:
                return False
            continue
        if brace == 0:
            if seen_selection:  # anything after the first operation closes: a second operation or fragment
                return False
            if paren == 0:
                header.append(token)
            continue
        if brace == 1 and paren == 0:
            if token not in _ROOT_FIELDS:  # an ordinary field, alias, directive, or fragment spread
                return False
    if brace != 0 or paren != 0 or not seen_selection:
        return False
    # The operation header: nothing, or `query` with an optional name. Never mutation/subscription.
    return not header or (header[0] == "query" and len(header) <= 2 and all(re.fullmatch(r"[A-Za-z_]\w*", h) for h in header))


def is_introspection_request(body: Any) -> bool:
    """True only for a JSON body whose single operation is a pure schema query."""
    if isinstance(body, (bytes, bytearray)):
        body = bytes(body).decode("utf-8", errors="replace")
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except ValueError:
            return False
    if not isinstance(body, Mapping):
        return False
    if set(body) - {"query", "operationName", "variables"}:
        return False
    query = body.get("query")
    if not isinstance(query, str) or not query.strip() or len(query) > 20000:
        return False
    return _is_pure_schema_query(query)



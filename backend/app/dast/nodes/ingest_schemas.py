"""Schema ingestion (DAST-07-040, -050): endpoints and body shapes the UI never exposes, read from
a published OpenAPI/Swagger description and from GraphQL introspection.

Every request goes through the guarded executor (so each probe is scope-checked and audited).
Documents are hostile input: size-capped, parsed defensively (YAML aliases are limited before the
parser sees them), and read by the bounded parsers in `domain.openapi` / `domain.graphql`. A
document that cannot be read is logged and skipped; it never fails the scan.
"""

from __future__ import annotations

import json
import re
from typing import Any

import yaml

from ..domain.fingerprint import GRAPHQL_PATHS, classify_schema_document
from ..domain.entities import Location
from ..domain.graphql import batch_accepted, batch_payload, endpoints_from_introspection, introspection_was_enabled
from ..stage_findings import enabled_checks, one_row, publish
from ..domain.introspection import INTROSPECTION_BODY
from ..domain.openapi import endpoints_from_openapi
from ..domain.policy import INTROSPECTION_INTENT
from ..sessions import SessionStore
from ..state import GraphState
from .fingerprint import SCHEMA_MAX_BYTES, origin_of

MAX_YAML_ALIASES = 20  # a YAML "billion laughs" document is mostly aliases
_YAML_ALIAS = re.compile(r"(?m)(?:^|[\s\[{,:-])[&*][A-Za-z0-9_-]+")
GRAPHQL_MAX_BYTES = 2 * 1024 * 1024


def parse_schema_text(text: str) -> tuple[Any, str]:
    """(document, problem). `problem` is "" when the text parsed into a mapping."""
    if not text or not text.strip():
        return None, "the document is empty"
    stripped = text.lstrip()
    try:
        if stripped.startswith(("{", "[")):
            return json.loads(text), ""
        if len(_YAML_ALIAS.findall(text)) > MAX_YAML_ALIASES:
            return None, "the YAML document uses too many anchors/aliases to be read safely"
        return yaml.safe_load(text), ""
    except (ValueError, yaml.YAMLError, RecursionError) as exc:
        return None, f"it could not be parsed ({type(exc).__name__})"


def _identity_for_probes(store: SessionStore) -> str:
    usable = store.usable()
    return usable[0].spec.identity_id if usable else store.all()[0].spec.identity_id


def ingest_openapi(state: GraphState) -> int:
    """Read the API description the fingerprint found (or the operator supplied). Returns the
    number of endpoints added to the inventory."""
    runtime, store = state["runtime"], state["sessions"]
    fingerprint = state.get("fingerprint") or {}
    text = state.get("schema_document")
    source = fingerprint.get("schema_url") or ""
    truncated = False
    if text is None and state.get("schema_too_large"):
        print(f"    The API description at {state['schema_too_large']} is larger than {SCHEMA_MAX_BYTES // 1024} KB and was cut off; skipping it.")
        return 0
    if text is None and fingerprint.get("schema") == "openapi" and source:
        decision = store.send(runtime.executor, _identity_for_probes(store), "GET", source, max_body_bytes=SCHEMA_MAX_BYTES)
        response = decision.response
        if response is None or response.status != 200:
            print(f"    The API description at {source} could not be fetched; skipping it.")
            return 0
        text, truncated = response.body_excerpt, response.length > len(response.body_excerpt.encode("utf-8", errors="ignore"))
    if text is None:
        return 0
    if truncated or len(text) >= SCHEMA_MAX_BYTES:
        print(f"    The API description at {source or 'the target'} is larger than {SCHEMA_MAX_BYTES // 1024} KB and was cut off; skipping it.")
        return 0
    document, problem = parse_schema_text(text)
    if problem or classify_schema_document(json.dumps(document) if isinstance(document, (dict, list)) else "") != "openapi":
        print(f"    The API description at {source or 'the target'} was skipped: {problem or 'it is not an OpenAPI or Swagger document'}.")
        return 0
    result = endpoints_from_openapi(document, base_url=origin_of(state["url"]))
    for warning in result.warnings:
        print(f"    OpenAPI: {warning}")
    inventory = state["inventory"]
    for endpoint in result.endpoints:
        inventory.add(endpoint)
    print(f"    Ingested {len(result.endpoints)} operation(s) from the OpenAPI/Swagger description (version {result.version or 'unknown'}).")
    return len(result.endpoints)


def graphql_candidates(state: GraphState) -> list[str]:
    base = origin_of(state["url"])
    urls = [base + path for path in GRAPHQL_PATHS]
    for call in state.get("api_calls") or []:  # a GraphQL endpoint the crawl actually saw
        url = str(call.get("url") or "")
        if "graphql" in url.lower() and url.split("?")[0] not in urls:
            urls.insert(0, url.split("?")[0])
    return urls


def should_probe_graphql(state: GraphState) -> bool:
    fingerprint = state.get("fingerprint") or {}
    return fingerprint.get("schema") == "graphql" or fingerprint.get("shape") == "api" or any(
        "graphql" in str(c.get("url") or "").lower() for c in state.get("api_calls") or []
    )


def ingest_graphql(state: GraphState) -> int:
    """Probe GraphQL endpoints with the read-only introspection query. Returns endpoints added."""
    runtime, store = state["runtime"], state["sessions"]
    identity = _identity_for_probes(store)
    inventory = state["inventory"]
    for url in graphql_candidates(state):
        if runtime.cancelled():
            break
        decision = store.send(
            runtime.executor, identity, "POST", url, body=INTROSPECTION_BODY,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            intent=INTROSPECTION_INTENT, max_body_bytes=GRAPHQL_MAX_BYTES,
        )
        response = decision.response
        if response is None or response.status in (404, 405) or response.status is None:
            continue
        try:
            payload = json.loads(response.body_excerpt)
        except ValueError:
            continue
        if not isinstance(payload, dict) or not ({"data", "errors"} & set(payload)):
            continue
        path = "/" + url.split("://", 1)[-1].split("/", 1)[-1].split("?")[0] if "/" in url.split("://", 1)[-1] else "/graphql"
        result = endpoints_from_introspection(payload, path=path, base_url=origin_of(url))
        for note in result.notes:
            print(f"    GraphQL {url}: {note}")
        for endpoint in result.endpoints:
            inventory.add(endpoint)
        if result.endpoints or result.introspection_disabled:
            print(f"    GraphQL {url}: {len(result.endpoints)} operation(s) ingested.")
            _graphql_findings(state, runtime, url, result)
            return len(result.endpoints)
    return 0


def _graphql_findings(state, runtime, url: str, result) -> None:
    checks = enabled_checks(getattr(runtime, "rule_set", None), ("dast-graphql-introspection", "dast-graphql-batch"), getattr(runtime, "skipped_degraded", ()) or ())
    rows = []
    if "dast-graphql-introspection" in checks and introspection_was_enabled(result):
        rows.append(
            one_row(
                checks["dast-graphql-introspection"],
                signal="graphql_introspection_enabled",
                detail=f"introspection returned {len(result.endpoints)} operation(s)",
                target=url,
                title=f"GraphQL introspection enabled: {url}",
                source="graphql",
                sink=url,
                location=Location.BODY,
            )
        )
    if "dast-graphql-batch" in checks and getattr(runtime, "executor", None) is not None:
        store = state.get("sessions")
        if store is not None:
            from ..sessions import anonymous_id

            identity = _identity_for_probes(store) or anonymous_id(store)
            try:
                decision = store.send(
                    runtime.executor, identity, "POST", url, body=batch_payload(),
                    headers={"Content-Type": "application/json", "Accept": "application/json"},
                    check_id="dast-graphql-batch", max_body_bytes=GRAPHQL_MAX_BYTES,
                )
                batched = decision.response
                text = batched.body_excerpt if batched is not None else ""
                if batch_accepted(text or ""):
                    rows.append(
                        one_row(
                            checks["dast-graphql-batch"],
                            signal="graphql_batch_accepted",
                            detail="a JSON array of two queries was answered with a JSON array of results",
                            target=url,
                            title=f"GraphQL batching accepted: {url}",
                            source="graphql",
                            sink=url,
                            location=Location.BODY,
                        )
                    )
            except Exception as exc:  # noqa: BLE001
                print(f"    GraphQL batch probe skipped: {exc}")
    publish(state, runtime, "graphql", rows)

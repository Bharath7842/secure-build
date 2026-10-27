"""The endpoint inventory (DAST-07-010): one model merging what the crawl observed with what a
schema documents, so later stages test each endpoint once.

Pure: no I/O. Stages feed it `Endpoint`s (`observed(...)`, `from_schema(...)`) and read back a
deterministic, deduplicated list.

Merge key: `(METHOD, canonical path template)`. A template is the URL path with identifier-like
segments replaced by placeholders (`/users/1` -> `/users/{id}`; see `dedupe.path_template`). For
the *key*, every placeholder is collapsed to `{}`, because an OpenAPI path names its parameter
(`/users/{userId}`) where an observed path has a generic one: both must land on the same entry.
The *displayed* template prefers the schema's, whose names are more informative.

Merging combines parameters (union by name and location, observed values accumulated up to a
cap), identities that reached the endpoint, and records both sources as `both`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import parse_qsl, urlsplit

from .dedupe import path_template
from .entities import Endpoint, EndpointSource, Location, Parameter
from .policy import STATE_CHANGING_METHODS
from .redaction import REDACTED, is_sensitive_name

MAX_OBSERVED_VALUES = 8  # distinct example values kept per parameter
MAX_VALUE_CHARS = 120
MAX_BODY_SAMPLE_CHARS = 2000

_PLACEHOLDER = re.compile(r"\{[^{}/]*\}")
_BRACED_COLON = re.compile(r":([A-Za-z_][A-Za-z0-9_]*)(?=/|$)")  # /users/:id (Express style)


def normalize_path_template(path: str) -> str:
    """Display template for a path from any source: query dropped, express-style `:id` and
    identifier-looking segments turned into `{...}` placeholders, trailing slash dropped.

    A `#operation` suffix is kept verbatim: it marks one GraphQL operation on a shared URL
    (`/graphql#Mutation.createUser`), which must stay a separate inventory entry."""
    base, hash_, operation = (path or "").partition("#")
    path = urlsplit(base).path or "/"
    path = _BRACED_COLON.sub(lambda m: "{" + m.group(1) + "}", path)
    return path_template(path) + (hash_ + operation if operation else "")


def canonical_key_path(template: str) -> str:
    """The comparison form of a template: every placeholder collapsed to `{}`."""
    return _PLACEHOLDER.sub("{}", template)


def endpoint_key(method: str, template: str) -> tuple[str, str]:
    return (method.strip().upper(), canonical_key_path(template))


def is_state_changing(method: str) -> bool:
    return method.strip().upper() in STATE_CHANGING_METHODS


def _merge_values(a: Sequence[str], b: Sequence[str]) -> tuple[str, ...]:
    out: list[str] = []
    for value in [*a, *b]:
        value = str(value)[:MAX_VALUE_CHARS]
        if value not in out:
            out.append(value)
        if len(out) >= MAX_OBSERVED_VALUES:
            break
    return tuple(out)


def merge_parameters(a: Sequence[Parameter], b: Sequence[Parameter]) -> tuple[Parameter, ...]:
    """Union by (name, location). Values accumulate; `required` and a known schema type win."""
    merged: dict[tuple[str, Location], Parameter] = {}
    for param in [*a, *b]:
        key = (param.name, param.location)
        existing = merged.get(key)
        if existing is None:
            merged[key] = replace(param, observed_values=_merge_values(param.observed_values, ()))
        else:
            merged[key] = replace(
                existing,
                observed_values=_merge_values(existing.observed_values, param.observed_values),
                required=existing.required or param.required,
                schema_type=existing.schema_type or param.schema_type,
            )
    return tuple(sorted(merged.values(), key=lambda p: (p.location.value, p.name)))


def _combine_sources(a: EndpointSource, b: EndpointSource) -> EndpointSource:
    return a if a is b else EndpointSource.BOTH


def merge_endpoints(a: Endpoint, b: Endpoint) -> Endpoint:
    """One endpoint from two sightings of the same key. Neither input is changed."""
    schema_first = a if a.source is EndpointSource.SCHEMA else b if b.source is EndpointSource.SCHEMA else a
    other = b if schema_first is a else a
    parameters = merge_parameters(a.parameters, b.parameters)
    return Endpoint(
        method=a.method.upper(),
        path_template=schema_first.path_template if schema_first.source is not EndpointSource.OBSERVED else a.path_template,
        params={p.name: p.location for p in parameters},
        seen_as=tuple(dict.fromkeys([*a.seen_as, *b.seen_as])),
        url=a.url or b.url,
        parameters=parameters,
        body_schema=a.body_schema or b.body_schema,
        body_sample=a.body_sample or b.body_sample,
        source=_combine_sources(a.source, b.source),
        state_changing=a.state_changing or b.state_changing,
        note=a.note or b.note,
        last_status=other.last_status if other.last_status is not None else schema_first.last_status,
        content_type=a.content_type or b.content_type,
        kind="api" if "api" in (a.kind, b.kind) else (a.kind if a.kind != "page" else b.kind),
        # The schema side is the only one that can ever know this; prefer it over an
        # observed-only sighting's unavoidable None.
        security_declared=schema_first.security_declared if schema_first.security_declared is not None else other.security_declared,
        user_supplied=a.user_supplied or b.user_supplied,
    )


def _query_parameters(url: str) -> list[Parameter]:
    return [
        Parameter(name, Location.QUERY, (value,) if value else ())
        for name, value in parse_qsl(urlsplit(url).query, keep_blank_values=True)
    ]


def _path_parameters(template: str, url: str) -> list[Parameter]:
    """Path placeholders as parameters, with the concrete value from `url` when it has one."""
    out: list[Parameter] = []
    concrete = urlsplit(url or "").path.split("/")
    for index, segment in enumerate(template.split("/")):
        if _PLACEHOLDER.fullmatch(segment):
            value = concrete[index] if index < len(concrete) and not _PLACEHOLDER.fullmatch(concrete[index]) else ""
            out.append(Parameter(segment.strip("{}") or "id", Location.PATH, (value,) if value else ()))
    return out


def observed(
    method: str,
    url: str,
    *,
    identity_id: str | None = None,
    parameters: Iterable[Parameter] = (),
    body_sample: str | None = None,
    status: int | None = None,
    content_type: str = "",
    kind: str | None = None,
) -> Endpoint:
    """An endpoint as the crawl or recorder saw it. `kind` defaults to a guess from the content
    type and path: JSON/XML or `/api/` is an API call, a static-file extension is an asset."""
    template = normalize_path_template(url)
    params = merge_parameters([*_query_parameters(url), *_path_parameters(template, url)], list(parameters))
    return Endpoint(
        method=method.strip().upper(),
        path_template=template,
        params={p.name: p.location for p in params},
        seen_as=(identity_id,) if identity_id else (),
        url=url,
        parameters=params,
        body_sample=(body_sample[:MAX_BODY_SAMPLE_CHARS] if body_sample else None),
        source=EndpointSource.OBSERVED,
        state_changing=is_state_changing(method),
        last_status=status,
        content_type=content_type,
        kind=kind or guess_kind(url, content_type, method),
    )


_ASSET_EXTENSIONS = (".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".webm", ".mp3", ".pdf", ".zip")

# Conventional static-asset mount points, regardless of file extension (e.g. `/assets/report.json`).
# The sole source of truth for "is this a static file" - `authz.py`'s replay skip reads `kind`
# instead of keeping its own copy of this, so the two can no longer disagree.
_ASSET_PATH_PREFIX = re.compile(r"^/(?:assets|static|public)/", re.IGNORECASE)


def guess_kind(url: str, content_type: str = "", method: str = "GET") -> str:
    path = urlsplit(url).path.lower()
    if path.endswith(_ASSET_EXTENSIONS) or _ASSET_PATH_PREFIX.match(path):
        return "asset"
    content_type = (content_type or "").lower()
    if "json" in content_type or "xml" in content_type and "html" not in content_type or "/api/" in path + "/" or path.startswith("/graphql") or "/graphql" in path:
        return "api"
    if method.upper() not in ("GET", "HEAD") and "html" not in content_type:
        return "api"
    return "page"


def from_schema(
    method: str,
    path: str,
    *,
    base_url: str = "",
    parameters: Iterable[Parameter] = (),
    body_schema: Mapping[str, Any] | None = None,
    state_changing: bool | None = None,
    note: str = "",
    operation: str = "",
    security_declared: bool | None = None,
) -> Endpoint:
    """An endpoint a schema documents (OpenAPI, GraphQL). `path` keeps the schema's own
    placeholder names; `operation` names one GraphQL operation sharing the URL."""
    template = normalize_path_template(path)
    explicit = (urlsplit(path).path or "/").rstrip("/") or "/"
    if _PLACEHOLDER.search(explicit):
        template = explicit
    if operation:
        template = f"{template.partition('#')[0]}#{operation}"
    params = merge_parameters(_path_parameters(template, ""), list(parameters))
    return Endpoint(
        method=method.strip().upper(),
        path_template=template,
        params={p.name: p.location for p in params},
        url=(base_url.rstrip("/") + template.partition("#")[0]) if base_url else "",
        parameters=params,
        body_schema=dict(body_schema) if body_schema else None,
        source=EndpointSource.SCHEMA,
        state_changing=is_state_changing(method) if state_changing is None else state_changing,
        note=note,
        kind="api",
        security_declared=security_declared,
    )


class Inventory:
    """Mutable collection keyed by `endpoint_key`. Not thread-safe: one stage writes at a time."""

    def __init__(self, endpoints: Iterable[Endpoint] = ()) -> None:
        self._by_key: dict[tuple[str, str], Endpoint] = {}
        for endpoint in endpoints:
            self.add(endpoint)

    def add(self, endpoint: Endpoint) -> Endpoint:
        key = endpoint_key(endpoint.method, endpoint.path_template)
        existing = self._by_key.get(key)
        merged = merge_endpoints(existing, endpoint) if existing is not None else endpoint
        self._by_key[key] = merged
        return merged

    def get(self, method: str, template_or_url: str) -> Endpoint | None:
        return self._by_key.get(endpoint_key(method, normalize_path_template(template_or_url)))

    def __len__(self) -> int:
        return len(self._by_key)

    def endpoints(self, source: EndpointSource | None = None) -> list[Endpoint]:
        """Deterministic order: path, then method. `source` keeps only entries seen by that source
        (`BOTH` entries count for each of `OBSERVED` and `SCHEMA`)."""
        items = sorted(self._by_key.values(), key=lambda e: (e.path_template, e.method))
        if source is None:
            return items
        return [e for e in items if e.source is source or e.source is EndpointSource.BOTH]

    def only(self, source: EndpointSource) -> list[Endpoint]:
        """Entries seen by exactly one source (not `BOTH`)."""
        return [e for e in self.endpoints() if e.source is source]

    def to_summary(self) -> list[dict[str, Any]]:
        """JSON-safe list for the discovery summary; each entry also carries the legacy
        `api_calls` keys (`method`, `url`, `status_code`, `content_type`)."""
        return [endpoint_to_dict(e) for e in self.endpoints()]


def endpoint_to_dict(e: Endpoint) -> dict[str, Any]:
    return {
        "method": e.method,
        "url": e.url,
        "status_code": e.last_status,
        "content_type": e.content_type,
        "path_template": e.path_template,
        "source": e.source.value,
        "state_changing": e.state_changing,
        "kind": e.kind,
        "identities": list(e.seen_as),
        "parameters": [
            {
                "name": p.name,
                "location": p.location.value,
                # Values of credential-looking fields (CSRF tokens, session ids) stay in memory for the
                # test loop (a baseline must carry them) but are never put in the stored summary.
                "values": [REDACTED] * len(p.observed_values) if is_sensitive_name(p.name) else list(p.observed_values),
                "required": p.required,
                "type": p.schema_type,
            }
            for p in e.parameters
        ],
        "body_schema": dict(e.body_schema) if e.body_schema else None,
        "body_sample": e.body_sample,
        "note": e.note,
        "user_supplied": e.user_supplied,
    }


@dataclass(frozen=True)
class InventoryDiff:
    """Observed against documented (DAST-07-060)."""

    compared: bool  # False when there was no schema to compare with
    undocumented: tuple[Endpoint, ...] = ()  # API calls seen live that the schema does not list
    unexercised: tuple[Endpoint, ...] = ()  # operations the schema lists that were never seen
    reason: str = ""  # why the diff was skipped

    def to_dict(self) -> dict[str, Any]:
        return {
            "compared": self.compared,
            "reason": self.reason,
            "undocumented": [endpoint_to_dict(e) for e in self.undocumented],
            "unexercised": [endpoint_to_dict(e) for e in self.unexercised],
        }


def compare_observed_vs_documented(inventory: "Inventory", *, schema_found: bool) -> InventoryDiff:
    """Endpoints seen only live (and API-like, not pages or static assets) are undocumented; schema
    operations never seen are unexercised. With no schema nothing can be called undocumented, so
    the diff is skipped and says so."""
    if not schema_found:
        return InventoryDiff(False, reason="no API schema was found, so observed endpoints cannot be compared with documentation")
    observed_only = [e for e in inventory.only(EndpointSource.OBSERVED) if e.kind == "api"]
    # An endpoint the operator pasted is not a statement by the schema, so it is not "documented but never seen".
    schema_only = [e for e in inventory.only(EndpointSource.SCHEMA) if not e.user_supplied]
    return InventoryDiff(True, tuple(observed_only), tuple(schema_only))

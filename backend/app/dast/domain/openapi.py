"""OpenAPI 3.x / Swagger 2.0 to inventory endpoints (DAST-07-040): pure parsing.

The caller fetches the document through the guarded executor, caps its size, and parses
JSON/YAML into a mapping; this module turns that mapping into `Endpoint`s. The document is
hostile input, so everything is bounded: `$ref` resolution has a depth limit and a total
expansion budget with cycle detection, endpoint count is capped, and a problem in one operation
never aborts the rest.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping
from urllib.parse import urlsplit

from .entities import Endpoint, Location, Parameter
from .inventory import from_schema

HTTP_METHODS = ("get", "put", "post", "delete", "patch", "head", "options")
MAX_ENDPOINTS = 500
MAX_REF_DEPTH = 6  # nested $ref hops resolved while expanding one schema
MAX_REF_EXPANSIONS = 2000  # total $ref resolutions per document
MAX_SCHEMA_DEPTH = 4  # how deep a body schema is kept
MAX_SCHEMA_PROPERTIES = 40
_LOCATIONS = {"query": Location.QUERY, "path": Location.PATH, "header": Location.HEADER, "cookie": Location.HEADER, "body": Location.BODY, "formData": Location.BODY}


@dataclass
class OpenApiResult:
    endpoints: list[Endpoint] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    version: str = ""
    truncated: bool = False


class _Resolver:
    def __init__(self, document: Mapping[str, Any]) -> None:
        self.doc = document
        self.expansions = 0
        self.exhausted = False

    def lookup(self, ref: str) -> Any:
        if not isinstance(ref, str) or not ref.startswith("#/"):
            return None  # external references are never followed
        node: Any = self.doc
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if isinstance(node, Mapping) and part in node:
                node = node[part]
            else:
                return None
        return node

    def resolve(self, node: Any, seen: tuple[str, ...] = ()) -> tuple[Any, tuple[str, ...]]:
        """`node` with top-level `$ref`s followed, plus the chain of refs followed to get there.
        A ref already on the chain, a chain longer than `MAX_REF_DEPTH`, or an exhausted
        expansion budget yields a marker node instead of expanding further."""
        while isinstance(node, Mapping) and "$ref" in node:
            ref = node["$ref"]
            if ref in seen or len(seen) >= MAX_REF_DEPTH:
                return {"type": "object", "x-recursive": str(ref).rsplit("/", 1)[-1]}, seen
            if self.expansions >= MAX_REF_EXPANSIONS:
                self.exhausted = True
                return {"type": "object", "x-truncated": True}, seen
            self.expansions += 1
            target = self.lookup(ref)
            if target is None:
                return {"type": "object", "x-unresolved": str(ref)}, seen
            seen, node = seen + (ref,), target
        return node, seen

    def schema(self, node: Any, seen: tuple[str, ...] = (), level: int = 0) -> dict[str, Any]:
        """A trimmed, ref-free copy of a schema: type, required, properties, items, enum."""
        node, seen = self.resolve(node, seen)
        if not isinstance(node, Mapping):
            return {}
        if "x-recursive" in node or "x-truncated" in node or "x-unresolved" in node:
            return {k: v for k, v in node.items() if k.startswith("x-") or k == "type"}
        out: dict[str, Any] = {}
        for key in ("type", "format", "enum", "required"):
            if key in node:
                out[key] = node[key]
        if level >= MAX_SCHEMA_DEPTH:
            return out
        if isinstance(node.get("properties"), Mapping):
            out["properties"] = {
                str(name): self.schema(sub, seen, level + 1)
                for name, sub in list(node["properties"].items())[:MAX_SCHEMA_PROPERTIES]
            }
        if isinstance(node.get("allOf"), list):
            merged = out.setdefault("properties", {})
            for part in node["allOf"][:10]:
                sub = self.schema(part, seen, level + 1)
                merged.update(sub.get("properties") or {})
                if sub.get("required"):
                    out["required"] = sorted(set(out.get("required") or []) | set(sub["required"]))
        if "items" in node:
            out["items"] = self.schema(node["items"], seen, level + 1)
        return out


def _server_prefix(document: Mapping[str, Any], base_url: str) -> str:
    """Path prefix every operation lives under (`basePath`, or the first server's path)."""
    if "swagger" in document:
        base = str(document.get("basePath") or "")
    else:
        servers = document.get("servers") or []
        url = str((servers[0] or {}).get("url") or "") if servers and isinstance(servers[0], Mapping) else ""
        parts = urlsplit(url)
        same_host = not parts.netloc or parts.hostname == (urlsplit(base_url).hostname or parts.hostname)
        base = parts.path if same_host else ""
    base = "/" + base.strip("/") if base.strip("/") else ""
    return "" if "{" in base else base


def _parameters(resolver: _Resolver, raw: Any) -> tuple[list[Parameter], dict[str, Any] | None]:
    params: list[Parameter] = []
    body: dict[str, Any] | None = None
    for item in raw or []:
        item, _ = resolver.resolve(item)
        if not isinstance(item, Mapping):
            continue
        where = str(item.get("in") or "")
        name = str(item.get("name") or "")
        if where == "body":
            body = resolver.schema(item.get("schema") or {})
            continue
        if not name or where not in _LOCATIONS:
            continue
        schema = item.get("schema") if isinstance(item.get("schema"), Mapping) else item
        resolved, _ = resolver.resolve(schema)
        schema_type = str(resolved.get("type") or "") if isinstance(resolved, Mapping) else ""
        params.append(Parameter(name, _LOCATIONS[where], required=bool(item.get("required")), schema_type=schema_type))
    return params, body


def endpoints_from_openapi(document: Any, *, base_url: str = "", max_endpoints: int = MAX_ENDPOINTS) -> OpenApiResult:
    result = OpenApiResult()
    if not isinstance(document, Mapping) or not isinstance(document.get("paths"), Mapping):
        result.warnings.append("the document has no 'paths' object, so no endpoints were read")
        return result
    version = str(document.get("openapi") or document.get("swagger") or "")
    result.version = version
    if not version[:1] in ("2", "3"):
        result.warnings.append(f"unrecognized specification version {version!r}; reading it as OpenAPI anyway")
    resolver = _Resolver(document)
    prefix = _server_prefix(document, base_url)
    is_swagger2 = "swagger" in document
    document_security = document.get("security")

    for path, item in document["paths"].items():
        item, _ = resolver.resolve(item)
        if not isinstance(item, Mapping) or not isinstance(path, str) or not path.startswith("/"):
            continue
        shared, shared_body = _parameters(resolver, item.get("parameters"))
        for method in HTTP_METHODS:
            operation = item.get(method)
            if not isinstance(operation, Mapping):
                continue
            if len(result.endpoints) >= max_endpoints:
                result.truncated = True
                result.warnings.append(f"stopped after {max_endpoints} operations")
                return result
            try:
                own, body = _parameters(resolver, operation.get("parameters"))
                body = body if body is not None else shared_body
                if not is_swagger2 and body is None and isinstance(operation.get("requestBody"), (Mapping,)):
                    request_body, _ = resolver.resolve(operation["requestBody"])
                    content = request_body.get("content") if isinstance(request_body, Mapping) else None
                    if isinstance(content, Mapping) and content:
                        media = content.get("application/json") or next(iter(content.values()))
                        if isinstance(media, Mapping):
                            body = resolver.schema(media.get("schema") or {})
                note = str(operation.get("summary") or operation.get("operationId") or "")[:160]
                # An operation's own `security` key (including an explicit `[]`, meaning "this
                # operation opts out") overrides the document's top-level one; only when the
                # operation names no `security` key at all does the document-level value apply.
                # Critically, "no `security` key anywhere for this operation" (by far the most
                # common case - most real OpenAPI documents never annotate auth at all, even when
                # it is genuinely enforced) is left as security_declared=None ("unknown"), not
                # False: only an *explicit* empty list is treated as a deliberate "this is public"
                # statement. Conflating silence with an explicit opt-out would suppress real
                # findings on every under-documented API, which is the common case, not the
                # exception.
                if "security" in operation:
                    op_security, has_declaration = operation["security"], True
                elif "security" in document:
                    op_security, has_declaration = document_security, True
                else:
                    op_security, has_declaration = None, False
                security_declared = bool(op_security) if has_declaration else None
                result.endpoints.append(
                    from_schema(
                        method, prefix + path, base_url=base_url, parameters=[*shared, *own], body_schema=body or None, note=note,
                        security_declared=security_declared,
                    )
                )
            except Exception as exc:  # noqa: BLE001 - one odd operation must not hide the others
                result.warnings.append(f"skipped {method.upper()} {path}: {type(exc).__name__}")
    if resolver.exhausted:
        result.truncated = True
        result.warnings.append("reference expansion limit reached; some body schemas are truncated")
    return result

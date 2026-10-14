"""Target fingerprinting (DAST-05-040): pure heuristics and the reconciliation of a model's guess.

The fingerprint answers three questions that decide which stages run:

    shape   mpa | spa | api        classic server-rendered site, single-page app, or API only
    auth    none | form | token | preauth   how the operator supplied authentication
    schema  none | openapi | graphql        whether a machine-readable API description exists

`heuristic_fingerprint` is the deterministic fallback; it reads only what was observed (root
response headers and body, the well-known schema paths that answered, the identities the operator
supplied). `reconcile` lets the model refine `shape` but never invent facts: `auth` always comes
from the supplied identities and `schema` only from what a probe actually found, so a
hallucinated "openapi" cannot send the pipeline looking for a schema that is not there.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .entities import ResponseSnapshot
from .identities import AuthMethod, IdentitySpec

SHAPES = ("mpa", "spa", "api")
AUTHS = ("none", "form", "token", "preauth")
SCHEMAS = ("none", "openapi", "graphql")

# Where published API descriptions usually live. Probed with GET through the guarded executor.
WELL_KNOWN_SCHEMA_PATHS: tuple[str, ...] = (
    "/openapi.json",
    "/swagger.json",
    "/v3/api-docs",
    "/v2/api-docs",
    "/api-docs",
    "/api/openapi.json",
    "/api/swagger.json",
    "/swagger/v1/swagger.json",
    "/openapi.yaml",
    "/openapi.yml",
)
GRAPHQL_PATHS: tuple[str, ...] = ("/graphql", "/api/graphql", "/graphql/v1", "/query")

_SPA_MARKERS = re.compile(
    r"(<div[^>]+id=[\"'](?:root|app|__next|__nuxt)[\"']|<app-root|ng-app|__NEXT_DATA__|window\.__NUXT__|data-reactroot|"
    r"<noscript>[^<]{0,200}(?:enable|requires?)[^<]{0,80}javascript)",
    re.IGNORECASE,
)
_TAG = re.compile(r"<(script|style|noscript)\b.*?</\1>", re.IGNORECASE | re.DOTALL)
_ANY_TAG = re.compile(r"<[^>]+>")


@dataclass(frozen=True)
class Fingerprint:
    shape: str
    auth: str
    schema: str
    source: str = "heuristic"  # "heuristic" | "model"
    schema_url: str = ""  # where the description was found, when schema != none
    evidence: tuple[str, ...] = ()  # short facts the decision rested on, for the log

    def to_dict(self) -> dict[str, Any]:
        return {
            "shape": self.shape, "auth": self.auth, "schema": self.schema, "source": self.source,
            "schema_url": self.schema_url, "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class SchemaProbe:
    """What a probe of one well-known location returned."""

    url: str
    response: ResponseSnapshot | None
    kind: str = ""  # "openapi" once recognized; "" otherwise


def _header(response: ResponseSnapshot, name: str) -> str:
    for key, value in (response.headers or {}).items():
        if str(key).lower() == name:
            return str(value).lower()
    return ""


def classify_schema_document(body: str) -> str:
    """"openapi" for an OpenAPI 3.x or Swagger 2.0 document (JSON or YAML text), else ""."""
    text = (body or "").lstrip()[:4000]
    if not text:
        return ""
    if text.startswith("{"):
        try:
            data = json.loads(body)
        except ValueError:
            data = None
        if isinstance(data, Mapping):
            version = str(data.get("openapi") or data.get("swagger") or "")
            return "openapi" if version[:1].isdigit() and ("paths" in data or "components" in data or "info" in data) else ""
        # Truncated JSON: fall back to a prefix look.
        return "openapi" if re.search(r'"(?:openapi|swagger)"\s*:\s*"[23]', text) else ""
    return "openapi" if re.search(r"^(?:openapi|swagger)\s*:\s*['\"]?[23]", text, re.MULTILINE) else ""


def find_schema(probes: Sequence[SchemaProbe]) -> SchemaProbe | None:
    """First probe whose response is a recognized API description."""
    for probe in probes:
        if probe.response is None or probe.response.status != 200:
            continue
        if (probe.kind or classify_schema_document(probe.response.body_excerpt)) == "openapi":
            return probe
    return None


def _visible_text_length(html: str) -> int:
    return len(" ".join(_ANY_TAG.sub(" ", _TAG.sub(" ", html)).split()))


def detect_shape(root: ResponseSnapshot | None) -> tuple[str, str]:
    """(shape, evidence) from the root document alone."""
    if root is None or root.status is None:
        return "mpa", "no root response; assuming a classic site"
    content_type = _header(root, "content-type")
    body = root.body_excerpt or ""
    if "json" in content_type or "xml" in content_type and "html" not in content_type or content_type.startswith("text/plain"):
        return "api", f"root returned {content_type or 'a non-HTML body'}"
    if "html" in content_type or body.lstrip().lower().startswith(("<!doctype html", "<html")):
        if _SPA_MARKERS.search(body):
            return "spa", "root document has a client-side app mount point"
        if len(re.findall(r"<script\b[^>]*\bsrc=", body, re.IGNORECASE)) >= 3 and _visible_text_length(body) < 400:
            return "spa", "root document is mostly script bundles with little visible content"
        return "mpa", "root document is server-rendered HTML"
    if body.lstrip().startswith(("{", "[")):
        return "api", "root body is JSON"
    return "mpa", "root content type is not recognizable; assuming a classic site"


def auth_from_identities(identities: Sequence[IdentitySpec]) -> str:
    """The authentication the operator supplied: form wins over token over preauth when mixed
    (form is the only one that needs a login stage)."""
    methods = {s.auth_method for s in identities if s.authenticated}
    for method, name in ((AuthMethod.FORM, "form"), (AuthMethod.TOKEN, "token"), (AuthMethod.PREAUTH, "preauth")):
        if method in methods:
            return name
    return "none"


def heuristic_fingerprint(
    root: ResponseSnapshot | None,
    probes: Sequence[SchemaProbe],
    identities: Sequence[IdentitySpec],
    *,
    graphql_url: str = "",
    schema_url_supplied: str = "",
) -> Fingerprint:
    shape, why = detect_shape(root)
    evidence = [why]
    found = find_schema(probes)
    schema, schema_url = "none", ""
    if found is not None:
        schema, schema_url = "openapi", found.url
        evidence.append(f"API description at {found.url}")
    elif graphql_url:
        schema, schema_url = "graphql", graphql_url
        evidence.append(f"GraphQL endpoint at {graphql_url}")
    elif schema_url_supplied:
        schema, schema_url = "openapi", schema_url_supplied
        evidence.append("schema URL supplied by the operator")
    if shape == "mpa" and schema == "none" and root is not None and _header(root, "content-type").startswith("application/"):
        shape = "api"
    return Fingerprint(shape, auth_from_identities(identities), schema, "heuristic", schema_url, tuple(evidence))


FINGERPRINT_REPLY_SCHEMA = {
    "type": "object",
    "required": ["shape"],
    "properties": {
        "shape": {"type": "string", "enum": list(SHAPES)},
        "auth": {"type": "string", "enum": list(AUTHS)},
        "schema": {"type": "string", "enum": list(SCHEMAS)},
        "reason": {"type": "string"},
    },
}


def reconcile(model: Mapping[str, Any] | None, heuristic: Fingerprint) -> Fingerprint:
    """Accept the model's `shape` when it is valid; everything else stays what was observed."""
    if not model:
        return heuristic
    shape = str(model.get("shape") or "").lower()
    if shape not in SHAPES or shape == heuristic.shape:
        return heuristic
    # A model must not turn a target that deterministically returned HTML into an API-only
    # target. That would skip the browser crawl and hide form/page coverage. It may refine an
    # HTML site between mpa and spa, but only the heuristic may declare an API-only target.
    if shape == "api" and heuristic.shape != "api":
        return heuristic
    note = f"model classified the shape as {shape} (heuristics said {heuristic.shape})"
    return Fingerprint(shape, heuristic.auth, heuristic.schema, "model", heuristic.schema_url, heuristic.evidence + (note,))


def routing_plan(fingerprint: Fingerprint, identities: Sequence[IdentitySpec]) -> dict[str, Any]:
    """Which stages the pipeline runs for this fingerprint (pure; the graph reads it)."""
    form_identities = [s.identity_id for s in identities if s.auth_method is AuthMethod.FORM]
    return {
        "browser_crawl": fingerprint.shape != "api",
        "schema_ingestion": fingerprint.schema != "none" or fingerprint.shape == "api",
        "form_login": bool(form_identities),
        "form_identity_ids": form_identities,
        "token_identity_ids": [s.identity_id for s in identities if s.auth_method is AuthMethod.TOKEN],
        "preauth_identity_ids": [s.identity_id for s in identities if s.auth_method is AuthMethod.PREAUTH],
    }

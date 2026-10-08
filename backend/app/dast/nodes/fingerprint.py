"""NODE 2: fingerprint (DAST-05-040): decide what kind of target this is so the pipeline runs only
the stages that fit.

Output (`state["fingerprint"]`, also shown in the log and kept in the discovery summary):

    {"shape": "mpa|spa|api", "auth": "none|form|token|preauth", "schema": "none|openapi|graphql", ...}

The facts come from requests made through the guarded executor: the root document the preflight
already fetched, plus up to one GET per well-known API-description location (stopping at the first
that answers with a real document). The `fingerprint` model task may refine the *shape*; it can
never invent authentication or a schema (`domain.fingerprint.reconcile`). With the model down the
heuristics decide alone, so this stage never fails a scan.
"""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from ..domain.fingerprint import (
    FINGERPRINT_REPLY_SCHEMA,
    WELL_KNOWN_SCHEMA_PATHS,
    SchemaProbe,
    classify_schema_document,
    heuristic_fingerprint,
    reconcile,
)
from ..llm_utils import ask_json
from ..sessions import SessionStore, anonymous_id
from ..state import GraphState

SCHEMA_MAX_BYTES = 2 * 1024 * 1024  # an API description larger than this is cut off (and said so)


def origin_of(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def probe_schema_locations(state: GraphState, extra_urls: list[str] | None = None) -> list[SchemaProbe]:
    """GET each well-known location (and any operator-supplied URL), stopping at the first
    recognized document. Every request goes through the guarded executor."""
    runtime, store = state["runtime"], state["sessions"]
    anon = anonymous_id(store)
    base = origin_of(state["url"])
    urls = list(extra_urls or []) + [base + path for path in WELL_KNOWN_SCHEMA_PATHS]
    probes: list[SchemaProbe] = []
    for url in urls:
        if runtime.cancelled():
            break
        decision = store.send(runtime.executor, anon, "GET", url, headers={"Accept": "application/json, application/yaml, */*"}, max_body_bytes=SCHEMA_MAX_BYTES)
        probe = SchemaProbe(url, decision.response)
        probes.append(probe)
        if decision.response is not None and decision.response.status == 200 and classify_schema_document(decision.response.body_excerpt) == "openapi":
            body = decision.response.body_excerpt
            if decision.response.length > len(body.encode("utf-8", errors="ignore")):
                state["schema_too_large"] = url  # cut off at the size cap: not safe to parse
            else:
                state["schema_document"] = body
            probes[-1] = SchemaProbe(url, decision.response, "openapi")
            break
    return probes


def fingerprint(state: GraphState) -> GraphState:
    runtime = state["runtime"]
    root = state.get("root_response")
    print("[2/4] Fingerprinting the target (shape, authentication, API description)...")

    supplied = (runtime.effective.get("schema_url") or "").strip()
    probes = probe_schema_locations(state, [supplied] if supplied else None)
    heuristic = heuristic_fingerprint(root, probes, runtime.identities, schema_url_supplied="" if state.get("schema_document") else supplied)

    summary = {
        "root_status": getattr(root, "status", None),
        "root_content_type": next((v for k, v in (getattr(root, "headers", None) or {}).items() if str(k).lower() == "content-type"), ""),
        "root_body_excerpt": (getattr(root, "body_excerpt", "") or "")[:600],
        "schema_found_at": heuristic.schema_url,
        "heuristic": {"shape": heuristic.shape, "auth": heuristic.auth, "schema": heuristic.schema},
    }
    prompt = (
        "Classify this target from the evidence below.\n"
        "shape: mpa (server-rendered pages), spa (single-page app) or api (JSON/API service with no pages).\n"
        "Authentication and the API description are facts already established; repeat them as given.\n\n"
        f"Evidence:\n{json.dumps(summary, indent=2)}\n\n"
        'Respond with JSON only: {"shape": "mpa|spa|api", "auth": "<as given>", "schema": "<as given>", "reason": "<short>"}'
    )
    model = ask_json(runtime.gateway, "fingerprint", prompt, FINGERPRINT_REPLY_SCHEMA)
    final = reconcile(model, heuristic)

    state["fingerprint"] = final.to_dict()
    state["schema_found"] = final.schema != "none"
    print(
        f"[2/4] Fingerprint: shape={final.shape} auth={final.auth} schema={final.schema}"
        f"{' at ' + final.schema_url if final.schema_url else ''} (source: {final.source})"
    )
    for fact in final.evidence:
        print(f"    - {fact}")
    return state

"""Pull API paths and postMessage listeners out of recorded script bodies."""

from __future__ import annotations

from urllib.parse import urlsplit

from .domain.entities import Location
from .domain.inventory import observed
from .domain.js_endpoints import extract_paths, postmessage_without_origin
from .stage_findings import enabled_checks, one_row, publish

POSTMESSAGE = "dast-postmessage"


def harvest_scripts(state, runtime) -> None:
    inventory = state.get("inventory")
    traffic = getattr(runtime, "traffic", None) or []
    origin = urlsplit(state.get("url") or "")
    base = f"{origin.scheme}://{origin.netloc}" if origin.scheme and origin.netloc else ""
    added = 0
    rows = []
    checks = enabled_checks(getattr(runtime, "rule_set", None), (POSTMESSAGE,), getattr(runtime, "skipped_degraded", ()) or ())
    for exchange in traffic:
        path = urlsplit(exchange.url).path.lower()
        if exchange.resource_type != "script" and not path.endswith((".js", ".mjs")):
            continue
        source = exchange.response_body or ""
        if inventory is not None and base and source:
            for rel in extract_paths(source):
                inventory.add(observed("GET", base + rel, identity_id=exchange.identity_id or None, kind="api"))
                added += 1
        if POSTMESSAGE in checks and source:
            for excerpt in postmessage_without_origin(source):
                rows.append(
                    one_row(
                        checks[POSTMESSAGE],
                        signal="postmessage_origin_missing",
                        detail=excerpt,
                        target=exchange.url,
                        title=f"postMessage listener without an origin check: {urlsplit(exchange.url).path}",
                        source="script harvest",
                        sink=exchange.url,
                        location=Location.RESPONSE,
                    )
                )
    if added:
        print(f"    Scripts: {added} endpoint path(s) extracted.")
    publish(state, runtime, "script harvest", rows)

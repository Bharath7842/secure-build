"""Recorded-login HAR import. HAR is JSON; this module only parses it.

Replay (sending the entries through the guarded executor) lives next to the
authenticate stage. Entries whose host is not the scan target are dropped here
so a HAR captured with third-party calls cannot widen the scan.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urlsplit


@dataclass(frozen=True)
class HarEntry:
    method: str
    url: str
    headers: tuple[tuple[str, str], ...] = ()
    body: str | None = None


def _pairs(raw: Any) -> tuple[tuple[str, str], ...]:
    out = []
    for item in raw or []:
        if isinstance(item, Mapping) and item.get("name"):
            out.append((str(item["name"]), str(item.get("value") or "")))
    return tuple(out)


def parse_har(raw: str | Mapping[str, Any] | None, *, target_url: str = "") -> tuple[HarEntry, ...]:
    """Entries from a HAR 1.2 document, in file order. Malformed input yields an empty tuple.

    When `target_url` is set, only entries on that exact host are kept."""
    if raw is None:
        return ()
    try:
        data = json.loads(raw) if isinstance(raw, str) else raw
    except (ValueError, TypeError):
        return ()
    if not isinstance(data, Mapping):
        return ()
    log = data.get("log") if isinstance(data.get("log"), Mapping) else data
    entries = log.get("entries") if isinstance(log, Mapping) else None
    if not isinstance(entries, list):
        return ()
    host = (urlsplit(target_url).hostname or "").lower()
    parsed: list[HarEntry] = []
    for item in entries:
        if not isinstance(item, Mapping):
            continue
        request = item.get("request") if isinstance(item.get("request"), Mapping) else None
        if request is None:
            continue
        url = str(request.get("url") or "")
        method = str(request.get("method") or "GET").upper()
        if not url or urlsplit(url).scheme not in ("http", "https"):
            continue
        if host and (urlsplit(url).hostname or "").lower() != host:
            continue
        post = request.get("postData") if isinstance(request.get("postData"), Mapping) else {}
        body = post.get("text")
        parsed.append(HarEntry(method, url, _pairs(request.get("headers")), str(body) if isinstance(body, str) and body else None))
        if len(parsed) >= 40:  # a login sequence, not a whole browsing session
            break
    return tuple(parsed)


def cookie_from_set_cookie(header: str) -> dict | None:
    """The name/value pair of one `Set-Cookie` header, or None when it has no name."""
    if not header or "=" not in header.split(";", 1)[0]:
        return None
    pair = header.split(";", 1)[0].strip()
    name, _, value = pair.partition("=")
    name = name.strip()
    if not name:
        return None
    return {"name": name, "value": value.strip(), "path": "/"}

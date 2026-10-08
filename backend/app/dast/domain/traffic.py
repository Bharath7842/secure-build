"""Recorded network traffic (DAST-07-030): the plain-data shape of what the browser saw, and the
rules for what may be kept.

The browser adapter (`app/services/dast_browser.py`) turns each Playwright request/response pair
into a `RecordedExchange` through `record_exchange`, which is where the rules live so they are
testable without a browser:

* only XHR/fetch (and document navigations that submit data) keep headers and bodies; **static
  assets are recorded by URL and status only**;
* header values and body fields that carry credentials are redacted before anything is stored;
* request and response bodies are size-capped.

Recorded traffic feeds the inventory (real request shapes instead of guesses) and the passive
analysis stage. It lives in the run state for the scan's lifetime and, as short excerpts, in
evidence; it is never persisted wholesale.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping
from urllib.parse import parse_qsl, urlencode, urlsplit

from .redaction import REDACTED, is_sensitive_name, redact_headers, redact_text, redact_url

BODY_CAP = 4096  # characters of a request or response body kept
ASSET_RESOURCE_TYPES = frozenset({"stylesheet", "image", "font", "media", "script", "manifest", "texttrack", "other", "websocket", "eventsource"})
DATA_RESOURCE_TYPES = frozenset({"xhr", "fetch"})
_ASSET_SUFFIXES = (".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".webm", ".mp3")


@dataclass(frozen=True)
class RecordedExchange:
    method: str
    url: str  # query values of sensitive parameters redacted
    status: int | None
    resource_type: str
    identity_id: str = ""
    content_type: str = ""
    request_headers: Mapping[str, str] | None = None
    request_body: str | None = None
    response_headers: Mapping[str, str] | None = None
    response_body: str | None = None
    asset: bool = False
    truncated: bool = False  # a body was cut at BODY_CAP

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method, "url": self.url, "status": self.status, "resource_type": self.resource_type,
            "identity_id": self.identity_id, "content_type": self.content_type, "asset": self.asset,
            "request_headers": dict(self.request_headers) if self.request_headers is not None else None,
            "request_body": self.request_body,
            "response_headers": dict(self.response_headers) if self.response_headers is not None else None,
            "response_body": self.response_body, "truncated": self.truncated,
        }


MAX_JSON_DEPTH = 40  # deeper than any real payload; a hostile body must not be able to blow the stack


def _redact_json(value: Any, depth: int = 0) -> Any:
    if depth > MAX_JSON_DEPTH:
        return "[nested too deeply]"
    if isinstance(value, Mapping):
        return {k: (REDACTED if is_sensitive_name(str(k)) and not isinstance(v, (Mapping, list)) else _redact_json(v, depth + 1)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_json(v, depth + 1) for v in value]
    return value


def redact_body(body: str | None, content_type: str = "", secrets: Iterable[str] = ()) -> str | None:
    """`body` with credential-bearing fields masked: JSON keys and form fields whose names look
    like secrets, plus any known secret value anywhere in the text."""
    if body is None:
        return None
    secrets = tuple(s for s in secrets if s)
    kind = (content_type or "").lower()
    text = body
    stripped = body.lstrip()
    if "json" in kind or stripped.startswith(("{", "[")):
        try:
            text = json.dumps(_redact_json(json.loads(body)), ensure_ascii=False)
        except (ValueError, RecursionError):  # not JSON, or nested past the parser's limit: redact it as plain text
            pass
    elif "x-www-form-urlencoded" in kind or ("=" in body and "&" in body and "<" not in body):
        pairs = parse_qsl(body, keep_blank_values=True)
        if pairs:
            text = urlencode([(k, REDACTED if is_sensitive_name(k) else v) for k, v in pairs])
    return redact_text(text, secrets)


def _cap(text: str | None, cap: int) -> tuple[str | None, bool]:
    if text is None:
        return None, False
    return (text, False) if len(text) <= cap else (text[:cap], True)


def is_asset(url: str, resource_type: str, content_type: str = "") -> bool:
    if resource_type in DATA_RESOURCE_TYPES:
        return False
    if resource_type == "document":
        return False
    return resource_type in ASSET_RESOURCE_TYPES or urlsplit(url).path.lower().endswith(_ASSET_SUFFIXES)


def record_exchange(
    *,
    method: str,
    url: str,
    resource_type: str,
    status: int | None,
    request_headers: Mapping[str, str] | None = None,
    request_body: str | None = None,
    response_headers: Mapping[str, str] | None = None,
    response_body: str | None = None,
    identity_id: str = "",
    secrets: Iterable[str] = (),
    body_cap: int = BODY_CAP,
) -> RecordedExchange:
    secrets = tuple(s for s in secrets if s)
    safe_url = redact_url(url, secrets)
    content_type = next((str(v) for k, v in (response_headers or {}).items() if str(k).lower() == "content-type"), "")
    script = resource_type == "script" or urlsplit(url).path.lower().endswith((".js", ".mjs"))
    if is_asset(url, resource_type, content_type) and not script:
        return RecordedExchange(method.upper(), safe_url, status, resource_type, identity_id, content_type, asset=True)
    if script and is_asset(url, resource_type, content_type):
        # Keep a capped body so endpoint extraction can read string literals. Still an asset:
        # it is not an API operation and passive header checks keep skipping it.
        resp_body, cut_resp = _cap(redact_body(response_body, content_type, secrets), body_cap)
        return RecordedExchange(
            method=method.upper(), url=safe_url, status=status, resource_type=resource_type, identity_id=identity_id,
            content_type=content_type, response_body=resp_body, asset=True, truncated=cut_resp,
        )
    req_ct = next((str(v) for k, v in (request_headers or {}).items() if str(k).lower() == "content-type"), "")
    req_body, cut_req = _cap(redact_body(request_body, req_ct, secrets), body_cap)
    resp_body, cut_resp = _cap(redact_body(response_body, content_type, secrets), body_cap)
    return RecordedExchange(
        method=method.upper(), url=safe_url, status=status, resource_type=resource_type, identity_id=identity_id,
        content_type=content_type, request_headers=redact_headers(request_headers, secrets),
        request_body=req_body, response_headers=redact_headers(response_headers, secrets, keep_cookie_attributes=True), response_body=resp_body,
        truncated=cut_req or cut_resp,
    )


def parameters_from_body(body: str | None, content_type: str = "") -> list[tuple[str, str]]:
    """Top-level (name, example value) pairs of a recorded JSON or form body, for the inventory.
    Values are already redacted when `body` came from `record_exchange`; nested values and long
    strings are summarized, never copied."""
    if not body:
        return []
    kind = (content_type or "").lower()
    pairs: list[tuple[str, str]] = []
    if "json" in kind or body.lstrip().startswith("{"):
        try:
            data = json.loads(body)
        except ValueError:
            return []
        if isinstance(data, Mapping):
            for key, value in list(data.items())[:40]:
                if isinstance(value, (Mapping, list)):
                    pairs.append((str(key), ""))
                else:
                    pairs.append((str(key), str(value)[:120]))
        return pairs
    if "x-www-form-urlencoded" in kind or "=" in body:
        return [(k, v[:120]) for k, v in parse_qsl(body, keep_blank_values=True)][:40]
    return pairs

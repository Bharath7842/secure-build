"""Authentication material helpers (DAST-06-040): pure functions over credentials.

* `validate_storage_state` checks an uploaded browser session before it is kept: JSON shape,
  size and entry caps. The content stays secret; only the verdict and generic problems leave.
* `token_header` builds the one header a token identity sends on every request.
* `cookie_header` turns a storage state's cookies into the `Cookie` header for a URL, with the
  domain/path/secure matching a browser applies, so a pre-authenticated identity can also make
  plain HTTP requests (the guarded executor keeps no cookie jar of its own).
"""

from __future__ import annotations

import json
import re
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

MAX_STORAGE_STATE_BYTES = 256 * 1024
MAX_COOKIES = 300
MAX_ORIGINS = 50
HEADER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-]{0,63}$")
DEFAULT_TOKEN_HEADER = "Authorization"
DEFAULT_TOKEN_SCHEME = "Bearer"


def validate_storage_state(data: Any) -> list[str]:
    """Problems with a Playwright storage state, as generic messages (never echoing content)."""
    problems: list[str] = []
    if not isinstance(data, Mapping):
        return ["the session file must be a JSON object with 'cookies' and 'origins'"]
    try:
        size = len(json.dumps(data).encode("utf-8"))
    except (TypeError, ValueError):
        return ["the session file is not valid JSON"]
    if size > MAX_STORAGE_STATE_BYTES:
        return [f"the session file is larger than {MAX_STORAGE_STATE_BYTES // 1024} KB"]
    unknown = set(data) - {"cookies", "origins"}
    if unknown:
        problems.append("the session file has unexpected top-level keys")
    cookies = data.get("cookies", [])
    origins = data.get("origins", [])
    if not isinstance(cookies, list) or not isinstance(origins, list):
        return problems + ["'cookies' and 'origins' must be lists"]
    if not cookies and not origins:
        problems.append("the session file holds no cookies or storage; it cannot authenticate anything")
    if len(cookies) > MAX_COOKIES:
        problems.append(f"the session file has more than {MAX_COOKIES} cookies")
    if len(origins) > MAX_ORIGINS:
        problems.append(f"the session file has more than {MAX_ORIGINS} origins")
    for cookie in cookies[:MAX_COOKIES]:
        if not isinstance(cookie, Mapping) or not isinstance(cookie.get("name"), str) or not isinstance(cookie.get("value"), str):
            problems.append("every cookie needs a string 'name' and 'value'")
            break
        if not (isinstance(cookie.get("domain"), str) or isinstance(cookie.get("url"), str)):
            problems.append("every cookie needs a 'domain' (or 'url')")
            break
    for origin in origins[:MAX_ORIGINS]:
        if not isinstance(origin, Mapping) or not isinstance(origin.get("origin"), str):
            problems.append("every origin entry needs a string 'origin'")
            break
    return problems


def token_header(header_name: str, scheme: str, token: str) -> tuple[str, str]:
    """`("Authorization", "Bearer <token>")`; an empty scheme sends the raw token (API keys)."""
    name = (header_name or DEFAULT_TOKEN_HEADER).strip()
    if not HEADER_NAME.match(name):
        raise ValueError("the token header name is not a valid HTTP header name")
    token = (token or "").strip()
    if not token or any(c in token for c in "\r\n"):
        raise ValueError("the token is empty or contains a line break")
    scheme = (scheme if scheme is not None else DEFAULT_TOKEN_SCHEME).strip()
    return name, f"{scheme} {token}" if scheme else token


def _domain_matches(cookie_domain: str, host: str) -> bool:
    domain = cookie_domain.lstrip(".").lower()
    host = host.lower()
    if cookie_domain.startswith("."):
        return host == domain or host.endswith("." + domain)
    return host == domain


def cookie_header(cookies: Sequence[Mapping[str, Any]], url: str) -> str:
    """The `Cookie` header value a browser would send to `url` for these cookies ("" if none)."""
    parts = urlsplit(url)
    host, path, secure = parts.hostname or "", parts.path or "/", parts.scheme == "https"
    pairs: list[str] = []
    for cookie in cookies:
        domain = cookie.get("domain")
        if not isinstance(domain, str):
            cookie_url = urlsplit(str(cookie.get("url") or ""))
            domain = cookie_url.hostname or ""
        if not domain or not _domain_matches(domain, host):
            continue
        cookie_path = str(cookie.get("path") or "/")
        if not path.startswith(cookie_path.rstrip("/") or "/"):
            continue
        if cookie.get("secure") and not secure:
            continue
        pairs.append(f"{cookie['name']}={cookie['value']}")
    return "; ".join(pairs)


def storage_state_secrets(raw: str) -> list[str]:
    """Every value inside a storage state that is itself a credential: cookie values and
    localStorage values (tokens often live there). The blob as a whole is registered by the
    caller; these are the pieces that appear alone in a header, URL or log line."""
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return []
    values: list[str] = []
    for cookie in (data.get("cookies") or []) if isinstance(data, Mapping) else []:
        if isinstance(cookie, Mapping) and isinstance(cookie.get("value"), str):
            values.append(cookie["value"])
    for origin in (data.get("origins") or []) if isinstance(data, Mapping) else []:
        for item in (origin.get("localStorage") or []) if isinstance(origin, Mapping) else []:
            if isinstance(item, Mapping) and isinstance(item.get("value"), str):
                values.append(item["value"])
    return [v for v in dict.fromkeys(values) if len(v) >= 4]

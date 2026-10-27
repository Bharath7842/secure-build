"""Operator-pasted REST endpoints: free text in, validated endpoint records out. Stdlib only.

The crawler cannot find every API, so an operator may paste the ones it missed: `METHOD /path`
lines, bare paths, full URLs, curl commands, markdown lists or an OpenAPI description. Everything
here is deterministic. Lines it cannot read are returned as `unparsed` so a model may *reformat*
them, and whatever the model returns is built through `build_endpoint`, the same checks as pasted
text, so a model can never add an off-host URL, an unknown method or a credential.

Pasted text is never stored. Only the validated records are: values of credential-looking
parameter or body fields are blanked, and any line that looks like a credential (an
Authorization/Cookie/API-key header, a bearer token, a JWT) rejects the whole paste, because
credentials belong in the scan's identities, which are held in memory only. Request headers are
read only to find those credentials: none are stored or replayed.
"""

from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass, field, replace
from typing import Any, Mapping, Sequence
from urllib.parse import parse_qsl, urlencode, urlsplit

from .entities import Endpoint, EndpointSource, Location, Parameter
from .inventory import MAX_BODY_SAMPLE_CHARS, from_schema, observed
from .policy import Scope, parse_url
from .redaction import is_sensitive_name
from .traffic import parameters_from_body

MAX_TEXT_CHARS = 65536
MAX_ENDPOINTS = 200
MAX_UNPARSED = 50
MAX_LINE_CHARS = 2000
MAX_PATH_CHARS = 500
MAX_QUERY_PARAMS = 20
METHODS = ("GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE")

_METHOD_LINE = re.compile(r"^(?P<method>" + "|".join(METHODS) + r")(?=[\s:]|$)[\s:]*(?P<rest>.*)$", re.IGNORECASE)
_BULLET = re.compile(r"^\s*(?:[-*•>]+|\d+[.)])\s+")
_HEADER_LINE = re.compile(r"^(?P<name>[A-Za-z][A-Za-z0-9-]{1,60}):\s*(?P<value>\S.*)$")
_PATH_OK = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/{}\[\]-]*$")
_HOST_FIRST = re.compile(r"^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?::\d+)?(?:/|$)")
_RELATIVE = re.compile(r"^[A-Za-z0-9._~%:@{}\[\]-]+(?:/[A-Za-z0-9._~!$&'()*+,;=:@%{}\[\]-]*)+$")
_ANGLE_PLACEHOLDER = re.compile(r"<([A-Za-z_][\w-]*)>")
_OPENAPI_YAML = re.compile(r"(?m)^(?:openapi|swagger)\s*:")
# Anything that is plainly a credential, wherever it sits in the pasted text.
_CREDENTIAL = re.compile(
    r"\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"
    r"|\bbasic\s+[A-Za-z0-9+/=]{12,}"
    r"|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\."
    r"|\bAKIA[0-9A-Z]{16}\b"
    r"|\bgh[pousr]_[A-Za-z0-9]{20,}"
    r"|\bsk-[A-Za-z0-9]{20,}",
    re.IGNORECASE,
)
_CREDENTIAL_ADVICE = "looks like a credential. Remove it and add the login under Identities, which is held in memory only."

# curl options that take a value we do not use (so the value is not mistaken for the URL).
_CURL_VALUE_FLAGS = frozenset({
    "-o", "--output", "-A", "--user-agent", "-e", "--referer", "-m", "--max-time", "--connect-timeout",
    "-w", "--write-out", "--proxy", "-x", "--retry", "--resolve", "--cacert", "--cert", "--key", "-T", "--upload-file",
    "-F", "--form", "--limit-rate", "--interface",
})
_CURL_DATA_FLAGS = frozenset({"-d", "--data", "--data-raw", "--data-binary", "--data-ascii", "--data-urlencode", "--json"})
_CURL_SECRET_FLAGS = frozenset({"-u", "--user", "-b", "--cookie", "--oauth2-bearer", "--netrc", "-n"})


@dataclass(frozen=True)
class UserEndpoint:
    """One validated endpoint the operator supplied. `path` may hold `{placeholder}`s."""

    method: str
    path: str
    query: tuple[tuple[str, str], ...] = ()
    body: str | None = None
    parameters: tuple[Parameter, ...] = ()  # extra parameters (an OpenAPI description declares them)
    body_schema: Mapping[str, Any] | None = None
    origin: str = "text"  # "text" | "openapi" | "model"

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"method": self.method, "path": self.path, "origin": self.origin}
        if self.query:
            out["query"] = [[n, v] for n, v in self.query]
        if self.body:
            out["body"] = self.body
        if self.parameters:
            out["parameters"] = [
                {"name": p.name, "location": p.location.value, "values": list(p.observed_values), "required": p.required, "type": p.schema_type}
                for p in self.parameters
            ]
        if self.body_schema:
            out["body_schema"] = dict(self.body_schema)
        return out

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "UserEndpoint | None":
        """Rebuild a stored record, re-checking it. None for anything malformed."""
        try:
            method, path = str(data["method"]).upper(), str(data["path"])
            if method not in METHODS or not _PATH_OK.match(path) or len(path) > MAX_PATH_CHARS:
                return None
            params = tuple(
                Parameter(str(p["name"])[:80], Location(p["location"]), tuple(str(v)[:120] for v in (p.get("values") or ()))[:8], bool(p.get("required")), str(p.get("type") or ""))
                for p in (data.get("parameters") or ())[:60]
            )
            query = tuple((str(n)[:80], str(v)[:120]) for n, v in (data.get("query") or ())[:MAX_QUERY_PARAMS])
            body = data.get("body")
            schema = data.get("body_schema")
            return cls(method, path, query, str(body)[:MAX_BODY_SAMPLE_CHARS] if body else None, params,
                       dict(schema) if isinstance(schema, Mapping) else None, str(data.get("origin") or "text")[:12])
        except (KeyError, TypeError, ValueError):
            return None


@dataclass
class ParseResult:
    endpoints: list[UserEndpoint] = field(default_factory=list)
    unparsed: list[str] = field(default_factory=list)  # lines nothing here could read; a model may reformat them
    warnings: list[str] = field(default_factory=list)
    rejected: list[tuple[int, str]] = field(default_factory=list)  # (line number, why): the paste must be fixed
    dropped_off_scope: int = 0
    truncated: bool = False
    openapi_text: str | None = None  # the whole paste is an OpenAPI/Swagger description (caller parses it)


# ---- one candidate -> a validated endpoint ----------------------------------------------------


def _clean_target(raw: str) -> str:
    raw = _ANGLE_PLACEHOLDER.sub(r"{\1}", raw.strip().strip("`'\"").rstrip(",;"))
    return raw.split("#", 1)[0]


def _split_target(raw: str, scope: Scope) -> tuple[str, str] | str:
    """`(path, query string)`, or the failure: "off_scope" / "invalid"."""
    raw = _clean_target(raw)
    if not raw or raw.startswith("//"):
        return "invalid"
    if re.match(r"(?i)^https?://", raw) or _HOST_FIRST.match(raw):
        url = raw if re.match(r"(?i)^https?://", raw) else "https://" + raw
        parsed = parse_url(url)
        if parsed is None:
            return "invalid"
        if not scope.contains_host(parsed.host):
            return "off_scope"
        parts = urlsplit(url)
        return parts.path or "/", parts.query
    if "://" in raw:
        return "invalid"
    if not raw.startswith("/"):
        if not _RELATIVE.match(raw):
            return "invalid"
        raw = "/" + raw
    path, _, query = raw.partition("?")
    return path, query


def _sanitize_body(body: str | None) -> tuple[str | None, str]:
    """`(body, warning)`. Credential-looking fields are blanked; a body that cannot be kept in
    a safe, bounded form is dropped (never stored raw)."""
    if not body or not body.strip():
        return None, ""
    body = body.strip()
    if body[:1] in "{[":
        try:
            data = json.loads(body)
        except ValueError:
            return None, "a request body was not valid JSON and was ignored"

        def scrub(value: Any, depth: int = 0) -> Any:
            if depth > 6:
                return ""
            if isinstance(value, Mapping):
                return {str(k): ("" if is_sensitive_name(str(k)) and isinstance(v, (str, int, float)) else scrub(v, depth + 1)) for k, v in value.items()}
            if isinstance(value, list):
                return [scrub(v, depth + 1) for v in value[:20]]
            return value

        text = json.dumps(scrub(data), separators=(",", ":"))
    elif "=" in body and "\n" not in body:
        text = urlencode([(k, "" if is_sensitive_name(k) else v) for k, v in parse_qsl(body, keep_blank_values=True)])
    else:
        return None, "a request body that is neither JSON nor form fields was ignored"
    if len(text) > MAX_BODY_SAMPLE_CHARS:
        return None, f"a request body longer than {MAX_BODY_SAMPLE_CHARS} characters was ignored"
    return text, ""


def build_endpoint(method: str, target: str, *, body: str | None = None, query: Sequence[tuple[str, str]] = (),
                   scope: Scope, origin: str = "text") -> tuple[UserEndpoint | None, str]:
    """The one gate every candidate passes, whether read from text or returned by a model.
    `(endpoint, "")` or `(None, reason)`; reason `off_scope` is counted, not reported."""
    method = (method or "").strip().upper()
    if method not in METHODS:
        return None, f"unsupported method {method or '(none)'!r}"
    if any(_CREDENTIAL.search(str(part)) for part in (target, body or "", *(v for _, v in query))):
        return None, "credential"
    split = _split_target(target, scope)
    if isinstance(split, str):
        return None, split
    path, query_string = split
    if len(path) > MAX_PATH_CHARS or not _PATH_OK.match(path):
        return None, "invalid"
    pairs = [*parse_qsl(query_string, keep_blank_values=True), *query][:MAX_QUERY_PARAMS]
    pairs = [(n[:80], "" if is_sensitive_name(n) else v[:120]) for n, v in pairs if n]
    clean_body, _warning = _sanitize_body(body)
    return UserEndpoint(method, path, tuple(pairs), clean_body, origin=origin), ""


# ---- reading the text -------------------------------------------------------------------------


def _balanced(text: str) -> bool:
    depth, in_string, escaped = 0, False, False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in "{[":
            depth += 1
        elif ch in "}]":
            depth -= 1
    return depth <= 0


def _take_body(first: str, lines: list[str], index: int) -> tuple[str, int]:
    """A JSON body that starts on this line, continued over the following lines until balanced."""
    body, used = first, 0
    while not _balanced(body) and index + 1 + used < len(lines) and used < 200:
        used += 1
        body += "\n" + lines[index + used]
    return body, used


def _parse_curl(command: str) -> tuple[str, str, str | None, list[str], str] | None:
    """`(method, url, body, header names, problem)` for one curl command, or None if unreadable."""
    try:
        tokens = shlex.split(command.replace("\\\n", " "), posix=True)
    except ValueError:
        return None
    if not tokens or tokens[0].lower() != "curl":
        return None
    method, url, data, headers, problem = "", "", [], [], ""
    i = 1
    while i < len(tokens):
        token = tokens[i]
        value = tokens[i + 1] if i + 1 < len(tokens) else ""
        inline = token.split("=", 1) if token.startswith("--") and "=" in token else None
        if inline:
            token, value = inline[0], inline[1]
            step = 1
        else:
            step = 2
        if token in ("-X", "--request"):
            method = value.upper()
        elif token in ("-H", "--header"):
            headers.append(value)
        elif token in _CURL_DATA_FLAGS:
            data.append(value)
        elif token == "--url":
            url = value
        elif token in _CURL_SECRET_FLAGS:
            problem = f"curl option {token} carries a credential"
            step = 1 if token == "-n" else step
        elif token in _CURL_VALUE_FLAGS:
            pass
        elif token.startswith("-"):
            step = 1  # a flag without a value (-s, -k, -L, -i, -G, ...)
        else:
            url = url or token
            step = 1
        i += step
    return method or ("POST" if data else "GET"), url, "&".join(data) if data else None, headers, problem


def parse_endpoint_text(text: str, *, base_url: str, max_endpoints: int = MAX_ENDPOINTS) -> ParseResult:
    """Read every endpoint the text names. Never raises: problems become `unparsed`, `warnings` or `rejected`."""
    result = ParseResult()
    text = (text or "").replace("﻿", "").replace("\r\n", "\n").replace("\r", "\n")
    if len(text) > MAX_TEXT_CHARS:
        text, result.truncated = text[:MAX_TEXT_CHARS], True
        result.warnings.append(f"the list was cut off after {MAX_TEXT_CHARS} characters")
    stripped = text.strip()
    if not stripped:
        return result
    if _OPENAPI_YAML.search(stripped) or (stripped[:1] == "{" and re.search(r'"(?:openapi|swagger)"\s*:', stripped[:2000])):
        result.openapi_text = stripped
        return result
    try:
        scope = Scope.for_target(base_url, "exact")
    except ValueError:
        result.warnings.append("the target address could not be read, so the pasted list was ignored")
        return result

    lines = text.split("\n")
    index = 0
    last_number = 0

    def add(method: str, target: str, body: str | None, number: int, query: Sequence[tuple[str, str]] = ()) -> bool:
        endpoint, why = build_endpoint(method, target, body=body, query=query, scope=scope)
        if endpoint is None:
            if why == "off_scope":
                result.dropped_off_scope += 1
            elif why == "credential":
                result.rejected.append((number, _CREDENTIAL_ADVICE))
            else:
                return False
            return True
        _, warning = _sanitize_body(body)
        if warning:
            result.warnings.append(f"line {number}: {warning}")
        if len(result.endpoints) >= max_endpoints:
            result.truncated = True
        else:
            result.endpoints.append(endpoint)
        return True

    while index < len(lines):
        number = index + 1
        raw = lines[index]
        index += 1
        line = _BULLET.sub("", raw).strip().strip("`").strip()
        if line.startswith("$ "):
            line = line[2:].strip()
        if not line or line.startswith(("#", "//")):
            continue
        line = line[:MAX_LINE_CHARS]
        if _CREDENTIAL.search(line):
            result.rejected.append((number, _CREDENTIAL_ADVICE))
            continue
        last_number = number

        if line.lower().startswith("curl"):
            command = line
            while True:
                if command.endswith("\\") and index < len(lines):
                    command, index = command[:-1] + " " + lines[index].strip(), index + 1
                    continue
                try:
                    shlex.split(command, posix=True)
                    break
                except ValueError:
                    if index >= len(lines) or index - number > 40:
                        break
                    command, index = command + "\n" + lines[index], index + 1
            if _CREDENTIAL.search(command):
                result.rejected.append((number, _CREDENTIAL_ADVICE))
                continue
            parsed = _parse_curl(command)
            if parsed is None or not parsed[1]:
                result.unparsed.append(line[:300])
                continue
            method, url, body, headers, problem = parsed
            bad = problem or next((f"header {h.split(':', 1)[0].strip()} {_CREDENTIAL_ADVICE}" for h in headers if is_sensitive_name(h.split(":", 1)[0])), "")
            if bad:
                result.rejected.append((number, bad if problem == "" else f"{problem}; {_CREDENTIAL_ADVICE}"))
                continue
            if not add(method, url, body, number):
                result.unparsed.append(line[:300])
            continue

        match = _METHOD_LINE.match(line)
        if match:
            rest = match.group("rest").strip()
            target, _, tail = rest.partition(" ")
            if not target:
                result.unparsed.append(line[:300])
                continue
            tail = tail.strip()
            body = None
            if tail[:1] in "{[":
                body, used = _take_body(tail, lines, index - 1)
                index += used
            elif tail and "=" in tail and " " not in tail:
                body = tail
            if not add(match.group("method"), target, body, number):
                result.unparsed.append(line[:300])
            continue

        header = _HEADER_LINE.match(line)
        if header and not re.match(r"(?i)^https?$", header.group("name")) and "/" not in header.group("name"):
            if is_sensitive_name(header.group("name")):
                result.rejected.append((number, f"header {header.group('name')} {_CREDENTIAL_ADVICE}"))
            else:
                result.warnings.append(f"line {number}: header {header.group('name')} is not used")
            continue

        target, _, tail = line.partition(" ")
        if target.startswith("/") or re.match(r"(?i)^https?://", target):
            tail = tail.strip()
            body = None
            if tail[:1] in "{[":
                body, used = _take_body(tail, lines, index - 1)
                index += used
            if add("GET", target, body, number):
                continue
        result.unparsed.append(line[:300])

    if len(result.unparsed) > MAX_UNPARSED:
        del result.unparsed[MAX_UNPARSED:]
        result.warnings.append(f"only the first {MAX_UNPARSED} unreadable lines were kept")
    if last_number and not result.endpoints and not result.unparsed and not result.rejected and not result.dropped_off_scope:
        result.warnings.append("no endpoints were found in the pasted text")
    return result


# ---- into the inventory -----------------------------------------------------------------------


def to_inventory_endpoint(user: UserEndpoint, base_url: str) -> Endpoint:
    """The inventory entry for a supplied endpoint. Built as a documented (schema-side) sighting,
    so it merges with a crawled one by `endpoint_key` and is not reported as undocumented."""
    base = base_url.rstrip("/")
    body_params = [Parameter(name, Location.BODY, (value,) if value else ()) for name, value in parameters_from_body(user.body)]
    query_params = [Parameter(name, Location.QUERY, (value,) if value else ()) for name, value in user.query]
    extra = [*query_params, *body_params, *user.parameters]
    if "{" in user.path:
        endpoint = from_schema(user.method, user.path, base_url=base, parameters=extra, body_schema=user.body_schema)
        endpoint = replace(endpoint, body_sample=user.body)
    else:
        url = base + user.path + (("?" + urlencode(list(user.query))) if user.query else "")
        endpoint = observed(user.method, url, parameters=[*body_params, *user.parameters], body_sample=user.body, kind="api")
        endpoint = replace(endpoint, body_schema=dict(user.body_schema) if user.body_schema else None)
    return replace(endpoint, source=EndpointSource.SCHEMA, user_supplied=True, note=endpoint.note or "supplied by the operator")

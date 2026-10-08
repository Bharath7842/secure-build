"""Request-framing classification. Pure: the bytes and the status are supplied.

The probe this describes sends one request that names both `Content-Length` and
`Transfer-Encoding`, then reads the status. A server that rejects the ambiguity
(4xx/5xx) is doing the safe thing. A 2xx means it accepted conflicting framing.
This is not a desync: the request does not carry a second, prefixable request
for a shared connection to deliver to someone else.
"""

from __future__ import annotations


def conflicting_request(host: str, path: str = "/") -> bytes:
    """One HTTP/1.1 request with both framing headers and an empty chunk body."""
    target = path if path.startswith("/") else "/" + path
    lines = [
        f"GET {target} HTTP/1.1",
        f"Host: {host}",
        "Content-Length: 0",
        "Transfer-Encoding: chunked",
        "Connection: close",
        "",
        "0",
        "",
        "",
    ]
    return "\r\n".join(lines).encode("ascii", errors="strict")


def framing_accepted(status: int | None) -> bool:
    """True when the server answered success despite the conflicting headers."""
    return status is not None and 200 <= status < 300


def status_from_response(raw: bytes) -> int | None:
    """The status code of an HTTP/1.x response head, or None when the bytes are not one."""
    head = raw.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
    parts = head.split(" ")
    if len(parts) < 2 or not parts[0].startswith("HTTP/"):
        return None
    try:
        return int(parts[1])
    except ValueError:
        return None

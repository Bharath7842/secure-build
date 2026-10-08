"""cURL reproduction strings from a stored request. Pure string building.

The audit row is already redacted, so the command repeats that redacted view: it is
something an operator can read, not a way to recover a credential the scan stripped.
"""

from __future__ import annotations

from typing import Mapping


def _shell(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def to_curl(method: str, url: str, headers: Mapping[str, str] | None = None, body: str | None = None) -> str:
    """One single-line `curl` command for this request."""
    parts = ["curl", "-k", "-sS", "-X", _shell((method or "GET").upper()), _shell(url or "")]
    for name, value in (headers or {}).items():
        parts.extend(["-H", _shell(f"{name}: {value}")])
    if body:
        parts.extend(["--data-binary", _shell(body)])
    return " ".join(parts)

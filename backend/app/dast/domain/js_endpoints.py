"""Heuristic endpoint and client-side issue extraction from a JavaScript source.

A regex over string literals, not a parser: it misses endpoints built by
concatenation and it will sometimes keep a path that is only a static asset.
That is the tradeoff for not taking a JS parser dependency. Callers cap how
many paths they keep.
"""

from __future__ import annotations

import re

# A quoted path that looks like an API route. The character class stops at a
# quote, space, or template interpolation so a minified bundle cannot run away.
_PATH = re.compile(
    r"""['"](/(?:api|graphql|v\d+|rest|auth|admin|internal)(?:/[A-Za-z0-9_.:{}\-]{1,60}){0,8})['"]"""
)
_LISTENER = re.compile(r"""addEventListener\(\s*['"]message['"]""", re.IGNORECASE)
_ORIGIN_CHECK = re.compile(r"""\.origin\b""")


def extract_paths(source: str, *, limit: int = 40) -> tuple[str, ...]:
    """Distinct absolute paths quoted in `source`, in order of appearance."""
    found: list[str] = []
    for match in _PATH.finditer(source or ""):
        path = match.group(1).split("?", 1)[0].split("#", 1)[0]
        if path not in found:
            found.append(path)
        if len(found) >= limit:
            break
    return tuple(found)


def postmessage_without_origin(source: str) -> tuple[str, ...]:
    """Excerpts of `message` listeners whose next few hundred characters never read `event.origin`."""
    hits: list[str] = []
    text = source or ""
    for match in _LISTENER.finditer(text):
        window = text[match.start() : match.start() + 500]
        if _ORIGIN_CHECK.search(window):
            continue
        excerpt = " ".join(window.split())[:160]
        if excerpt not in hits:
            hits.append(excerpt)
        if len(hits) >= 5:
            break
    return tuple(hits)

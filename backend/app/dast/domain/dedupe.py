"""Finding dedupe (DAST-04-050): pure key and merge logic.

Findings dedupe on (check id, endpoint path template, parameter). Concrete ids in a path are
replaced by placeholders so `/users/1` and `/users/2` are one issue seen in two places.
"""

from __future__ import annotations

import re
from typing import Callable, Sequence
from urllib.parse import urlsplit

from .entities import Finding

DedupeKey = tuple[str, str, str]  # (check_id, path_template, param or "")

DedupeKeyFn = Callable[[Finding], DedupeKey]

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
_NUMERIC = re.compile(r"^\d+$")
_HEX_ID = re.compile(r"^(?=.*\d)[0-9a-f]{16,}$", re.IGNORECASE)  # long hex: object ids, hashes
_SLUG_WITH_DIGITS = re.compile(r"^(?=.*\d)[a-z0-9]+(?:[-_][a-z0-9]+)+$", re.IGNORECASE)  # order-2024-0042
_PLACEHOLDER = re.compile(r"^\{[A-Za-z0-9_]+\}$")


def template_segment(segment: str) -> str:
    """One path segment with identifier-looking content replaced by a placeholder."""
    if not segment or _PLACEHOLDER.match(segment):
        return segment
    if _UUID.match(segment):
        return "{uuid}"
    if _NUMERIC.match(segment):
        return "{id}"
    if _HEX_ID.match(segment):
        return "{hex}"
    if _SLUG_WITH_DIGITS.match(segment) and sum(c.isdigit() for c in segment) >= 2:
        return "{slug}"
    return segment


def path_template(url_or_path: str) -> str:
    """Path of a URL (or a bare path) with query/fragment dropped and id segments templated."""
    path = urlsplit(url_or_path or "").path or "/"
    if not path.startswith("/"):
        path = "/" + path
    segments = [template_segment(s) for s in path.split("/")]
    templated = "/".join(segments)
    return templated if len(templated) == 1 else templated.rstrip("/")


def target_path_template(target: str) -> str:
    """Template of a finding target (`"GET /users/42"`); the method is kept, the path templated."""
    method, _, path = (target or "").strip().partition(" ")
    if not path:
        return path_template(method)
    return f"{method.upper()} {path_template(path)}"


def dedupe_key(finding: Finding) -> DedupeKey:
    return (finding.check_id, target_path_template(finding.target), finding.param or "")


def key_for(check_id: str, target: str, param: str | None) -> DedupeKey:
    """The same key from loose parts (used by the writer, which holds dict rows)."""
    return (check_id, target_path_template(target), param or "")


def merge_locations(existing: Sequence[str], new: str) -> list[str]:
    """`existing` plus `new`, order kept, duplicates dropped."""
    merged = list(existing)
    if new and new not in merged:
        merged.append(new)
    return merged

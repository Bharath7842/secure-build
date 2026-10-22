"""A finding occurrence's stable identity (EPIC-00, SAST-00-040).

`occurrence_id` joins one finding across rescans and exports. It is the sha256
of the parts that describe *what* the finding is and where it sits in the code
structure — never its line number, so inserting a blank line above it leaves
the id unchanged, while changing the sink expression or moving the sink into a
different method changes it:

    project | file | rule | cwe | normalized sink expression
            | enclosing method signature | ordinal of the sink within the method

The engine computes the file-dependent parts (`sast_engine/pipeline/occurrence.py`
stamps `sink_expression`, `enclosing_method`, `sink_ordinal` and
`identity_quality` on each finding dict); this module only hashes them. It is a
different thing from `feedback._fingerprint`, which hashes the *group* key and
backs `FindingReview` — keep both.
"""

from __future__ import annotations

import hashlib
from typing import Any, Mapping

IDENTITY_EXACT = "exact"
IDENTITY_FILE_LEVEL = "file_level"

# Sink expressions are stored and hashed in this normalized, bounded form.
SINK_EXPRESSION_MAX_CHARS = 300


def normalize_expression(text: Any) -> str:
    """Whitespace collapse — the one normalization `scan_export._normalized_match`
    and the engine's sink expressions share."""
    return " ".join(str(text or "").split())


UNRESOLVED_SIGNATURE = "unresolved"


def semantic_signature(facts: Mapping[str, Any] | None) -> str:
    """The part of an occurrence's facts that decides whether two occurrences
    are one construct (SAST-01-060). Mirrors
    `sast_engine/pipeline/occurrence_facts.semantic_signature` — the app cannot
    import the engine; `tests/test_group_key_parity.py` keeps the two equal.

    A call is identified by its owner type, name and arity, its receiver's type
    and the kinds of its arguments; a declaration by method name, arity and
    whether its body is a stub; no facts at all is `unresolved`."""
    if not facts:
        return UNRESOLVED_SIGNATURE
    if facts.get("in_comment"):
        return "comment"
    call = facts.get("call")
    if call:
        kinds = ",".join(a.get("kind", "unknown") for a in facts.get("args") or [])
        owner = call.get("owner_fqn") or "?"
        receiver = call.get("receiver_fqn") or "?"
        return f"call:{owner}.{call.get('callee')}/{call.get('arity')}|{receiver}|({kinds})"
    enclosing = facts.get("enclosing") or {}
    if facts.get("is_declaration"):
        shape = "stub" if facts.get("is_stub") else "impl"
        return f"decl:{enclosing.get('method')}/{enclosing.get('arity')}|{shape}"
    return f"other:{'stub' if facts.get('is_stub') else 'body'}"


def _sink_expression(f: Mapping[str, Any]) -> str:
    stamped = f.get("sink_expression")
    if stamped is not None:
        return str(stamped)
    # Findings that bypassed the engine's stamping (SCA hits, tests): the
    # literal match, else the named sink, else the first line of the snippet.
    snippet = (f.get("snippet") or "").strip().splitlines()
    return normalize_expression(
        f.get("matched_text") or f.get("sink") or (snippet[0] if snippet else "")
    )[:SINK_EXPRESSION_MAX_CHARS]


def occurrence_parts(f: Mapping[str, Any], file_path: str) -> dict[str, Any]:
    """The values `occurrence_id` hashes, plus the identity quality."""
    method = f.get("enclosing_method")
    quality = f.get("identity_quality") or (IDENTITY_EXACT if method else IDENTITY_FILE_LEVEL)
    return {
        "file_path": f.get("file_path") or file_path or "",
        "rule_id": f.get("rule_id") or "",
        "cwe": (f.get("cwe") or "").upper(),
        "sink_expression": _sink_expression(f),
        "enclosing_method": method or "",
        "sink_ordinal": int(f.get("sink_ordinal") or 0),
        "identity_quality": quality,
    }


def occurrence_id(project_id: str, f: Mapping[str, Any], file_path: str = "") -> str:
    parts = occurrence_parts(f, file_path)
    material = "|".join(
        (
            project_id,
            parts["file_path"],
            parts["rule_id"],
            parts["cwe"],
            parts["sink_expression"],
            parts["enclosing_method"],
            str(parts["sink_ordinal"]),
        )
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()

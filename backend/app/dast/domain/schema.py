"""Reply handling for the model gateway (DAST-02-010): pull JSON out of model text and
validate it against a small JSON-Schema subset.

Supported keywords: `type` (a name or a list; "integer"/"number"/"string"/"boolean"/"object"/
"array"/"null"), `enum`, `required`, `properties`, `additionalProperties` (false only),
`items`, `minItems`/`maxItems`, `minLength`/`maxLength`, `minimum`/`maximum`. Anything else in a
schema is ignored, never an error, so a caller may pass a fuller schema for documentation.
Model output is untrusted input; this is the check that it has the shape the caller expects.
"""

from __future__ import annotations

import json
import re
from typing import Any, Mapping

_FENCE = re.compile(r"^\s*```(?:json|JSON)?\s*\n?(.*?)\n?```\s*$", re.DOTALL)


def extract_json(text: str) -> Any:
    """Parse the JSON value in `text`, tolerating markdown fences and prose around it.
    Raises ValueError when there is none."""
    if text is None:
        raise ValueError("empty reply")
    stripped = text.strip()
    if not stripped:
        raise ValueError("empty reply")
    fenced = _FENCE.match(stripped)
    if fenced:
        stripped = fenced.group(1).strip()
    try:
        return json.loads(stripped)
    except ValueError:
        pass
    for opener, closer in (("{", "}"), ("[", "]")):
        start, end = stripped.find(opener), stripped.rfind(closer)
        if 0 <= start < end:
            try:
                return json.loads(stripped[start : end + 1])
            except ValueError:
                continue
    raise ValueError("reply contains no valid JSON")


def _type_ok(value: Any, name: str) -> bool:
    if name == "string":
        return isinstance(value, str)
    if name == "boolean":
        return isinstance(value, bool)
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if name == "object":
        return isinstance(value, dict)
    if name == "array":
        return isinstance(value, list)
    if name == "null":
        return value is None
    return True  # an unknown type name is not something to fail a reply over


def validate_reply(value: Any, schema: Mapping[str, Any] | None, path: str = "$") -> list[str]:
    """Problems with `value` against `schema`, as readable strings. Empty means valid."""
    if not schema:
        return []
    problems: list[str] = []
    wanted = schema.get("type")
    if wanted is not None:
        names = [wanted] if isinstance(wanted, str) else list(wanted)
        if not any(_type_ok(value, n) for n in names):
            return [f"{path}: expected {' or '.join(names)}, got {type(value).__name__}"]
    if "enum" in schema and value not in schema["enum"]:
        problems.append(f"{path}: {value!r} is not one of {list(schema['enum'])}")
    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            problems.append(f"{path}: shorter than {schema['minLength']} characters")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            problems.append(f"{path}: longer than {schema['maxLength']} characters")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            problems.append(f"{path}: below minimum {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            problems.append(f"{path}: above maximum {schema['maximum']}")
    if isinstance(value, dict):
        properties = schema.get("properties") or {}
        for name in schema.get("required") or ():
            if name not in value:
                problems.append(f"{path}: missing required property {name!r}")
        for name, sub in properties.items():
            if name in value:
                problems.extend(validate_reply(value[name], sub, f"{path}.{name}"))
        if schema.get("additionalProperties") is False:
            for name in value:
                if name not in properties:
                    problems.append(f"{path}: unexpected property {name!r}")
    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            problems.append(f"{path}: fewer than {schema['minItems']} items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            problems.append(f"{path}: more than {schema['maxItems']} items")
        item_schema = schema.get("items")
        if isinstance(item_schema, Mapping):
            for index, item in enumerate(value):
                problems.extend(validate_reply(item, item_schema, f"{path}[{index}]"))
    return problems

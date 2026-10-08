"""Maps engine result dicts onto the domain entities and validates them.

The mock engine and the real engine both emit finding rows and identity dicts;
`validate_result` runs them through the same domain types so a shape drift in
either one fails loudly instead of reaching the database. Engine layer: may use
the domain, nothing else.
"""

from __future__ import annotations

from typing import Any, Mapping

from .domain.entities import Finding, Identity, Role, RoleName
from .domain.mapping import evidence_from_dict, finding_from_row as _finding_from_row  # noqa: F401

_AUTHZ_RESULTS = {"OK", "FAIL", "untested"}


def identity_from_dict(data: Mapping[str, Any]) -> Identity:
    role = Role(name=RoleName(data["role"]), label=data.get("role_label") or "")
    return Identity(identity_id=data["identity_id"], label=data["label"], role=role)


def finding_from_row(row: Mapping[str, Any]) -> Finding:
    """Build the domain `Finding` for an engine finding row (see `domain.mapping`). Raises on
    any invalid enum value."""
    return _finding_from_row(row)


def validate_result(discovery: Mapping[str, Any], finding_rows: list[Mapping[str, Any]]) -> None:
    """Raise ValueError/KeyError if the result does not fit the domain contract."""
    for row in finding_rows:
        finding_from_row(row)

    authorization = discovery.get("authorization")
    if authorization:
        identities = [identity_from_dict(i) for i in authorization["identities"]]
        roles = {i.role.name.value for i in identities} | {RoleName.ANONYMOUS.value}
        for cell in authorization["matrix"]:
            if cell["owner"] not in roles or cell["actor"] not in roles:
                raise ValueError(f"matrix cell names an unknown role: {cell}")
            if cell["result"] not in _AUTHZ_RESULTS:
                raise ValueError(f"matrix cell has an invalid result: {cell}")
            if (cell["result"] == "FAIL") != (cell.get("failures", 0) > 0):
                raise ValueError(f"matrix cell failure count disagrees with its result: {cell}")
            if cell["result"] == "untested" and not cell.get("reason"):
                raise ValueError(f"untested matrix cell needs a reason: {cell}")

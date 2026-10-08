"""Identities (DAST-06-020, and the request side of DAST-05-010): who a scan acts as.

An identity is a label, a role and one authentication method. This module holds no secret:
credentials live in the credential holder, and only `has_secret`-style flags travel with the
scan record. `build_identities` is the single place a request's identity list is validated and
normalized:

* labels are unique (case-insensitively), non-empty and printable;
* a role is `Admin|User|Viewer|Anonymous|Custom`, `Custom` needing a name;
* an Anonymous identity is always present and carries no credentials; it is added when the
  request does not supply one, and cannot be removed;
* a scan with no authenticated identity runs as Anonymous only (no login stage).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Sequence

from .entities import Identity, Role, RoleName

MAX_IDENTITIES = 8
MAX_LABEL_CHARS = 60
ANONYMOUS_LABEL = "anonymous"


class AuthMethod(str, Enum):
    FORM = "form"
    TOKEN = "token"
    PREAUTH = "preauth"  # a saved browser session (storage state)
    NONE = "none"  # Anonymous


class IdentityError(ValueError):
    """The identity list is invalid. The message is safe to show the operator."""


@dataclass(frozen=True)
class IdentitySpec:
    label: str
    role: Role
    auth_method: AuthMethod
    identity_id: str
    implicit: bool = False  # added by the engine, not supplied by the operator

    @property
    def is_anonymous(self) -> bool:
        return self.role.name is RoleName.ANONYMOUS

    @property
    def authenticated(self) -> bool:
        return self.auth_method is not AuthMethod.NONE

    @property
    def role_display(self) -> str:
        return self.role.label if self.role.name is RoleName.CUSTOM else self.role.name.value

    def to_identity(self) -> Identity:
        return Identity(identity_id=self.identity_id, label=self.label, role=self.role)

    def to_public(self) -> dict[str, Any]:
        """The non-secret description stored on the scan."""
        return {
            "identity_id": self.identity_id,
            "label": self.label,
            "role": self.role.name.value,
            "role_label": self.role.label,
            "auth_method": self.auth_method.value,
            "implicit": self.implicit,
        }


_SLUG = re.compile(r"[^a-z0-9]+")


def identity_id_for(label: str) -> str:
    return "identity-" + (_SLUG.sub("-", label.strip().lower()).strip("-") or "x")


def parse_role(name: str, custom_name: str = "") -> Role:
    key = (name or "").strip().lower()
    try:
        role = RoleName(key)
    except ValueError:
        allowed = ", ".join(r.name.capitalize() for r in RoleName)
        raise IdentityError(f"role {name!r} is not one of: {allowed}") from None
    if role is RoleName.CUSTOM:
        custom_name = (custom_name or "").strip()
        if not custom_name:
            raise IdentityError("a Custom role needs a role name")
        if len(custom_name) > MAX_LABEL_CHARS:
            raise IdentityError(f"a custom role name may not exceed {MAX_LABEL_CHARS} characters")
        return Role(role, custom_name)
    return Role(role, "")


def _check_label(label: str) -> str:
    label = (label or "").strip()
    if not label:
        raise IdentityError("every identity needs a label")
    if len(label) > MAX_LABEL_CHARS:
        raise IdentityError(f"identity label {label[:20]!r}... is longer than {MAX_LABEL_CHARS} characters")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in label):
        raise IdentityError("identity labels may not contain control characters")
    return label


def build_identities(raw: Sequence[Mapping[str, Any]]) -> list[IdentitySpec]:
    """Validate the requested identities and return them with Anonymous always included
    (last when implicit). Raises `IdentityError`."""
    if len(raw) > MAX_IDENTITIES:
        raise IdentityError(f"a scan may have at most {MAX_IDENTITIES} identities")
    specs: list[IdentitySpec] = []
    seen_labels: set[str] = set()
    for item in raw:
        label = _check_label(str(item.get("label") or ""))
        if label.lower() in seen_labels:
            raise IdentityError(f"identity label {label!r} is used more than once; labels must be unique")
        seen_labels.add(label.lower())
        role = parse_role(str(item.get("role") or ""), str(item.get("custom_role") or item.get("role_label") or ""))
        try:
            method = AuthMethod(str(item.get("auth_method") or "").strip().lower() or "none")
        except ValueError:
            raise IdentityError(f"identity {label!r}: unknown authentication method {item.get('auth_method')!r}") from None
        if role.name is RoleName.ANONYMOUS:
            if method is not AuthMethod.NONE:
                raise IdentityError(f"identity {label!r}: an Anonymous identity cannot carry credentials")
        elif method is AuthMethod.NONE:
            raise IdentityError(f"identity {label!r}: choose an authentication method (form, token or preauth)")
        specs.append(IdentitySpec(label, role, method, identity_id_for(label)))

    anonymous = [s for s in specs if s.is_anonymous]
    if len(anonymous) > 1:
        raise IdentityError("a scan has exactly one Anonymous identity")
    if not anonymous:
        label = ANONYMOUS_LABEL
        if label in seen_labels:
            label = "anonymous (baseline)"
        specs.append(IdentitySpec(label, Role(RoleName.ANONYMOUS), AuthMethod.NONE, identity_id_for(label), implicit=True))
    ids = [s.identity_id for s in specs]
    if len(set(ids)) != len(ids):  # two labels that differ only in punctuation
        raise IdentityError("identity labels must differ by more than punctuation or case")
    return specs


def authenticated(specs: Sequence[IdentitySpec]) -> list[IdentitySpec]:
    return [s for s in specs if s.authenticated]


def has_second_identity(specs: Sequence[IdentitySpec]) -> bool:
    """Cross-role checks need two *authenticated* identities; Anonymous alone is only a baseline."""
    return len(authenticated(specs)) >= 2


def identity_from_public(data: Mapping[str, Any]) -> Identity:
    """Rebuild a domain `Identity` from its stored, non-secret description."""
    role = Role(RoleName(str(data.get("role") or "user")), str(data.get("role_label") or ""))
    return Identity(identity_id=str(data["identity_id"]), label=str(data.get("label") or data["identity_id"]), role=role)


def spec_from_public(data: Mapping[str, Any]) -> IdentitySpec:
    return IdentitySpec(
        label=str(data.get("label") or data["identity_id"]),
        role=Role(RoleName(str(data.get("role") or "user")), str(data.get("role_label") or "")),
        auth_method=AuthMethod(str(data.get("auth_method") or "none")),
        identity_id=str(data["identity_id"]),
        implicit=bool(data.get("implicit")),
    )

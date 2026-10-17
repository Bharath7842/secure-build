"""The permission catalog and how a user's effective permissions are worked out.

Two kinds of keys, both stored the same way:
- `page.*`: which pages a user sees in the app (visibility only).
- actions: what the API lets them do. Every protected route requires one.

Admins always hold every key; per-user overrides don't apply to them. A regular
user holds the `user_default` keys, plus their `grant` overrides, minus their
`deny` overrides (deny wins). Keys an admin may never hand to a user
(`grantable_to_user=False`) are never effective for one. Finally a key whose
`requires` aren't all held is dropped, so a page never shows without the
action behind it.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

ADMIN = "admin"
USER = "user"
ROLES = (ADMIN, USER)
EFFECTS = ("grant", "deny")


@dataclass(frozen=True)
class Permission:
    key: str
    kind: str  # "page" | "action"
    label: str
    description: str
    user_default: bool
    grantable_to_user: bool = True
    requires: tuple[str, ...] = ()


PERMISSIONS: tuple[Permission, ...] = (
    # --- Actions ---
    Permission(
        "projects.view", "action", "View projects",
        "See projects and the scan options offered for them.", user_default=True,
    ),
    Permission(
        "projects.manage", "action", "Manage projects",
        "Create, edit and delete projects, connect Git, and change a project's scan limitations and DAST rules.",
        user_default=False, requires=("projects.view",),
    ),
    Permission(
        "scans.view_own", "action", "View own scans",
        "See status, logs, results and findings of scans they started.", user_default=True,
    ),
    Permission(
        "scans.view_all", "action", "View all scans",
        "See every scan, including other users', CI scans and scans from before sign-in existed.",
        user_default=False, requires=("scans.view_own",),
    ),
    Permission(
        "scans.create", "action", "Start SAST, SCA and SBOM scans",
        "Start code scans on projects they can see.", user_default=True,
        requires=("projects.view", "scans.view_own"),
    ),
    Permission(
        "scans.create_dast", "action", "Start DAST scans",
        "Start, schedule and replay DAST scans, which send live traffic to target sites.",
        user_default=False, requires=("projects.view", "scans.view_own"),
    ),
    Permission(
        "scans.cancel_own", "action", "Stop own scans",
        "Cancel, pause and resume scans they started.", user_default=True,
        requires=("scans.view_own",),
    ),
    Permission(
        "scans.cancel_any", "action", "Stop any scan",
        "Cancel, pause and resume any scan they can see.", user_default=False,
        requires=("scans.view_own",),
    ),
    Permission(
        "scans.delete", "action", "Delete scans",
        "Delete finished scans they can see, with their findings.", user_default=False,
        requires=("scans.view_own",),
    ),
    Permission(
        "reports.export", "action", "Export reports",
        "Download PDF, Excel, SARIF and JUnit reports for scans they can see.", user_default=True,
        requires=("scans.view_own",),
    ),
    Permission(
        "findings.review", "action", "Review findings",
        "Record review verdicts and triage on findings of scans they can see.", user_default=False,
        requires=("scans.view_own",),
    ),
    Permission(
        "feedback.manage", "action", "Manage review feedback",
        "Approve reviews for learning and export the feedback dataset.", user_default=False,
        requires=("findings.review",),
    ),
    Permission(
        "settings.manage", "action", "Manage global settings",
        "Change model settings and global DAST settings, rules and schedules.",
        user_default=False, grantable_to_user=False,
    ),
    Permission(
        "dast.training", "action", "Manage DAST training data",
        "Turn training-data capture on or off and read captured examples.",
        user_default=False, grantable_to_user=False,
    ),
    Permission(
        "users.manage", "action", "Manage users",
        "Create and disable users, and change roles and permissions.",
        user_default=False, grantable_to_user=False,
    ),
    Permission(
        "audit.view", "action", "View audit log", "Read the audit log.",
        user_default=False, grantable_to_user=False,
    ),
    # --- Pages ---
    Permission(
        "page.projects", "page", "Projects", "/projects and project details.", user_default=True,
        requires=("projects.view",),
    ),
    Permission(
        "page.project_new", "page", "New project", "/projects/new.", user_default=False,
        requires=("projects.manage",),
    ),
    Permission(
        "page.project_settings", "page", "Project settings", "/projects/[id]/settings.", user_default=False,
        requires=("projects.manage",),
    ),
    Permission(
        "page.scan_sast", "page", "SAST", "/scans/new, the SAST launcher.", user_default=True,
        requires=("scans.create",),
    ),
    Permission(
        "page.scan_sca", "page", "SCA", "/sca.", user_default=True, requires=("scans.view_own",),
    ),
    Permission(
        "page.scan_sbom", "page", "SBOM", "/sbom.", user_default=True, requires=("scans.view_own",),
    ),
    Permission(
        "page.dast", "page", "DAST", "/dast.", user_default=False, requires=("scans.view_own",),
    ),
    Permission(
        "page.history", "page", "History", "/scans and scan details.", user_default=True,
        requires=("scans.view_own",),
    ),
    Permission(
        "page.feedback", "page", "Feedback & Review", "/feedback.", user_default=False,
        requires=("findings.review",),
    ),
    Permission(
        "page.settings", "page", "Settings", "/settings and /dast/settings.",
        user_default=False, grantable_to_user=False, requires=("settings.manage",),
    ),
    Permission(
        "page.admin_users", "page", "Users", "/admin/users.",
        user_default=False, grantable_to_user=False, requires=("users.manage",),
    ),
    Permission(
        "page.admin_audit", "page", "Audit log", "/admin/audit.",
        user_default=False, grantable_to_user=False, requires=("audit.view",),
    ),
)

BY_KEY: dict[str, Permission] = {p.key: p for p in PERMISSIONS}
ALL_KEYS: frozenset[str] = frozenset(BY_KEY)

# What the CI bearer token (SAST_API_TOKEN) may do: the documented CI flow of
# create project -> trigger scan -> poll -> read results. Nothing admin.
CI_SERVICE_PERMISSIONS: frozenset[str] = frozenset(
    {"projects.view", "projects.manage", "scans.view_own", "scans.view_all", "scans.create", "reports.export"}
)


def _drop_unmet(keys: set[str]) -> set[str]:
    """Remove keys whose requirements aren't held, until nothing changes."""
    while True:
        unmet = {k for k in keys if not set(BY_KEY[k].requires) <= keys}
        if not unmet:
            return keys
        keys -= unmet


def effective_permissions(role: str, overrides: Mapping[str, str] | None = None) -> frozenset[str]:
    """Every key `role` holds after `overrides` ({key: "grant"|"deny"})."""
    if role == ADMIN:
        return ALL_KEYS
    if role != USER:
        return frozenset()  # unknown role: deny by default
    overrides = overrides or {}
    keys = {p.key for p in PERMISSIONS if p.user_default}
    keys |= {k for k, effect in overrides.items() if effect == "grant" and k in BY_KEY}
    keys -= {k for k, effect in overrides.items() if effect == "deny"}
    keys = {k for k in keys if BY_KEY[k].grantable_to_user}
    return frozenset(_drop_unmet(keys))


def inactive_permissions(role: str, overrides: Mapping[str, str] | None = None) -> dict[str, list[str]]:
    """Keys the user would hold but for an unmet requirement: {key: [missing keys]}."""
    if role != USER:
        return {}
    overrides = overrides or {}
    held = effective_permissions(role, overrides)
    wanted = {p.key for p in PERMISSIONS if p.user_default and p.grantable_to_user}
    wanted |= {k for k, effect in overrides.items() if effect == "grant" and k in BY_KEY}
    wanted -= {k for k, effect in overrides.items() if effect == "deny"}
    return {
        k: sorted(set(BY_KEY[k].requires) - held)
        for k in sorted(wanted - held)
        if BY_KEY[k].grantable_to_user
    }


def validate_overrides(overrides: Mapping[str, str]) -> None:
    """Raise ValueError for an unknown key, an unknown effect, or a grant of
    a key that can't be given to a regular user."""
    for key, effect in overrides.items():
        if key not in BY_KEY:
            raise ValueError(f"Unknown permission: {key}")
        if effect not in EFFECTS:
            raise ValueError(f"Effect for {key} must be 'grant' or 'deny'.")
        if effect == "grant" and not BY_KEY[key].grantable_to_user:
            raise ValueError(f"{BY_KEY[key].label} is admin-only and can't be granted to a user.")


def with_requirements(overrides: Mapping[str, str]) -> tuple[dict[str, str], list[str]]:
    """`overrides` plus a grant for every requirement of a granted key that the
    user wouldn't otherwise hold, so a grant is never silently inactive.
    Returns (overrides, keys that were added). Requirements the admin denied
    explicitly stay denied; the key then shows as inactive instead."""
    result = dict(overrides)
    added: list[str] = []
    pending = [k for k, effect in result.items() if effect == "grant"]
    while pending:
        key = pending.pop()
        for req in BY_KEY[key].requires:
            if req in result:
                continue
            if req in effective_permissions(USER, {}):
                continue
            if BY_KEY[req].grantable_to_user:
                result[req] = "grant"
                added.append(req)
                pending.append(req)
    return result, sorted(added)


def catalog_entries(keys: Iterable[str] | None = None) -> list[dict]:
    """JSON-ready catalog for the admin UI."""
    wanted = set(keys) if keys is not None else None
    return [
        {
            "key": p.key,
            "kind": p.kind,
            "label": p.label,
            "description": p.description,
            "user_default": p.user_default,
            "grantable_to_user": p.grantable_to_user,
            "requires": list(p.requires),
        }
        for p in PERMISSIONS
        if wanted is None or p.key in wanted
    ]


# Where a user lands after signing in: the first page they can see, in this order.
LANDING_PAGES: tuple[tuple[str, str], ...] = (
    ("page.projects", "/projects"),
    ("page.history", "/scans"),
    ("page.scan_sast", "/scans/new"),
    ("page.scan_sca", "/sca"),
    ("page.scan_sbom", "/sbom"),
    ("page.dast", "/dast"),
    ("page.feedback", "/feedback"),
    ("page.admin_users", "/admin/users"),
)


def landing_path(permissions: Iterable[str]) -> str:
    held = set(permissions)
    return next((path for key, path in LANDING_PAGES if key in held), "/account")

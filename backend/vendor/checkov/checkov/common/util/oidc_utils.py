import re
from typing import Any, List, Set

GH_ABUSABLE_CLAIMS: Set[str] = {"actor", "head_ref", "base_ref", "ref", "workflow"}

gh_repo_regex = re.compile(r"(\$\{)?[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)*(\})?/[^/]+")
gh_sub_condition = re.compile(r"^token\.actions\.githubusercontent\.com(?:/[a-zA-Z0-9_-]+)?:sub$")


def gh_abusable_claims() -> Set[str]:
    return GH_ABUSABLE_CLAIMS


def is_oidc_principal(principal: Any) -> bool:
    if isinstance(principal, str):
        return "token.actions.githubusercontent.com" in principal
    if isinstance(principal, list):
        return any(is_oidc_principal(p) for p in principal)
    return False


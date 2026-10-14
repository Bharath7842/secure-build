"""SAST LLM provider names and the per-project data policy.

Mirrors the constants in `sast_engine/llm_client.py`, which the app can't
import directly (it is loaded by path and needs boto3 — see agent_bridge).
The engine re-checks the policy on every call; the check here only exists to
refuse a misconfigured scan up front instead of failing it mid-run.
"""

import ipaddress
from urllib.parse import urlparse

SAST_LLM_PROVIDERS = ("bedrock", "openai_compat", "ollama")
# "none": stop LLM work at the cost cutoff instead of switching providers.
SAST_FALLBACK_PROVIDERS = ("none", *SAST_LLM_PROVIDERS)
DATA_POLICY_ALLOW_EXTERNAL = "allow_external"
DATA_POLICY_LOCAL_ONLY = "local_only"
DATA_POLICIES = (DATA_POLICY_ALLOW_EXTERNAL, DATA_POLICY_LOCAL_ONLY)


def is_local_base_url(url: str | None) -> bool:
    """True for loopback, private-network and link-local hosts."""
    host = (urlparse(url or "").hostname or "").strip().lower()
    if not host:
        return False
    if host == "localhost" or host.endswith(".localhost") or host.endswith(".local"):
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return addr.is_loopback or addr.is_private or addr.is_link_local


def data_policy_violation(
    *,
    policy: str | None,
    provider: str | None,
    base_url: str | None,
) -> str | None:
    """Why `provider` at `base_url` is not allowed under `policy`, or None."""
    if (policy or DATA_POLICY_ALLOW_EXTERNAL) != DATA_POLICY_LOCAL_ONLY or not provider:
        return None
    provider = provider.strip().lower()
    if provider == "bedrock":
        return "data policy is local_only, but Bedrock is an external provider"
    if provider in ("openai_compat", "ollama") and not is_local_base_url(base_url):
        host = urlparse(base_url or "").hostname or base_url or "unset"
        return f"data policy is local_only, but the {provider} endpoint {host!r} is not local"
    return None

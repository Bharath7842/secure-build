"""SAST LLM provider names.

Mirrors the constants in `sast_engine/llm_client.py`, which the app can't
import directly (it is loaded by path and needs boto3 — see agent_bridge).
"""

SAST_LLM_PROVIDERS = ("bedrock", "openai_compat", "ollama", "claude_cli")
# "none": stop LLM work at the cost cutoff instead of switching providers.
SAST_FALLBACK_PROVIDERS = ("none", *SAST_LLM_PROVIDERS)

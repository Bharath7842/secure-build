"""Shared LLM client — Bedrock (Claude), any OpenAI-compatible
`/chat/completions` server (vLLM, LM Studio, llama.cpp, OpenAI, ...), and
Ollama (local, optional)."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import boto3
import requests

AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
BEDROCK_MODEL_ID = os.environ.get(
    "BEDROCK_MODEL_ID", "us.anthropic.claude-haiku-4-5-20251001-v1:0"
)
DEFAULT_LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "bedrock")
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "granite-code:3b")
OLLAMA_REQUEST_TIMEOUT = int(os.environ.get("OLLAMA_REQUEST_TIMEOUT", "600"))
OLLAMA_NUM_CTX = int(os.environ.get("OLLAMA_NUM_CTX", "8192"))

BEDROCK_INPUT_PRICE_PER_MTOK = float(os.environ.get("BEDROCK_INPUT_PRICE_PER_MTOK", "1.00"))
BEDROCK_OUTPUT_PRICE_PER_MTOK = float(os.environ.get("BEDROCK_OUTPUT_PRICE_PER_MTOK", "5.00"))
# Claude Sonnet is priced above the Haiku defaults above.
BEDROCK_SONNET_INPUT_PRICE_PER_MTOK = float(os.environ.get("BEDROCK_SONNET_INPUT_PRICE_PER_MTOK", "3.00"))
BEDROCK_SONNET_OUTPUT_PRICE_PER_MTOK = float(os.environ.get("BEDROCK_SONNET_OUTPUT_PRICE_PER_MTOK", "15.00"))

_USAGE_LOCK = threading.Lock()
OLLAMA_INPUT_PRICE_PER_MTOK = float(os.environ.get("OLLAMA_INPUT_PRICE_PER_MTOK", "0.00"))
OLLAMA_OUTPUT_PRICE_PER_MTOK = float(os.environ.get("OLLAMA_OUTPUT_PRICE_PER_MTOK", "0.00"))

# OpenAI-compatible chat-completions endpoint. The base URL includes the API
# version prefix (".../v1"); per-scan overrides ride on the usage dict (see
# PROVIDER_OPTIONS_USAGE_KEY) so call sites only ever pass provider/model.
OPENAI_COMPAT_BASE_URL = os.environ.get("OPENAI_COMPAT_BASE_URL", "http://localhost:8000/v1")
OPENAI_COMPAT_API_KEY = os.environ.get("OPENAI_COMPAT_API_KEY", "")
OPENAI_COMPAT_MODEL = os.environ.get("OPENAI_COMPAT_MODEL", "")
OPENAI_COMPAT_REQUEST_TIMEOUT = int(os.environ.get("OPENAI_COMPAT_REQUEST_TIMEOUT", "600"))
# Local servers are free; set these when pointing at a paid endpoint so the
# cost cutoff means something.
OPENAI_COMPAT_INPUT_PRICE_PER_MTOK = float(os.environ.get("OPENAI_COMPAT_INPUT_PRICE_PER_MTOK", "0.00"))
OPENAI_COMPAT_OUTPUT_PRICE_PER_MTOK = float(os.environ.get("OPENAI_COMPAT_OUTPUT_PRICE_PER_MTOK", "0.00"))
OPENAI_COMPAT_CACHE_READ_PRICE_MULTIPLIER = float(
    os.environ.get("OPENAI_COMPAT_CACHE_READ_PRICE_MULTIPLIER", "0.5")
)

PROVIDER_BEDROCK = "bedrock"
PROVIDER_OLLAMA = "ollama"
PROVIDER_OPENAI_COMPAT = "openai_compat"
# Fallback-only: stop making LLM calls once the cost cutoff is reached.
PROVIDER_NONE = "none"
KNOWN_PROVIDERS = (PROVIDER_BEDROCK, PROVIDER_OLLAMA, PROVIDER_OPENAI_COMPAT)

# Soft spend cap: once estimated cost_usd reaches this, remaining calls route
# to the fallback provider — or, with the default fallback "none", raise
# LlmBudgetExhausted so each stage records its remaining work as unverified.
# Disabled when the primary provider is ollama. Parallel workers may slightly
# overshoot before the next call sees the updated total.
LLM_COST_CUTOFF_USD = float(os.environ.get("LLM_COST_CUTOFF_USD", "2.0"))
DEFAULT_FALLBACK_LLM_PROVIDER = os.environ.get("FALLBACK_LLM_PROVIDER", PROVIDER_NONE)
DEFAULT_FALLBACK_LLM_MODEL = os.environ.get("FALLBACK_LLM_MODEL", "")

# Per-scan provider settings (base_url / api_key per provider, data policy).
# Underscore-prefixed like the result cache: never part of usage_cost_summary.
PROVIDER_OPTIONS_USAGE_KEY = "_provider_options"
DATA_POLICY_USAGE_KEY = "_data_policy"
DATA_POLICY_LOCAL_ONLY = "local_only"
DATA_POLICY_ALLOW_EXTERNAL = "allow_external"


class LlmBudgetExhausted(RuntimeError):
    """The cost cutoff was reached and no fallback provider is configured."""


class LlmPolicyViolation(RuntimeError):
    """A call would send repository content somewhere the data policy forbids."""

_bedrock = boto3.client("bedrock-runtime", region_name=AWS_REGION)

# Bedrock prompt caching: a cache checkpoint after the system prompt lets every
# later chunk/file of the same language reuse the (large, catalog-bearing)
# prefix at the cache-read price. Below the model's minimum cacheable length
# Bedrock simply doesn't cache, so the checkpoint is only attached once the
# system prompt plausibly clears it — never pad a prompt to get there.
BEDROCK_PROMPT_CACHE = os.environ.get("BEDROCK_PROMPT_CACHE", "1").strip().lower() not in ("0", "false", "no")
CACHE_WRITE_PRICE_MULTIPLIER = 1.25
CACHE_READ_PRICE_MULTIPLIER = 0.10


# Bedrock only reads a cache entry once the call that wrote it has returned.
# Several workers starting on the same system prompt at once therefore all
# pay the 1.25x write instead of one write and N-1 reads (a 9-file scan saw
# 3 writes, 1 read — about break-even). The first call per (model, system
# prompt) runs alone; the rest wait for it, then fan out in parallel.
# Entries expire after ~5 minutes idle, so a gate re-arms before then.
PROMPT_CACHE_WARM_TTL_SECONDS = 240.0


class _WarmGate:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.warmed_at: Optional[float] = None

    def is_warm(self) -> bool:
        return (
            self.warmed_at is not None
            and time.monotonic() - self.warmed_at < PROMPT_CACHE_WARM_TTL_SECONDS
        )


_WARM_GATES: Dict[Tuple[str, str], _WarmGate] = {}
_WARM_GATES_LOCK = threading.Lock()


def _warm_gate_for(model: str, system: str) -> _WarmGate:
    import hashlib

    key = (model, hashlib.sha256(system.encode("utf-8")).hexdigest())
    with _WARM_GATES_LOCK:
        gate = _WARM_GATES.get(key)
        if gate is None:
            gate = _WARM_GATES[key] = _WarmGate()
        return gate


def prompt_cache_min_tokens(model: Optional[str]) -> int:
    override = os.environ.get("BEDROCK_PROMPT_CACHE_MIN_TOKENS")
    if override:
        return int(override)
    name = (model or "").lower()
    if "haiku" in name or "opus" in name:
        return 4096
    return 1024


def should_cache_system_prompt(system: str, model: Optional[str]) -> bool:
    return BEDROCK_PROMPT_CACHE and estimate_token_count(system) >= prompt_cache_min_tokens(model)


def _price_per_mtok(provider: str, model: Optional[str] = None) -> Tuple[float, float]:
    name = (provider or "").strip().lower()
    if name == PROVIDER_OLLAMA:
        return OLLAMA_INPUT_PRICE_PER_MTOK, OLLAMA_OUTPUT_PRICE_PER_MTOK
    if name == PROVIDER_OPENAI_COMPAT:
        return OPENAI_COMPAT_INPUT_PRICE_PER_MTOK, OPENAI_COMPAT_OUTPUT_PRICE_PER_MTOK
    if "sonnet" in (model or "").lower():
        return BEDROCK_SONNET_INPUT_PRICE_PER_MTOK, BEDROCK_SONNET_OUTPUT_PRICE_PER_MTOK
    return BEDROCK_INPUT_PRICE_PER_MTOK, BEDROCK_OUTPUT_PRICE_PER_MTOK


def llm_cost_usd(
    input_tokens: int,
    output_tokens: int,
    provider: str = "bedrock",
    model: Optional[str] = None,
    *,
    cache_read_tokens: int = 0,
    cache_write_tokens: int = 0,
) -> float:
    """`input_tokens` is the logical prompt size (cached + uncached); the
    cached portions are re-priced at the provider's read/write multipliers."""
    in_price, out_price = _price_per_mtok(provider, model)
    read_multiplier = (
        OPENAI_COMPAT_CACHE_READ_PRICE_MULTIPLIER
        if (provider or "").strip().lower() == PROVIDER_OPENAI_COMPAT
        else CACHE_READ_PRICE_MULTIPLIER
    )
    uncached = max(0, input_tokens - cache_read_tokens - cache_write_tokens)
    return (
        uncached / 1_000_000 * in_price
        + cache_write_tokens / 1_000_000 * in_price * CACHE_WRITE_PRICE_MULTIPLIER
        + cache_read_tokens / 1_000_000 * in_price * read_multiplier
        + output_tokens / 1_000_000 * out_price
    )


def _default_model_for(provider: str) -> str:
    if provider == PROVIDER_OLLAMA:
        return OLLAMA_MODEL
    if provider == PROVIDER_OPENAI_COMPAT:
        return OPENAI_COMPAT_MODEL
    return BEDROCK_MODEL_ID


def is_local_base_url(url: Optional[str]) -> bool:
    """True for loopback, private-network and link-local hosts — the
    endpoints a `local_only` data policy allows."""
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


def provider_base_url(usage: Optional[Dict[str, Any]], provider: str) -> str:
    options = ((usage or {}).get(PROVIDER_OPTIONS_USAGE_KEY) or {}).get(provider) or {}
    if options.get("base_url"):
        return str(options["base_url"])
    if provider == PROVIDER_OLLAMA:
        return OLLAMA_BASE_URL
    if provider == PROVIDER_OPENAI_COMPAT:
        return OPENAI_COMPAT_BASE_URL
    return ""


def check_data_policy(usage: Optional[Dict[str, Any]], provider: str) -> None:
    """Raise LlmPolicyViolation when `local_only` is set and this provider
    would send prompts (repository code) off the local network."""
    policy = (usage or {}).get(DATA_POLICY_USAGE_KEY) or DATA_POLICY_ALLOW_EXTERNAL
    if policy != DATA_POLICY_LOCAL_ONLY:
        return
    if provider == PROVIDER_BEDROCK:
        raise LlmPolicyViolation("data policy is local_only; Bedrock is an external provider")
    if provider in (PROVIDER_OLLAMA, PROVIDER_OPENAI_COMPAT):
        url = provider_base_url(usage, provider)
        if not is_local_base_url(url):
            raise LlmPolicyViolation(
                f"data policy is local_only; {provider} endpoint {urlparse(url).hostname!r} is not local"
            )


def init_usage(
    provider: Optional[str] = None,
    model: Optional[str] = None,
    *,
    fallback_provider: Optional[str] = None,
    fallback_model: Optional[str] = None,
    cost_cutoff_usd: Optional[float] = None,
    provider_options: Optional[Dict[str, Dict[str, Any]]] = None,
    data_policy: Optional[str] = None,
) -> Dict[str, Any]:
    """`provider_options` maps provider name -> {"base_url", "api_key"} for
    this scan (falling back to env); `data_policy` is `allow_external`
    (default) or `local_only`."""
    provider = (provider or DEFAULT_LLM_PROVIDER or "bedrock").strip().lower()
    model = model or _default_model_for(provider)
    # Ollama primary: no Bedrock spend, so no cutoff. Otherwise use env default
    # unless the caller passes an explicit override (including 0 to disable).
    if provider == "ollama":
        cutoff: Optional[float] = None
    elif cost_cutoff_usd is None:
        cutoff = LLM_COST_CUTOFF_USD
    else:
        cutoff = float(cost_cutoff_usd)
        if cutoff <= 0:
            cutoff = None

    fb_provider = (fallback_provider or DEFAULT_FALLBACK_LLM_PROVIDER or PROVIDER_NONE).strip().lower()
    if fb_provider == PROVIDER_NONE:
        fb_model = ""
    else:
        fb_model = (fallback_model or DEFAULT_FALLBACK_LLM_MODEL or _default_model_for(fb_provider)).strip()
    usage: Dict[str, Any] = {
        "input_tokens": 0,
        "output_tokens": 0,
        "cost_usd": 0.0,
        "estimated_tokens": False,
        "calls": [],
        "provider": provider,
        "model": model,
        "active_provider": provider,
        "active_model": model,
        "cost_cutoff_usd": cutoff,
        "fallback_provider": fb_provider,
        "fallback_model": fb_model,
        "fallback_switched": False,
    }
    if provider_options:
        usage[PROVIDER_OPTIONS_USAGE_KEY] = {
            str(name).strip().lower(): dict(opts or {}) for name, opts in provider_options.items()
        }
    if data_policy:
        usage[DATA_POLICY_USAGE_KEY] = data_policy
    return usage


def estimate_token_count(text: str) -> int:
    return max(1, len(text) // 4)


def record_llm_usage(
    usage: Dict[str, Any],
    step: str,
    input_tokens: int,
    output_tokens: int,
    *,
    estimated: bool = False,
    provider: Optional[str] = None,
    model: Optional[str] = None,
    cache_read_tokens: int = 0,
    cache_write_tokens: int = 0,
    stop_reason: Optional[str] = None,
) -> None:
    """`input_tokens` is the logical prompt size, including any portion served
    from or written to the provider's prompt cache — so token totals measure
    prompt volume, and only `cost_usd` reflects the cache discount."""
    # Parallel triage batches may call this concurrently; keep counters consistent.
    call_provider = (
        provider
        or usage.get("active_provider")
        or usage.get("provider")
        or DEFAULT_LLM_PROVIDER
        or "bedrock"
    ).strip().lower()
    call_model = model or usage.get("active_model") or usage.get("model")
    call_cost = llm_cost_usd(
        input_tokens, output_tokens, call_provider, call_model,
        cache_read_tokens=cache_read_tokens, cache_write_tokens=cache_write_tokens,
    )
    with _USAGE_LOCK:
        usage["input_tokens"] = usage.get("input_tokens", 0) + input_tokens
        usage["output_tokens"] = usage.get("output_tokens", 0) + output_tokens
        usage["cache_read_input_tokens"] = usage.get("cache_read_input_tokens", 0) + cache_read_tokens
        usage["cache_write_input_tokens"] = usage.get("cache_write_input_tokens", 0) + cache_write_tokens
        usage["cost_usd"] = float(usage.get("cost_usd") or 0.0) + call_cost
        if estimated:
            usage["estimated_tokens"] = True
        entry: Dict[str, Any] = {
            "step": step,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "estimated": estimated,
            "provider": call_provider,
            "model": call_model,
            "cost_usd": call_cost,
        }
        if cache_read_tokens or cache_write_tokens:
            entry["cache_read_input_tokens"] = cache_read_tokens
            entry["cache_write_input_tokens"] = cache_write_tokens
        if stop_reason:
            entry["stop_reason"] = stop_reason
        usage.setdefault("calls", []).append(entry)


def record_result_cache_hit(
    usage: Optional[Dict[str, Any]],
    step: str,
    *,
    saved_input_tokens: int = 0,
    saved_output_tokens: int = 0,
) -> None:
    """A response served from the cross-scan result cache: no provider call,
    no tokens, no cost — tracked separately so `calls`/token totals keep
    meaning "what this scan actually sent"."""
    if usage is None:
        return
    with _USAGE_LOCK:
        stats = usage.setdefault("result_cache_stats", {
            "hits": 0, "saved_input_tokens": 0, "saved_output_tokens": 0, "by_step": {},
        })
        stats["hits"] += 1
        stats["saved_input_tokens"] += int(saved_input_tokens or 0)
        stats["saved_output_tokens"] += int(saved_output_tokens or 0)
        stats["by_step"][step] = stats["by_step"].get(step, 0) + 1


def _resolve_provider_for_call(
    usage: Optional[Dict[str, Any]],
    provider: Optional[str],
    model: Optional[str],
) -> Tuple[str, str]:
    """Pick the primary vs fallback provider based on running cost_usd vs
    cutoff. Raises LlmBudgetExhausted past the cutoff when the fallback is
    "none"."""
    primary = (provider or DEFAULT_LLM_PROVIDER or "bedrock").strip().lower()
    primary_model = model or _default_model_for(primary)
    if usage is None:
        return primary, primary_model

    # Prefer primary from usage when caller omits provider (shared scan usage).
    if provider is None and usage.get("provider"):
        primary = str(usage["provider"]).strip().lower()
        primary_model = model or usage.get("model") or primary_model

    cutoff = usage.get("cost_cutoff_usd")
    if cutoff is None or primary == "ollama":
        usage["active_provider"] = primary
        usage["active_model"] = primary_model
        return primary, primary_model

    with _USAGE_LOCK:
        current_cost = float(usage.get("cost_usd") or 0.0)
        if current_cost < float(cutoff):
            usage["active_provider"] = primary
            usage["active_model"] = primary_model
            return primary, primary_model

        fb_provider = (
            str(usage.get("fallback_provider") or DEFAULT_FALLBACK_LLM_PROVIDER or PROVIDER_NONE)
            .strip()
            .lower()
        )
        if fb_provider == PROVIDER_NONE:
            if not usage.get("budget_exhausted"):
                usage["budget_exhausted"] = True
                print(
                    f"  [llm] {primary} spend ${current_cost:.4f} reached cutoff "
                    f"${float(cutoff):.2f} — no fallback provider; remaining LLM work is skipped"
                )
            raise LlmBudgetExhausted(
                f"LLM cost cutoff ${float(cutoff):.2f} reached and no fallback provider is configured"
            )
        fb_model = str(
            usage.get("fallback_model") or DEFAULT_FALLBACK_LLM_MODEL or _default_model_for(fb_provider)
        ).strip()
        if not usage.get("fallback_switched"):
            usage["fallback_switched"] = True
            print(
                f"  [llm] {primary} spend ${current_cost:.4f} reached cutoff "
                f"${float(cutoff):.2f} — continuing on {fb_provider}/{fb_model}"
            )
        usage["active_provider"] = fb_provider
        usage["active_model"] = fb_model
        return fb_provider, fb_model


def usage_cost_summary(usage: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    usage = usage or init_usage()
    provider = (usage.get("provider") or DEFAULT_LLM_PROVIDER or "bedrock").strip().lower()
    model = usage.get("model") or _default_model_for(provider)
    active_provider = (
        usage.get("active_provider") or provider
    )
    active_model = usage.get("active_model") or model
    inp = usage.get("input_tokens", 0)
    out = usage.get("output_tokens", 0)
    calls = usage.get("calls", [])
    by_step: Dict[str, Dict[str, int]] = {}
    for call in calls:
        bucket = by_step.setdefault(
            call["step"], {"calls": 0, "input_tokens": 0, "output_tokens": 0}
        )
        bucket["calls"] += 1
        bucket["input_tokens"] += call["input_tokens"]
        bucket["output_tokens"] += call["output_tokens"]
        if call.get("cache_read_input_tokens") or call.get("cache_write_input_tokens"):
            bucket["cache_read_input_tokens"] = (
                bucket.get("cache_read_input_tokens", 0) + int(call.get("cache_read_input_tokens") or 0)
            )
            bucket["cache_write_input_tokens"] = (
                bucket.get("cache_write_input_tokens", 0) + int(call.get("cache_write_input_tokens") or 0)
            )
        if call.get("stop_reason") == "max_tokens":
            bucket["truncated"] = bucket.get("truncated", 0) + 1
    result_cache = usage.get("result_cache_stats") or {}
    for step_name, hits in (result_cache.get("by_step") or {}).items():
        bucket = by_step.setdefault(
            step_name, {"calls": 0, "input_tokens": 0, "output_tokens": 0}
        )
        bucket["result_cache_hits"] = hits
    # Prefer accumulated per-call cost (correct after mid-scan Bedrock→Ollama switch).
    cost = usage.get("cost_usd")
    if cost is None:
        cost = llm_cost_usd(inp, out, provider, active_model)
    in_price, out_price = _price_per_mtok(active_provider, active_model)
    return {
        "provider": provider,
        "model": model,
        "active_provider": active_provider,
        "active_model": active_model,
        "fallback_switched": bool(usage.get("fallback_switched")),
        "budget_exhausted": bool(usage.get("budget_exhausted")),
        "cost_cutoff_usd": usage.get("cost_cutoff_usd"),
        "input_tokens": inp,
        "output_tokens": out,
        "total_tokens": inp + out,
        "cost_usd": float(cost),
        "call_count": len(calls),
        "by_step": by_step,
        "estimated": bool(usage.get("estimated_tokens")),
        "input_price_per_mtok": in_price,
        "output_price_per_mtok": out_price,
        # Provider prompt-cache volume is a billing discount, not removed
        # tokens — it is already included in input_tokens above.
        "cache_read_input_tokens": int(usage.get("cache_read_input_tokens") or 0),
        "cache_write_input_tokens": int(usage.get("cache_write_input_tokens") or 0),
        # Cross-scan result reuse: calls never sent at all.
        "result_cache_hits": int(result_cache.get("hits") or 0),
        "result_cache_saved_tokens": int(result_cache.get("saved_input_tokens") or 0)
        + int(result_cache.get("saved_output_tokens") or 0),
    }


def call_llm(
    system: str,
    user: str,
    max_tokens: int = 4096,
    temperature: float = 0.0,
    retries: int = 3,
    *,
    usage: Optional[Dict[str, Any]] = None,
    step: str = "unknown",
    provider: Optional[str] = None,
    model: Optional[str] = None,
    json_mode: bool = False,
    meta_out: Optional[Dict[str, Any]] = None,
) -> str:
    """`meta_out`, when given, receives this call's own provider, model and
    recorded token counts (zero on a result-cache hit) — the only reliable
    per-call figure when parallel workers share one usage dict."""
    provider, model = _resolve_provider_for_call(usage, provider, model)
    if provider not in KNOWN_PROVIDERS:
        # Used to fall through to Bedrock silently — a typo'd provider would
        # have shipped code to AWS on a scan configured for a local model.
        raise ValueError(f"unknown LLM provider {provider!r}; expected one of {KNOWN_PROVIDERS}")
    model = model or _default_model_for(provider)
    if not model:
        raise ValueError(f"no model configured for LLM provider {provider!r}")
    check_data_policy(usage, provider)

    # Cross-scan result reuse (see RESULT_CACHE_VERSION). Only JSON-mode calls
    # are eligible: their completeness can be checked structurally before a
    # response is stored, so a truncated or garbled answer is never replayed.
    result_cache = usage.get(RESULT_CACHE_USAGE_KEY) if usage is not None else None
    cache_key: Optional[str] = None
    if result_cache is not None and json_mode:
        cache_key = result_cache_key(
            system, user, provider=provider, model=model,
            max_tokens=max_tokens, temperature=temperature, json_mode=json_mode,
        )
        try:
            hit = result_cache.get(cache_key)
        except Exception as exc:  # noqa: BLE001 — a cache fault must never fail the scan
            print(f"  [llm] result cache read failed ({exc}); calling the model")
            hit = None
        if hit is not None:
            record_result_cache_hit(
                usage, step,
                saved_input_tokens=hit.get("input_tokens") or 0,
                saved_output_tokens=hit.get("output_tokens") or 0,
            )
            if meta_out is not None:
                meta_out.update({
                    "provider": provider, "model": model,
                    "input_tokens": 0, "output_tokens": 0, "result_cache_hit": True,
                })
            return hit["text"]

    caller_meta = meta_out
    meta_out = {}
    if provider == "ollama":
        text = _call_ollama(
            system,
            user,
            model,
            max_tokens,
            temperature,
            retries,
            usage=usage,
            step=step,
            json_mode=json_mode,
            provider_label=provider,
            model_label=model,
            meta_out=meta_out,
        )
    elif provider == PROVIDER_OPENAI_COMPAT:
        options = ((usage or {}).get(PROVIDER_OPTIONS_USAGE_KEY) or {}).get(provider) or {}
        text = _call_openai_compat(
            system,
            user,
            model,
            max_tokens,
            temperature,
            retries,
            usage=usage,
            step=step,
            json_mode=json_mode,
            base_url=provider_base_url(usage, provider),
            api_key=str(options.get("api_key") or OPENAI_COMPAT_API_KEY or ""),
            meta_out=meta_out,
        )
    else:
        cache_system = should_cache_system_prompt(system, model)

        def _bedrock_call() -> str:
            return _call_bedrock(
                system,
                user,
                model,
                max_tokens,
                temperature,
                retries,
                usage=usage,
                step=step,
                provider_label=provider,
                model_label=model,
                json_mode=json_mode,
                cache_system=cache_system,
                meta_out=meta_out,
            )

        gate = _warm_gate_for(model, system) if cache_system else None
        leader = False
        text = ""
        if gate is not None and not gate.is_warm():
            # Only the warming call runs under the lock. Waiters get through
            # one at a time, find it warm, and leave the lock before calling
            # so the followers still run in parallel. If the leader raises,
            # the gate stays cold and the next waiter becomes the leader.
            with gate.lock:
                if not gate.is_warm():
                    leader = True
                    text = _bedrock_call()
                    gate.warmed_at = time.monotonic()
        if not leader:
            text = _bedrock_call()

    if cache_key is not None and is_complete_json_response(text, meta_out.get("stop_reason")):
        try:
            result_cache.put(
                cache_key, step=step, model=model, text=text,
                input_tokens=meta_out.get("input_tokens"),
                output_tokens=meta_out.get("output_tokens"),
            )
        except Exception as exc:  # noqa: BLE001
            print(f"  [llm] result cache write failed ({exc})")
    if caller_meta is not None:
        caller_meta.update(meta_out)
        caller_meta.update({"provider": provider, "model": model})
    return text


# Bump whenever prompt construction or response handling changes in a way that
# should invalidate previously cached responses even if the prompt bytes match.
RESULT_CACHE_VERSION = "1"
# The cache object rides on the shared scan usage dict — the one object every
# LLM-calling stage already threads through — rather than a new parameter on
# every call site. It must expose get(key) -> {text, input_tokens,
# output_tokens} | None and put(key, *, step, model, text, input_tokens,
# output_tokens).
RESULT_CACHE_USAGE_KEY = "_result_cache"


def result_cache_key(
    system: str,
    user: str,
    *,
    provider: str,
    model: str,
    max_tokens: int,
    temperature: float,
    json_mode: bool,
) -> str:
    import hashlib

    digest = hashlib.sha256()
    for part in (
        RESULT_CACHE_VERSION, provider, model, str(max_tokens), repr(float(temperature)),
        "json" if json_mode else "text", system, user,
    ):
        digest.update(part.encode("utf-8"))
        digest.update(b"\x00")
    return digest.hexdigest()


def is_complete_json_response(text: str, stop_reason: Optional[str]) -> bool:
    """True only for an untruncated response that parses as JSON outright —
    salvaged/repaired output is good enough to use once, never to replay."""
    if (stop_reason or "") in ("max_tokens", "length"):
        return False
    if not (text or "").strip():
        return False
    try:
        parsed = extract_json(text)
    except (json.JSONDecodeError, ValueError):
        return False
    return isinstance(parsed, (dict, list))


def _call_bedrock(
    system: str,
    user: str,
    model_id: str,
    max_tokens: int,
    temperature: float,
    retries: int,
    *,
    usage: Optional[Dict[str, Any]],
    step: str,
    provider_label: str = "bedrock",
    model_label: Optional[str] = None,
    json_mode: bool = False,
    cache_system: bool = False,
    meta_out: Optional[Dict[str, Any]] = None,
) -> str:
    messages: List[Dict[str, str]] = [{"role": "user", "content": user}]
    if json_mode:
        # Claude continues from the prefilled "{" — prepend when assembling text.
        messages.append({"role": "assistant", "content": "{"})
    system_field: Any = system
    if cache_system:
        system_field = [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}]
    body = json.dumps(
        {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens,
            "temperature": temperature,
            "system": system_field,
            "messages": messages,
        }
    )
    last_exc: Optional[Exception] = None
    for attempt in range(retries):
        try:
            resp = _bedrock.invoke_model(
                modelId=model_id,
                body=body,
                contentType="application/json",
                accept="application/json",
            )
            payload = json.loads(resp["body"].read())
            text = "".join(b.get("text", "") for b in payload.get("content", []))
            if json_mode and text and not text.lstrip().startswith("{"):
                text = "{" + text
            stop_reason = payload.get("stop_reason") or ""
            # Every response is billed, including an empty one that gets
            # retried — record it before deciding whether to retry.
            recorded = _record_llm_usage_from_meta(
                usage,
                step,
                system,
                user,
                text,
                _bedrock_usage_meta(payload.get("usage")),
                provider=provider_label,
                model=model_label or model_id,
                stop_reason=stop_reason,
            )
            if not text.strip():
                if attempt < retries - 1:
                    wait = 2**attempt
                    print(
                        f"  [bedrock] empty response (stop_reason={stop_reason!r}), "
                        f"retrying in {wait}s..."
                    )
                    time.sleep(wait)
                    continue
                print(f"  [bedrock] empty response after {retries} attempt(s) (stop_reason={stop_reason!r})")
            if meta_out is not None:
                meta_out.update(recorded)
                meta_out["stop_reason"] = stop_reason
            return text
        except Exception as exc:  # noqa: BLE001 — throttle + network
            last_exc = exc
            wait = 2**attempt
            print(f"  [bedrock] error ({exc}), retrying in {wait}s...")
            time.sleep(wait)
    raise last_exc  # type: ignore[misc]


def _bedrock_usage_meta(raw: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Anthropic reports input_tokens *excluding* cache reads/writes; fold them
    back in so input_tokens stays the logical prompt size."""
    if not raw:
        return raw
    read = int(raw.get("cache_read_input_tokens") or 0)
    write = int(raw.get("cache_creation_input_tokens") or 0)
    meta = dict(raw)
    if raw.get("input_tokens") is not None:
        meta["input_tokens"] = int(raw["input_tokens"]) + read + write
    meta["cache_read_tokens"] = read
    meta["cache_write_tokens"] = write
    return meta


def _call_ollama(
    system: str,
    user: str,
    model: str,
    max_tokens: int,
    temperature: float,
    retries: int,
    *,
    usage: Optional[Dict[str, Any]],
    step: str,
    json_mode: bool = False,
    provider_label: str = "ollama",
    model_label: Optional[str] = None,
    meta_out: Optional[Dict[str, Any]] = None,
) -> str:
    payload_body: Dict[str, Any] = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "stream": False,
        "options": {
            "temperature": temperature,
            "num_predict": max_tokens,
            "num_ctx": OLLAMA_NUM_CTX,
        },
    }
    if json_mode:
        payload_body["format"] = "json"
    last_exc: Optional[Exception] = None
    timeout = int(os.environ.get("OLLAMA_REQUEST_TIMEOUT", str(OLLAMA_REQUEST_TIMEOUT)))
    for attempt in range(retries):
        try:
            resp = requests.post(
                f"{OLLAMA_BASE_URL.rstrip('/')}/api/chat",
                json=payload_body,
                timeout=timeout,
            )
            resp.raise_for_status()
            payload = resp.json()
            text = (payload.get("message") or {}).get("content", "")
            meta = {
                "input_tokens": payload.get("prompt_eval_count"),
                "output_tokens": payload.get("eval_count"),
            }
            stop_reason = payload.get("done_reason") or ""
            recorded = _record_llm_usage_from_meta(
                usage,
                step,
                system,
                user,
                text,
                meta,
                provider=provider_label,
                model=model_label or model,
                stop_reason=stop_reason,
            )
            if meta_out is not None:
                meta_out.update(recorded)
                meta_out["stop_reason"] = stop_reason
            return text
        except requests.RequestException as exc:
            last_exc = exc
            wait = 2**attempt
            print(f"  [ollama] request failed ({exc}), retrying in {wait}s...")
            time.sleep(wait)
    raise last_exc  # type: ignore[misc]


# Base URLs whose server rejected `response_format` — remembered so every
# later call skips straight to the plain request instead of paying a 400 first.
_RESPONSE_FORMAT_UNSUPPORTED: set = set()
_RESPONSE_FORMAT_LOCK = threading.Lock()
# Reasoning models served locally (DeepSeek-R1, Qwen3, ...) often prepend a
# <think> block even in JSON mode.
_THINK_BLOCK_RE = re.compile(r"^\s*<think>.*?</think>\s*", re.DOTALL)


class _NonRetryableHttpError(RuntimeError):
    pass


def _call_openai_compat(
    system: str,
    user: str,
    model: str,
    max_tokens: int,
    temperature: float,
    retries: int,
    *,
    usage: Optional[Dict[str, Any]],
    step: str,
    json_mode: bool = False,
    base_url: str = "",
    api_key: str = "",
    meta_out: Optional[Dict[str, Any]] = None,
) -> str:
    """One chat-completions call against any OpenAI-compatible server.
    429/5xx/network errors are retried with backoff; other 4xx are not (a
    bad model name or key won't fix itself), except a 400 caused by
    `response_format`, which is retried once without it."""
    url = f"{(base_url or OPENAI_COMPAT_BASE_URL).rstrip('/')}/chat/completions"
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    body: Dict[str, Any] = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "max_tokens": max_tokens,
        "temperature": temperature,
        "stream": False,
    }
    with _RESPONSE_FORMAT_LOCK:
        use_response_format = json_mode and url not in _RESPONSE_FORMAT_UNSUPPORTED
    timeout = int(os.environ.get("OPENAI_COMPAT_REQUEST_TIMEOUT", str(OPENAI_COMPAT_REQUEST_TIMEOUT)))
    last_exc: Optional[Exception] = None
    attempt = 0
    while attempt < retries:
        payload_body = dict(body)
        if use_response_format:
            payload_body["response_format"] = {"type": "json_object"}
        try:
            resp = requests.post(url, json=payload_body, headers=headers, timeout=timeout)
            if resp.status_code == 400 and use_response_format and "response_format" in (resp.text or ""):
                with _RESPONSE_FORMAT_LOCK:
                    _RESPONSE_FORMAT_UNSUPPORTED.add(url)
                use_response_format = False
                print("  [openai_compat] server rejected response_format; retrying without it")
                continue  # does not consume a retry
            if 400 <= resp.status_code < 500 and resp.status_code not in (408, 429):
                # Never echo the request (it carries the key header) — only
                # the status and a bounded slice of the server's message.
                raise _NonRetryableHttpError(
                    f"openai_compat HTTP {resp.status_code}: {(resp.text or '')[:300]}"
                )
            resp.raise_for_status()
            payload = resp.json()
            choice = (payload.get("choices") or [{}])[0]
            text = ((choice.get("message") or {}).get("content")) or ""
            if json_mode:
                text = _THINK_BLOCK_RE.sub("", text)
            raw_usage = payload.get("usage") or {}
            meta: Dict[str, Any] = {
                "input_tokens": raw_usage.get("prompt_tokens"),
                "output_tokens": raw_usage.get("completion_tokens"),
                "cache_read_tokens": int(
                    ((raw_usage.get("prompt_tokens_details") or {}).get("cached_tokens")) or 0
                ),
            }
            stop_reason = choice.get("finish_reason") or ""
            recorded = _record_llm_usage_from_meta(
                usage,
                step,
                system,
                user,
                text,
                meta,
                provider=PROVIDER_OPENAI_COMPAT,
                model=model,
                stop_reason=stop_reason,
            )
            if meta_out is not None:
                meta_out.update(recorded)
                meta_out["stop_reason"] = stop_reason
            return text
        except _NonRetryableHttpError:
            raise
        except (requests.RequestException, ValueError) as exc:
            last_exc = exc
            wait = 2**attempt
            print(f"  [openai_compat] request failed ({type(exc).__name__}), retrying in {wait}s...")
            time.sleep(wait)
            attempt += 1
    raise last_exc  # type: ignore[misc]


def _record_llm_usage_from_meta(
    usage: Optional[Dict[str, Any]],
    step: str,
    system: str,
    user: str,
    text: str,
    meta: Optional[Dict[str, Any]],
    *,
    provider: Optional[str] = None,
    model: Optional[str] = None,
    stop_reason: Optional[str] = None,
) -> Dict[str, Any]:
    """Record one provider response; returns the token counts it recorded."""
    meta = meta or {}
    inp = meta.get("input_tokens")
    out = meta.get("output_tokens")
    estimated = False
    if inp is None or out is None:
        inp = estimate_token_count(system) + estimate_token_count(user)
        out = estimate_token_count(text)
        estimated = True
    recorded = {"input_tokens": int(inp), "output_tokens": int(out)}
    if usage is None:
        return recorded
    record_llm_usage(
        usage,
        step,
        int(inp),
        int(out),
        estimated=estimated,
        provider=provider,
        model=model,
        cache_read_tokens=int(meta.get("cache_read_tokens") or 0),
        cache_write_tokens=int(meta.get("cache_write_tokens") or 0),
        stop_reason=stop_reason,
    )
    return recorded


def extract_json(text: str) -> Any:
    cleaned = text.strip()
    cleaned = re.sub(r"^```(?:json)?", "", cleaned).strip()
    cleaned = re.sub(r"```$", "", cleaned).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    starts = [i for i in (cleaned.find("["), cleaned.find("{")) if i != -1]
    if not starts:
        raise ValueError(f"No JSON found in model output: {cleaned[:200]!r}")
    start = min(starts)
    closing = "]" if cleaned[start] == "[" else "}"
    end = cleaned.rfind(closing)
    if end == -1 or end < start:
        raise ValueError(f"Unbalanced JSON in model output: {cleaned[:200]!r}")
    return json.loads(cleaned[start : end + 1])


# Array-returning prompts wrap their list in one of these keys so JSON mode
# (Bedrock prefills "{") and the requested shape agree.
ARRAY_ENVELOPE_KEYS = ("findings", "decisions", "rules", "hypotheses")


def coerce_to_list(data: Any) -> List[Any]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ARRAY_ENVELOPE_KEYS + ("patterns", "items", "results", "data"):
            nested = data.get(key)
            if isinstance(nested, list):
                return nested
    return []


def repair_truncated_json(text: str) -> str:
    """Best-effort close of truncated JSON (open strings / braces / brackets)."""
    s = (text or "").strip()
    s = re.sub(r"^```(?:json)?\s*", "", s).strip()
    s = re.sub(r"\s*```\s*$", "", s).strip()
    if not s:
        return s

    in_string = False
    escape = False
    stack: List[str] = []
    for ch in s:
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
            continue
        if ch in "{[":
            stack.append("}" if ch == "{" else "]")
        elif ch in "}]" and stack and stack[-1] == ch:
            stack.pop()

    s = re.sub(r",\s*$", "", s.rstrip())
    if in_string:
        s += '"'
        s = re.sub(r",\s*$", "", s.rstrip())
    while stack:
        s += stack.pop()
    return s


def salvage_json_array_items(raw: str) -> List[Any]:
    """Extract dict items from a (possibly truncated) JSON array."""
    text = raw.strip()
    text = re.sub(r"^```(?:json)?", "", text).strip()
    text = re.sub(r"```$", "", text).strip()
    start = text.find("[")
    if start < 0:
        return salvage_json_objects(raw)
    decoder = json.JSONDecoder()
    pos = start + 1
    items: List[Any] = []
    while pos < len(text):
        while pos < len(text) and text[pos] in " \t\n\r,":
            pos += 1
        if pos >= len(text) or text[pos] == "]":
            break
        try:
            obj, end = decoder.raw_decode(text, pos)
            if isinstance(obj, dict):
                items.append(obj)
            pos = end
        except json.JSONDecodeError:
            fragment = text[pos:]
            repaired = repair_truncated_json(
                fragment if fragment.lstrip().startswith("{") else "{" + fragment
            )
            try:
                obj = json.loads(repaired)
                if isinstance(obj, dict):
                    items.append(obj)
            except json.JSONDecodeError:
                items.extend(salvage_json_objects(fragment))
            break
    return items


def salvage_json_objects(raw: str) -> List[Any]:
    text = raw.strip()
    text = re.sub(r"^```(?:json)?", "", text).strip()
    text = re.sub(r"```$", "", text).strip()
    objects: List[Any] = []
    depth = 0
    start: Optional[int] = None
    in_string = False
    escape = False
    for i, ch in enumerate(text):
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
            continue
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth > 0:
            depth -= 1
            if depth == 0 and start is not None:
                chunk = text[start : i + 1]
                try:
                    obj = json.loads(chunk)
                    if isinstance(obj, dict):
                        objects.append(obj)
                except json.JSONDecodeError:
                    pass
                start = None
    if depth > 0 and start is not None:
        repaired = repair_truncated_json(text[start:])
        try:
            obj = json.loads(repaired)
            if isinstance(obj, dict):
                objects.append(obj)
        except json.JSONDecodeError:
            pass
    return objects


def parse_llm_json_array(raw: str) -> Tuple[List[Any], Optional[str]]:
    try:
        parsed = extract_json(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        salvaged = salvage_json_array_items(raw) or salvage_json_objects(raw)
        if salvaged:
            return salvaged, None
        return [], str(exc)
    if isinstance(parsed, dict):
        for key in ARRAY_ENVELOPE_KEYS:
            if isinstance(parsed.get(key), list):
                # A well-formed envelope is authoritative, including an empty
                # one ("nothing found") — never a parse failure.
                return parsed[key], None
    items = coerce_to_list(parsed)
    if items:
        return items, None
    if isinstance(parsed, dict) and ("matcher" in parsed or "cwe" in parsed):
        return [parsed], None
    salvaged = salvage_json_array_items(raw) or salvage_json_objects(raw)
    if salvaged:
        return salvaged, None
    if parsed == []:
        # A well-formed empty array is a legitimate "I found nothing" answer,
        # not a parse failure. Returning an error here used to make every
        # clean file/chunk re-send its whole prompt for a pointless second
        # opinion (doubling cost on the most common outcome) and then get
        # recorded as a scan error.
        return [], None
    if parsed == {}:
        return [], "empty object"
    return [], f"expected JSON array, got {type(parsed).__name__}"


def salvage_synthesis_dict(raw: str) -> Optional[Dict[str, Any]]:
    """Recover a synthesis payload when the top-level JSON object is truncated."""
    text = (raw or "").strip()
    text = re.sub(r"^```(?:json)?\s*", "", text).strip()
    text = re.sub(r"\s*```\s*$", "", text).strip()

    for candidate in (text, repair_truncated_json(text)):
        try:
            data = json.loads(candidate)
            if isinstance(data, dict) and isinstance(data.get("findings"), list):
                return data
        except json.JSONDecodeError:
            pass

    match = re.search(r'"findings"\s*:\s*\[', text)
    if not match:
        return None
    items = salvage_json_array_items(text[match.end() - 1 :])
    if not items:
        return None
    result: Dict[str, Any] = {"findings": items}
    for key in ("overall_severity", "deployment_recommendation"):
        km = re.search(rf'"{key}"\s*:\s*"((?:\\.|[^"\\])*)"', text)
        if km:
            result[key] = km.group(1)
    return result


def parse_llm_json_dict(raw: str) -> Tuple[Dict[str, Any], Optional[str]]:
    """Parse a single JSON object from LLM output; ignores trailing extra text."""
    text = (raw or "").strip()
    text = re.sub(r"^```(?:json)?\s*", "", text).strip()
    text = re.sub(r"\s*```\s*$", "", text).strip()
    decoder = json.JSONDecoder()
    obj_idx = text.find("{")
    last_err = "expected JSON object"
    if obj_idx >= 0:
        try:
            data, _end = decoder.raw_decode(text[obj_idx:])
            if isinstance(data, dict):
                return data, None
        except json.JSONDecodeError as exc:
            last_err = str(exc)
            repaired = repair_truncated_json(text[obj_idx:])
            try:
                data = json.loads(repaired)
                if isinstance(data, dict):
                    return data, None
            except json.JSONDecodeError:
                pass
    try:
        parsed = extract_json(raw)
        if isinstance(parsed, dict):
            return parsed, None
        if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
            return parsed[0], None
    except (json.JSONDecodeError, ValueError) as exc:
        last_err = str(exc)
    salvaged_synthesis = salvage_synthesis_dict(raw)
    if salvaged_synthesis:
        return salvaged_synthesis, None
    salvaged = salvage_json_objects(raw)
    if salvaged and isinstance(salvaged[0], dict):
        for obj in salvaged:
            if isinstance(obj, dict) and "findings" in obj:
                return obj, None
        return salvaged[0], None
    return {}, last_err

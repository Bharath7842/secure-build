"""Shared LLM client — Bedrock (Claude) and Ollama (local)."""

from __future__ import annotations

import json
import os
import re
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

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

_USAGE_LOCK = threading.Lock()
OLLAMA_INPUT_PRICE_PER_MTOK = float(os.environ.get("OLLAMA_INPUT_PRICE_PER_MTOK", "0.00"))
OLLAMA_OUTPUT_PRICE_PER_MTOK = float(os.environ.get("OLLAMA_OUTPUT_PRICE_PER_MTOK", "0.00"))

# Soft Bedrock spend cap: once estimated cost_usd reaches this, remaining calls
# route to the fallback Ollama model. Disabled when primary provider is ollama.
# Parallel workers may slightly overshoot before the next call sees the updated total.
LLM_COST_CUTOFF_USD = float(os.environ.get("LLM_COST_CUTOFF_USD", "2.0"))
DEFAULT_FALLBACK_LLM_PROVIDER = "ollama"
DEFAULT_FALLBACK_LLM_MODEL = os.environ.get("FALLBACK_LLM_MODEL", OLLAMA_MODEL)

_bedrock = boto3.client("bedrock-runtime", region_name=AWS_REGION)


def _price_per_mtok(provider: str) -> Tuple[float, float]:
    if (provider or "").strip().lower() == "ollama":
        return OLLAMA_INPUT_PRICE_PER_MTOK, OLLAMA_OUTPUT_PRICE_PER_MTOK
    return BEDROCK_INPUT_PRICE_PER_MTOK, BEDROCK_OUTPUT_PRICE_PER_MTOK


def llm_cost_usd(input_tokens: int, output_tokens: int, provider: str = "bedrock") -> float:
    in_price, out_price = _price_per_mtok(provider)
    return input_tokens / 1_000_000 * in_price + output_tokens / 1_000_000 * out_price


def init_usage(
    provider: Optional[str] = None,
    model: Optional[str] = None,
    *,
    fallback_provider: Optional[str] = None,
    fallback_model: Optional[str] = None,
    cost_cutoff_usd: Optional[float] = None,
) -> Dict[str, Any]:
    provider = (provider or DEFAULT_LLM_PROVIDER or "bedrock").strip().lower()
    model = model or (OLLAMA_MODEL if provider == "ollama" else BEDROCK_MODEL_ID)
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

    fb_provider = (fallback_provider or DEFAULT_FALLBACK_LLM_PROVIDER).strip().lower()
    fb_model = (fallback_model or DEFAULT_FALLBACK_LLM_MODEL or OLLAMA_MODEL).strip()
    return {
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
) -> None:
    # Parallel triage batches may call this concurrently; keep counters consistent.
    call_provider = (
        provider
        or usage.get("active_provider")
        or usage.get("provider")
        or DEFAULT_LLM_PROVIDER
        or "bedrock"
    ).strip().lower()
    call_model = model or usage.get("active_model") or usage.get("model")
    call_cost = llm_cost_usd(input_tokens, output_tokens, call_provider)
    with _USAGE_LOCK:
        usage["input_tokens"] = usage.get("input_tokens", 0) + input_tokens
        usage["output_tokens"] = usage.get("output_tokens", 0) + output_tokens
        usage["cost_usd"] = float(usage.get("cost_usd") or 0.0) + call_cost
        if estimated:
            usage["estimated_tokens"] = True
        usage.setdefault("calls", []).append(
            {
                "step": step,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "estimated": estimated,
                "provider": call_provider,
                "model": call_model,
                "cost_usd": call_cost,
            }
        )


def _resolve_provider_for_call(
    usage: Optional[Dict[str, Any]],
    provider: Optional[str],
    model: Optional[str],
) -> Tuple[str, str]:
    """Pick Bedrock vs fallback Ollama based on running cost_usd vs cutoff."""
    primary = (provider or DEFAULT_LLM_PROVIDER or "bedrock").strip().lower()
    primary_model = model or (
        OLLAMA_MODEL if primary == "ollama" else BEDROCK_MODEL_ID
    )
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
            str(usage.get("fallback_provider") or DEFAULT_FALLBACK_LLM_PROVIDER)
            .strip()
            .lower()
        )
        fb_model = str(
            usage.get("fallback_model") or DEFAULT_FALLBACK_LLM_MODEL or OLLAMA_MODEL
        ).strip()
        if not usage.get("fallback_switched"):
            usage["fallback_switched"] = True
            print(
                f"  [llm] Bedrock spend ${current_cost:.4f} reached cutoff "
                f"${float(cutoff):.2f} — continuing on {fb_provider}/{fb_model}"
            )
        usage["active_provider"] = fb_provider
        usage["active_model"] = fb_model
        return fb_provider, fb_model


def usage_cost_summary(usage: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    usage = usage or init_usage()
    provider = (usage.get("provider") or DEFAULT_LLM_PROVIDER or "bedrock").strip().lower()
    model = usage.get("model") or (OLLAMA_MODEL if provider == "ollama" else BEDROCK_MODEL_ID)
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
    # Prefer accumulated per-call cost (correct after mid-scan Bedrock→Ollama switch).
    cost = usage.get("cost_usd")
    if cost is None:
        cost = llm_cost_usd(inp, out, provider)
    in_price, out_price = _price_per_mtok(provider)
    return {
        "provider": provider,
        "model": model,
        "active_provider": active_provider,
        "active_model": active_model,
        "fallback_switched": bool(usage.get("fallback_switched")),
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
) -> str:
    provider, model = _resolve_provider_for_call(usage, provider, model)
    if provider == "ollama":
        return _call_ollama(
            system,
            user,
            model or OLLAMA_MODEL,
            max_tokens,
            temperature,
            retries,
            usage=usage,
            step=step,
            json_mode=json_mode,
            provider_label=provider,
            model_label=model or OLLAMA_MODEL,
        )
    return _call_bedrock(
        system,
        user,
        model or BEDROCK_MODEL_ID,
        max_tokens,
        temperature,
        retries,
        usage=usage,
        step=step,
        provider_label=provider,
        model_label=model or BEDROCK_MODEL_ID,
        json_mode=json_mode,
    )


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
) -> str:
    messages: List[Dict[str, str]] = [{"role": "user", "content": user}]
    if json_mode:
        # Claude continues from the prefilled "{" — prepend when assembling text.
        messages.append({"role": "assistant", "content": "{"})
    body = json.dumps(
        {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens,
            "temperature": temperature,
            "system": system,
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
            _record_llm_usage_from_meta(
                usage,
                step,
                system,
                user,
                text,
                payload.get("usage"),
                provider=provider_label,
                model=model_label or model_id,
            )
            return text
        except Exception as exc:  # noqa: BLE001 — throttle + network
            last_exc = exc
            wait = 2**attempt
            print(f"  [bedrock] error ({exc}), retrying in {wait}s...")
            time.sleep(wait)
    raise last_exc  # type: ignore[misc]


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
            _record_llm_usage_from_meta(
                usage,
                step,
                system,
                user,
                text,
                meta,
                provider=provider_label,
                model=model_label or model,
            )
            return text
        except requests.RequestException as exc:
            last_exc = exc
            wait = 2**attempt
            print(f"  [ollama] request failed ({exc}), retrying in {wait}s...")
            time.sleep(wait)
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
) -> None:
    if usage is None:
        return
    meta = meta or {}
    inp = meta.get("input_tokens")
    out = meta.get("output_tokens")
    estimated = False
    if inp is None or out is None:
        inp = estimate_token_count(system) + estimate_token_count(user)
        out = estimate_token_count(text)
        estimated = True
    record_llm_usage(
        usage,
        step,
        int(inp),
        int(out),
        estimated=estimated,
        provider=provider,
        model=model,
    )


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


def coerce_to_list(data: Any) -> List[Any]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("patterns", "items", "results", "data"):
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

"""Optional Langfuse tracing of SAST LLM calls.

Off unless the scan's usage dict carries `USAGE_KEY` (set by
`agent_bridge.llm_usage_options` from `LANGFUSE_HOST` + both keys). Each finished
call becomes one observation, and every call of a scan shares one trace and one
session named by the scan id. Spans go to Langfuse's OTLP/HTTP endpoint as JSON,
so no SDK is needed.

A scan must behave the same with Langfuse up, down or absent, so `record` only
puts the call on a bounded queue and one daemon thread sends it. A full queue
drops the record; a failed send drops the batch and pauses sending for
`PAUSE_SECONDS`. Nothing here raises into a scan.

Prompts are repository code (LLM03): the host is checked against the endpoint
policy again before every send, redirects are refused, and secret values are
masked here even when the scan's own `secret-masking` is off. The keys are never
printed.

A separate module because `agent_bridge` reloads `llm_client` on every scan; the
queue and its thread must outlive that.
"""

from __future__ import annotations

import atexit
import hashlib
import json
import queue
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

import requests

import endpoint_policy
import secret_mask

USAGE_KEY = "_llm_tracing"
OTLP_PATH = "/api/public/otel/v1/traces"
MAX_QUEUE = 500
MAX_BATCH = 20
MAX_TEXT_CHARS = 100_000
ERROR_CHARS = 300
PAUSE_SECONDS = 60.0
TIMEOUT = (3, 10)  # connect, read

_QUEUE: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=MAX_QUEUE)
_LOCK = threading.Lock()
_worker: Optional[threading.Thread] = None
_paused_until = 0.0
dropped = 0  # records lost to a full queue, a pause or a failed send


def enabled(usage: Optional[Dict[str, Any]]) -> bool:
    ctx = (usage or {}).get(USAGE_KEY) or {}
    return bool(ctx.get("host") and ctx.get("public_key") and ctx.get("secret_key"))


def record(usage: Optional[Dict[str, Any]], **call: Any) -> None:
    """Queue one finished call. Never blocks and never raises."""
    global dropped
    if not enabled(usage):
        return
    try:
        if time.monotonic() < _paused_until:
            dropped += 1
            return
        _QUEUE.put_nowait({"ctx": dict(usage[USAGE_KEY]), **call})
        _ensure_worker()
    except queue.Full:
        dropped += 1
    except Exception:  # noqa: BLE001 - monitoring must never fail a call
        pass


def flush(timeout: float = 3.0) -> None:
    """Wait (bounded) until everything queued so far has been sent or dropped."""
    deadline = time.monotonic() + timeout
    while _QUEUE.unfinished_tasks and time.monotonic() < deadline:
        time.sleep(0.02)


def trace_id(scan_id: Optional[str]) -> str:
    return hashlib.sha256(f"secure-build-scan:{scan_id}".encode("utf-8")).hexdigest()[:32]


def _ensure_worker() -> None:
    global _worker
    with _LOCK:
        if _worker is None or not _worker.is_alive():
            _worker = threading.Thread(target=_run, name="llm-tracing", daemon=True)
            _worker.start()


def _run() -> None:
    while True:
        batch = [_QUEUE.get()]
        while len(batch) < MAX_BATCH:
            try:
                batch.append(_QUEUE.get_nowait())
            except queue.Empty:
                break
        try:
            _send(batch)
        finally:
            for _ in batch:
                _QUEUE.task_done()


def _send(batch: List[Dict[str, Any]]) -> None:
    global _paused_until, dropped
    by_target: Dict[tuple, List[Dict[str, Any]]] = {}
    for item in batch:
        ctx = item["ctx"]
        key = (ctx["host"].rstrip("/"), ctx["public_key"], ctx["secret_key"])
        by_target.setdefault(key, []).append(item)
    for (host, public_key, secret_key), items in by_target.items():
        problem = _post(host, public_key, secret_key, items)
        if problem:
            dropped += len(items)
            _paused_until = time.monotonic() + PAUSE_SECONDS
            print(f"  [langfuse] tracing paused for {PAUSE_SECONDS:.0f}s ({problem}); the scan is not affected")


def _post(host: str, public_key: str, secret_key: str, items: List[Dict[str, Any]]) -> Optional[str]:
    """None when Langfuse accepted the spans, otherwise why not (never a key or a URL query)."""
    try:
        policy = items[0]["ctx"].get("policy") or {}
        reason = endpoint_policy.check_endpoint(
            host,
            allowed_hosts=policy.get("allowed_hosts") or (),
            allow_loopback=bool(policy.get("allow_loopback", True)),
        )
        if reason:
            return reason
        resp = requests.post(
            host + OTLP_PATH,
            data=json.dumps(_payload(items), ensure_ascii=False).encode("utf-8"),
            auth=(public_key, secret_key),
            headers={"Content-Type": "application/json", "x-langfuse-ingestion-version": "4"},
            timeout=TIMEOUT,
            allow_redirects=False,
        )
        return None if 200 <= resp.status_code < 300 else f"HTTP {resp.status_code}"
    except Exception as exc:  # noqa: BLE001 - monitoring must never fail a scan
        return type(exc).__name__


def _payload(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "resourceSpans": [{
            "resource": {"attributes": [_attr("service.name", "secure-build")]},
            "scopeSpans": [{"scope": {"name": "secure-build.sast"}, "spans": [_span(i) for i in items]}],
        }]
    }


def _text(value: Optional[str], limit: int = MAX_TEXT_CHARS) -> str:
    # Masked before it is cut: half a secret no longer looks like one.
    text = secret_mask.mask(str(value or ""))
    return text if len(text) <= limit else text[:limit] + f"… [+{len(text) - limit} chars]"


def _span(item: Dict[str, Any]) -> Dict[str, Any]:
    ctx = item["ctx"]
    scan_id = ctx.get("scan_id")
    cache_hit = bool(item.get("cache_hit"))
    error = item.get("error")
    step = item.get("step") or "unknown"
    input_tokens, output_tokens = int(item.get("input_tokens") or 0), int(item.get("output_tokens") or 0)
    attributes = {
        "langfuse.trace.name": "sast-scan",
        "langfuse.session.id": scan_id,
        "langfuse.trace.tags": ["sast"],
        "langfuse.trace.metadata.scan_id": scan_id,
        "langfuse.trace.metadata.project": ctx.get("project"),
        # A cached answer called no model, so it must not count as a generation.
        "langfuse.observation.type": "span" if cache_hit else "generation",
        "langfuse.observation.input": json.dumps(
            [
                {"role": "system", "content": _text(item.get("system"))},
                {"role": "user", "content": _text(item.get("user"))},
            ],
            ensure_ascii=False,
        ),
        "langfuse.observation.metadata.step": step,
        "langfuse.observation.metadata.provider": item.get("provider"),
        "langfuse.observation.metadata.result_cache_hit": str(cache_hit).lower(),
    }
    if item.get("output") is not None:
        attributes["langfuse.observation.output"] = _text(item["output"])
    if item.get("thinking"):
        attributes["langfuse.observation.metadata.thinking"] = _text(item["thinking"])
    for key in ("stop_reason", "queue_ms", "cache_read_tokens", "cache_write_tokens"):
        if item.get(key):
            attributes[f"langfuse.observation.metadata.{key}"] = str(item[key])
    if not cache_hit:
        attributes["langfuse.observation.model.name"] = item.get("model")
        attributes["langfuse.observation.model.parameters"] = json.dumps(
            {"max_tokens": item.get("max_tokens"), "temperature": item.get("temperature")}
        )
        # Both given explicitly so Langfuse does not price or re-tokenise the call itself.
        attributes["langfuse.observation.usage_details"] = json.dumps(
            {"input": input_tokens, "output": output_tokens, "total": input_tokens + output_tokens}
        )
        attributes["langfuse.observation.cost_details"] = json.dumps({"total": float(item.get("cost_usd") or 0.0)})
    if error:
        attributes["langfuse.observation.level"] = "WARNING" if item.get("cancelled") else "ERROR"
        attributes["langfuse.observation.status_message"] = _text(error, ERROR_CHARS)
    return {
        "traceId": trace_id(scan_id),
        "spanId": uuid.uuid4().hex[:16],
        "name": step,
        "kind": 3,  # CLIENT
        "startTimeUnixNano": str(int(item["start_ns"])),
        "endTimeUnixNano": str(int(item["end_ns"])),
        "attributes": [_attr(k, v) for k, v in attributes.items() if v is not None],
        "status": {"code": 2} if error else {},
    }


def _attr(key: str, value: Any) -> Dict[str, Any]:
    if isinstance(value, list):
        return {"key": key, "value": {"arrayValue": {"values": [{"stringValue": str(v)} for v in value]}}}
    return {"key": key, "value": {"stringValue": str(value)}}


atexit.register(flush)

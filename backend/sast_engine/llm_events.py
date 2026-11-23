"""Append-only JSONL log of every SAST LLM call, read by the local live monitor
(`tools/llm_monitor/app.py`).

Off unless the scan's usage dict carries `USAGE_KEY` with a file path (set by
`agent_bridge.llm_usage_options` from `LLM_EVENTS_FILE`). One line per state
change of a call: `queued` (asked for a concurrency slot), `started` (slot
granted, sent to the provider), `retry` (sent again after a backoff), then one
of `done` / `failed` / `cancelled` / `cache_hit`. Prompts are the masked ones
the provider receives, cut to previews in the JSONL (so the monitor can re-read
it every few seconds); the complete texts go to `<file stem>_bodies/` beside it
(`store_body`): `<call id>.user.txt` / `.response.txt` / `.error.txt`, and each
distinct system prompt once as `system-<sha>.txt` (named by the queued event's
`system_sha`). Bodies older than the discarded rotation are pruned with it.

A separate module because `agent_bridge` reloads `llm_client` on every scan;
the write lock must outlive that. It never raises: a monitoring fault must not
touch a scan.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import uuid
from typing import Any, Dict, Optional

USAGE_KEY = "_llm_events"
MAX_BYTES = 20 * 1024 * 1024  # rotated to `<file>.1` past this
SYSTEM_PREVIEW_CHARS = 600
USER_PREVIEW_CHARS = 4000
RESPONSE_PREVIEW_CHARS = 2000
ERROR_CHARS = 300

_LOCK = threading.Lock()


def new_call_id() -> str:
    return uuid.uuid4().hex[:12]


def enabled(usage: Optional[Dict[str, Any]]) -> bool:
    ctx = (usage or {}).get(USAGE_KEY) or {}
    return bool(ctx.get("file"))


def emit(usage: Optional[Dict[str, Any]], event: str, call_id: str, **fields: Any) -> None:
    ctx = (usage or {}).get(USAGE_KEY) or {}
    path = ctx.get("file")
    if not path:
        return
    try:
        record = {
            "ts": round(time.time(), 3),
            "event": event,
            "id": call_id,
            "pid": os.getpid(),
            "scan_id": ctx.get("scan_id"),
            **fields,
        }
        line = json.dumps(record, default=str, ensure_ascii=False) + "\n"
        with _LOCK:
            directory = os.path.dirname(path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            try:
                if os.path.getsize(path) > MAX_BYTES:
                    _prune_bodies(path)
                    os.replace(path, path + ".1")
            except OSError:
                pass
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(line)
    except Exception:  # noqa: BLE001 - monitoring must never fail a call
        pass


def bodies_dir(path: str) -> str:
    root, _ext = os.path.splitext(path)
    return root + "_bodies"


def system_sha(text: Optional[str]) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()[:16]


def store_body(usage: Optional[Dict[str, Any]], name: str, text: Optional[str]) -> None:
    """Write one complete prompt/response text for the monitor. Never raises."""
    path = ((usage or {}).get(USAGE_KEY) or {}).get("file")
    if not path or text is None:
        return
    try:
        directory = bodies_dir(path)
        os.makedirs(directory, exist_ok=True)
        target = os.path.join(directory, name)
        if name.startswith("system-") and os.path.exists(target):
            os.utime(target)  # still in use: keep it past the next prune
            return
        tmp = f"{target}.{os.getpid()}.{threading.get_ident()}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, target)
    except Exception:  # noqa: BLE001 - monitoring must never fail a call
        pass


def _prune_bodies(path: str) -> None:
    """Drop bodies last touched before the rotation about to be discarded ended."""
    try:
        cutoff = os.path.getmtime(path + ".1")
    except OSError:
        return
    directory = bodies_dir(path)
    try:
        names = os.listdir(directory)
    except OSError:
        return
    for name in names:
        full = os.path.join(directory, name)
        try:
            if os.path.getmtime(full) < cutoff:
                os.remove(full)
        except OSError:
            continue


def preview(text: Optional[str], limit: int) -> str:
    text = text or ""
    return text if len(text) <= limit else text[:limit] + f"… [+{len(text) - limit} chars]"

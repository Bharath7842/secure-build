"""A file-backed LLM result cache that replays (and, deliberately, records).

It implements the `get`/`put` object the engine reads from
`usage[RESULT_CACHE_USAGE_KEY]`, so a replayed run exercises the real
prompt-building code: the response is looked up by `result_cache_key`, which
hashes the provider, model, parameters and the full system + user prompt. A
prompt or catalog change therefore shows up as an *unrecorded call* — the
signal that responses need re-recording and a reviewer must accept the new
outputs.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

REPLAY = "replay"
RECORD = "record"


class UnrecordedLlmCall(RuntimeError):
    """The scan asked for an LLM response the case has no recording for."""


class ReplayResultCache:
    def __init__(self, directory: Path, mode: str = REPLAY):
        if mode not in (REPLAY, RECORD):
            raise ValueError(f"unknown cache mode {mode!r}")
        self.directory = Path(directory)
        self.mode = mode
        self.misses: list[dict[str, str]] = []
        self.hits = 0
        self.written = 0
        self._lock = threading.Lock()
        self._steps: dict[str, str] = {}

    def _path(self, key: str) -> Path:
        return self.directory / f"{key}.json"

    def get(self, key: str) -> dict[str, Any] | None:
        if self.mode == RECORD:
            return None  # always record fresh, never reuse an old answer
        try:
            data = json.loads(self._path(key).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            with self._lock:
                self.misses.append({"key": key, "step": self._steps.get(key, "")})
            return None
        with self._lock:
            self.hits += 1
        return {
            "text": data["text"],
            "input_tokens": data.get("input_tokens"),
            "output_tokens": data.get("output_tokens"),
        }

    def put(self, key: str, *, step: str, model: str, text: str,
            input_tokens: int | None, output_tokens: int | None) -> None:
        if self.mode != RECORD:
            return
        self.directory.mkdir(parents=True, exist_ok=True)
        payload = {
            "key": key, "step": step, "model": model, "text": text,
            "input_tokens": input_tokens, "output_tokens": output_tokens,
        }
        self._path(key).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        with self._lock:
            self.written += 1

    def clear(self) -> None:
        """Drop every recording (before re-recording a case from scratch)."""
        for path in self.directory.glob("*.json"):
            path.unlink()

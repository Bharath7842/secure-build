"""Per-scan live log capture for running (and completed) scans.

The real SAST engine (`backend/sast_engine/sast_scan_agent.py`) reports its
progress via plain `print()` calls (STEP 1..7 banners, per-file/per-rule
lines) — there is no callback hook to wire into instead of stdout. This
module installs one process-wide stdout tee that, for the duration of a
scan's background thread, also appends each printed line into:

  1. an in-memory ring buffer keyed by `scan_id` (for low-latency polling)
  2. a durable file under `data/scan_logs/{scan_id}.log` (so completed scans
     remain inspectable after a server restart or memory eviction)

The frontend polls `GET /scans/{id}/logs?after=<seq>` on the same interval
it already polls `/status` — "live" here means "visible on the next ~2s
poll", not a push/streaming connection.

File format (one JSON object per line):
    {"seq": 1, "line": "Scan started."}
"""

from __future__ import annotations

import json
import sys
import threading
from collections import OrderedDict
from pathlib import Path

from app.config import settings

_MAX_LINES_PER_SCAN = 2000
_MAX_TRACKED_SCANS = 50

_lock = threading.Lock()
_buffers: "OrderedDict[str, list[tuple[int, str]]]" = OrderedDict()
_next_seq: dict[str, int] = {}
_line_hooks: dict[str, list] = {}
_secrets: dict[str, list[str]] = {}
_thread_local = threading.local()
_installed = False


def register_line_hook(scan_id: str, callback) -> None:
    """Register a per-line callback (e.g. progress updates) for a scan."""
    with _lock:
        _line_hooks.setdefault(scan_id, []).append(callback)


def register_secrets(scan_id: str, secrets: list[str]) -> None:
    """Values (e.g. a DAST target password) that must never reach the log
    buffer or the on-disk log — `_append` masks them before storing."""
    cleaned = [s for s in secrets if s]
    with _lock:
        if cleaned:
            _secrets[scan_id] = cleaned
        else:
            _secrets.pop(scan_id, None)


def unregister_line_hooks(scan_id: str) -> None:
    with _lock:
        _line_hooks.pop(scan_id, None)


def _configure_utf8_stdio(stream) -> None:
    """Windows consoles default to cp1252; engine narration uses box-drawing
    and em dashes that that codec cannot encode. Prefer UTF-8 so `print()`
    of the project tree cannot abort a scan."""
    reconfigure = getattr(stream, "reconfigure", None)
    if not callable(reconfigure):
        return
    try:
        reconfigure(encoding="utf-8", errors="replace")
    except (OSError, ValueError, AttributeError):
        pass


def _safe_write(stream, data: str) -> None:
    try:
        stream.write(data)
        return
    except UnicodeEncodeError:
        pass
    encoding = getattr(stream, "encoding", None) or "ascii"
    try:
        stream.write(data.encode(encoding, errors="replace").decode(encoding, errors="replace"))
    except Exception:  # noqa: BLE001 — console I/O must not abort the scan
        pass


class _TeeStdout:
    """Writes through to the real stdout unconditionally; additionally
    routes lines into the active thread's scan log buffer, if any."""

    def __init__(self, real_stream):
        self._real = real_stream

    def write(self, data: str) -> int:
        _safe_write(self._real, data)
        scan_id = getattr(_thread_local, "scan_id", None)
        if scan_id:
            # `print(tok, end="")` streams (e.g. LLM thinking tokens) arrive as
            # many tiny writes — hold the trailing partial line until its
            # newline so one printed line is one log line, not one per token.
            pending = getattr(_thread_local, "pending", "") + data
            *complete, rest = pending.split("\n")
            _thread_local.pending = rest
            buffer = getattr(_thread_local, "buffer", None)
            prefix = getattr(_thread_local, "prefix", "")
            for line in complete:
                stripped = line.rstrip()
                if stripped:
                    if buffer is not None:
                        buffer.append(stripped)  # a parallel task: kept together, flushed as one block
                    else:
                        _append(scan_id, f"{prefix}{stripped}")
        return len(data)

    def flush(self) -> None:
        self._real.flush()

    def isatty(self) -> bool:
        return getattr(self._real, "isatty", lambda: False)()

    def __getattr__(self, name):
        return getattr(self._real, name)


def install() -> None:
    """Idempotent: replace `sys.stdout` with the tee once per process.

    Re-wraps when something else (e.g. pytest's capture fixture) has
    temporarily replaced `sys.stdout` after a previous install — otherwise
    `print()` would stop reaching the scan buffer mid-test / mid-process.
    """
    global _installed
    if isinstance(sys.stdout, _TeeStdout):
        _installed = True
        return
    _configure_utf8_stdio(sys.stdout)
    _configure_utf8_stdio(sys.stderr)
    sys.stdout = _TeeStdout(sys.stdout)
    _installed = True


def _logs_dir() -> Path:
    path = Path(
        getattr(settings, "scan_logs_dir", None)
        or (Path(settings.workspaces_dir).parent / "scan_logs")
    )
    path.mkdir(parents=True, exist_ok=True)
    return path


def _log_path(scan_id: str) -> Path:
    # sanitize so a weird id can't escape the logs directory
    safe = "".join(c for c in scan_id if c.isalnum() or c in "-_")
    return _logs_dir() / f"{safe}.log"


def reset(scan_id: str) -> None:
    """Clear any previous in-memory + on-disk log for this scan id (call at
    scan start so a force re-scan doesn't append onto stale history)."""
    path = _log_path(scan_id)
    with _lock:
        _buffers[scan_id] = []
        _next_seq[scan_id] = 0
        _line_hooks.pop(scan_id, None)
        _secrets.pop(scan_id, None)
        _buffers.move_to_end(scan_id)
        while len(_buffers) > _MAX_TRACKED_SCANS:
            evicted_id, _ = _buffers.popitem(last=False)
            _next_seq.pop(evicted_id, None)
    try:
        path.write_text("", encoding="utf-8")
    except OSError:
        pass


def _append(scan_id: str, line: str) -> None:
    with _lock:
        for secret in _secrets.get(scan_id, ()):
            line = line.replace(secret, "********")
        buf = _buffers.setdefault(scan_id, [])
        seq = _next_seq.get(scan_id, 0) + 1
        _next_seq[scan_id] = seq
        buf.append((seq, line))
        if len(buf) > _MAX_LINES_PER_SCAN:
            del buf[: len(buf) - _MAX_LINES_PER_SCAN]
        _buffers.move_to_end(scan_id)
        while len(_buffers) > _MAX_TRACKED_SCANS:
            evicted_id, _ = _buffers.popitem(last=False)
            _next_seq.pop(evicted_id, None)

    # Invoke line hooks outside the buffer lock (hooks may touch the DB).
    hooks: list = []
    with _lock:
        hooks = list(_line_hooks.get(scan_id, []))
    for hook in hooks:
        try:
            hook(line)
        except Exception:  # noqa: BLE001 — logging must not break the scan
            pass

    # Persist outside the memory-eviction critical section so a slow disk
    # write never blocks unrelated scans' log appends for long.
    try:
        with open(_log_path(scan_id), "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"seq": seq, "line": line}, ensure_ascii=False) + "\n")
    except OSError:
        pass


def log(scan_id: str, line: str) -> None:
    """Manually record a log line for `scan_id` — used for lifecycle events
    the engine itself doesn't print (workspace checkout, persistence, ...).
    Inside a prefixed `capture` for the same scan, the line gets that prefix
    too, so it lands in the same stage as the thread's printed output."""
    install()
    if getattr(_thread_local, "scan_id", None) == scan_id:
        line = f"{getattr(_thread_local, 'prefix', '')}{line}"
    _append(scan_id, line)


def delete(scan_id: str) -> None:
    """Drop `scan_id`'s in-memory buffer and durable on-disk log file —
    called when the scan (or its whole project) is deleted so no orphaned
    log file is left under `scan_logs_dir`."""
    with _lock:
        _buffers.pop(scan_id, None)
        _next_seq.pop(scan_id, None)
        _line_hooks.pop(scan_id, None)
        _secrets.pop(scan_id, None)
    try:
        _log_path(scan_id).unlink(missing_ok=True)
    except OSError:
        pass


class capture:
    """Context manager: route this thread's `print()` output into
    `scan_id`'s buffer for the duration of the `with` block. `prefix` is
    prepended to every line — the engine's parallel stages use
    "[[stage:<name>]] " so the UI can route interleaved lines."""

    def __init__(self, scan_id: str, prefix: str = ""):
        self.scan_id = scan_id
        self.prefix = prefix
        self._previous: tuple | None = None

    def __enter__(self) -> "capture":
        install()
        self._previous = (getattr(_thread_local, "scan_id", None), getattr(_thread_local, "prefix", ""))
        _thread_local.scan_id = self.scan_id
        _thread_local.prefix = self.prefix
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        # Flush a trailing line that never got its newline.
        pending = getattr(_thread_local, "pending", "").rstrip()
        _thread_local.pending = ""
        if pending:
            _append(self.scan_id, f"{self.prefix}{pending}")
        _thread_local.scan_id, _thread_local.prefix = self._previous  # type: ignore[misc]


_block_lock = threading.Lock()


class buffered_capture:
    """Like `capture`, for one of several tasks running in parallel threads: the thread's
    `print()` output is held and appended to `scan_id`'s log as one contiguous block when the
    `with` block ends, so lines from concurrent tasks never interleave. Nests inside nothing:
    use it in the worker thread itself."""

    def __init__(self, scan_id: str, prefix: str = ""):
        self.scan_id, self.prefix = scan_id, prefix
        self._previous: tuple | None = None

    def __enter__(self) -> "buffered_capture":
        install()
        self._previous = (getattr(_thread_local, "scan_id", None), getattr(_thread_local, "buffer", None), getattr(_thread_local, "pending", ""), getattr(_thread_local, "prefix", ""))
        _thread_local.scan_id = self.scan_id
        _thread_local.buffer = []
        _thread_local.pending = ""
        _thread_local.prefix = ""
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        pending = getattr(_thread_local, "pending", "").rstrip()
        lines: list[str] = list(getattr(_thread_local, "buffer", []))
        if pending:
            lines.append(pending)
        _thread_local.scan_id, _thread_local.buffer, _thread_local.pending, _thread_local.prefix = self._previous  # type: ignore[misc]
        with _block_lock:  # the block goes in whole
            for line in lines:
                _append(self.scan_id, f"{self.prefix}{line}" if self.prefix else line)


def _load_from_disk(scan_id: str) -> list[tuple[int, str]]:
    path = _log_path(scan_id)
    if not path.is_file():
        return []
    rows: list[tuple[int, str]] = []
    try:
        for raw in path.read_text(encoding="utf-8").splitlines():
            raw = raw.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
                rows.append((int(obj["seq"]), str(obj["line"])))
            except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                continue
    except OSError:
        return []
    return rows


def get_logs(scan_id: str, after: int = 0) -> tuple[list[dict], int]:
    """Return log lines with seq > `after`, plus the highest seq seen so far
    (0 if none / after) so the caller can pass it back in as `after` next poll.

    Prefers the in-memory buffer when present; otherwise falls back to the
    durable on-disk log so completed scans remain readable after restart.
    """
    with _lock:
        mem = list(_buffers.get(scan_id, []))

    buf = mem if mem else _load_from_disk(scan_id)
    lines = [{"seq": seq, "line": text} for seq, text in buf if seq > after]
    next_after = buf[-1][0] if buf else after
    return lines, next_after

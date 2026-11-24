"""Clone credentials a CI pipeline hands over with its scan request (its CI_JOB_TOKEN).

Memory only, like the DAST credentials in `scan_runner`: never written to the database,
`Scan.metadata_json`, the scan log or `.git/config`. The scan log masks the value
(`scan_log.register_secrets`). A restart loses it; the scan then clones anonymously and,
for a private repository, fails with git's own error rather than using someone else's
credentials. Entries expire after `TTL_SECONDS`: a job token stops working when its job
ends, so a longer life would only keep a dead secret around.
"""

from __future__ import annotations

import threading
import time

from app.services import scan_log

TTL_SECONDS = 6 * 60 * 60

_lock = threading.Lock()
_tokens: dict[str, tuple[str, float]] = {}


def _purge_expired(now: float) -> None:
    for scan_id in [s for s, (_, expires) in _tokens.items() if expires <= now]:
        _tokens.pop(scan_id, None)


def set_job_token(scan_id: str, token: str) -> None:
    """Keep `token` for `scan_id` and register it for log masking first."""
    token = (token or "").strip()
    if not token:
        return
    scan_log.register_secrets(scan_id, [token])
    now = time.monotonic()
    with _lock:
        _purge_expired(now)
        _tokens[scan_id] = (token, now + TTL_SECONDS)


def get_job_token(scan_id: str) -> str | None:
    now = time.monotonic()
    with _lock:
        entry = _tokens.get(scan_id)
        if entry is None:
            return None
        if entry[1] <= now:
            _tokens.pop(scan_id, None)
            return None
        return entry[0]


def clear(scan_id: str) -> None:
    with _lock:
        _tokens.pop(scan_id, None)

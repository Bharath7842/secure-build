import hashlib
import json
import logging
import time
from pathlib import Path
from threading import Lock, Timer

logger = logging.getLogger("sbom.cache")

FLUSH_INTERVAL = 5.0
FLUSH_BATCH_SIZE = 20


class ApiCache:

    def __init__(self, cache_dir: Path | None = None, ttl_seconds: int = 3600):
        self._memory_cache: dict[str, tuple[float, any]] = {}
        self._lock = Lock()
        self.ttl_seconds = ttl_seconds

        if cache_dir:
            self.cache_dir = cache_dir
        else:
            import tempfile
            self.cache_dir = Path(tempfile.gettempdir()) / "sbom-cache"

        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self._pending_writes: dict[str, any] = {}
        self._flush_timer: Timer | None = None

    def _make_key(self, url: str) -> str:
        return hashlib.sha256(url.encode()).hexdigest()

    def _memory_get(self, key: str) -> any | None:
        with self._lock:
            if key in self._memory_cache:
                ts, value = self._memory_cache[key]
                if time.time() - ts < self.ttl_seconds:
                    return value
                del self._memory_cache[key]
        return None

    def _memory_set(self, key: str, value: any):
        with self._lock:
            self._memory_cache[key] = (time.time(), value)

    def _disk_get(self, key: str) -> any | None:
        cache_file = self.cache_dir / f"{key}.json"
        if cache_file.exists():
            try:
                data = json.loads(cache_file.read_text(encoding="utf-8-sig"))
                if time.time() - data.get("ts", 0) < self.ttl_seconds:
                    return data.get("value")
                cache_file.unlink()
            except Exception:
                pass
        return None

    def _disk_set(self, key: str, value: any):
        cache_file = self.cache_dir / f"{key}.json"
        try:
            data = {"ts": time.time(), "value": value}
            cache_file.write_text(json.dumps(data), encoding="utf-8")
        except Exception as e:
            logger.warning("Failed to write cache: %s", e)

    def _schedule_flush(self):
        if self._flush_timer is not None:
            return
        self._flush_timer = Timer(FLUSH_INTERVAL, self._flush_pending)
        self._flush_timer.daemon = True
        self._flush_timer.start()

    def _flush_pending(self):
        with self._lock:
            self._flush_timer = None
            pending = dict(self._pending_writes)
            self._pending_writes.clear()

        for key, value in pending.items():
            self._disk_set(key, value)

    def _buffer_disk_write(self, key: str, value: any):
        with self._lock:
            self._pending_writes[key] = value
            if len(self._pending_writes) >= FLUSH_BATCH_SIZE:
                pending = dict(self._pending_writes)
                self._pending_writes.clear()
            else:
                self._schedule_flush()
                return

        for k, v in pending.items():
            self._disk_set(k, v)

    def get(self, url: str) -> any | None:
        key = self._make_key(url)

        value = self._memory_get(key)
        if value is not None:
            return value

        value = self._disk_get(key)
        if value is not None:
            self._memory_set(key, value)
            return value

        return None

    def set(self, url: str, value: any):
        key = self._make_key(url)
        self._memory_set(key, value)
        self._buffer_disk_write(key, value)

    def has(self, url: str) -> bool:
        return self.get(url) is not None

    def flush(self):
        self._flush_pending()

    def clear(self):
        self._flush_pending()
        with self._lock:
            self._memory_cache.clear()
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                cache_file.unlink()
            except Exception:
                pass

    def stats(self) -> dict:
        with self._lock:
            memory_count = len(self._memory_cache)
            pending_count = len(self._pending_writes)
        disk_count = len(list(self.cache_dir.glob("*.json")))
        return {"memory_entries": memory_count, "disk_entries": disk_count, "pending_writes": pending_count}


_cache_instance: ApiCache | None = None


def get_cache(cache_dir: Path | None = None, ttl_seconds: int = 3600) -> ApiCache:
    global _cache_instance
    if _cache_instance is None:
        _cache_instance = ApiCache(cache_dir, ttl_seconds)
    return _cache_instance

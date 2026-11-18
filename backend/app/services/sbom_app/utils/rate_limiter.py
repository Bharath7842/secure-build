import logging
import time
import threading
from collections import defaultdict

import httpx

logger = logging.getLogger("sbom.utils.http")

DEFAULT_TIMEOUT = 10.0
MAX_RETRIES = 3
BACKOFF_BASE = 1.0


class RetryClient:
    """HTTP client with automatic retry and backoff for external API calls."""

    def __init__(self, timeout: float = DEFAULT_TIMEOUT, max_retries: int = MAX_RETRIES):
        self._timeout = timeout
        self._max_retries = max_retries
        self._client = httpx.Client(timeout=timeout)
        self._lock = threading.Lock()

    def get(self, url: str, **kwargs) -> httpx.Response | None:
        return self._request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> httpx.Response | None:
        return self._request("POST", url, **kwargs)

    def _request(self, method: str, url: str, **kwargs) -> httpx.Response | None:
        kwargs.setdefault("timeout", self._timeout)

        for attempt in range(self._max_retries):
            try:
                resp = self._client.request(method, url, **kwargs)
                if resp.status_code < 500:
                    return resp
                if attempt < self._max_retries - 1:
                    wait = BACKOFF_BASE * (2 ** attempt)
                    logger.debug("Retry %d for %s after %.1fs (status %d)", attempt + 1, url, wait, resp.status_code)
                    time.sleep(wait)
            except httpx.TimeoutException:
                if attempt < self._max_retries - 1:
                    wait = BACKOFF_BASE * (2 ** attempt)
                    logger.debug("Retry %d for %s after %.1fs (timeout)", attempt + 1, url, wait)
                    time.sleep(wait)
            except httpx.RequestError as e:
                logger.warning("Request failed for %s: %s", url, e)
                return None

        return None

    def close(self):
        self._client.close()


class RateLimiter:
    """Simple token-bucket rate limiter per domain."""

    def __init__(self, requests_per_second: float = 5.0, burst: int = 10):
        self._rate = requests_per_second
        self._burst = burst
        self._tokens: dict[str, float] = defaultdict(lambda: float(burst))
        self._last_refill: dict[str, float] = defaultdict(time.monotonic)
        self._lock = threading.Lock()

    def acquire(self, domain: str) -> float:
        """Block until a token is available. Returns wait time in seconds."""
        wait_time = 0.0
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill[domain]
            self._tokens[domain] = min(
                self._burst,
                self._tokens[domain] + elapsed * self._rate,
            )
            self._last_refill[domain] = now

            if self._tokens[domain] < 1.0:
                wait_time = (1.0 - self._tokens[domain]) / self._rate
                self._tokens[domain] = 0.0
            else:
                self._tokens[domain] -= 1.0

        if wait_time > 0:
            time.sleep(wait_time)
        return wait_time


_api_limiter = RateLimiter(
    requests_per_second=float(__import__("os").getenv("SBOM_API_RATE_RPS", "5")),
    burst=int(__import__("os").getenv("SBOM_API_RATE_BURST", "10")),
)

_depsdev_limiter = RateLimiter(requests_per_second=10.0, burst=20)
_ecosystems_limiter = RateLimiter(requests_per_second=4.0, burst=8)
_osv_limiter = RateLimiter(requests_per_second=10.0, burst=20)

# NVD anonymous quota: 5 requests / 30s (0.166 rps, burst 5); with a free
# API key (SBOM_NVD_API_KEY): 50 requests / 30s (1.66 rps, burst 10).
_NVD_HAS_KEY = bool((__import__("os").getenv("SBOM_NVD_API_KEY") or "").strip())
_nvd_limiter = RateLimiter(
    requests_per_second=1.66 if _NVD_HAS_KEY else 0.166,
    burst=10 if _NVD_HAS_KEY else 5,
)

_DOMAIN_LIMITERS = {
    "api.deps.dev": _depsdev_limiter,
    "packages.ecosyste.ms": _ecosystems_limiter,
    "api.osv.dev": _osv_limiter,
    "services.nvd.nist.gov": _nvd_limiter,
}


def rate_limit_request(domain: str) -> None:
    """Call before making an external HTTP request to rate-limit."""
    limiter = _DOMAIN_LIMITERS.get(domain)
    if limiter:
        limiter.acquire(domain)
    else:
        _api_limiter.acquire(domain)

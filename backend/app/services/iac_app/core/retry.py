"""Retry utility with exponential backoff for external scanner calls."""

from __future__ import annotations

import logging
import time
from functools import wraps
from typing import Callable, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


def retry_with_backoff(
    func: Callable[..., T] | None = None,
    *,
    max_retries: int = 1,
    backoff_factor: float = 1.0,
    max_delay: float = 30.0,
    exceptions: tuple[type[Exception], ...] = (Exception,),
) -> Callable[..., T] | Callable[[Callable[..., T]], Callable[..., T]]:
    """Decorator that retries a function on failure with exponential backoff.

    Args:
        func: The function to decorate (if used without parentheses).
        max_retries: Maximum number of retry attempts (default 1 = one retry).
        backoff_factor: Multiplier for delay between retries.
        max_delay: Maximum delay in seconds between retries.
        exceptions: Tuple of exception types to catch and retry on.
    """

    def decorator(fn: Callable[..., T]) -> Callable[..., T]:
        @wraps(fn)
        def wrapper(*args, **kwargs) -> T:
            last_exc: Exception | None = None
            for attempt in range(1 + max_retries):
                try:
                    return fn(*args, **kwargs)
                except exceptions as exc:
                    last_exc = exc
                    if attempt < max_retries:
                        delay = min(backoff_factor * (2 ** attempt), max_delay)
                        logger.warning(
                            "Attempt %d/%d for %s failed: %s. Retrying in %.1fs",
                            attempt + 1,
                            1 + max_retries,
                            fn.__qualname__,
                            exc,
                            delay,
                        )
                        time.sleep(delay)
                    else:
                        logger.error(
                            "All %d attempts for %s exhausted. Last error: %s",
                            1 + max_retries,
                            fn.__qualname__,
                            exc,
                        )
            raise last_exc  # type: ignore[misc]

        return wrapper

    if func is not None:
        return decorator(func)
    return decorator

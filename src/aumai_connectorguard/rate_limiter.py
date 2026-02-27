"""Sliding-window rate limiting for aumai-connectorguard."""

from __future__ import annotations

import datetime
import threading
from collections import deque


class SlidingWindowRateLimiter:
    """Per-connector sliding-window rate limiter using a timestamp deque.

    Maintains an in-process deque of request timestamps for each connector.
    Requests older than *window_seconds* are evicted before each check, giving
    an accurate sliding window without a fixed epoch.

    This implementation is thread-safe.

    Example::

        limiter = SlidingWindowRateLimiter()
        for _ in range(5):
            allowed = limiter.check_rate_limit("openai-chat", 60, 3)
            print(allowed)  # True, True, True, False, False
    """

    def __init__(self) -> None:
        # Map connector name -> deque of UTC datetimes for recent requests.
        self._windows: dict[str, deque[datetime.datetime]] = {}
        self._lock = threading.Lock()

    def check_rate_limit(
        self,
        connector: str,
        window_seconds: int,
        max_requests: int,
    ) -> bool:
        """Check whether a request to *connector* is within the rate limit.

        Records the request timestamp when allowed.

        Args:
            connector: Connector identifier.
            window_seconds: Size of the sliding window in seconds.
            max_requests: Maximum requests allowed within the window.

        Returns:
            ``True`` if the request is within limits and has been recorded,
            ``False`` if the limit is already reached.
        """
        now = datetime.datetime.now(datetime.UTC)
        cutoff = now - datetime.timedelta(seconds=window_seconds)

        with self._lock:
            if connector not in self._windows:
                self._windows[connector] = deque()

            window = self._windows[connector]

            # Evict timestamps that have fallen outside the window.
            while window and window[0] < cutoff:
                window.popleft()

            if len(window) >= max_requests:
                return False

            window.append(now)
            return True

    def current_count(self, connector: str, window_seconds: int) -> int:
        """Return the number of requests recorded within the last *window_seconds*."""
        now = datetime.datetime.now(datetime.UTC)
        cutoff = now - datetime.timedelta(seconds=window_seconds)

        with self._lock:
            if connector not in self._windows:
                return 0
            window = self._windows[connector]
            # Evict stale entries so the deque stays compact over time.
            while window and window[0] < cutoff:
                window.popleft()
            return len(window)

    def reset(self, connector: str) -> None:
        """Clear all recorded timestamps for *connector*."""
        with self._lock:
            self._windows.pop(connector, None)


def check_rate_limit(
    connector: str,
    window_seconds: int,
    max_requests: int,
    *,
    _limiter: SlidingWindowRateLimiter | None = None,
) -> bool:
    """Module-level convenience that uses a shared global limiter instance.

    Args:
        connector: Connector identifier.
        window_seconds: Sliding window size in seconds.
        max_requests: Maximum requests in the window.
        _limiter: Optional limiter override (useful for testing).

    Returns:
        ``True`` if the request is within limits.
    """
    limiter = _limiter if _limiter is not None else _global_limiter
    return limiter.check_rate_limit(connector, window_seconds, max_requests)


# Module-level shared instance.
_global_limiter: SlidingWindowRateLimiter = SlidingWindowRateLimiter()

__all__ = ["SlidingWindowRateLimiter", "check_rate_limit"]

"""Tests for aumai_connectorguard.rate_limiter."""

from __future__ import annotations

import datetime
import threading
from unittest.mock import patch

from hypothesis import given, settings
from hypothesis import strategies as st

from aumai_connectorguard.rate_limiter import (
    SlidingWindowRateLimiter,
    check_rate_limit,
)

# ---------------------------------------------------------------------------
# SlidingWindowRateLimiter
# ---------------------------------------------------------------------------


class TestSlidingWindowRateLimiter:
    def test_first_request_always_allowed(self) -> None:
        limiter = SlidingWindowRateLimiter()
        assert limiter.check_rate_limit("connector-a", 60, 10) is True

    def test_requests_up_to_limit_allowed(self) -> None:
        limiter = SlidingWindowRateLimiter()
        for i in range(5):
            result = limiter.check_rate_limit("connector-a", 60, 5)
            assert result is True, f"Request {i + 1} should be allowed"

    def test_request_at_limit_boundary_denied(self) -> None:
        limiter = SlidingWindowRateLimiter()
        for _ in range(5):
            limiter.check_rate_limit("connector-a", 60, 5)
        assert limiter.check_rate_limit("connector-a", 60, 5) is False

    def test_multiple_requests_beyond_limit_all_denied(self) -> None:
        limiter = SlidingWindowRateLimiter()
        for _ in range(3):
            limiter.check_rate_limit("c", 60, 3)
        for _ in range(10):
            assert limiter.check_rate_limit("c", 60, 3) is False

    def test_different_connectors_tracked_independently(self) -> None:
        limiter = SlidingWindowRateLimiter()
        for _ in range(3):
            limiter.check_rate_limit("connector-x", 60, 3)
        # connector-y should still be within limit
        assert limiter.check_rate_limit("connector-y", 60, 3) is True

    def test_reset_clears_connector_window(self) -> None:
        limiter = SlidingWindowRateLimiter()
        for _ in range(3):
            limiter.check_rate_limit("connector-a", 60, 3)
        assert limiter.check_rate_limit("connector-a", 60, 3) is False
        limiter.reset("connector-a")
        assert limiter.check_rate_limit("connector-a", 60, 3) is True

    def test_reset_unknown_connector_is_no_op(self) -> None:
        limiter = SlidingWindowRateLimiter()
        limiter.reset("does-not-exist")  # must not raise

    def test_current_count_zero_for_new_connector(self) -> None:
        limiter = SlidingWindowRateLimiter()
        assert limiter.current_count("new-connector", 60) == 0

    def test_current_count_matches_recorded_requests(self) -> None:
        limiter = SlidingWindowRateLimiter()
        for _ in range(4):
            limiter.check_rate_limit("c", 60, 10)
        assert limiter.current_count("c", 60) == 4

    def test_current_count_after_reset_is_zero(self) -> None:
        limiter = SlidingWindowRateLimiter()
        for _ in range(4):
            limiter.check_rate_limit("c", 60, 10)
        limiter.reset("c")
        assert limiter.current_count("c", 60) == 0

    def test_sliding_window_evicts_old_requests(self) -> None:
        """Old timestamps outside the window should not count against the limit."""
        limiter = SlidingWindowRateLimiter()
        connector = "sliding-test"

        # Manually inject old timestamps that are outside the window
        old_ts = datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=120)
        with limiter._lock:
            from collections import deque

            limiter._windows[connector] = deque([old_ts, old_ts, old_ts])

        # With window_seconds=60, those old entries should be evicted
        # so we should be able to make max_requests fresh requests
        for _ in range(3):
            result = limiter.check_rate_limit(connector, 60, 3)
            assert result is True

    def test_count_excludes_requests_older_than_window(self) -> None:
        """Requests older than the window should not appear in current_count."""
        limiter = SlidingWindowRateLimiter()
        connector = "aging-test"

        # Inject a timestamp that is 200 seconds old — outside any 60-second window
        old_ts = datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=200)
        with limiter._lock:
            from collections import deque

            limiter._windows[connector] = deque([old_ts, old_ts])

        # With a 60-second window the two old entries should not be counted
        count = limiter.current_count(connector, 60)
        assert count == 0

    def test_thread_safety_concurrent_check(self) -> None:
        limiter = SlidingWindowRateLimiter()
        allowed_count = 0
        lock = threading.Lock()

        def make_requests() -> None:
            nonlocal allowed_count
            for _ in range(20):
                if limiter.check_rate_limit("shared", 60, 50):
                    with lock:
                        allowed_count += 1

        threads = [threading.Thread(target=make_requests) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        # Exactly 50 should have been allowed regardless of thread ordering
        assert allowed_count == 50

    def test_max_requests_one_allows_exactly_one(self) -> None:
        limiter = SlidingWindowRateLimiter()
        assert limiter.check_rate_limit("c", 60, 1) is True
        assert limiter.check_rate_limit("c", 60, 1) is False

    @given(
        max_requests=st.integers(min_value=1, max_value=20),
        extra=st.integers(min_value=1, max_value=10),
    )
    @settings(max_examples=30)
    def test_property_exactly_max_requests_allowed(
        self, max_requests: int, extra: int
    ) -> None:
        limiter = SlidingWindowRateLimiter()
        connector = f"prop-{max_requests}-{extra}"
        allowed = sum(
            1
            for _ in range(max_requests + extra)
            if limiter.check_rate_limit(connector, 60, max_requests)
        )
        assert allowed == max_requests


# ---------------------------------------------------------------------------
# Module-level check_rate_limit convenience function
# ---------------------------------------------------------------------------


class TestModuleLevelCheckRateLimit:
    def test_uses_provided_limiter(self) -> None:
        limiter = SlidingWindowRateLimiter()
        assert check_rate_limit("c", 60, 3, _limiter=limiter) is True

    def test_respects_max_requests_with_provided_limiter(self) -> None:
        limiter = SlidingWindowRateLimiter()
        for _ in range(3):
            check_rate_limit("c", 60, 3, _limiter=limiter)
        assert check_rate_limit("c", 60, 3, _limiter=limiter) is False

    def test_falls_back_to_global_limiter(self) -> None:
        fresh_limiter = SlidingWindowRateLimiter()
        with patch("aumai_connectorguard.rate_limiter._global_limiter", fresh_limiter):
            result = check_rate_limit("global-test-connector-unique", 60, 10)
            assert result is True

    def test_independent_limiters_do_not_share_state(self) -> None:
        limiter_a = SlidingWindowRateLimiter()
        limiter_b = SlidingWindowRateLimiter()
        for _ in range(3):
            check_rate_limit("c", 60, 3, _limiter=limiter_a)
        # limiter_b should be unaffected
        assert check_rate_limit("c", 60, 3, _limiter=limiter_b) is True

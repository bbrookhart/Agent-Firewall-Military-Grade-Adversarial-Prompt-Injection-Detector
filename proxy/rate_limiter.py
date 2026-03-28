"""
Token bucket rate limiter — NIST SP 800-53 SC-5 (DoS protection).
In-memory for single-process; swap to Redis for distributed deployment.
"""

from __future__ import annotations

import time
import threading
from collections import defaultdict
from typing import Optional


class TokenBucketRateLimiter:
    """
    Token bucket algorithm. Thread-safe. Per-session and global limits.
    Redis backend: replace _buckets with redis INCR + EXPIRE for distributed.
    """

    def __init__(
        self,
        requests_per_minute: int = 60,
        requests_per_session: int = 500,
    ):
        self._rpm = requests_per_minute
        self._rps = requests_per_session
        self._lock = threading.Lock()
        # {session_id: [timestamp, ...]}
        self._session_windows: dict[str, list[float]] = defaultdict(list)
        self._session_totals: dict[str, int] = defaultdict(int)
        self._global_window: list[float] = []

    def _clean_window(self, window: list[float], cutoff: float) -> list[float]:
        return [t for t in window if t > cutoff]

    def check(self, session_id: str = "global") -> tuple[bool, str]:
        """
        Returns (allowed, reason). Call before processing each request.
        """
        now = time.time()
        minute_ago = now - 60.0

        with self._lock:
            # Global rate limit
            self._global_window = self._clean_window(self._global_window, minute_ago)
            if len(self._global_window) >= self._rpm * 10:  # 10x global buffer
                return False, f"Global rate limit: {self._rpm * 10}/min exceeded"
            self._global_window.append(now)

            # Per-session minute limit
            self._session_windows[session_id] = self._clean_window(
                self._session_windows[session_id], minute_ago
            )
            if len(self._session_windows[session_id]) >= self._rpm:
                return False, f"Session rate limit: {self._rpm}/min exceeded"
            self._session_windows[session_id].append(now)

            # Per-session total limit
            self._session_totals[session_id] += 1
            if self._session_totals[session_id] > self._rps:
                return False, f"Session total limit: {self._rps} requests exceeded"

        return True, "ok"

    def get_stats(self) -> dict:
        now = time.time()
        minute_ago = now - 60.0
        with self._lock:
            return {
                "global_rpm": len([t for t in self._global_window if t > minute_ago]),
                "active_sessions": len(self._session_windows),
                "max_rpm": self._rpm,
            }


_limiter: Optional[TokenBucketRateLimiter] = None

def get_rate_limiter() -> TokenBucketRateLimiter:
    global _limiter
    if _limiter is None:
        from config.settings import settings
        _limiter = TokenBucketRateLimiter(
            requests_per_minute=settings.max_requests_per_minute,
            requests_per_session=settings.max_requests_per_session,
        )
    return _limiter

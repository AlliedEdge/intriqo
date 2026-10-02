"""Small in-process guard against obvious auth endpoint abuse.

This is intentionally not a replacement for a shared Redis/API-gateway rate
limit. It keeps a single local control-plane process from being accidentally
hammered while leaving room for a distributed limiter when deployment needs it.
"""

from __future__ import annotations

from threading import Lock
from time import monotonic

from fastapi import HTTPException, status


class SlidingWindowLimiter:
    """Bounded, process-local sliding-window counter."""

    def __init__(self, *, limit: int, window_seconds: float, max_keys: int = 4096) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self._entries: dict[str, list[float]] = {}
        self._lock = Lock()

    def allow(self, key: str) -> bool:
        now = monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            timestamps = [stamp for stamp in self._entries.get(key, []) if stamp > cutoff]
            if len(timestamps) >= self.limit:
                self._entries[key] = timestamps
                return False
            timestamps.append(now)
            self._entries[key] = timestamps
            if len(self._entries) > self.max_keys:
                oldest_key = min(self._entries, key=lambda candidate: self._entries[candidate][-1])
                self._entries.pop(oldest_key, None)
            return True


_registration = SlidingWindowLimiter(limit=60, window_seconds=60)
_login = SlidingWindowLimiter(limit=20, window_seconds=60)
_email_requests = SlidingWindowLimiter(limit=8, window_seconds=60)
_token_consumption = SlidingWindowLimiter(limit=20, window_seconds=60)


def client_key(host: str | None, value: str = "") -> str:
    return f"{host or 'unknown'}:{value.strip().lower()}"


def enforce(limiter: SlidingWindowLimiter, key: str) -> None:
    if limiter.allow(key):
        return
    raise HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail={
            "error": {
                "code": "AUTH_RATE_LIMITED",
                "message": "Too many authentication requests. Try again shortly.",
            }
        },
        headers={"Retry-After": "60"},
    )


__all__ = [
    "_email_requests",
    "_login",
    "_registration",
    "_token_consumption",
    "client_key",
    "enforce",
]

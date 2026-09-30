from collections import deque
from dataclasses import dataclass
from time import monotonic


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    retry_after: int = 0


class InMemoryRateLimiter:
    """Small process-local sliding-window limiter with bounded, expiring keys."""

    def __init__(self, window_seconds: float = 60, max_keys: int = 2000) -> None:
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self._events: dict[str, deque[float]] = {}

    def cleanup(self, now: float | None = None) -> int:
        current = monotonic() if now is None else now
        cutoff = current - self.window_seconds
        removed = 0
        for key in list(self._events):
            events = self._events[key]
            while events and events[0] <= cutoff:
                events.popleft()
            if not events:
                del self._events[key]
                removed += 1
        return removed

    def check(self, key: str, limit: int, now: float | None = None) -> RateLimitResult:
        current = monotonic() if now is None else now
        self.cleanup(current)
        events = self._events.setdefault(key, deque())
        if len(events) >= limit:
            retry = max(1, round(self.window_seconds - (current - events[0])))
            return RateLimitResult(False, retry)
        events.append(current)
        if len(self._events) > self.max_keys:
            oldest = min(self._events, key=lambda item: self._events[item][-1])
            del self._events[oldest]
        return RateLimitResult(True)

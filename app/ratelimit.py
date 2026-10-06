"""按来源的时间窗限流器，线程安全，来源之间互不影响。"""
from __future__ import annotations

import threading


class FixedWindowRateLimiter:
    """固定窗口计数限流。

    判定与计数在同一把锁内完成，并发下不会重复扣减或漏计；
    计数按来源（source）隔离，某个来源被限不影响其他来源。
    """

    def __init__(self, window_seconds: int, max_requests: int) -> None:
        if window_seconds <= 0 or max_requests <= 0:
            raise ValueError("window_seconds 与 max_requests 必须为正数")
        self._window_seconds = window_seconds
        self._max_requests = max_requests
        self._lock = threading.Lock()
        # source -> (窗口起点时间戳, 窗口内已计数)
        self._counters: dict[str, tuple[float, int]] = {}

    def hit(self, source: str, now: float) -> tuple[bool, int]:
        """记录一次请求。返回 (是否放行, 拒绝时还需等待的秒数)。"""
        with self._lock:
            window_start, count = self._counters.get(source, (now, 0))
            if now - window_start >= self._window_seconds:
                # 窗口已过期，开启新窗口
                window_start, count = now, 0
            if count >= self._max_requests:
                retry_after = int(self._window_seconds - (now - window_start)) + 1
                return False, retry_after
            self._counters[source] = (window_start, count + 1)
            return True, 0

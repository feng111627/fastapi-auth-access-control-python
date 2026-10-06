"""按来源（IP + 入口桶）的固定时间窗限流，线程安全。"""

import threading
import time
from dataclasses import dataclass


@dataclass
class RateLimitResult:
    allowed: bool
    retry_after: int  # 秒；未被限流时为 0
    remaining: int


class RateLimiter:
    """固定窗口计数器：key = (bucket, source)。

    同一把锁内完成"读计数 + 自增"，并发下不会重复扣减或漏计；
    不同 source/bucket 的计数互相独立，互不影响。
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # (bucket, source) -> (window_start, count)
        self._windows: dict[tuple[str, str], tuple[float, int]] = {}

    def hit(self, bucket: str, source: str, limit: int, window: int) -> RateLimitResult:
        now = time.monotonic()
        key = (bucket, source)
        with self._lock:
            start, count = self._windows.get(key, (now, 0))
            if now - start >= window:
                # 窗口过期，重新开窗
                start, count = now, 0
            if count >= limit:
                retry_after = max(1, int(window - (now - start)) + 1)
                return RateLimitResult(False, retry_after, 0)
            count += 1
            self._windows[key] = (start, count)
            return RateLimitResult(True, 0, limit - count)

    def reset(self) -> None:
        with self._lock:
            self._windows.clear()


rate_limiter = RateLimiter()

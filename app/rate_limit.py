"""按来源（IP + 入口桶）的固定时间窗限流，线程安全、状态有界。"""

import threading
import time
from dataclasses import dataclass

from app import config


@dataclass
class RateLimitResult:
    allowed: bool
    retry_after: int  # 秒；未被限流时为 0
    remaining: int


@dataclass
class _Window:
    start: float
    count: int
    window: int  # 该键使用的窗口时长（秒），回收时据此判断是否过期


class RateLimiter:
    """固定窗口计数器：key = (bucket, source)。

    同一把锁内完成"读计数 + 自增"，并发下不会重复扣减或漏计；
    不同 source/bucket 的计数互相独立，互不影响。
    键数超过 max_keys 时先回收已过期窗口，仍超则淘汰最旧窗口，
    保证长期运行、来源很多时状态不无限增长。
    """

    def __init__(self, max_keys: int | None = None) -> None:
        self._lock = threading.Lock()
        # (bucket, source) -> _Window
        self._windows: dict[tuple[str, str], _Window] = {}
        self._max_keys = (
            max_keys if max_keys is not None else config.RATE_LIMIT_MAX_KEYS
        )

    def _evict(self, now: float) -> None:
        """在锁内回收状态：优先删掉已过期窗口，仍超限则淘汰最旧的。"""
        if len(self._windows) < self._max_keys:
            return
        for key in [k for k, w in self._windows.items() if now - w.start >= w.window]:
            del self._windows[key]
        if len(self._windows) < self._max_keys:
            return
        # 没有可回收的过期窗口时，按开窗时间淘汰最旧的直到腾出空间
        overflow = len(self._windows) - self._max_keys + 1
        for key in sorted(self._windows, key=lambda k: self._windows[k].start)[
            :overflow
        ]:
            del self._windows[key]

    def hit(self, bucket: str, source: str, limit: int, window: int) -> RateLimitResult:
        now = time.monotonic()
        key = (bucket, source)
        with self._lock:
            if key not in self._windows:
                self._evict(now)
            w = self._windows.get(key)
            if w is None or now - w.start >= window:
                # 首次访问或窗口过期：重新开窗
                w = _Window(start=now, count=0, window=window)
                self._windows[key] = w
            if w.count >= limit:
                retry_after = max(1, int(window - (now - w.start)) + 1)
                return RateLimitResult(False, retry_after, 0)
            w.count += 1
            return RateLimitResult(True, 0, limit - w.count)

    def reset(self) -> None:
        with self._lock:
            self._windows.clear()

    @property
    def tracked_keys(self) -> int:
        """当前追踪的 (桶, 来源) 键数，供测试与运维观察。"""
        with self._lock:
            return len(self._windows)


rate_limiter = RateLimiter()

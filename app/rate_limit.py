"""按来源（IP + 入口桶）的固定时间窗限流，线程安全，过期计数可回收。"""

import threading
import time
from dataclasses import dataclass

from app import config


@dataclass
class RateLimitResult:
    allowed: bool
    retry_after: int  # 秒；未被限流时为 0
    remaining: int


class RateLimiter:
    """固定窗口计数器：key = (bucket, source)。

    同一把锁内完成"读计数 + 自增"，并发下不会重复扣减或漏计；
    不同 source/bucket 的计数互相独立，互不影响。

    内存有界：每次命中顺带处理本 key 的过期窗口；当键数超过容量上限时，
    按清扫间隔节流地做一次全量回收，删除所有已过期窗口，保证长期运行下
    大量来源的过期计数不会无限堆积。
    """

    def __init__(
        self,
        max_keys: int = config.RATE_LIMIT_MAX_KEYS,
        sweep_interval: float = config.RATE_LIMIT_SWEEP_INTERVAL,
    ) -> None:
        self._lock = threading.Lock()
        # (bucket, source) -> (window_start, count, window_seconds)
        self._windows: dict[tuple[str, str], tuple[float, int, float]] = {}
        self._max_keys = max_keys
        self._sweep_interval = sweep_interval
        self._last_sweep = 0.0

    def hit(self, bucket: str, source: str, limit: int, window: int) -> RateLimitResult:
        now = time.monotonic()
        key = (bucket, source)
        with self._lock:
            record = self._windows.get(key)
            if record is None:
                start, count = now, 0
            else:
                start, count, _ = record
                if now - start >= window:
                    # 窗口过期，重新开窗
                    start, count = now, 0
            if count >= limit:
                retry_after = max(1, int(window - (now - start)) + 1)
                result = RateLimitResult(False, retry_after, 0)
            else:
                count += 1
                self._windows[key] = (start, count, float(window))
                result = RateLimitResult(True, 0, limit - count)
            self._evict_if_needed(now)
            return result

    def _evict_if_needed(self, now: float) -> None:
        """键数超容量时做节流的全量清扫；调用方需持有 self._lock。"""
        if len(self._windows) < self._max_keys:
            return
        if now - self._last_sweep < self._sweep_interval:
            return
        self._last_sweep = now
        stale = [
            key
            for key, (start, _count, window) in self._windows.items()
            if now - start >= window
        ]
        for key in stale:
            self._windows.pop(key, None)

    def purge_expired(self, now: float | None = None) -> int:
        """主动回收所有已过期窗口，返回清除条数（测试与运维巡检可用）。"""
        now = time.monotonic() if now is None else now
        with self._lock:
            stale = [
                key
                for key, (start, _count, window) in self._windows.items()
                if now - start >= window
            ]
            for key in stale:
                self._windows.pop(key, None)
            if stale:
                self._last_sweep = now
            return len(stale)

    def reset(self) -> None:
        with self._lock:
            self._windows.clear()
            self._last_sweep = 0.0


rate_limiter = RateLimiter()

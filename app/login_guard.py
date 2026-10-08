"""账号维度的登录失败保护：连续失败计数 + 临时锁定，线程安全。

- 以账号名为 key，不同账号之间完全独立；
- 失败计数在固定窗口内累计，窗口滑过后重新计数；
- 达到阈值后账号进入锁定，锁定到期自动恢复（无需额外清理线程）；
- 登录成功后计数清零；
- 全部"读状态 + 改状态"在同一把锁内完成，并发下计数精确，
  不会因竞争提前解锁，也不会把账号永久锁死。
"""

import threading
import time
from dataclasses import dataclass, field


def _clock() -> float:
    return time.monotonic()


@dataclass
class _AccountState:
    window_start: float
    failures: int = 0
    locked_until: float = 0.0


@dataclass
class LockResult:
    locked: bool
    retry_after: int  # 秒；未锁定时为 0


class LoginGuard:
    def __init__(
        self,
        threshold: int,
        window: int,
        lock_duration: int,
        clock=_clock,
        max_keys: int = 10_000,
        sweep_interval: float = 30.0,
    ) -> None:
        self._threshold = threshold
        self._window = window
        self._lock_duration = lock_duration
        self._clock = clock
        self._max_keys = max_keys
        self._sweep_interval = sweep_interval
        self._lock = threading.Lock()
        self._accounts: dict[str, _AccountState] = {}
        self._last_sweep = 0.0

    def _is_stale(self, state: _AccountState, now: float) -> bool:
        # 锁定中的状态一律保留（未到点不能误清）；其余以计数窗口过期为准
        return not state.locked_until and now - state.window_start >= self._window

    def _sweep_if_needed(self, now: float) -> None:
        """账号名来自请求，攻击者可用海量随机名制造键；超容量时节流回收。"""
        if len(self._accounts) < self._max_keys:
            return
        if now - self._last_sweep < self._sweep_interval:
            return
        self._last_sweep = now
        stale = [k for k, s in self._accounts.items() if self._is_stale(s, now)]
        for k in stale:
            self._accounts.pop(k, None)

    def _effective_state(self, key: str, now: float) -> _AccountState:
        """取出该账号在 now 时刻的有效状态，过期的锁定/计数就地恢复。"""
        state = self._accounts.get(key)
        if state is None:
            self._sweep_if_needed(now)
            state = _AccountState(window_start=now)
            self._accounts[key] = state
            return state
        if state.locked_until and now >= state.locked_until:
            # 锁定到期：自动恢复，计数清零，重新开窗
            state.failures = 0
            state.locked_until = 0.0
            state.window_start = now
        elif now - state.window_start >= self._window and not state.locked_until:
            # 未锁定且计数窗口已过：失败计数重新开始
            state.failures = 0
            state.window_start = now
        return state

    def check_locked(self, key: str) -> LockResult:
        """账号当前是否处于锁定中；返回剩余锁定秒数（向上取整，至少 1）。"""
        now = self._clock()
        with self._lock:
            state = self._effective_state(key, now)
            if state.locked_until and now < state.locked_until:
                return LockResult(True, max(1, int(state.locked_until - now) + 1))
            return LockResult(False, 0)

    def record_failure(self, key: str) -> LockResult:
        """登记一次失败，必要时锁定账号，返回登记后的锁定状态。"""
        now = self._clock()
        with self._lock:
            state = self._effective_state(key, now)
            if state.locked_until and now < state.locked_until:
                return LockResult(True, max(1, int(state.locked_until - now) + 1))
            state.failures += 1
            if state.failures >= self._threshold:
                state.locked_until = now + self._lock_duration
                return LockResult(True, max(1, self._lock_duration))
            return LockResult(False, 0)

    def record_success(self, key: str) -> None:
        """登录成功：清零该账号的失败计数与锁定。"""
        with self._lock:
            self._accounts.pop(key, None)

    def purge(self, now: float | None = None) -> int:
        """回收过期（未锁定且计数窗口已过）的账号状态，返回清除条数。"""
        now = self._clock() if now is None else now
        with self._lock:
            stale = [key for key, state in self._accounts.items()
                     if self._is_stale(state, now)]
            for key in stale:
                self._accounts.pop(key, None)
            if stale:
                self._last_sweep = now
            return len(stale)

    def reset(self) -> None:
        with self._lock:
            self._accounts.clear()
            self._last_sweep = 0.0


# 默认单例：阈值/窗口/锁定时长取自全局配置
def _default_guard() -> "LoginGuard":
    from app import config

    return LoginGuard(
        threshold=config.LOGIN_LOCKOUT_THRESHOLD,
        window=config.LOGIN_LOCKOUT_WINDOW,
        lock_duration=config.LOGIN_LOCKOUT_DURATION,
    )


login_guard = _default_guard()

"""账号维度的登录失败保护：连续失败临时锁定，线程安全。

与按来源的限流互补：限流防的是"一个来源打爆接口"，
这里防的是"同一个账号被来自许多来源轮流猜密码"。
"""

import threading
import time


class LoginGuard:
    """按账号记录登录失败，达到阈值后临时锁定该账号。

    - 计数与状态迁移都在同一把锁内完成，并发下不会提前解锁或锁死；
    - 不同账号的失败计数与锁定状态互相独立；
    - 锁定到期后自动恢复（惰性清理，无需后台线程）；
    - 登录成功会清零该账号的失败计数。
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # username -> (window_start, fail_count)
        self._failures: dict[str, tuple[float, int]] = {}
        # username -> locked_until（monotonic 时间戳）
        self._locked_until: dict[str, float] = {}

    def locked_remaining(self, username: str) -> int:
        """返回该账号还需等待的锁定秒数；未锁定或锁定已到期返回 0。

        到期的锁定在这里惰性解除，同时清掉残留的失败计数。
        """
        now = time.monotonic()
        with self._lock:
            until = self._locked_until.get(username)
            if until is None:
                return 0
            if now < until:
                return max(1, int(until - now) + 1)
            # 锁定到期：自动恢复
            del self._locked_until[username]
            self._failures.pop(username, None)
            return 0

    def record_failure(
        self, username: str, max_failures: int, window: int, lock_seconds: int
    ) -> int:
        """记录一次登录失败；若本次失败触发锁定，返回锁定时长秒数，否则返回 0。"""
        now = time.monotonic()
        with self._lock:
            start, count = self._failures.get(username, (now, 0))
            if now - start >= window:
                # 计数窗口过期，重新开窗
                start, count = now, 0
            count += 1
            if count >= max_failures:
                self._locked_until[username] = now + lock_seconds
                self._failures.pop(username, None)
                return lock_seconds
            self._failures[username] = (start, count)
            return 0

    def record_success(self, username: str) -> None:
        """登录成功：清零该账号的失败计数（不影响尚未到期的既有锁定）。"""
        with self._lock:
            self._failures.pop(username, None)

    def reset(self) -> None:
        with self._lock:
            self._failures.clear()
            self._locked_until.clear()


login_guard = LoginGuard()

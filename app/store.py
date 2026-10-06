"""内存数据存储：用户、令牌撤销登记。本地可运行，进程内状态。"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class User:
    username: str
    password: str
    role: str


class InMemoryStore:
    """线程安全的内存存储，保存用户表与令牌状态。

    - _revoked: 被撤销（登出 / 主动撤销）的令牌 jti -> 过期时间戳
    - _used_refresh: 已轮换过的旧刷新令牌 jti -> 过期时间戳，用于重放检测
    条目过期后会被惰性清理，避免无限增长。
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._users: dict[str, User] = {}
        self._revoked: dict[str, float] = {}
        self._used_refresh: dict[str, float] = {}

    # ---- 用户 ----

    def add_user(self, user: User) -> None:
        with self._lock:
            self._users[user.username] = user

    def get_user(self, username: str) -> User | None:
        with self._lock:
            return self._users.get(username)

    # ---- 撤销登记 ----

    def revoke(self, jti: str, expires_at: float) -> None:
        with self._lock:
            self._revoked[jti] = expires_at
            self._purge_locked(self._revoked)

    def is_revoked(self, jti: str) -> bool:
        with self._lock:
            self._purge_locked(self._revoked)
            return jti in self._revoked

    # ---- 刷新令牌轮换记录 ----

    def mark_refresh_used(self, jti: str, expires_at: float) -> None:
        with self._lock:
            self._used_refresh[jti] = expires_at
            self._purge_locked(self._used_refresh)

    def is_refresh_used(self, jti: str) -> bool:
        with self._lock:
            self._purge_locked(self._used_refresh)
            return jti in self._used_refresh

    # ---- 内部 ----

    @staticmethod
    def _purge_locked(table: dict[str, float]) -> None:
        now = time.time()
        expired = [k for k, exp in table.items() if exp <= now]
        for k in expired:
            del table[k]

"""内存数据存储：用户、已撤销令牌、刷新令牌轮换记录。"""

import hashlib
import hmac
import secrets
import threading


def _hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes.fromhex(salt), 100_000
    ).hex()


def _make_user(username: str, password: str, role: str) -> dict:
    salt = secrets.token_hex(16)
    return {
        "username": username,
        "role": role,
        "salt": salt,
        "password_hash": _hash_password(password, salt),
    }


class UserStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._users: dict[str, dict] = {}
        # 预置三种角色的本地账号
        for username, password, role in (
            ("admin", "admin-pass", "admin"),
            ("editor", "editor-pass", "editor"),
            ("viewer", "viewer-pass", "viewer"),
        ):
            self._users[username] = _make_user(username, password, role)

    def get_by_username(self, username: str) -> dict | None:
        with self._lock:
            return self._users.get(username)

    def verify_password(self, username: str, password: str) -> dict | None:
        user = self.get_by_username(username)
        if user is None:
            return None
        candidate = _hash_password(password, user["salt"])
        if hmac.compare_digest(candidate, user["password_hash"]):
            return user
        return None


class TokenStore:
    """记录撤销的访问令牌 jti、刷新令牌状态、会话链与账号令牌代数。

    - 访问令牌：单个 jti 的撤销名单（登出/单令牌撤销）；
    - 刷新令牌：jti -> 状态(active/rotated/revoked) + 所属会话链 sid；
    - 会话链 sid -> 撤销原因（"revoked" 主动撤销 / "compromised" 疑似泄露）；
    - 账号令牌代数 gen：每次"全端作废"递增，旧代数的令牌一律失效，
      作废后重新登录签发的新代数令牌不受影响，也不牵连其他账号。
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._revoked_access: set[str] = set()
        # jti -> {"status": "active" | "rotated" | "revoked", "sid": str}
        self._refresh: dict[str, dict] = {}
        # sid -> "revoked" | "compromised"
        self._revoked_sessions: dict[str, str] = {}
        # 账号 -> 当前令牌代数
        self._account_gen: dict[str, int] = {}
        # 账号 -> 该账号历史登录产生的会话链 sid 集合
        self._account_sessions: dict[str, set[str]] = {}

    def register_refresh(self, jti: str, sid: str) -> None:
        with self._lock:
            self._refresh[jti] = {"status": "active", "sid": sid}

    def refresh_status(self, jti: str) -> str | None:
        with self._lock:
            record = self._refresh.get(jti)
            return record["status"] if record is not None else None

    def refresh_sid(self, jti: str) -> str | None:
        with self._lock:
            record = self._refresh.get(jti)
            return record["sid"] if record is not None else None

    def mark_rotated(self, jti: str) -> bool:
        """原子地将 active 的刷新令牌标记为已轮换，返回是否成功。

        并发轮换时只有一个调用能拿到 True，保证旧令牌不会被重复换新。
        """
        with self._lock:
            record = self._refresh.get(jti)
            if record is not None and record["status"] == "active":
                record["status"] = "rotated"
                return True
            return False

    def revoke_refresh(self, jti: str) -> None:
        with self._lock:
            record = self._refresh.get(jti)
            if record is not None:
                record["status"] = "revoked"

    def revoke_access(self, jti: str) -> None:
        with self._lock:
            self._revoked_access.add(jti)

    def is_access_revoked(self, jti: str) -> bool:
        with self._lock:
            return jti in self._revoked_access

    # ---- 会话链与全端作废 ----

    def current_generation(self, account: str) -> int:
        with self._lock:
            return self._account_gen.get(account, 0)

    def bump_generation(self, account: str) -> int:
        """全端作废：账号令牌代数 +1，并把该账号所有会话链标记为主动撤销。"""
        with self._lock:
            new_gen = self._account_gen.get(account, 0) + 1
            self._account_gen[account] = new_gen
            for sid in self._account_sessions.get(account, ()):
                self._revoked_sessions.setdefault(sid, "revoked")
            return new_gen

    def register_session(self, account: str, sid: str) -> int:
        """登记一次登录产生的会话链，返回该账号当前令牌代数。"""
        with self._lock:
            self._account_sessions.setdefault(account, set()).add(sid)
            return self._account_gen.get(account, 0)

    def revoke_sessions_for_account(self, account: str, reason: str) -> None:
        """把该账号名下所有会话链统一标记撤销原因。"""
        with self._lock:
            for sid in self._account_sessions.get(account, ()):
                self._revoked_sessions[sid] = reason

    def revoke_session(self, sid: str, reason: str) -> None:
        with self._lock:
            # 疑似泄露是更"重"的结论，不被普通撤销覆盖
            if self._revoked_sessions.get(sid) != "compromised":
                self._revoked_sessions[sid] = reason

    def session_revocation(self, sid: str) -> str | None:
        with self._lock:
            return self._revoked_sessions.get(sid)

    def reset(self) -> None:
        """清空全部易失状态（测试隔离用）。"""
        with self._lock:
            self._revoked_access.clear()
            self._refresh.clear()
            self._revoked_sessions.clear()
            self._account_gen.clear()
            self._account_sessions.clear()


user_store = UserStore()
token_store = TokenStore()

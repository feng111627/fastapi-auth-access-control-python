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
    """记录撤销的访问令牌 jti 与刷新令牌状态（active/rotated/revoked）。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._revoked_access: set[str] = set()
        # jti -> "active" | "rotated" | "revoked"
        self._refresh: dict[str, str] = {}

    def register_refresh(self, jti: str) -> None:
        with self._lock:
            self._refresh[jti] = "active"

    def refresh_status(self, jti: str) -> str | None:
        with self._lock:
            return self._refresh.get(jti)

    def mark_rotated(self, jti: str) -> bool:
        """原子地将 active 的刷新令牌标记为已轮换，返回是否成功。

        并发轮换时只有一个调用能拿到 True，保证旧令牌不会被重复换新。
        """
        with self._lock:
            if self._refresh.get(jti) == "active":
                self._refresh[jti] = "rotated"
                return True
            return False

    def revoke_refresh(self, jti: str) -> None:
        with self._lock:
            if jti in self._refresh:
                self._refresh[jti] = "revoked"

    def revoke_access(self, jti: str) -> None:
        with self._lock:
            self._revoked_access.add(jti)

    def is_access_revoked(self, jti: str) -> bool:
        with self._lock:
            return jti in self._revoked_access


user_store = UserStore()
token_store = TokenStore()

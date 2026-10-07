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
    """记录撤销的访问令牌 jti、刷新令牌状态、会话链（family）与账号令牌版本。

    - 刷新令牌按 jti 记录状态（active/rotated/revoked），并归属某条会话链；
    - 会话链（family）：一次登录签发的刷新令牌及其轮换出的所有后继同属一条链，
      旧令牌被复用时整条链作废；
    - 账号令牌版本：revoke-all 时单调递增，所有携带旧版本号的令牌立即失效。
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._revoked_access: set[str] = set()
        # jti -> "active" | "rotated" | "revoked"
        self._refresh: dict[str, str] = {}
        # 刷新令牌 jti -> 会话链 fid
        self._refresh_family: dict[str, str] = {}
        # 会话链 fid -> "active" | "revoked"
        self._families: dict[str, str] = {}
        # 账号 -> 其名下会话链集合
        self._user_families: dict[str, set[str]] = {}
        # 账号 -> 当前令牌版本号（单调递增）
        self._user_version: dict[str, int] = {}

    def register_refresh(self, jti: str, fid: str) -> None:
        with self._lock:
            self._refresh[jti] = "active"
            self._refresh_family[jti] = fid

    def refresh_status(self, jti: str) -> str | None:
        with self._lock:
            return self._refresh.get(jti)

    def refresh_family(self, jti: str) -> str | None:
        with self._lock:
            return self._refresh_family.get(jti)

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

    # ---- 会话链（family） ----

    def register_family(self, fid: str, username: str) -> None:
        with self._lock:
            self._families[fid] = "active"
            self._user_families.setdefault(username, set()).add(fid)

    def family_status(self, fid: str) -> str | None:
        with self._lock:
            return self._families.get(fid)

    def revoke_family(self, fid: str) -> None:
        """整条会话链作废：链上所有刷新令牌一并失效。"""
        with self._lock:
            if fid in self._families:
                self._families[fid] = "revoked"
            for jti, family in self._refresh_family.items():
                if family == fid and self._refresh.get(jti) == "active":
                    self._refresh[jti] = "revoked"

    # ---- 账号令牌版本 ----

    def current_version(self, username: str) -> int:
        with self._lock:
            return self._user_version.get(username, 0)

    def revoke_all_for_user(self, username: str) -> None:
        """一次性作废该账号此前签发的全部令牌（访问 + 刷新，含各会话链后继）。

        通过递增令牌版本号实现：所有携带旧版本号的令牌立即失效；
        同时吊销该账号名下所有会话链。不影响其他账号。
        """
        with self._lock:
            self._user_version[username] = self._user_version.get(username, 0) + 1
            user_families = self._user_families.get(username, set())
            for fid in user_families:
                self._families[fid] = "revoked"
            for jti, family in self._refresh_family.items():
                if family in user_families and self._refresh.get(jti) == "active":
                    self._refresh[jti] = "revoked"


user_store = UserStore()
token_store = TokenStore()

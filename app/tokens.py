"""令牌签发、校验、轮换。访问令牌短时效，刷新令牌可轮换。"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Callable

import jwt

from app.config import Settings
from app.errors import TokenError, TokenErrorReason
from app.store import InMemoryStore

ACCESS = "access"
REFRESH = "refresh"


@dataclass(frozen=True)
class TokenPair:
    access_token: str
    refresh_token: str
    access_expires_in: int
    refresh_expires_in: int


@dataclass(frozen=True)
class TokenClaims:
    sub: str
    role: str
    jti: str
    token_type: str  # "access" | "refresh"
    exp: float


class TokenService:
    """负责签发与校验令牌，撤销与轮换状态落在 store 中。

    clock 可注入，便于测试构造过期场景。
    """

    def __init__(
        self,
        settings: Settings,
        store: InMemoryStore,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._settings = settings
        self._store = store
        self._clock = clock

    # ---- 签发 ----

    def issue_pair(self, username: str, role: str) -> TokenPair:
        now = self._clock()
        access = self._encode(username, role, ACCESS, now,
                              self._settings.access_token_ttl_seconds)
        refresh = self._encode(username, role, REFRESH, now,
                               self._settings.refresh_token_ttl_seconds)
        return TokenPair(
            access_token=access,
            refresh_token=refresh,
            access_expires_in=self._settings.access_token_ttl_seconds,
            refresh_expires_in=self._settings.refresh_token_ttl_seconds,
        )

    def _encode(self, sub: str, role: str, token_type: str,
                now: float, ttl: int) -> str:
        payload = {
            "sub": sub,
            "role": role,
            "jti": uuid.uuid4().hex,
            "type": token_type,
            "iat": int(now),
            "exp": int(now) + ttl,
        }
        return jwt.encode(payload, self._settings.secret_key,
                          algorithm=self._settings.algorithm)

    # ---- 校验 ----

    def verify_access(self, token: str) -> TokenClaims:
        claims = self._decode(token)
        if claims.token_type != ACCESS:
            raise TokenError(TokenErrorReason.WRONG_TYPE)
        if self._store.is_revoked(claims.jti):
            raise TokenError(TokenErrorReason.REVOKED)
        return claims

    def _decode(self, token: str) -> TokenClaims:
        try:
            payload = jwt.decode(
                token,
                self._settings.secret_key,
                algorithms=[self._settings.algorithm],
            )
        except jwt.ExpiredSignatureError:
            raise TokenError(TokenErrorReason.EXPIRED) from None
        except jwt.InvalidSignatureError:
            raise TokenError(TokenErrorReason.TAMPERED) from None
        except jwt.InvalidTokenError:
            raise TokenError(TokenErrorReason.MALFORMED) from None
        try:
            return TokenClaims(
                sub=payload["sub"],
                role=payload["role"],
                jti=payload["jti"],
                token_type=payload["type"],
                exp=float(payload["exp"]),
            )
        except (KeyError, TypeError, ValueError):
            raise TokenError(TokenErrorReason.MALFORMED) from None

    # ---- 轮换 ----

    def rotate_refresh(self, refresh_token: str) -> TokenPair:
        claims = self._decode(refresh_token)
        if claims.token_type != REFRESH:
            raise TokenError(TokenErrorReason.WRONG_TYPE)
        if self._store.is_revoked(claims.jti):
            raise TokenError(TokenErrorReason.REVOKED)
        if self._store.is_refresh_used(claims.jti):
            raise TokenError(TokenErrorReason.REUSED_REFRESH)
        # 旧刷新令牌立即作废并登记，再次使用即判定为重放
        self._store.mark_refresh_used(claims.jti, claims.exp)
        return self.issue_pair(claims.sub, claims.role)

    # ---- 撤销 ----

    def revoke_token(self, token: str) -> None:
        """撤销单个令牌（登出 / 主动撤销时调用）。"""
        claims = self._decode(token)
        self._store.revoke(claims.jti, claims.exp)

    def revoke_jti(self, jti: str, exp: float) -> None:
        """按 jti 撤销（已校验过的令牌无需再次解码）。"""
        self._store.revoke(jti, exp)

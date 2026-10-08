"""令牌签发与校验：区分过期/篡改/撤销/复用/疑似泄露/旧代数。"""

import time
import uuid

import jwt

from app import config
from app.errors import (
    RefreshTokenReused,
    SessionCompromised,
    TokenExpired,
    TokenRevoked,
    TokenTampered,
)
from app.store import token_store, user_store


def _now() -> int:
    return int(time.time())


def _revocation_error(reason: str, compromised_message: str, revoked_message: str):
    """会话链撤销原因 -> 对应业务错误。"""
    if reason == "compromised":
        return SessionCompromised(compromised_message)
    return TokenRevoked(revoked_message)


def issue_access_token(
    username: str, role: str, sid: str, gen: int = 0
) -> str:
    now = _now()
    payload = {
        "sub": username,
        "role": role,
        "type": "access",
        "jti": uuid.uuid4().hex,
        "sid": sid,
        "gen": gen,
        "iat": now,
        "exp": now + config.ACCESS_TOKEN_TTL_SECONDS,
    }
    return jwt.encode(payload, config.SECRET_KEY, algorithm=config.ALGORITHM)


def issue_refresh_token(username: str, sid: str, gen: int = 0) -> str:
    now = _now()
    jti = uuid.uuid4().hex
    payload = {
        "sub": username,
        "type": "refresh",
        "jti": jti,
        "sid": sid,
        "gen": gen,
        "iat": now,
        "exp": now + config.REFRESH_TOKEN_TTL_SECONDS,
    }
    token_store.register_refresh(jti, sid)
    return jwt.encode(payload, config.SECRET_KEY, algorithm=config.ALGORITHM)


def open_session(username: str, role: str) -> tuple[str, str, str]:
    """一次登录开启一条新会话链：新 sid 带上账号当前令牌代数。"""
    sid = uuid.uuid4().hex
    gen = token_store.register_session(username, sid)
    access_token = issue_access_token(username, role, sid, gen)
    refresh_token = issue_refresh_token(username, sid, gen)
    return access_token, refresh_token, sid


def _decode(token: str, expected_type: str) -> dict:
    """解码并做基础校验，把 jwt 异常映射为可区分的业务错误。"""
    try:
        payload = jwt.decode(
            token, config.SECRET_KEY, algorithms=[config.ALGORITHM]
        )
    except jwt.ExpiredSignatureError:
        raise TokenExpired("令牌已过期") from None
    except jwt.InvalidTokenError:
        raise TokenTampered("令牌签名或格式非法") from None
    if payload.get("type") != expected_type:
        raise TokenTampered("令牌类型不符")
    return payload


def _check_generation(account: str, gen: int) -> None:
    """账号已全端作废（代数递增）后，旧代数令牌一律按主动撤销拒绝。"""
    if token_store.current_generation(account) != gen:
        raise TokenRevoked("该账号此前签发的令牌已被全部作废")


def verify_access_token(token: str) -> dict:
    """校验访问令牌，依次区分：过期 / 篡改 / 旧代数 / 链撤销(含泄露) / 单令牌撤销。"""
    payload = _decode(token, "access")
    _check_generation(payload.get("sub", ""), payload.get("gen", 0))
    reason = token_store.session_revocation(payload.get("sid", ""))
    if reason is not None:
        raise _revocation_error(
            reason,
            "会话链因疑似令牌泄露已被全部作废",
            "访问令牌所属会话已被撤销",
        )
    if token_store.is_access_revoked(payload["jti"]):
        raise TokenRevoked("访问令牌已被撤销")
    return payload


def rotate_refresh_token(token: str) -> tuple[str, str]:
    """校验并轮换刷新令牌，返回 (新访问令牌, 新刷新令牌)。

    依次区分：过期 / 篡改 / 旧代数 / 链撤销(主动/泄露) / 单令牌撤销 /
    已轮换旧令牌复用（疑似泄露，整条会话链作废）。轮换后继令牌沿用同一 sid
    与同一代数，因此全端作废时后继令牌同样失效。
    """
    payload = _decode(token, "refresh")
    account = payload["sub"]
    sid = payload.get("sid", "")
    gen = payload.get("gen", 0)
    jti = payload["jti"]

    _check_generation(account, gen)

    reason = token_store.session_revocation(sid)
    if reason is not None:
        raise _revocation_error(
            reason,
            "会话链因疑似令牌泄露已被全部作废",
            "刷新令牌所属会话已被撤销",
        )

    status = token_store.refresh_status(jti)
    if status == "revoked":
        raise TokenRevoked("刷新令牌已被撤销")
    if status != "active" or not token_store.mark_rotated(jti):
        # 已轮换过的旧刷新令牌再次出现：判定为疑似泄露，整条会话链作废
        token_store.revoke_session(sid, "compromised")
        raise RefreshTokenReused("刷新令牌已被轮换，旧令牌不得重复使用")

    user = user_store.get_by_username(account)
    if user is None:
        raise TokenTampered("令牌对应的用户不存在")
    return issue_access_token(user["username"], user["role"], sid, gen), (
        issue_refresh_token(user["username"], sid, gen)
    )


def revoke_all_for_account(account: str) -> int:
    """全端作废：账号令牌代数 +1，名下所有会话链立即失效。返回新代数。"""
    return token_store.bump_generation(account)


def revoke_token(token: str) -> None:
    """撤销令牌：按类型分别吊销访问令牌或刷新令牌。"""
    # 先不校验类型地解码，确认是合法令牌后再按类型撤销
    try:
        payload = jwt.decode(
            token, config.SECRET_KEY, algorithms=[config.ALGORITHM]
        )
    except jwt.ExpiredSignatureError:
        raise TokenExpired("令牌已过期") from None
    except jwt.InvalidTokenError:
        raise TokenTampered("令牌签名或格式非法") from None
    if payload.get("type") == "access":
        token_store.revoke_access(payload["jti"])
    elif payload.get("type") == "refresh":
        token_store.revoke_refresh(payload["jti"])
    else:
        raise TokenTampered("令牌类型不符")

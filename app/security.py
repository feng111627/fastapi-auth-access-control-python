"""令牌签发与校验：区分过期/篡改/撤销/复用，支持会话链与全端撤销。"""

import time
import uuid

import jwt

from app import config
from app.errors import (
    RefreshTokenReused,
    TokenExpired,
    TokenRevoked,
    TokenTampered,
)
from app.store import token_store


def _now() -> int:
    return int(time.time())


def issue_access_token(username: str, role: str, fid: str, version: int) -> str:
    now = _now()
    payload = {
        "sub": username,
        "role": role,
        "type": "access",
        "jti": uuid.uuid4().hex,
        "fid": fid,
        "tv": version,
        "iat": now,
        "exp": now + config.ACCESS_TOKEN_TTL_SECONDS,
    }
    return jwt.encode(payload, config.SECRET_KEY, algorithm=config.ALGORITHM)


def issue_refresh_token(username: str, fid: str, version: int) -> str:
    now = _now()
    jti = uuid.uuid4().hex
    payload = {
        "sub": username,
        "type": "refresh",
        "jti": jti,
        "fid": fid,
        "tv": version,
        "iat": now,
        "exp": now + config.REFRESH_TOKEN_TTL_SECONDS,
    }
    token_store.register_refresh(jti, fid)
    return jwt.encode(payload, config.SECRET_KEY, algorithm=config.ALGORITHM)


def issue_token_pair(username: str, role: str, fid: str | None = None) -> tuple[str, str]:
    """签发一对令牌；不传 fid 时开启一条新的会话链（登录场景）。"""
    if fid is None:
        fid = uuid.uuid4().hex
        token_store.register_family(fid, username)
    version = token_store.current_version(username)
    return (
        issue_access_token(username, role, fid, version),
        issue_refresh_token(username, fid, version),
    )


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


def _check_still_valid(payload: dict) -> None:
    """公共有效性检查：所属会话链未作废、令牌版本未被淘汰。"""
    fid = payload.get("fid")
    if fid is not None and token_store.family_status(fid) == "revoked":
        raise TokenRevoked("所属会话链已整体作废")
    if payload.get("tv", 0) < token_store.current_version(payload["sub"]):
        raise TokenRevoked("账号令牌已全端撤销")


def verify_access_token(token: str) -> dict:
    """校验访问令牌，依次区分：过期 / 篡改 / 已撤销。"""
    payload = _decode(token, "access")
    if token_store.is_access_revoked(payload["jti"]):
        raise TokenRevoked("访问令牌已被撤销")
    _check_still_valid(payload)
    return payload


def rotate_refresh_token(token: str) -> tuple[str, str]:
    """校验并轮换刷新令牌，返回 (新访问令牌, 新刷新令牌)。

    依次区分：过期 / 篡改 / 已撤销 / 已轮换过的旧令牌复用。
    旧令牌复用按疑似泄露处置：整条会话链立即作废。
    """
    payload = _decode(token, "refresh")
    jti = payload["jti"]
    status = token_store.refresh_status(jti)
    if status == "revoked":
        raise TokenRevoked("刷新令牌已被撤销")
    _check_still_valid(payload)
    if status != "active" or not token_store.mark_rotated(jti):
        # 已轮换过的旧令牌再次使用：疑似泄露，整条会话链作废
        fid = token_store.refresh_family(jti)
        if fid is not None:
            token_store.revoke_family(fid)
        raise RefreshTokenReused("刷新令牌已被轮换，旧令牌不得重复使用")
    from app.store import user_store

    user = user_store.get_by_username(payload["sub"])
    if user is None:
        raise TokenTampered("令牌对应的用户不存在")
    # 后继令牌留在同一条会话链上
    return issue_token_pair(user["username"], user["role"], fid=payload.get("fid"))


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

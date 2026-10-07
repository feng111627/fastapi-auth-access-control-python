"""认证入口：登录、刷新、登出、撤销。"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app import config
from app.deps import (
    current_user,
    login_rate_limit,
    logout_rate_limit,
    refresh_rate_limit,
    revoke_rate_limit,
)
from app.errors import AuthError
from app.login_guard import login_guard
from app.security import (
    issue_token_pair,
    revoke_token,
    rotate_refresh_token,
)
from app.store import token_store, user_store

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str


def _account_locked_response(retry_after: int) -> HTTPException:
    return HTTPException(
        status_code=423,
        detail={
            "code": "account_locked",
            "message": f"账号已临时锁定，请 {retry_after} 秒后重试",
            "retry_after": retry_after,
        },
        headers={"Retry-After": str(retry_after)},
    )


@router.post("/login", response_model=TokenPair, dependencies=[Depends(login_rate_limit)])
def login(body: LoginRequest) -> TokenPair:
    # 账号维度锁定优先于密码校验：锁定期间无论来源、无论密码对错都拒绝
    remaining = login_guard.locked_remaining(body.username)
    if remaining > 0:
        raise _account_locked_response(remaining)
    user = user_store.verify_password(body.username, body.password)
    if user is None:
        locked_for = login_guard.record_failure(
            body.username,
            config.LOGIN_MAX_FAILURES,
            config.LOGIN_FAILURE_WINDOW_SECONDS,
            config.LOGIN_LOCK_SECONDS,
        )
        if locked_for > 0:
            raise _account_locked_response(locked_for)
        raise HTTPException(
            status_code=401,
            detail={"code": "invalid_credentials", "message": "用户名或密码错误"},
        )
    login_guard.record_success(body.username)
    access_token, refresh_token = issue_token_pair(user["username"], user["role"])
    return TokenPair(access_token=access_token, refresh_token=refresh_token)


@router.post("/refresh", response_model=TokenPair, dependencies=[Depends(refresh_rate_limit)])
def refresh(body: RefreshRequest) -> TokenPair:
    try:
        access_token, refresh_token = rotate_refresh_token(body.refresh_token)
    except AuthError as exc:
        raise HTTPException(
            status_code=401, detail={"code": exc.code, "message": str(exc)}
        ) from None
    return TokenPair(access_token=access_token, refresh_token=refresh_token)


@router.post("/logout", dependencies=[Depends(logout_rate_limit)])
def logout(body: LogoutRequest, user: dict = Depends(current_user)) -> dict:
    """登出：当前访问令牌与提交的刷新令牌同时立刻失效。"""
    token_store.revoke_access(user["jti"])
    try:
        revoke_token(body.refresh_token)
    except AuthError:
        # 刷新令牌本身已失效不影响登出语义：访问令牌已被吊销
        pass
    return {"detail": "logged_out"}


@router.post("/revoke", dependencies=[Depends(revoke_rate_limit)])
def revoke(body: RefreshRequest, user: dict = Depends(current_user)) -> dict:
    """主动撤销指定刷新令牌（需持有有效访问令牌）。"""
    try:
        revoke_token(body.refresh_token)
    except AuthError as exc:
        raise HTTPException(
            status_code=401, detail={"code": exc.code, "message": str(exc)}
        ) from None
    return {"detail": "revoked"}


@router.post("/revoke-all", dependencies=[Depends(revoke_rate_limit)])
def revoke_all(user: dict = Depends(current_user)) -> dict:
    """全端撤销：本账号此前签发的全部令牌（含各会话链后继）立即失效。

    用于改密码或怀疑令牌泄露的场景；不影响其他账号，
    之后重新登录可正常拿到新令牌。
    """
    token_store.revoke_all_for_user(user["sub"])
    return {"detail": "all_tokens_revoked"}

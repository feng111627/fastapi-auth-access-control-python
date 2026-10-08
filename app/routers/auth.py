"""认证入口：登录、刷新、登出、撤销、全端作废。"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

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
    open_session,
    revoke_all_for_account,
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
        status_code=429,
        detail={
            "code": "account_locked",
            "message": f"账号已临时锁定，请 {retry_after} 秒后再试",
            "retry_after": retry_after,
        },
        headers={"Retry-After": str(retry_after)},
    )


@router.post("/login", response_model=TokenPair, dependencies=[Depends(login_rate_limit)])
def login(body: LoginRequest) -> TokenPair:
    # 账号锁先于密码校验：锁定期间换来源也拒绝，且不泄露密码是否正确
    locked = login_guard.check_locked(body.username)
    if locked.locked:
        raise _account_locked_response(locked.retry_after)

    user = user_store.verify_password(body.username, body.password)
    if user is None:
        result = login_guard.record_failure(body.username)
        if result.locked:
            raise _account_locked_response(result.retry_after)
        raise HTTPException(
            status_code=401,
            detail={"code": "invalid_credentials", "message": "用户名或密码错误"},
        )

    login_guard.record_success(body.username)
    access_token, refresh_token, _sid = open_session(
        user["username"], user["role"]
    )
    return TokenPair(access_token=access_token, refresh_token=refresh_token)


@router.post(
    "/refresh",
    response_model=TokenPair,
    dependencies=[Depends(refresh_rate_limit)],
)
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
    """全端作废：把当前账号此前签发的访问/刷新令牌（含轮换后继）一次性失效。

    只作用于当前账号，不牵连其他账号；作废后重新登录会拿到新代数令牌，
    可正常使用。适用于改密或怀疑令牌泄露的场景。
    """
    new_generation = revoke_all_for_account(user["sub"])
    return {
        "detail": "all_tokens_revoked",
        "generation": new_generation,
    }

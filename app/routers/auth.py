"""认证入口：登录、刷新、登出、撤销。"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.deps import current_user, login_rate_limit
from app.errors import AuthError
from app.security import (
    issue_access_token,
    issue_refresh_token,
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


@router.post("/login", response_model=TokenPair, dependencies=[Depends(login_rate_limit)])
def login(body: LoginRequest) -> TokenPair:
    user = user_store.verify_password(body.username, body.password)
    if user is None:
        raise HTTPException(
            status_code=401,
            detail={"code": "invalid_credentials", "message": "用户名或密码错误"},
        )
    return TokenPair(
        access_token=issue_access_token(user["username"], user["role"]),
        refresh_token=issue_refresh_token(user["username"]),
    )


@router.post("/refresh", response_model=TokenPair)
def refresh(body: RefreshRequest) -> TokenPair:
    try:
        access_token, refresh_token = rotate_refresh_token(body.refresh_token)
    except AuthError as exc:
        raise HTTPException(
            status_code=401, detail={"code": exc.code, "message": str(exc)}
        ) from None
    return TokenPair(access_token=access_token, refresh_token=refresh_token)


@router.post("/logout")
def logout(body: LogoutRequest, user: dict = Depends(current_user)) -> dict:
    """登出：当前访问令牌与提交的刷新令牌同时立刻失效。"""
    token_store.revoke_access(user["jti"])
    try:
        revoke_token(body.refresh_token)
    except AuthError:
        # 刷新令牌本身已失效不影响登出语义：访问令牌已被吊销
        pass
    return {"detail": "logged_out"}


@router.post("/revoke")
def revoke(body: RefreshRequest, user: dict = Depends(current_user)) -> dict:
    """主动撤销指定刷新令牌（需持有有效访问令牌）。"""
    try:
        revoke_token(body.refresh_token)
    except AuthError as exc:
        raise HTTPException(
            status_code=401, detail={"code": exc.code, "message": str(exc)}
        ) from None
    return {"detail": "revoked"}

"""路由：认证入口与受保护资源入口。"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app import rbac
from app.dependencies import (
    AppContext,
    get_context,
    rate_limit_api,
    rate_limit_login,
    require_scope,
)
from app.errors import TokenError
from app.tokens import TokenClaims

router = APIRouter()


# ---- 请求模型 ----

class LoginRequest(BaseModel):
    username: str
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str


class RevokeRequest(BaseModel):
    token: str


class DocumentIn(BaseModel):
    title: str
    body: str = ""


def _pair_response(pair) -> dict:
    return {
        "access_token": pair.access_token,
        "refresh_token": pair.refresh_token,
        "token_type": "bearer",
        "expires_in": pair.access_expires_in,
        "refresh_expires_in": pair.refresh_expires_in,
    }


# ---- 认证入口 ----

@router.post("/auth/login", dependencies=[Depends(rate_limit_login)])
def login(body: LoginRequest, ctx: AppContext = Depends(get_context)):
    user = ctx.store.get_user(body.username)
    if user is None or user.password != body.password:
        # 用户不存在与密码错误统一口径，避免枚举用户
        raise HTTPException(
            status_code=401,
            detail={"reason": "invalid_credentials",
                    "message": "用户名或密码错误"},
        )
    return _pair_response(ctx.token_service.issue_pair(user.username, user.role))


@router.post("/auth/refresh", dependencies=[Depends(rate_limit_login)])
def refresh(body: RefreshRequest, ctx: AppContext = Depends(get_context)):
    try:
        pair = ctx.token_service.rotate_refresh(body.refresh_token)
    except TokenError as e:
        raise HTTPException(
            status_code=401,
            detail={"reason": e.reason.value,
                    "message": f"刷新令牌无效: {e.reason.value}"},
        ) from None
    return _pair_response(pair)


@router.post("/auth/logout", dependencies=[Depends(rate_limit_api)])
def logout(body: LogoutRequest,
           claims: TokenClaims = Depends(
               require_scope(rbac.SCOPE_DOCUMENTS_READ)),
           ctx: AppContext = Depends(get_context)):
    """登出：当前访问令牌与提交的刷新令牌都立即失效。"""
    ctx.token_service.revoke_jti(claims.jti, claims.exp)
    try:
        ctx.token_service.revoke_token(body.refresh_token)
    except TokenError:
        pass  # 刷新令牌本已失效不影响登出语义
    return {"status": "logged_out"}


@router.post("/auth/revoke", dependencies=[Depends(rate_limit_api)])
def revoke(body: RevokeRequest,
           claims: TokenClaims = Depends(
               require_scope(rbac.SCOPE_DOCUMENTS_READ)),
           ctx: AppContext = Depends(get_context)):
    """主动撤销一个令牌（访问或刷新），立即生效。"""
    try:
        ctx.token_service.revoke_token(body.token)
    except TokenError as e:
        raise HTTPException(
            status_code=401,
            detail={"reason": e.reason.value,
                    "message": f"待撤销令牌无效: {e.reason.value}"},
        ) from None
    return {"status": "revoked"}


# ---- 受保护资源：同一资源的读 / 写 / 管理分别判定 ----

@router.get("/documents", dependencies=[Depends(rate_limit_api)])
def list_documents(claims: TokenClaims = Depends(
        require_scope(rbac.SCOPE_DOCUMENTS_READ))):
    return {"documents": [], "owner": claims.sub}


@router.post("/documents", dependencies=[Depends(rate_limit_api)])
def create_document(body: DocumentIn,
                    claims: TokenClaims = Depends(
                        require_scope(rbac.SCOPE_DOCUMENTS_WRITE))):
    return {"created": body.title, "by": claims.sub}


@router.delete("/documents/{doc_id}", dependencies=[Depends(rate_limit_api)])
def delete_document(doc_id: str,
                    claims: TokenClaims = Depends(
                        require_scope(rbac.SCOPE_DOCUMENTS_MANAGE))):
    return {"deleted": doc_id, "by": claims.sub}

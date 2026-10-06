"""FastAPI 依赖：限流、当前用户解析、作用域鉴权。"""
from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.errors import RateLimitExceeded, TokenError
from app.rbac import is_allowed
from app.ratelimit import FixedWindowRateLimiter
from app.tokens import TokenClaims, TokenService


@dataclass(frozen=True)
class CurrentUser:
    username: str
    role: str


class AppContext:
    """应用级状态容器：配置、存储、令牌服务、限流器。"""

    def __init__(self, token_service: TokenService,
                 store,
                 login_limiter: FixedWindowRateLimiter,
                 api_limiter: FixedWindowRateLimiter) -> None:
        self.token_service = token_service
        self.store = store
        self.login_limiter = login_limiter
        self.api_limiter = api_limiter


def get_context(request: Request) -> AppContext:
    return request.app.state.context


_bearer = HTTPBearer(auto_error=False)


def _client_source(request: Request) -> str:
    """限流口径：按客户端来源 IP。"""
    return request.client.host if request.client else "unknown"


def rate_limit_login(request: Request,
                     ctx: AppContext = Depends(get_context)) -> None:
    allowed, retry_after = ctx.login_limiter.hit(
        _client_source(request), _now())
    if not allowed:
        raise RateLimitExceeded(retry_after)


def rate_limit_api(request: Request,
                   ctx: AppContext = Depends(get_context)) -> None:
    allowed, retry_after = ctx.api_limiter.hit(
        _client_source(request), _now())
    if not allowed:
        raise RateLimitExceeded(retry_after)


def _now() -> float:
    import time
    return time.time()


def get_current_claims(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    ctx: AppContext = Depends(get_context),
) -> TokenClaims:
    """未携带或携带无效令牌 -> 401，且原因可区分。"""
    if credentials is None:
        raise HTTPException(
            status_code=401,
            detail={"reason": "missing_credentials",
                    "message": "缺少访问令牌"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        return ctx.token_service.verify_access(credentials.credentials)
    except TokenError as e:
        raise HTTPException(
            status_code=401,
            detail={"reason": e.reason.value,
                    "message": f"访问令牌无效: {e.reason.value}"},
            headers={"WWW-Authenticate": "Bearer"},
        ) from None


def get_current_user(
    claims: TokenClaims = Depends(get_current_claims),
) -> CurrentUser:
    return CurrentUser(username=claims.sub, role=claims.role)


def require_scope(scope: str):
    """已登录但作用域不足 -> 403；默认拒绝。返回通过校验的令牌声明。"""

    def checker(claims: TokenClaims = Depends(get_current_claims)) -> TokenClaims:
        if not is_allowed(claims.role, scope):
            raise HTTPException(
                status_code=403,
                detail={"reason": "insufficient_scope",
                        "required_scope": scope,
                        "message": f"角色 {claims.role} 无权执行 {scope}"},
            )
        return claims

    return checker

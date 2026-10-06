"""FastAPI 依赖：限流、当前用户解析、作用域校验。"""

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app import config
from app.errors import AuthError
from app.rate_limit import rate_limiter
from app.rbac import has_scope
from app.security import verify_access_token

_bearer = HTTPBearer(auto_error=False)


def client_source(request: Request) -> str:
    """限流口径里的"来源"：优先 X-Forwarded-For 首跳，否则直连 IP。"""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def rate_limit(bucket: str, limit: int, window: int):
    """生成一个限流依赖：超限返回 429 并告知还需等待多久。"""

    def dependency(request: Request) -> None:
        source = client_source(request)
        result = rate_limiter.hit(bucket, source, limit, window)
        if not result.allowed:
            raise HTTPException(
                status_code=429,
                detail={
                    "code": "rate_limited",
                    "message": f"请求过于频繁，请 {result.retry_after} 秒后重试",
                    "retry_after": result.retry_after,
                },
                headers={"Retry-After": str(result.retry_after)},
            )

    return dependency


login_rate_limit = rate_limit(
    "login", config.LOGIN_RATE_LIMIT_MAX, config.LOGIN_RATE_LIMIT_WINDOW
)
api_rate_limit = rate_limit(
    "api", config.API_RATE_LIMIT_MAX, config.API_RATE_LIMIT_WINDOW
)


def current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> dict:
    """解析 Bearer 访问令牌；未登录 401，令牌问题按原因区分。"""
    if credentials is None:
        raise HTTPException(
            status_code=401,
            detail={"code": "not_authenticated", "message": "缺少访问令牌"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        return verify_access_token(credentials.credentials)
    except AuthError as exc:
        raise HTTPException(
            status_code=401,
            detail={"code": exc.code, "message": str(exc)},
            headers={"WWW-Authenticate": "Bearer"},
        ) from None


def require_scope(scope: str):
    """生成作用域校验依赖：已登录但权限不够返回 403，默认拒绝。"""

    def dependency(user: dict = Depends(current_user)) -> dict:
        if not has_scope(user.get("role", ""), scope):
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "forbidden",
                    "message": f"角色 {user.get('role')} 无权执行 {scope}",
                    "required_scope": scope,
                },
            )
        return user

    return dependency

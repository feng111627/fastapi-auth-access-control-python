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
    """限流口径里的"来源"：以服务端确认的连接对端为准。

    只有当直连对端属于可信代理（config.TRUSTED_PROXY_HOSTS）时，
    才采信其转发的 X-Forwarded-For 首跳；否则一律使用连接对端本身，
    客户端自带的请求头无法左右判定，也就不能借此绕过限流。
    """
    peer = request.client.host if request.client else "unknown"
    if peer in config.TRUSTED_PROXY_HOSTS:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return peer


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
refresh_rate_limit = rate_limit(
    "refresh", config.REFRESH_RATE_LIMIT_MAX, config.REFRESH_RATE_LIMIT_WINDOW
)
logout_rate_limit = rate_limit(
    "logout", config.LOGOUT_RATE_LIMIT_MAX, config.LOGOUT_RATE_LIMIT_WINDOW
)
revoke_rate_limit = rate_limit(
    "revoke", config.REVOKE_RATE_LIMIT_MAX, config.REVOKE_RATE_LIMIT_WINDOW
)
# 文档资源按操作分桶：读沿用原 api 口径，写/管理各有独立阈值
doc_read_rate_limit = rate_limit(
    "documents:read", config.API_RATE_LIMIT_MAX, config.API_RATE_LIMIT_WINDOW
)
doc_write_rate_limit = rate_limit(
    "documents:write", config.DOC_WRITE_RATE_LIMIT_MAX, config.DOC_WRITE_RATE_LIMIT_WINDOW
)
doc_manage_rate_limit = rate_limit(
    "documents:manage",
    config.DOC_MANAGE_RATE_LIMIT_MAX,
    config.DOC_MANAGE_RATE_LIMIT_WINDOW,
)
# 兼容旧引用：受保护资源读入口的限流桶
api_rate_limit = doc_read_rate_limit


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

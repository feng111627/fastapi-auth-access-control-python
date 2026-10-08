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
    """限流判定使用的"来源"。

    口径：只认真实 TCP 连接对端；只有当直连对端属于 config.TRUSTED_PROXIES
    时，才采纳 X-Forwarded-For，并且取最右侧（离对端最近、由可信代理写入）
    的、非可信代理的一跳。请求体/请求头里客户端自报的任何其它信息
    （X-Real-IP、From 等）一律不参与判定，无法据此伪造或绕过来源。
    """
    peer = request.client.host if request.client else "unknown"
    if peer not in config.TRUSTED_PROXIES:
        return peer
    forwarded = request.headers.get("x-forwarded-for", "")
    chain = [part.strip() for part in forwarded.split(",") if part.strip()]
    if not chain:
        return peer
    # 从右向左跳过可信代理自身写入的地址，第一个非可信地址才是真实来源
    for hop in reversed(chain):
        if hop not in config.TRUSTED_PROXIES:
            return hop
    return chain[-1]


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


# 认证类入口：各自独立的桶
login_rate_limit = rate_limit(
    "auth:login", config.LOGIN_RATE_LIMIT_MAX, config.LOGIN_RATE_LIMIT_WINDOW
)
refresh_rate_limit = rate_limit(
    "auth:refresh", config.REFRESH_RATE_LIMIT_MAX, config.REFRESH_RATE_LIMIT_WINDOW
)
logout_rate_limit = rate_limit(
    "auth:logout", config.LOGOUT_RATE_LIMIT_MAX, config.LOGOUT_RATE_LIMIT_WINDOW
)
revoke_rate_limit = rate_limit(
    "auth:revoke", config.REVOKE_RATE_LIMIT_MAX, config.REVOKE_RATE_LIMIT_WINDOW
)

# 文档资源入口：读 / 写 / 管理三个桶
documents_read_rate_limit = rate_limit(
    "documents:read",
    config.DOCUMENTS_READ_RATE_LIMIT_MAX,
    config.DOCUMENTS_READ_RATE_LIMIT_WINDOW,
)
documents_write_rate_limit = rate_limit(
    "documents:write",
    config.DOCUMENTS_WRITE_RATE_LIMIT_MAX,
    config.DOCUMENTS_WRITE_RATE_LIMIT_WINDOW,
)
documents_manage_rate_limit = rate_limit(
    "documents:manage",
    config.DOCUMENTS_MANAGE_RATE_LIMIT_MAX,
    config.DOCUMENTS_MANAGE_RATE_LIMIT_WINDOW,
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

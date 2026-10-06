"""应用工厂：组装配置、存储、令牌服务、限流器与路由。"""
from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.config import DEFAULT_SETTINGS, Settings
from app.dependencies import AppContext
from app.errors import RateLimitExceeded
from app.ratelimit import FixedWindowRateLimiter
from app.routes import router
from app.store import InMemoryStore, User
from app.tokens import TokenService

# 本地演示账号（真实系统应使用哈希口令与外部存储）
SEED_USERS = [
    User("viewer", "viewer-pass", "viewer"),
    User("editor", "editor-pass", "editor"),
    User("admin", "admin-pass", "admin"),
]


def create_app(settings: Settings = DEFAULT_SETTINGS) -> FastAPI:
    app = FastAPI(title="auth-access-control-demo")

    store = InMemoryStore()
    for user in SEED_USERS:
        store.add_user(user)

    token_service = TokenService(settings, store)
    app.state.context = AppContext(
        token_service=token_service,
        store=store,
        login_limiter=FixedWindowRateLimiter(
            settings.rate_limit_window_seconds,
            settings.login_rate_limit_max_requests),
        api_limiter=FixedWindowRateLimiter(
            settings.rate_limit_window_seconds,
            settings.rate_limit_max_requests),
    )

    @app.exception_handler(RateLimitExceeded)
    async def rate_limit_handler(request: Request,
                                 exc: RateLimitExceeded) -> JSONResponse:
        return JSONResponse(
            status_code=429,
            headers={"Retry-After": str(exc.retry_after_seconds)},
            content={"detail": {
                "reason": "rate_limited",
                "retry_after_seconds": exc.retry_after_seconds,
                "message": f"请求过于频繁，请 {exc.retry_after_seconds} 秒后重试",
            }},
        )

    # 保留既有接口行为
    @app.get("/")
    def read_root():
        return {"Hello": "World"}

    app.include_router(router)
    return app

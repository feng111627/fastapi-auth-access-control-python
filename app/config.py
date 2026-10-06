"""全局配置：令牌时效、密钥、限流口径。"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Settings:
    """服务运行参数，测试可构造独立实例覆盖默认值。"""

    secret_key: str = "local-dev-secret-change-me-0123456789abcdef"
    algorithm: str = "HS256"
    access_token_ttl_seconds: int = 300
    refresh_token_ttl_seconds: int = 3600
    rate_limit_window_seconds: int = 60
    rate_limit_max_requests: int = 10
    login_rate_limit_max_requests: int = 5


DEFAULT_SETTINGS = Settings()

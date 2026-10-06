"""全局配置：密钥、令牌时效、限流口径。"""

SECRET_KEY = "dev-only-secret-change-me-0123456789abcdef"
ALGORITHM = "HS256"

ACCESS_TOKEN_TTL_SECONDS = 15 * 60        # 访问令牌 15 分钟
REFRESH_TOKEN_TTL_SECONDS = 7 * 24 * 3600  # 刷新令牌 7 天

# 限流：时间窗（秒）与窗口内最大请求数
LOGIN_RATE_LIMIT_WINDOW = 60
LOGIN_RATE_LIMIT_MAX = 5
API_RATE_LIMIT_WINDOW = 60
API_RATE_LIMIT_MAX = 30

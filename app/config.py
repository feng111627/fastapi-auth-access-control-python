"""全局配置：密钥、令牌时效、限流口径。"""

SECRET_KEY = "dev-only-secret-change-me-0123456789abcdef"
ALGORITHM = "HS256"

ACCESS_TOKEN_TTL_SECONDS = 15 * 60        # 访问令牌 15 分钟
REFRESH_TOKEN_TTL_SECONDS = 7 * 24 * 3600  # 刷新令牌 7 天

# 限流：时间窗（秒）与窗口内最大请求数
LOGIN_RATE_LIMIT_WINDOW = 60
LOGIN_RATE_LIMIT_MAX = 5
API_RATE_LIMIT_WINDOW = 60          # 文档读入口沿用该口径
API_RATE_LIMIT_MAX = 30
REFRESH_RATE_LIMIT_WINDOW = 60
REFRESH_RATE_LIMIT_MAX = 10
LOGOUT_RATE_LIMIT_WINDOW = 60
LOGOUT_RATE_LIMIT_MAX = 10
REVOKE_RATE_LIMIT_WINDOW = 60
REVOKE_RATE_LIMIT_MAX = 10
DOC_WRITE_RATE_LIMIT_WINDOW = 60
DOC_WRITE_RATE_LIMIT_MAX = 10
DOC_MANAGE_RATE_LIMIT_WINDOW = 60
DOC_MANAGE_RATE_LIMIT_MAX = 10

# 可信直连对端：只有来自这些对端的请求才采信 X-Forwarded-For，
# 其余一律以服务端确认的连接对端作为限流来源，防止客户端伪造来源绕过限流。
# "testclient" 为本地测试客户端的对端名。
TRUSTED_PROXY_HOSTS = ("127.0.0.1", "::1", "testclient")

# 限流状态上限：键数超过该值时优先回收过期窗口，仍超则淘汰最旧窗口，
# 保证长期运行、来源很多时内存不无限增长。
RATE_LIMIT_MAX_KEYS = 100_000

# 账号维度登录保护：窗口内连续失败达到阈值即临时锁定
LOGIN_FAILURE_WINDOW_SECONDS = 300   # 失败计数窗口
LOGIN_MAX_FAILURES = 5               # 连续失败阈值
LOGIN_LOCK_SECONDS = 300             # 锁定时长

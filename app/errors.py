"""可区分的认证/授权错误类型。"""


class AuthError(Exception):
    """认证失败基类，code 用于客户端区分原因。"""

    code = "auth_error"


class TokenExpired(AuthError):
    code = "token_expired"


class TokenTampered(AuthError):
    code = "token_tampered"


class TokenRevoked(AuthError):
    code = "token_revoked"


class RefreshTokenReused(AuthError):
    code = "refresh_token_reused"


class SessionCompromised(AuthError):
    """同一刷新链上的旧令牌被复用，整条会话链已按疑似泄露作废。"""

    code = "session_compromised"


class AccountLocked(AuthError):
    """账号因连续登录失败被临时锁定。"""

    code = "account_locked"


class InvalidCredentials(AuthError):
    code = "invalid_credentials"


class Forbidden(Exception):
    """已登录但权限不足。"""

    code = "forbidden"

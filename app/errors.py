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


class InvalidCredentials(AuthError):
    code = "invalid_credentials"


class Forbidden(Exception):
    """已登录但权限不足。"""

    code = "forbidden"

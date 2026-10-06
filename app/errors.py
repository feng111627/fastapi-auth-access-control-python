"""可区分的认证 / 授权 / 限流错误类型。"""
from __future__ import annotations

from enum import Enum


class TokenErrorReason(str, Enum):
    """令牌被拒绝的具体原因，彼此可区分。"""

    EXPIRED = "token_expired"
    TAMPERED = "token_tampered"
    REVOKED = "token_revoked"
    REUSED_REFRESH = "refresh_token_reused"
    WRONG_TYPE = "token_wrong_type"
    MALFORMED = "token_malformed"


class TokenError(Exception):
    """令牌校验失败，携带可区分的原因。"""

    def __init__(self, reason: TokenErrorReason) -> None:
        self.reason = reason
        super().__init__(reason.value)


class RateLimitExceeded(Exception):
    """触发限流，携带还需等待的秒数。"""

    def __init__(self, retry_after_seconds: int) -> None:
        self.retry_after_seconds = retry_after_seconds
        super().__init__(f"retry after {retry_after_seconds}s")

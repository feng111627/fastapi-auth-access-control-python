"""角色与作用域：默认拒绝，仅明确放行的操作可通过。"""
from __future__ import annotations

# 作用域命名："<资源>:<操作>"，操作为 read / write / manage
SCOPE_DOCUMENTS_READ = "documents:read"
SCOPE_DOCUMENTS_WRITE = "documents:write"
SCOPE_DOCUMENTS_MANAGE = "documents:manage"

ROLE_SCOPES: dict[str, frozenset[str]] = {
    "viewer": frozenset({SCOPE_DOCUMENTS_READ}),
    "editor": frozenset({SCOPE_DOCUMENTS_READ, SCOPE_DOCUMENTS_WRITE}),
    "admin": frozenset(
        {SCOPE_DOCUMENTS_READ, SCOPE_DOCUMENTS_WRITE, SCOPE_DOCUMENTS_MANAGE}
    ),
}


def scopes_for_role(role: str) -> frozenset[str]:
    """未知角色返回空集合（默认拒绝）。"""
    return ROLE_SCOPES.get(role, frozenset())


def is_allowed(role: str, scope: str) -> bool:
    """仅当角色的作用域集合明确包含该作用域时放行。"""
    return scope in scopes_for_role(role)

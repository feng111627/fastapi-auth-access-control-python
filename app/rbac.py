"""角色与作用域（scope）的对应关系，默认拒绝。"""

# scope 形如 "<resource>:<action>"，action ∈ {read, write, manage}
# manage 蕴含 write 与 read；未在表中明确放行的 (role, scope) 一律拒绝。
ROLE_SCOPES: dict[str, frozenset[str]] = {
    "admin": frozenset({
        "documents:manage",
    }),
    "editor": frozenset({
        "documents:read",
        "documents:write",
    }),
    "viewer": frozenset({
        "documents:read",
    }),
}

# manage 蕴含的较低权限
_IMPLIED = {"manage": ("write", "read"), "write": ("read",)}


def has_scope(role: str, scope: str) -> bool:
    """判断角色是否拥有某作用域；未明确放行一律拒绝。"""
    granted = ROLE_SCOPES.get(role)
    if not granted:
        return False
    if scope in granted:
        return True
    try:
        resource, action = scope.split(":", 1)
    except ValueError:
        return False
    # 检查是否被更高权限蕴含，例如 documents:manage 蕴含 documents:read
    for higher, lowers in _IMPLIED.items():
        if action in lowers and f"{resource}:{higher}" in granted:
            return True
    return False

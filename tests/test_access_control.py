"""业务链路二：按角色与作用域判定，未登录与权限不足区分，默认拒绝。"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.rbac import is_allowed, scopes_for_role
from tests.conftest import auth_header


class Test未登录与权限不足的区分:
    """401（未认证）与 403（已认证但越权）必须能区分。"""

    @pytest.mark.parametrize("method,path", [
        ("GET", "/documents"),
        ("POST", "/documents"),
        ("DELETE", "/documents/1"),
    ])
    def test_未携带令牌一律401(self, client: TestClient, method, path):
        resp = client.request(method, path, json={"title": "t"})
        assert resp.status_code == 401
        assert resp.json()["detail"]["reason"] == "missing_credentials"

    def test_已登录但越权是403而非401(self, client: TestClient, viewer_tokens):
        resp = client.post("/documents", json={"title": "t"},
                           headers=auth_header(viewer_tokens))
        assert resp.status_code == 403
        detail = resp.json()["detail"]
        assert detail["reason"] == "insufficient_scope"
        assert detail["required_scope"] == "documents:write"


class Test角色对同一资源的不同结论:
    """viewer / editor / admin 对 documents 的读写管理结论不同。"""

    def test_viewer可读不可写不可管理(self, client: TestClient, viewer_tokens):
        assert client.get("/documents",
                          headers=auth_header(viewer_tokens)).status_code == 200
        assert client.post("/documents", json={"title": "t"},
                           headers=auth_header(viewer_tokens)).status_code == 403
        assert client.delete("/documents/1",
                             headers=auth_header(viewer_tokens)).status_code == 403

    def test_editor可读写不可管理(self, client: TestClient, editor_tokens):
        assert client.get("/documents",
                          headers=auth_header(editor_tokens)).status_code == 200
        assert client.post("/documents", json={"title": "t"},
                           headers=auth_header(editor_tokens)).status_code == 200
        assert client.delete("/documents/1",
                             headers=auth_header(editor_tokens)).status_code == 403

    def test_admin可读写可管理(self, client: TestClient, admin_tokens):
        assert client.get("/documents",
                          headers=auth_header(admin_tokens)).status_code == 200
        assert client.post("/documents", json={"title": "t"},
                           headers=auth_header(admin_tokens)).status_code == 200
        assert client.delete("/documents/1",
                             headers=auth_header(admin_tokens)).status_code == 200


class Test默认拒绝:
    """未被明确放行的角色与作用域一律拒绝。"""

    def test_未知角色没有任何作用域(self):
        assert scopes_for_role("superuser") == frozenset()
        assert not is_allowed("superuser", "documents:read")

    def test_未定义的作用域对任何角色都拒绝(self):
        for role in ("viewer", "editor", "admin"):
            assert not is_allowed(role, "documents:delete-everything")
            assert not is_allowed(role, "billing:read")

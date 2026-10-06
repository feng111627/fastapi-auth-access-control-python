"""业务链路二：角色 × 作用域的访问控制，未登录与越权可区分，默认拒绝。"""

from tests.conftest import auth_header


class TestAuthenticationRequired:
    def test_未登录访问受保护资源返回401(self, client):
        resp = client.get("/resources/documents")
        assert resp.status_code == 401
        assert resp.json()["detail"]["code"] == "not_authenticated"

    def test_未登录与权限不足的状态码不同(self, client, viewer_tokens):
        anon = client.post(
            "/resources/documents", json={"title": "t", "body": "b"}
        )
        forbidden = client.post(
            "/resources/documents",
            headers=auth_header(viewer_tokens),
            json={"title": "t", "body": "b"},
        )
        assert anon.status_code == 401
        assert forbidden.status_code == 403
        assert forbidden.json()["detail"]["code"] == "forbidden"


class TestRoleScopeMatrix:
    def test_viewer_可读不可写不可管理(self, client, viewer_tokens):
        h = auth_header(viewer_tokens)
        assert client.get("/resources/documents", headers=h).status_code == 200
        write = client.post(
            "/resources/documents", headers=h, json={"title": "t", "body": "b"}
        )
        assert write.status_code == 403
        manage = client.delete("/resources/documents/1", headers=h)
        assert manage.status_code == 403

    def test_editor_可读写不可管理(self, client, editor_tokens):
        h = auth_header(editor_tokens)
        assert client.get("/resources/documents", headers=h).status_code == 200
        write = client.post(
            "/resources/documents", headers=h, json={"title": "t", "body": "b"}
        )
        assert write.status_code == 201
        manage = client.delete("/resources/documents/1", headers=h)
        assert manage.status_code == 403

    def test_admin_通过manage蕴含获得读写管理全部权限(self, client, admin_tokens):
        h = auth_header(admin_tokens)
        assert client.get("/resources/documents", headers=h).status_code == 200
        write = client.post(
            "/resources/documents", headers=h, json={"title": "t", "body": "b"}
        )
        assert write.status_code == 201
        manage = client.delete("/resources/documents/1", headers=h)
        assert manage.status_code == 200

    def test_同一资源不同操作结论不同(self, client, editor_tokens):
        h = auth_header(editor_tokens)
        results = {
            "read": client.get("/resources/documents", headers=h).status_code,
            "write": client.post(
                "/resources/documents", headers=h, json={"title": "t", "body": "b"}
            ).status_code,
            "manage": client.delete("/resources/documents/2", headers=h).status_code,
        }
        assert results == {"read": 200, "write": 201, "manage": 403}


class TestDefaultDeny:
    def test_未定义的作用域一律拒绝(self):
        from app.rbac import has_scope

        assert not has_scope("admin", "documents:delete")
        assert not has_scope("admin", "users:read")
        assert not has_scope("viewer", "documents:write")

    def test_未知角色没有任何权限(self):
        from app.rbac import has_scope

        assert not has_scope("ghost", "documents:read")

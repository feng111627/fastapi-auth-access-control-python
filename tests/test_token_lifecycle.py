"""业务链路一：令牌签发、轮换、撤销与各类非法令牌的区分。"""

import time

import jwt

from app import config
from tests.conftest import auth_header, login


class TestLogin:
    def test_登录成功签发访问与刷新令牌(self, client):
        tokens = login(client, "viewer", "viewer-pass", "10.1.0.1")
        assert tokens["token_type"] == "bearer"
        assert tokens["access_token"] and tokens["refresh_token"]

    def test_密码错误返回可区分原因(self, client):
        resp = client.post(
            "/auth/login", json={"username": "viewer", "password": "wrong"}
        )
        assert resp.status_code == 401
        assert resp.json()["detail"]["code"] == "invalid_credentials"


class TestRefreshRotation:
    def test_刷新后旧刷新令牌立即失效(self, client, viewer_tokens):
        resp = client.post(
            "/auth/refresh", json={"refresh_token": viewer_tokens["refresh_token"]}
        )
        assert resp.status_code == 200
        replay = client.post(
            "/auth/refresh", json={"refresh_token": viewer_tokens["refresh_token"]}
        )
        assert replay.status_code == 401
        assert replay.json()["detail"]["code"] == "refresh_token_reused"

    def test_新刷新令牌可继续轮换(self, client, viewer_tokens):
        first = client.post(
            "/auth/refresh", json={"refresh_token": viewer_tokens["refresh_token"]}
        ).json()
        second = client.post(
            "/auth/refresh", json={"refresh_token": first["refresh_token"]}
        )
        assert second.status_code == 200


class TestRevocation:
    def test_登出后访问令牌与刷新令牌都失效(self, client, viewer_tokens):
        resp = client.post(
            "/auth/logout",
            headers=auth_header(viewer_tokens),
            json={"refresh_token": viewer_tokens["refresh_token"]},
        )
        assert resp.status_code == 200

        denied = client.get("/resources/documents", headers=auth_header(viewer_tokens))
        assert denied.status_code == 401
        assert denied.json()["detail"]["code"] == "token_revoked"

        refresh = client.post(
            "/auth/refresh", json={"refresh_token": viewer_tokens["refresh_token"]}
        )
        assert refresh.status_code == 401
        assert refresh.json()["detail"]["code"] == "token_revoked"

    def test_主动撤销刷新令牌后不能再换新(self, client, viewer_tokens):
        resp = client.post(
            "/auth/revoke",
            headers=auth_header(viewer_tokens),
            json={"refresh_token": viewer_tokens["refresh_token"]},
        )
        assert resp.status_code == 200
        refresh = client.post(
            "/auth/refresh", json={"refresh_token": viewer_tokens["refresh_token"]}
        )
        assert refresh.json()["detail"]["code"] == "token_revoked"


class TestMalformedTokens:
    def test_过期令牌被拒绝且原因可区分(self, client):
        now = int(time.time())
        expired = jwt.encode(
            {
                "sub": "viewer",
                "role": "viewer",
                "type": "access",
                "jti": "expired-jti",
                "iat": now - 7200,
                "exp": now - 3600,
            },
            config.SECRET_KEY,
            algorithm=config.ALGORITHM,
        )
        resp = client.get(
            "/resources/documents",
            headers={"Authorization": f"Bearer {expired}"},
        )
        assert resp.status_code == 401
        assert resp.json()["detail"]["code"] == "token_expired"

    def test_被篡改的令牌被拒绝且原因可区分(self, client, viewer_tokens):
        tampered = viewer_tokens["access_token"][:-2] + "xx"
        resp = client.get(
            "/resources/documents", headers={"Authorization": f"Bearer {tampered}"}
        )
        assert resp.status_code == 401
        assert resp.json()["detail"]["code"] == "token_tampered"

    def test_刷新令牌不能当访问令牌用(self, client, viewer_tokens):
        resp = client.get(
            "/resources/documents",
            headers={"Authorization": f"Bearer {viewer_tokens['refresh_token']}"},
        )
        assert resp.status_code == 401
        assert resp.json()["detail"]["code"] == "token_tampered"

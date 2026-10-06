"""业务链路一：令牌签发、轮换、撤销与各类非法令牌的区分拒绝。"""
from __future__ import annotations

import jwt as pyjwt
import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from tests.conftest import auth_header, login


class Test登录签发:
    """登录后应同时拿到短时效访问令牌与可轮换刷新令牌。"""

    def test_正确口令签发两种令牌(self, client: TestClient):
        tokens = login(client, "viewer", "viewer-pass")
        assert tokens["access_token"]
        assert tokens["refresh_token"]
        assert tokens["token_type"] == "bearer"
        assert tokens["expires_in"] < tokens["refresh_expires_in"]

    def test_错误口令被拒绝(self, client: TestClient):
        resp = client.post("/auth/login",
                           json={"username": "viewer", "password": "wrong"})
        assert resp.status_code == 401
        assert resp.json()["detail"]["reason"] == "invalid_credentials"

    def test_不存在的用户与错误口令同口径(self, client: TestClient):
        resp = client.post("/auth/login",
                           json={"username": "ghost", "password": "x"})
        assert resp.status_code == 401
        assert resp.json()["detail"]["reason"] == "invalid_credentials"


class Test刷新令牌轮换:
    """刷新令牌可换新，旧令牌立即作废，重放要被单独识别。"""

    def test_轮换后拿到新令牌对(self, client: TestClient, viewer_tokens):
        resp = client.post("/auth/refresh",
                           json={"refresh_token": viewer_tokens["refresh_token"]})
        assert resp.status_code == 200
        new = resp.json()
        assert new["refresh_token"] != viewer_tokens["refresh_token"]
        assert new["access_token"] != viewer_tokens["access_token"]

    def test_旧刷新令牌重放被拒绝且原因可区分(self, client: TestClient, viewer_tokens):
        first = client.post("/auth/refresh",
                            json={"refresh_token": viewer_tokens["refresh_token"]})
        assert first.status_code == 200
        replay = client.post("/auth/refresh",
                             json={"refresh_token": viewer_tokens["refresh_token"]})
        assert replay.status_code == 401
        assert replay.json()["detail"]["reason"] == "refresh_token_reused"

    def test_拿访问令牌当刷新令牌被拒绝(self, client: TestClient, viewer_tokens):
        resp = client.post("/auth/refresh",
                           json={"refresh_token": viewer_tokens["access_token"]})
        assert resp.status_code == 401
        assert resp.json()["detail"]["reason"] == "token_wrong_type"


class Test撤销与登出:
    """登出或主动撤销后，访问令牌与刷新令牌都要立刻失效。"""

    def test_登出后访问令牌立即失效(self, client: TestClient, viewer_tokens):
        resp = client.post("/auth/logout",
                           json={"refresh_token": viewer_tokens["refresh_token"]},
                           headers=auth_header(viewer_tokens))
        assert resp.status_code == 200
        denied = client.get("/documents", headers=auth_header(viewer_tokens))
        assert denied.status_code == 401
        assert denied.json()["detail"]["reason"] == "token_revoked"

    def test_登出后刷新令牌立即失效(self, client: TestClient, viewer_tokens):
        client.post("/auth/logout",
                    json={"refresh_token": viewer_tokens["refresh_token"]},
                    headers=auth_header(viewer_tokens))
        resp = client.post("/auth/refresh",
                           json={"refresh_token": viewer_tokens["refresh_token"]})
        assert resp.status_code == 401
        assert resp.json()["detail"]["reason"] == "token_revoked"

    def test_主动撤销刷新令牌(self, client: TestClient, viewer_tokens):
        resp = client.post("/auth/revoke",
                           json={"token": viewer_tokens["refresh_token"]},
                           headers=auth_header(viewer_tokens))
        assert resp.status_code == 200
        denied = client.post("/auth/refresh",
                             json={"refresh_token": viewer_tokens["refresh_token"]})
        assert denied.status_code == 401
        assert denied.json()["detail"]["reason"] == "token_revoked"

    def test_主动撤销访问令牌(self: None, client: TestClient, admin_tokens):
        # 用 admin 撤销另一个用户的访问令牌
        other = login(client, "viewer", "viewer-pass")
        resp = client.post("/auth/revoke",
                           json={"token": other["access_token"]},
                           headers=auth_header(admin_tokens))
        assert resp.status_code == 200
        denied = client.get("/documents", headers=auth_header(other))
        assert denied.status_code == 401
        assert denied.json()["detail"]["reason"] == "token_revoked"


class Test非法令牌区分:
    """过期、篡改、类型错误、畸形令牌各有独立拒绝原因。"""

    def test_过期访问令牌(self):
        client = TestClient(create_app(Settings(access_token_ttl_seconds=-1)))
        tokens = login(client, "viewer", "viewer-pass")
        resp = client.get("/documents", headers=auth_header(tokens))
        assert resp.status_code == 401
        assert resp.json()["detail"]["reason"] == "token_expired"

    def test_过期刷新令牌(self):
        client = TestClient(create_app(Settings(refresh_token_ttl_seconds=-1)))
        tokens = login(client, "viewer", "viewer-pass")
        resp = client.post("/auth/refresh",
                           json={"refresh_token": tokens["refresh_token"]})
        assert resp.status_code == 401
        assert resp.json()["detail"]["reason"] == "token_expired"

    def test_被篡改的令牌(self, client: TestClient, viewer_tokens):
        forged = pyjwt.encode(
            {"sub": "viewer", "role": "admin", "jti": "x",
             "type": "access", "exp": 9999999999},
            "attacker-key-attacker-key-00000000", algorithm="HS256")
        resp = client.get("/documents",
                          headers={"Authorization": f"Bearer {forged}"})
        assert resp.status_code == 401
        assert resp.json()["detail"]["reason"] == "token_tampered"

    def test_畸形令牌(self, client: TestClient):
        resp = client.get("/documents",
                          headers={"Authorization": "Bearer not-a-jwt"})
        assert resp.status_code == 401
        assert resp.json()["detail"]["reason"] == "token_malformed"

    def test_刷新令牌不能当访问令牌用(self, client: TestClient, viewer_tokens):
        resp = client.get(
            "/documents",
            headers={"Authorization": f"Bearer {viewer_tokens['refresh_token']}"})
        assert resp.status_code == 401
        assert resp.json()["detail"]["reason"] == "token_wrong_type"

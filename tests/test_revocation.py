"""业务链路五：全端作废（改密/泄露）与旧刷新令牌复用的疑似泄露处置。"""

from tests.conftest import auth_header, login


def _refresh(client, refresh_token: str, source: str | None = None):
    headers = {"X-Forwarded-For": source} if source else {}
    return client.post(
        "/auth/refresh",
        json={"refresh_token": refresh_token},
        headers=headers,
    )


class TestRevokeAll:
    def test_全端作废后当前访问与刷新令牌立即失效(self, client):
        tokens = login(client, "viewer", "viewer-pass", "10.2.0.1")
        resp = client.post("/auth/revoke-all", headers=auth_header(tokens))
        assert resp.status_code == 200
        assert resp.json()["detail"] == "all_tokens_revoked"

        denied = client.get(
            "/resources/documents", headers=auth_header(tokens)
        )
        assert denied.status_code == 401
        assert denied.json()["detail"]["code"] == "token_revoked"

        refresh = _refresh(client, tokens["refresh_token"])
        assert refresh.status_code == 401
        assert refresh.json()["detail"]["code"] == "token_revoked"

    def test_轮换出来的后继令牌也一起失效(self, client):
        tokens = login(client, "viewer", "viewer-pass", "10.2.0.2")
        first = _refresh(client, tokens["refresh_token"]).json()
        second = _refresh(client, first["refresh_token"]).json()

        # 用最早的访问令牌做全端作废
        revoke = client.post("/auth/revoke-all", headers=auth_header(tokens))
        assert revoke.status_code == 200

        # 原始、第一代、第二代后继令牌全部失效
        for pair in (tokens, first, second):
            denied = client.get(
                "/resources/documents",
                headers={"Authorization": f"Bearer {pair['access_token']}"},
            )
            assert denied.status_code == 401
            assert denied.json()["detail"]["code"] == "token_revoked"
            r = _refresh(client, pair["refresh_token"])
            assert r.status_code == 401
            assert r.json()["detail"]["code"] == "token_revoked"

    def test_全端作绝不牵连其他账号(self, client):
        victim = login(client, "viewer", "viewer-pass", "10.2.0.3")
        other = login(client, "editor", "editor-pass", "10.2.0.4")
        client.post("/auth/revoke-all", headers=auth_header(victim))

        still_ok = client.get(
            "/resources/documents", headers=auth_header(other)
        )
        assert still_ok.status_code == 200
        rotated = _refresh(client, other["refresh_token"])
        assert rotated.status_code == 200

    def test_作废后重新登录拿到的新令牌可正常使用(self, client):
        tokens = login(client, "viewer", "viewer-pass", "10.2.0.5")
        client.post("/auth/revoke-all", headers=auth_header(tokens))
        assert client.get(
            "/resources/documents", headers=auth_header(tokens)
        ).status_code == 401

        relogged = login(client, "viewer", "viewer-pass", "10.2.0.6")
        assert client.get(
            "/resources/documents", headers=auth_header(relogged)
        ).status_code == 200
        assert _refresh(client, relogged["refresh_token"]).status_code == 200

    def test_旧代数令牌不能在作废后通过刷新复活(self, client):
        tokens = login(client, "viewer", "viewer-pass", "10.2.0.7")
        # 先轮换出一对后继令牌但不使用
        client.post("/auth/revoke-all", headers=auth_header(tokens))
        # 作废后即便拿作废前未轮换的刷新令牌也换不出新令牌
        resp = _refresh(client, tokens["refresh_token"])
        assert resp.status_code == 401
        assert resp.json()["detail"]["code"] == "token_revoked"


class TestSuspectedLeak:
    def test_旧刷新令牌复用返回复用码并作废整条链的后继令牌(self, client):
        tokens = login(client, "viewer", "viewer-pass", "10.2.1.1")
        first = _refresh(client, tokens["refresh_token"]).json()
        second = _refresh(client, first["refresh_token"]).json()

        # 早已轮换的旧刷新令牌又被拿出来用 -> 疑似泄露
        replay = _refresh(client, tokens["refresh_token"])
        assert replay.status_code == 401
        assert replay.json()["detail"]["code"] == "refresh_token_reused"

        # 链上所有尚未到期的后继令牌（含访问令牌）全部失效，
        # 且原因是 session_compromised，区别于普通撤销与过期
        for pair in (first, second):
            denied = client.get(
                "/resources/documents",
                headers={"Authorization": f"Bearer {pair['access_token']}"},
            )
            assert denied.status_code == 401
            assert denied.json()["detail"]["code"] == "session_compromised"
            r = _refresh(client, pair["refresh_token"])
            assert r.status_code == 401
            assert r.json()["detail"]["code"] == "session_compromised"

    def test_泄露处置只废这一条会话链不牵连同账号其他登录(self, client):
        chain_a = login(client, "viewer", "viewer-pass", "10.2.2.1")
        chain_b = login(client, "viewer", "viewer-pass", "10.2.2.2")

        # 在 A 链上制造复用泄露
        first_a = _refresh(client, chain_a["refresh_token"]).json()
        _refresh(client, chain_a["refresh_token"])
        assert client.get(
            "/resources/documents",
            headers={"Authorization": f"Bearer {first_a['access_token']}"},
        ).json()["detail"]["code"] == "session_compromised"

        # 同账号的另一条登录链 B 完全不受影响
        assert client.get(
            "/resources/documents", headers=auth_header(chain_b)
        ).status_code == 200
        assert _refresh(client, chain_b["refresh_token"]).status_code == 200

    def test_三种情形前端可区分_过期_主动撤销_疑似泄露(self, client):
        import time

        import jwt

        from app import config

        # 1) 过期
        now = int(time.time())
        expired = jwt.encode(
            {
                "sub": "viewer", "role": "viewer", "type": "refresh",
                "jti": "x", "sid": "x", "gen": 0,
                "iat": now - 7200, "exp": now - 3600,
            },
            config.SECRET_KEY, algorithm=config.ALGORITHM,
        )
        r_expired = _refresh(client, expired)
        assert r_expired.json()["detail"]["code"] == "token_expired"

        # 2) 主动全端作废
        tokens = login(client, "viewer", "viewer-pass", "10.2.3.1")
        client.post("/auth/revoke-all", headers=auth_header(tokens))
        r_revoked = _refresh(client, tokens["refresh_token"])
        assert r_revoked.json()["detail"]["code"] == "token_revoked"

        # 3) 疑似泄露
        leaked = login(client, "viewer", "viewer-pass", "10.2.3.2")
        _refresh(client, leaked["refresh_token"])
        r_leak = _refresh(client, leaked["refresh_token"])
        assert r_leak.json()["detail"]["code"] == "refresh_token_reused"
        successor = login(client, "editor", "editor-pass", "10.2.3.3")
        # editor 不受 viewer 处置影响
        assert client.get(
            "/resources/documents", headers=auth_header(successor)
        ).status_code == 200

    def test_访问令牌在会话链泄露后也按泄露原因拒绝(self, client):
        tokens = login(client, "viewer", "viewer-pass", "10.2.4.1")
        access = tokens["access_token"]
        # 正常可用
        assert client.get(
            "/resources/documents", headers={"Authorization": f"Bearer {access}"}
        ).status_code == 200
        # 触发链泄露
        _refresh(client, tokens["refresh_token"])
        _refresh(client, tokens["refresh_token"])
        denied = client.get(
            "/resources/documents", headers={"Authorization": f"Bearer {access}"}
        )
        assert denied.status_code == 401
        assert denied.json()["detail"]["code"] == "session_compromised"

"""业务链路五：全端撤销（revoke-all）与旧刷新令牌复用的泄露处置。"""

from tests.conftest import auth_header, login


def _refresh(client, refresh_token: str):
    return client.post("/auth/refresh", json={"refresh_token": refresh_token})


def _revoke_all(client, tokens: dict):
    return client.post("/auth/revoke-all", headers=auth_header(tokens))


class TestRevokeAll:
    def test_全端撤销后访问令牌与刷新令牌立即失效(self, client):
        tokens = login(client, "viewer", "viewer-pass", "10.30.0.1")
        resp = _revoke_all(client, tokens)
        assert resp.status_code == 200
        assert resp.json()["detail"] == "all_tokens_revoked"

        denied = client.get("/resources/documents", headers=auth_header(tokens))
        assert denied.status_code == 401
        assert denied.json()["detail"]["code"] == "token_revoked"

        refresh = _refresh(client, tokens["refresh_token"])
        assert refresh.status_code == 401
        assert refresh.json()["detail"]["code"] == "token_revoked"

    def test_旧刷新令牌换出的后继令牌一并失效(self, client):
        first = login(client, "viewer", "viewer-pass", "10.30.0.2")
        # 旧刷新令牌轮换出的后继令牌（目前还有效）
        second = _refresh(client, first["refresh_token"]).json()
        assert client.get(
            "/resources/documents", headers=auth_header(second)
        ).status_code == 200

        assert _revoke_all(client, second).status_code == 200

        # 后继访问令牌、后继刷新令牌、最初的刷新令牌全部失效
        assert client.get(
            "/resources/documents", headers=auth_header(second)
        ).status_code == 401
        assert _refresh(client, second["refresh_token"]).json()["detail"]["code"] == (
            "token_revoked"
        )
        assert _refresh(client, first["refresh_token"]).json()["detail"]["code"] == (
            "token_revoked"
        )

    def test_全端撤销不牵连其他账号(self, client, editor_tokens):
        viewer_tokens = login(client, "viewer", "viewer-pass", "10.30.0.3")
        assert _revoke_all(client, viewer_tokens).status_code == 200
        # 其他账号的令牌照常可用
        resp = client.get("/resources/documents", headers=auth_header(editor_tokens))
        assert resp.status_code == 200
        assert _refresh(client, editor_tokens["refresh_token"]).status_code == 200

    def test_全端撤销后重新登录可正常拿新令牌(self, client):
        old = login(client, "viewer", "viewer-pass", "10.30.0.4")
        assert _revoke_all(client, old).status_code == 200

        fresh = login(client, "viewer", "viewer-pass", "10.30.0.4")
        assert client.get(
            "/resources/documents", headers=auth_header(fresh)
        ).status_code == 200
        assert _refresh(client, fresh["refresh_token"]).status_code == 200

    def test_未登录不能调用全端撤销(self, client):
        resp = client.post("/auth/revoke-all")
        assert resp.status_code == 401
        assert resp.json()["detail"]["code"] == "not_authenticated"


class TestRefreshReuseLeakHandling:
    def test_旧刷新令牌复用按疑似泄露处理并作废整条链(self, client):
        first = login(client, "viewer", "viewer-pass", "10.31.0.1")
        second = _refresh(client, first["refresh_token"]).json()

        # 已轮换的旧令牌再次被使用：疑似泄露
        replay = _refresh(client, first["refresh_token"])
        assert replay.status_code == 401
        assert replay.json()["detail"]["code"] == "refresh_token_reused"

        # 整条会话链作废：当前最新的刷新令牌与访问令牌都不能再用
        assert _refresh(client, second["refresh_token"]).json()["detail"]["code"] == (
            "token_revoked"
        )
        denied = client.get("/resources/documents", headers=auth_header(second))
        assert denied.status_code == 401
        assert denied.json()["detail"]["code"] == "token_revoked"

    def test_泄露处置不波及其他会话链(self, client):
        # 同一账号的另一条会话链（另一次登录）不受泄露处置影响
        chain_a = login(client, "viewer", "viewer-pass", "10.31.0.2")
        chain_b = login(client, "viewer", "viewer-pass", "10.31.0.2")

        rotated_a = _refresh(client, chain_a["refresh_token"]).json()
        _refresh(client, chain_a["refresh_token"])  # 复用，作废链 A

        assert client.get(
            "/resources/documents", headers=auth_header(chain_b)
        ).status_code == 200
        assert _refresh(client, chain_b["refresh_token"]).status_code == 200
        # 链 A 确认已死
        assert _refresh(client, rotated_a["refresh_token"]).json()["detail"][
            "code"
        ] == "token_revoked"

    def test_复用与过期及主动撤销的原因可区分(self, client, viewer_tokens):
        rotated = _refresh(client, viewer_tokens["refresh_token"]).json()

        reuse = _refresh(client, viewer_tokens["refresh_token"])
        assert reuse.json()["detail"]["code"] == "refresh_token_reused"

        # 主动撤销另一条链的刷新令牌后再用：原因是 revoked 而非 reused
        other = login(client, "viewer", "viewer-pass", "10.31.0.3")
        client.post(
            "/auth/revoke",
            headers=auth_header(other),
            json={"refresh_token": other["refresh_token"]},
        )
        revoked = _refresh(client, other["refresh_token"])
        assert revoked.json()["detail"]["code"] == "token_revoked"

        # 三者两两不同，前端可据此区分处置
        codes = {
            reuse.json()["detail"]["code"],
            revoked.json()["detail"]["code"],
            "token_expired",
        }
        assert len(codes) == 3
        # 泄露处置已把 rotated 所在链作废
        assert _refresh(client, rotated["refresh_token"]).json()["detail"]["code"] == (
            "token_revoked"
        )

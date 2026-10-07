"""业务链路三（扩展）：全入口限流覆盖、来源防伪、状态回收。"""

from types import SimpleNamespace

from app import config
from app.deps import client_source
from app.rate_limit import RateLimiter
from tests.conftest import auth_header


def _request(headers: dict, peer: str):
    return SimpleNamespace(headers=headers, client=SimpleNamespace(host=peer))


class TestSourceAttribution:
    def test_可信代理的转发头被采信(self, monkeypatch):
        monkeypatch.setattr(config, "TRUSTED_PROXY_HOSTS", ("10.0.0.1",))
        req = _request({"x-forwarded-for": "1.2.3.4, 10.0.0.1"}, "10.0.0.1")
        assert client_source(req) == "1.2.3.4"

    def test_不可信对端自带的转发头不影响判定(self, monkeypatch):
        monkeypatch.setattr(config, "TRUSTED_PROXY_HOSTS", ("10.0.0.1",))
        req = _request({"x-forwarded-for": "1.2.3.4"}, "9.9.9.9")
        # 客户端自己塞的来源被忽略，以服务端确认的连接对端为准
        assert client_source(req) == "9.9.9.9"

    def test_可信对端未带转发头时回退到连接对端(self, monkeypatch):
        monkeypatch.setattr(config, "TRUSTED_PROXY_HOSTS", ("10.0.0.1",))
        assert client_source(_request({}, "10.0.0.1")) == "10.0.0.1"

    def test_伪造来源不能绕过限流(self, client, monkeypatch):
        # 直连对端不可信时，换不同的 X-Forwarded-For 也躲不开同一个桶
        monkeypatch.setattr(config, "TRUSTED_PROXY_HOSTS", ())
        for i in range(config.LOGIN_RATE_LIMIT_MAX):
            resp = client.post(
                "/auth/login",
                json={"username": "viewer", "password": "viewer-pass"},
                headers={"X-Forwarded-For": f"203.0.113.{i}"},
            )
            assert resp.status_code == 200
        blocked = client.post(
            "/auth/login",
            json={"username": "viewer", "password": "viewer-pass"},
            headers={"X-Forwarded-For": "203.0.113.99"},
        )
        assert blocked.status_code == 429


class TestAuthEntryRateLimits:
    def test_刷新入口超限返回429并告知等待(self, client):
        source = "172.20.0.1"
        headers = {"X-Forwarded-For": source}
        for _ in range(config.REFRESH_RATE_LIMIT_MAX):
            resp = client.post(
                "/auth/refresh", json={"refresh_token": "bad"}, headers=headers
            )
            assert resp.status_code == 401
        blocked = client.post(
            "/auth/refresh", json={"refresh_token": "bad"}, headers=headers
        )
        assert blocked.status_code == 429
        assert blocked.json()["detail"]["code"] == "rate_limited"
        assert blocked.json()["detail"]["retry_after"] >= 1

    def test_登出入口超限返回429(self, client):
        headers = {"X-Forwarded-For": "172.20.0.2"}
        for _ in range(config.LOGOUT_RATE_LIMIT_MAX):
            client.post("/auth/logout", json={"refresh_token": "x"}, headers=headers)
        blocked = client.post(
            "/auth/logout", json={"refresh_token": "x"}, headers=headers
        )
        assert blocked.status_code == 429

    def test_撤销入口超限返回429(self, client):
        headers = {"X-Forwarded-For": "172.20.0.3"}
        for _ in range(config.REVOKE_RATE_LIMIT_MAX):
            client.post("/auth/revoke", json={"refresh_token": "x"}, headers=headers)
        blocked = client.post(
            "/auth/revoke", json={"refresh_token": "x"}, headers=headers
        )
        assert blocked.status_code == 429

    def test_刷新被限不牵连登录入口(self, client):
        source = "172.20.0.4"
        headers = {"X-Forwarded-For": source}
        for _ in range(config.REFRESH_RATE_LIMIT_MAX):
            client.post("/auth/refresh", json={"refresh_token": "bad"}, headers=headers)
        assert (
            client.post("/auth/refresh", json={"refresh_token": "bad"}, headers=headers).status_code
            == 429
        )
        # 同一来源的登录入口是另一个桶，不受影响
        resp = client.post(
            "/auth/login",
            json={"username": "viewer", "password": "viewer-pass"},
            headers=headers,
        )
        assert resp.status_code == 200


class TestDocumentOperationRateLimits:
    def test_写入口超限返回429(self, client, editor_tokens):
        headers = {**auth_header(editor_tokens), "X-Forwarded-For": "172.21.0.1"}
        for _ in range(config.DOC_WRITE_RATE_LIMIT_MAX):
            resp = client.post(
                "/resources/documents",
                headers=headers,
                json={"title": "t", "body": "b"},
            )
            assert resp.status_code == 201
        blocked = client.post(
            "/resources/documents", headers=headers, json={"title": "t", "body": "b"}
        )
        assert blocked.status_code == 429
        assert blocked.json()["detail"]["retry_after"] >= 1

    def test_管理入口超限返回429(self, client, admin_tokens):
        headers = {**auth_header(admin_tokens), "X-Forwarded-For": "172.21.0.2"}
        for _ in range(config.DOC_MANAGE_RATE_LIMIT_MAX):
            client.delete("/resources/documents/1", headers=headers)
        blocked = client.delete("/resources/documents/1", headers=headers)
        assert blocked.status_code == 429

    def test_写被限不牵连同一来源的读(self, client, editor_tokens):
        source = "172.21.0.3"
        headers = {**auth_header(editor_tokens), "X-Forwarded-For": source}
        for _ in range(config.DOC_WRITE_RATE_LIMIT_MAX):
            client.post(
                "/resources/documents",
                headers=headers,
                json={"title": "t", "body": "b"},
            )
        assert (
            client.post(
                "/resources/documents", headers=headers, json={"title": "t", "body": "b"}
            ).status_code
            == 429
        )
        assert client.get("/resources/documents", headers=headers).status_code == 200


class TestStateEviction:
    def test_键数有界不会无限增长(self):
        limiter = RateLimiter(max_keys=10)
        for i in range(100):
            limiter.hit("api", f"10.0.{i // 256}.{i % 256}", 5, 60)
        assert limiter.tracked_keys <= 10

    def test_优先回收已过期的窗口(self):
        limiter = RateLimiter(max_keys=2)
        # a 的窗口立即过期；b 的窗口长期有效
        limiter.hit("api", "a", 5, 0)
        limiter.hit("api", "b", 5, 60)
        # c 到来触发回收：应删掉已过期的 a 而不是活跃的 b
        limiter.hit("api", "c", 5, 60)
        assert ("api", "a") not in limiter._windows
        assert ("api", "b") in limiter._windows
        assert ("api", "c") in limiter._windows

    def test_回收不影响活跃键的计数(self):
        limiter = RateLimiter(max_keys=2)
        assert limiter.hit("api", "x", 3, 60).remaining == 2
        limiter.hit("api", "expired", 5, 0)  # 立即过期，等待被回收
        limiter.hit("api", "y", 3, 60)  # 触发回收，expired 被淘汰
        # x 的计数被保留：第二次命中 remaining 应为 1
        assert limiter.hit("api", "x", 3, 60).remaining == 1

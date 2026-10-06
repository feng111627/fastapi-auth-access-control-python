"""业务链路三：按来源的时间窗限流，含边界、隔离与并发计数。"""

import threading

from app import config
from app.rate_limit import RateLimiter
from tests.conftest import auth_header


def _login_once(client, source: str):
    return client.post(
        "/auth/login",
        json={"username": "viewer", "password": "viewer-pass"},
        headers={"X-Forwarded-For": source},
    )


class TestLoginRateLimit:
    def test_窗口内超过阈值被拒绝并告知等待时间(self, client):
        source = "172.16.0.1"
        for _ in range(config.LOGIN_RATE_LIMIT_MAX):
            assert _login_once(client, source).status_code == 200
        blocked = _login_once(client, source)
        assert blocked.status_code == 429
        detail = blocked.json()["detail"]
        assert detail["code"] == "rate_limited"
        assert detail["retry_after"] >= 1
        assert int(blocked.headers["retry-after"]) >= 1

    def test_阈值边界恰好允许到上限(self, client):
        source = "172.16.0.2"
        results = [
            _login_once(client, source).status_code
            for _ in range(config.LOGIN_RATE_LIMIT_MAX + 2)
        ]
        assert results[: config.LOGIN_RATE_LIMIT_MAX] == [200] * (
            config.LOGIN_RATE_LIMIT_MAX
        )
        assert results[config.LOGIN_RATE_LIMIT_MAX:] == [429, 429]

    def test_某来源被限不牵连其他来源(self, client):
        for _ in range(config.LOGIN_RATE_LIMIT_MAX):
            _login_once(client, "172.16.0.3")
        assert _login_once(client, "172.16.0.3").status_code == 429
        assert _login_once(client, "172.16.0.4").status_code == 200

    def test_登录限流与接口限流是独立的桶(self, client, viewer_tokens):
        source = "172.16.0.5"
        for _ in range(config.LOGIN_RATE_LIMIT_MAX):
            _login_once(client, source)
        assert _login_once(client, source).status_code == 429
        # 同一来源访问受保护接口仍放行（不同桶）
        resp = client.get(
            "/resources/documents",
            headers={**auth_header(viewer_tokens), "X-Forwarded-For": source},
        )
        assert resp.status_code == 200


class TestApiRateLimit:
    def test_受保护入口超限返回429(self, client, viewer_tokens):
        source = "172.16.1.1"
        headers = {**auth_header(viewer_tokens), "X-Forwarded-For": source}
        for _ in range(config.API_RATE_LIMIT_MAX):
            assert client.get("/resources/documents", headers=headers).status_code == 200
        blocked = client.get("/resources/documents", headers=headers)
        assert blocked.status_code == 429
        assert blocked.json()["detail"]["retry_after"] >= 1


class TestConcurrency:
    def test_并发下同一来源计数准确(self):
        limiter = RateLimiter()
        limit, threads = 50, 200
        allowed = []
        lock = threading.Lock()

        def worker():
            result = limiter.hit("api", "10.9.9.9", limit, 60)
            with lock:
                allowed.append(result.allowed)

        pool = [threading.Thread(target=worker) for _ in range(threads)]
        for t in pool:
            t.start()
        for t in pool:
            t.join()

        # 恰好放行 limit 个：不漏计（应少于 limit）也不重复扣减（应多于 limit）
        assert sum(allowed) == limit

    def test_并发下不同来源互不影响(self):
        limiter = RateLimiter()
        results: dict[str, list] = {"a": [], "b": []}
        lock = threading.Lock()

        def worker(source):
            r = limiter.hit("api", source, 10, 60)
            with lock:
                results[source].append(r.allowed)

        pool = [
            threading.Thread(target=worker, args=(s,))
            for s in ("a", "b")
            for _ in range(20)
        ]
        for t in pool:
            t.start()
        for t in pool:
            t.join()

        assert sum(results["a"]) == 10
        assert sum(results["b"]) == 10

    def test_窗口过期后重新计数(self):
        limiter = RateLimiter()
        assert limiter.hit("api", "10.8.8.8", 1, 0).allowed
        # window=0 表示窗口立即过期，下一次请求重新开窗
        assert limiter.hit("api", "10.8.8.8", 1, 0).allowed

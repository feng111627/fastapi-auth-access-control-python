"""业务链路三：按来源的时间窗限流，含并发计数准确性与来源隔离。"""
from __future__ import annotations

import threading
import time

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.ratelimit import FixedWindowRateLimiter
from tests.conftest import auth_header, login


def make_client(**overrides) -> TestClient:
    return TestClient(create_app(Settings(**overrides)))


class Test登录入口限流:
    """登录按来源限流，超过阈值返回 429 并告知等待时长。"""

    def test_超过阈值返回429及等待时长(self):
        client = make_client(login_rate_limit_max_requests=3,
                             rate_limit_window_seconds=60)
        body = {"username": "viewer", "password": "viewer-pass"}
        for _ in range(3):
            assert client.post("/auth/login", json=body).status_code == 200
        resp = client.post("/auth/login", json=body)
        assert resp.status_code == 429
        detail = resp.json()["detail"]
        assert detail["reason"] == "rate_limited"
        assert 1 <= detail["retry_after_seconds"] <= 60
        assert resp.headers["Retry-After"] == str(detail["retry_after_seconds"])

    def test_窗口滚动后恢复放行(self):
        client = make_client(login_rate_limit_max_requests=2,
                             rate_limit_window_seconds=1)
        body = {"username": "viewer", "password": "viewer-pass"}
        assert client.post("/auth/login", json=body).status_code == 200
        assert client.post("/auth/login", json=body).status_code == 200
        assert client.post("/auth/login", json=body).status_code == 429
        time.sleep(1.1)
        assert client.post("/auth/login", json=body).status_code == 200

    def test_登录与受保护入口计数相互独立(self):
        client = make_client(login_rate_limit_max_requests=2,
                             rate_limit_max_requests=2,
                             rate_limit_window_seconds=60)
        tokens = login(client, "viewer", "viewer-pass")
        login(client, "editor", "editor-pass")
        # 登录额度已用尽，但受保护入口仍有自己的额度
        assert client.get("/documents",
                          headers=auth_header(tokens)).status_code == 200


class Test受保护入口限流:

    def test_超过阈值后受保护入口被拒绝(self):
        client = make_client(rate_limit_max_requests=3,
                             rate_limit_window_seconds=60)
        tokens = login(client, "viewer", "viewer-pass")
        headers = auth_header(tokens)
        for _ in range(3):
            assert client.get("/documents", headers=headers).status_code == 200
        resp = client.get("/documents", headers=headers)
        assert resp.status_code == 429
        assert resp.json()["detail"]["reason"] == "rate_limited"


class Test限流器并发与隔离:
    """并发下计数准确，不多扣不漏扣；来源之间互不影响。"""

    def test_并发请求计数准确(self):
        limiter = FixedWindowRateLimiter(window_seconds=60, max_requests=100)
        results: list[bool] = []
        lock = threading.Lock()

        def hammer():
            for _ in range(10):
                allowed, _ = limiter.hit("source-a", time.time())
                with lock:
                    results.append(allowed)

        threads = [threading.Thread(target=hammer) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        # 100 次请求应恰好全部放行，第 101 次拒绝
        assert results.count(True) == 100
        allowed, retry = limiter.hit("source-a", time.time())
        assert not allowed and retry > 0

    def test_并发下超额请求被稳定拒绝(self):
        limiter = FixedWindowRateLimiter(window_seconds=60, max_requests=50)
        results: list[bool] = []
        lock = threading.Lock()

        def hammer():
            for _ in range(10):
                allowed, _ = limiter.hit("source-b", time.time())
                with lock:
                    results.append(allowed)

        threads = [threading.Thread(target=hammer) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        # 100 次请求中恰好放行 50 次，拒绝 50 次
        assert results.count(True) == 50
        assert results.count(False) == 50

    def test_来源被限不牵连其他来源(self):
        limiter = FixedWindowRateLimiter(window_seconds=60, max_requests=2)
        assert limiter.hit("a", 0.0)[0]
        assert limiter.hit("a", 0.1)[0]
        allowed, retry = limiter.hit("a", 0.2)
        assert not allowed and retry > 0
        # 其他来源不受影响
        assert limiter.hit("b", 0.2)[0]
        assert limiter.hit("c", 0.2)[0]

    def test_同一来源窗口边界(self):
        limiter = FixedWindowRateLimiter(window_seconds=10, max_requests=2)
        assert limiter.hit("a", 0.0)[0]
        assert limiter.hit("a", 9.9)[0]
        assert not limiter.hit("a", 9.99)[0]
        # 窗口起点 +10s 后开启新窗口
        assert limiter.hit("a", 10.0)[0]

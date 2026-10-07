"""业务链路四：账号维度登录保护——连续失败临时锁定、自动恢复、并发计数。"""

import threading

import pytest

from app import config
from app.login_guard import LoginGuard


@pytest.fixture
def strict_guard(monkeypatch):
    """把锁定阈值调小，便于用少量请求触发锁定。"""
    monkeypatch.setattr(config, "LOGIN_MAX_FAILURES", 3)
    monkeypatch.setattr(config, "LOGIN_FAILURE_WINDOW_SECONDS", 300)
    monkeypatch.setattr(config, "LOGIN_LOCK_SECONDS", 300)
    return config


def _login(client, username: str, password: str, source: str):
    return client.post(
        "/auth/login",
        json={"username": username, "password": password},
        headers={"X-Forwarded-For": source},
    )


class TestAccountLockout:
    def test_连续失败达到阈值后锁定并告知等待秒数(self, client, strict_guard):
        source = "192.168.10.1"
        for _ in range(config.LOGIN_MAX_FAILURES - 1):
            resp = _login(client, "viewer", "wrong", source)
            assert resp.status_code == 401
            assert resp.json()["detail"]["code"] == "invalid_credentials"
        # 第 N 次失败触发锁定
        resp = _login(client, "viewer", "wrong", source)
        assert resp.status_code == 423
        detail = resp.json()["detail"]
        assert detail["code"] == "account_locked"
        assert 1 <= detail["retry_after"] <= config.LOGIN_LOCK_SECONDS
        assert int(resp.headers["retry-after"]) >= 1

    def test_锁定期间正确密码也被拒绝(self, client, strict_guard):
        source = "192.168.10.2"
        for _ in range(config.LOGIN_MAX_FAILURES):
            _login(client, "viewer", "wrong", source)
        resp = _login(client, "viewer", "viewer-pass", source)
        assert resp.status_code == 423
        assert resp.json()["detail"]["code"] == "account_locked"

    def test_锁定期间换来源仍被拒绝(self, client, strict_guard):
        for i in range(config.LOGIN_MAX_FAILURES):
            _login(client, "viewer", "wrong", f"192.168.11.{i}")
        # 从一个全新的来源登录，账号锁仍然生效
        resp = _login(client, "viewer", "viewer-pass", "10.250.250.1")
        assert resp.status_code == 423
        assert resp.json()["detail"]["retry_after"] >= 1

    def test_不同账号互不影响(self, client, strict_guard):
        source = "192.168.12.1"
        for _ in range(config.LOGIN_MAX_FAILURES):
            _login(client, "viewer", "wrong", source)
        assert _login(client, "viewer", "viewer-pass", source).status_code == 423
        # 其他账号从同一来源正常登录
        resp = _login(client, "editor", "editor-pass", source)
        assert resp.status_code == 200

    def test_锁定到期自动恢复(self, client, monkeypatch):
        monkeypatch.setattr(config, "LOGIN_MAX_FAILURES", 2)
        monkeypatch.setattr(config, "LOGIN_FAILURE_WINDOW_SECONDS", 300)
        # 锁定时长为 0：锁定立即到期，下一次请求自动恢复
        monkeypatch.setattr(config, "LOGIN_LOCK_SECONDS", 0)
        source = "192.168.13.1"
        for _ in range(2):
            _login(client, "viewer", "wrong", source)
        resp = _login(client, "viewer", "viewer-pass", source)
        assert resp.status_code == 200

    def test_登录成功后失败计数清零(self, client, strict_guard):
        source = "192.168.14.1"
        for _ in range(config.LOGIN_MAX_FAILURES - 1):
            assert _login(client, "viewer", "wrong", source).status_code == 401
        # 成功登录清零计数
        assert _login(client, "viewer", "viewer-pass", source).status_code == 200
        # 再失败 N-1 次仍不应锁定
        for _ in range(config.LOGIN_MAX_FAILURES - 1):
            resp = _login(client, "viewer", "wrong", source)
            assert resp.status_code == 401
            assert resp.json()["detail"]["code"] == "invalid_credentials"


class TestLoginGuardConcurrency:
    def test_并发失败恰好到阈值才锁定(self):
        guard = LoginGuard()
        threshold = 50
        triggered = []
        lock = threading.Lock()

        def worker():
            result = guard.record_failure("alice", threshold, 300, 300)
            with lock:
                triggered.append(result > 0)

        pool = [threading.Thread(target=worker) for _ in range(threshold)]
        for t in pool:
            t.start()
        for t in pool:
            t.join()

        # 恰好一个调用观察到锁定触发：不会提前锁（少于阈值就锁），也不会漏计
        assert sum(triggered) == 1
        assert guard.locked_remaining("alice") > 0

    def test_并发失败不足阈值不锁定(self):
        guard = LoginGuard()
        threshold = 50

        def worker():
            guard.record_failure("bob", threshold, 300, 300)

        pool = [threading.Thread(target=worker) for _ in range(threshold - 1)]
        for t in pool:
            t.start()
        for t in pool:
            t.join()

        assert guard.locked_remaining("bob") == 0

    def test_并发下不同账号互不影响(self):
        guard = LoginGuard()
        results: dict[str, list] = {"a": [], "b": []}
        lock = threading.Lock()

        def worker(name):
            r = guard.record_failure(name, 10, 300, 300)
            with lock:
                results[name].append(r > 0)

        pool = [
            threading.Thread(target=worker, args=(name,))
            for name in ("a", "b")
            for _ in range(10)
        ]
        for t in pool:
            t.start()
        for t in pool:
            t.join()

        assert sum(results["a"]) == 1
        assert sum(results["b"]) == 1
        assert guard.locked_remaining("a") > 0
        assert guard.locked_remaining("b") > 0

    def test_失败计数窗口过期后重新计数(self):
        guard = LoginGuard()
        # window=0 表示窗口立即过期，每次失败都重新开窗，永远不会累积到阈值
        for _ in range(10):
            assert guard.record_failure("carol", 2, 0, 300) == 0
        assert guard.locked_remaining("carol") == 0

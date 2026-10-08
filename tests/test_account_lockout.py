"""业务链路四：账号维度的连续登录失败保护。"""

import threading

from app import config
from app.login_guard import LoginGuard
from tests.conftest import auth_header


def _fail(client, username: str, source: str):
    return client.post(
        "/auth/login",
        json={"username": username, "password": "wrong-password"},
        headers={"X-Forwarded-For": source},
    )


def _ok(client, username: str, password: str, source: str):
    return client.post(
        "/auth/login",
        json={"username": username, "password": password},
        headers={"X-Forwarded-For": source},
    )


class TestLockoutAfterFailures:
    def test_连续失败达到阈值后账号被临时锁定并告知剩余秒数(self, client):
        threshold = config.LOGIN_LOCKOUT_THRESHOLD
        for _ in range(threshold - 1):
            resp = _fail(client, "viewer", "203.0.0.1")
            assert resp.status_code == 401
            assert resp.json()["detail"]["code"] == "invalid_credentials"
        locked = _fail(client, "viewer", "203.0.0.2")
        assert locked.status_code == 429
        detail = locked.json()["detail"]
        assert detail["code"] == "account_locked"
        assert detail["retry_after"] >= 1
        assert int(locked.headers["retry-after"]) == detail["retry_after"]

    def test_锁定期间即使密码正确且更换来源也必须拒绝(self, client):
        for _ in range(config.LOGIN_LOCKOUT_THRESHOLD):
            _fail(client, "editor", "203.0.1.1")
        # 来源完全不同、且这次密码是对的
        resp = _ok(client, "editor", "editor-pass", "203.0.9.9")
        assert resp.status_code == 429
        assert resp.json()["detail"]["code"] == "account_locked"

    def test_不同账号之间互不影响(self, client):
        for _ in range(config.LOGIN_LOCKOUT_THRESHOLD):
            _fail(client, "viewer", "203.0.2.1")
        assert _fail(client, "viewer", "203.0.2.2").status_code == 429
        # 另一个账号一切正常
        assert _ok(client, "editor", "editor-pass", "203.0.2.3").status_code == 200

    def test_失败计数不把别的账号拖下水(self, client):
        for _ in range(config.LOGIN_LOCKOUT_THRESHOLD - 1):
            _fail(client, "viewer", "203.0.3.1")
        # admin 登录成功，不影响 viewer 的计数
        assert _ok(client, "admin", "admin-pass", "203.0.3.2").status_code == 200
        # viewer 再失败一次仍会被锁（计数没有被清零）
        assert _fail(client, "viewer", "203.0.3.3").status_code == 429

    def test_锁定到期自动恢复(self, client):
        # 用可控时钟的 guard 单测到期恢复，避免真实等待
        clock = {"t": 1000.0}
        guard = LoginGuard(threshold=3, window=300, lock_duration=900,
                           clock=lambda: clock["t"])
        for _ in range(2):
            assert not guard.record_failure("alice").locked
        assert guard.record_failure("alice").locked is True
        assert guard.check_locked("alice").locked
        clock["t"] += 901
        result = guard.check_locked("alice")
        assert not result.locked
        # 恢复后可以正常计数/登录，不再被锁状态拦住
        assert not guard.record_failure("alice").locked

    def test_倒计时随时间递减(self):
        clock = {"t": 0.0}
        guard = LoginGuard(threshold=1, window=1000, lock_duration=100,
                           clock=lambda: clock["t"])
        guard.record_failure("bob")
        at_start = guard.check_locked("bob").retry_after
        clock["t"] = 30
        at_later = guard.check_locked("bob").retry_after
        assert at_later < at_start
        assert 1 <= at_later

    def test_登录成功后失败计数清零(self, client):
        for _ in range(config.LOGIN_LOCKOUT_THRESHOLD - 1):
            _fail(client, "admin", "203.0.4.1")
        # 一次成功登录把计数清零
        assert _ok(client, "admin", "admin-pass", "203.0.4.2").status_code == 200
        # 再失败 threshold-1 次也不该被锁（计数从 0 重新开始）
        for _ in range(config.LOGIN_LOCKOUT_THRESHOLD - 1):
            assert _fail(client, "admin", "203.0.4.3").status_code == 401
        assert _fail(client, "admin", "203.0.4.4").status_code == 429

    def test_失败窗口滑过后计数重置(self):
        clock = {"t": 0.0}
        guard = LoginGuard(threshold=3, window=300, lock_duration=900,
                           clock=lambda: clock["t"])
        guard.record_failure("carol")
        guard.record_failure("carol")
        clock["t"] += 301
        # 窗口已过，两次失败不再累计，不应锁定
        assert not guard.record_failure("carol").locked
        assert not guard.record_failure("carol").locked

    def test_账号锁定与来源限流是两道独立的闸(self, client):
        # 闸一：同一来源连续打（用不存在的账号，避免干扰 viewer 的失败计数），
        # 超过每来源阈值后撞上"来源限流"
        for _ in range(config.LOGIN_RATE_LIMIT_MAX):
            _fail(client, "nobody-x", "203.0.5.0")
        resp = _fail(client, "nobody-x", "203.0.5.0")
        assert resp.status_code == 429
        assert resp.json()["detail"]["code"] == "rate_limited"
        # 换全新来源可以继续尝试 viewer，直到失败次数累积到"账号锁"阈值
        for i in range(config.LOGIN_LOCKOUT_THRESHOLD - 1):
            r = _fail(client, "viewer", f"203.0.6.{i}")
            assert r.status_code == 401
        locked = _fail(client, "viewer", "203.0.6.99")
        assert locked.status_code == 429
        assert locked.json()["detail"]["code"] == "account_locked"
        # 锁定后即便换新来源、密码正确也被拒
        assert _ok(client, "viewer", "viewer-pass", "203.0.7.7").status_code == 429


class TestLockoutConcurrency:
    def test_并发失败计数精确不会提前解锁也不会锁死(self):
        clock = {"t": 0.0}
        guard = LoginGuard(threshold=50, window=300, lock_duration=900,
                           clock=lambda: clock["t"])
        locked_results: list[bool] = []
        lock = threading.Lock()

        def worker():
            result = guard.record_failure("dag")
            with lock:
                locked_results.append(result.locked)

        threads = [threading.Thread(target=worker) for _ in range(120)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # 恰好从第 50 次失败起锁定：前 49 次未锁、后 71 次锁定
        assert locked_results.count(False) == 49
        assert locked_results.count(True) == 71
        # 锁到点自动开，不会把账号永久锁死
        clock["t"] += 901
        assert not guard.check_locked("dag").locked

    def test_账号锁不影响已签发的其他来源令牌使用(self, client, viewer_tokens):
        for _ in range(config.LOGIN_LOCKOUT_THRESHOLD):
            _fail(client, "viewer", "203.0.8.1")
        # 已登录持有的令牌仍可访问（锁的是"登录"入口）
        resp = client.get(
            "/resources/documents",
            headers={**auth_header(viewer_tokens), "X-Forwarded-For": "203.0.8.2"},
        )
        assert resp.status_code == 200

    def test_海量随机账号名不会让锁定状态无限堆积(self):
        clock = {"t": 0.0}
        guard = LoginGuard(
            threshold=5, window=10, lock_duration=900,
            clock=lambda: clock["t"], max_keys=50, sweep_interval=0,
        )
        for i in range(50):
            guard.record_failure(f"rand-{i}")
        # 容量已满；推进时间让计数窗口过期，再插入新账号会触发回收
        clock["t"] = 11
        guard.record_failure("rand-fresh")
        assert len(guard._accounts) <= 50
        # 锁定中的账号不被误清
        guard.record_failure("keep")
        for _ in range(4):
            guard.record_failure("keep")
        clock["t"] = 30
        guard.record_failure("another")
        assert guard.check_locked("keep").locked

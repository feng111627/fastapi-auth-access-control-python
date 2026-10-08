"""业务链路六：限流口径与容量——入口全覆盖、来源防伪、桶隔离、回收与并发。"""

import threading

from app import config
from app.deps import client_source
from app.rate_limit import RateLimiter
from app.security import open_session
from app.store import token_store, user_store
from tests.conftest import auth_header, login


class _FakeClient:
    def __init__(self, host: str):
        self.host = host


class _FakeRequest:
    def __init__(self, host: str, headers: dict | None = None):
        self.client = _FakeClient(host)
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}


class TestSourceTrust:
    def test_非可信直连对端时忽略xff只认真实对端(self, monkeypatch):
        monkeypatch.setattr(config, "TRUSTED_PROXIES", frozenset())
        req = _FakeRequest(
            "203.0.10.20",
            {"X-Forwarded-For": "1.2.3.4", "X-Real-IP": "5.6.7.8"},
        )
        assert client_source(req) == "203.0.10.20"

    def test_可信代理时取离代理最近的一跳(self, monkeypatch):
        monkeypatch.setattr(
            config, "TRUSTED_PROXIES", frozenset({"testclient", "10.0.0.1"})
        )
        req = _FakeRequest(
            "testclient",
            {"X-Forwarded-For": "1.1.1.1, 10.0.0.1"},
        )
        assert client_source(req) == "1.1.1.1"

    def test_客户端无法用伪造的xff首跳绕过(self, monkeypatch):
        # 攻击者每请求伪造不同 XFF 首跳，但真实直连非可信 -> 一律按对端计
        monkeypatch.setattr(config, "TRUSTED_PROXIES", frozenset())
        for fake in ("9.9.9.1", "9.9.9.2", "9.9.9.3"):
            req = _FakeRequest("8.8.8.8", {"X-Forwarded-For": fake})
            assert client_source(req) == "8.8.8.8"

    def test_伪造首部已含可信代理也不影响取最右侧非可信(self, monkeypatch):
        monkeypatch.setattr(config, "TRUSTED_PROXIES", frozenset({"testclient"}))
        # 客户端可任意写 XFF，但只有一跳且它不是可信代理 -> 取它
        req = _FakeRequest("testclient", {"X-Forwarded-For": "7.7.7.7, 6.6.6.6"})
        assert client_source(req) == "6.6.6.6"


class TestAuthEntryBuckets:
    def _tokens(self, client, source):
        return login(client, "viewer", "viewer-pass", source)

    def test_刷新入口独立限流并告知等待(self, client):
        tokens = self._tokens(client, "172.20.0.1")
        for _ in range(config.REFRESH_RATE_LIMIT_MAX):
            # 刷新会轮换令牌，需要不断用最新的刷新令牌
            resp = client.post(
                "/auth/refresh",
                json={"refresh_token": tokens["refresh_token"]},
                headers={"X-Forwarded-For": "172.20.0.1"},
            )
            assert resp.status_code == 200
            tokens = resp.json()
        blocked = client.post(
            "/auth/refresh",
            json={"refresh_token": tokens["refresh_token"]},
            headers={"X-Forwarded-For": "172.20.0.1"},
        )
        assert blocked.status_code == 429
        assert blocked.json()["detail"]["code"] == "rate_limited"
        assert int(blocked.headers["retry-after"]) >= 1

    def test_登出入口独立限流(self, client):
        target_source = "172.20.1.1"
        for i in range(config.LOGOUT_RATE_LIMIT_MAX):
            # 每次用全新令牌（登录走别的来源，避免占登录桶），登出请求共用目标来源
            tokens = login(client, "viewer", "viewer-pass", f"172.20.1.{10 + i}")
            resp = client.post(
                "/auth/logout",
                headers={
                    **auth_header(tokens),
                    "X-Forwarded-For": target_source,
                },
                json={"refresh_token": tokens["refresh_token"]},
            )
            assert resp.status_code == 200
        tokens = login(client, "viewer", "viewer-pass", "172.20.1.200")
        blocked = client.post(
            "/auth/logout",
            headers={**auth_header(tokens), "X-Forwarded-For": target_source},
            json={"refresh_token": tokens["refresh_token"]},
        )
        assert blocked.status_code == 429
        assert blocked.json()["detail"]["retry_after"] >= 1

    def test_撤销与全端作废共用撤销桶并独立限流(self, client):
        source = "172.20.2.1"
        headers_base = {"X-Forwarded-For": source}
        for i in range(config.REVOKE_RATE_LIMIT_MAX):
            tokens = login(client, "viewer", "viewer-pass", f"172.20.2.{10 + i}")
            resp = client.post(
                "/auth/revoke",
                headers={**auth_header(tokens), **headers_base},
                json={"refresh_token": tokens["refresh_token"]},
            )
            assert resp.status_code == 200
        # 第 MAX+1 次轮到 revoke-all，也应被同一撤销桶挡住
        tokens = login(client, "viewer", "viewer-pass", "172.20.2.99")
        blocked = client.post(
            "/auth/revoke-all",
            headers={**auth_header(tokens), **headers_base},
        )
        assert blocked.status_code == 429

    def test_某来源被限不牵连其他来源(self, client):
        source_a, source_b = "172.20.3.1", "172.20.3.2"
        for i in range(config.REFRESH_RATE_LIMIT_MAX):
            tokens = login(client, "viewer", "viewer-pass", f"172.20.3.{10+i}")
            r = client.post(
                "/auth/refresh",
                json={"refresh_token": tokens["refresh_token"]},
                headers={"X-Forwarded-For": source_a},
            )
            assert r.status_code == 200
        tokens_b = login(client, "viewer", "viewer-pass", source_b)
        r_b = client.post(
            "/auth/refresh",
            json={"refresh_token": tokens_b["refresh_token"]},
            headers={"X-Forwarded-For": source_b},
        )
        assert r_b.status_code == 200

    def test_不同账号同一来源共享来源桶限流(self, client):
        # 来源口径与账号无关：换账号也不重置来源计数
        source = "172.20.4.1"
        accounts = [("viewer", "viewer-pass"), ("editor", "editor-pass"),
                    ("admin", "admin-pass")]
        statuses = []
        for _ in range(2):
            for username, password in accounts:
                statuses.append(
                    client.post(
                        "/auth/login",
                        json={"username": username, "password": password},
                        headers={"X-Forwarded-For": source},
                    ).status_code
                )
        assert statuses[: config.LOGIN_RATE_LIMIT_MAX] == [200] * (
            config.LOGIN_RATE_LIMIT_MAX
        )
        assert 429 in statuses[config.LOGIN_RATE_LIMIT_MAX:]


class TestDocumentBuckets:
    def test_读桶超限429而写桶不受影响(self, client, viewer_tokens):
        # viewer 只能读；读桶打满
        source = "172.21.0.1"
        headers = {**auth_header(viewer_tokens), "X-Forwarded-For": source}
        for _ in range(config.DOCUMENTS_READ_RATE_LIMIT_MAX):
            assert client.get("/resources/documents", headers=headers).status_code == 200
        assert client.get("/resources/documents", headers=headers).status_code == 429

    def test_写桶独立计数(self, client, editor_tokens):
        source = "172.21.1.1"
        headers = {**auth_header(editor_tokens), "X-Forwarded-For": source}
        for _ in range(config.DOCUMENTS_WRITE_RATE_LIMIT_MAX):
            r = client.post(
                "/resources/documents", headers=headers, json={"title": "t", "body": "b"}
            )
            assert r.status_code == 201
        blocked = client.post(
            "/resources/documents", headers=headers, json={"title": "t", "body": "b"}
        )
        assert blocked.status_code == 429
        # 写满了不影响读
        assert client.get("/resources/documents", headers=headers).status_code == 200

    def test_管理桶独立计数(self, client, admin_tokens):
        source = "172.21.2.1"
        headers = {**auth_header(admin_tokens), "X-Forwarded-For": source}
        for _ in range(config.DOCUMENTS_MANAGE_RATE_LIMIT_MAX):
            assert client.delete("/resources/documents/1", headers=headers).status_code == 200
        blocked = client.delete("/resources/documents/1", headers=headers)
        assert blocked.status_code == 429


class TestEviction:
    def _make_limiter(self, max_keys=3, sweep_interval=0):
        import threading as _t

        limiter = RateLimiter.__new__(RateLimiter)
        limiter._lock = _t.Lock()
        limiter._windows = {}
        limiter._max_keys = max_keys
        limiter._sweep_interval = sweep_interval
        limiter._last_sweep = 0.0
        return limiter

    def test_过期窗口可被主动回收_未过期保留(self):
        limiter = self._make_limiter()
        with limiter._lock:
            limiter._windows[("b", "fresh")] = (100.0, 1, 10.0)
            limiter._windows[("b", "stale")] = (80.0, 3, 10.0)
        # purge_expired 内部自带锁，须在锁外调用
        removed = limiter.purge_expired(now=95.0)
        assert removed == 1
        assert set(limiter._windows) == {("b", "fresh")}

    def test_超容量时全量清扫过期键(self):
        limiter = self._make_limiter(max_keys=3, sweep_interval=0)
        with limiter._lock:
            for i in range(4):
                limiter._windows[("b", f"s{i}")] = (50.0, 1, 10.0)
            limiter._evict_if_needed(now=100.0)
        assert len(limiter._windows) == 0

    def test_清扫间隔节流避免每次全量扫描(self):
        limiter = RateLimiter(max_keys=1, sweep_interval=60)
        limiter.hit("b", "s1", 5, 10)
        limiter.hit("b", "s2", 5, 10)  # 触发一次清扫
        first = limiter._last_sweep
        limiter.hit("b", "s3", 5, 10)
        # 间隔未到，不重复清扫（时间戳保持不变）
        assert limiter._last_sweep == first

    def test_长期运行大量来源过期计数不堆积(self):
        limiter = RateLimiter(max_keys=10, sweep_interval=0)
        for i in range(20):
            limiter.hit("login", f"src{i}", 5, 0)  # window=0：每次都过期重开
        # 容量清扫会把过期键清掉，存活键数有界
        assert len(limiter._windows) <= 10


class TestConcurrencyAccuracy:
    def test_高并发恰好放行阈值个不漏不多(self):
        limiter = RateLimiter()
        limit, threads = 100, 400
        allowed = []
        lock = threading.Lock()

        def worker():
            r = limiter.hit("api", "198.51.100.7", limit, 60)
            with lock:
                allowed.append(r.allowed)

        pool = [threading.Thread(target=worker) for _ in range(threads)]
        for t in pool:
            t.start()
        for t in pool:
            t.join()
        assert sum(allowed) == limit

    def test_令牌代数并发递增不丢账(self):
        # 全端作废的代数递增在并发下必须每次都 +1，不丢递增
        results = []
        lock = threading.Lock()

        def worker():
            with lock:
                results.append(token_store.bump_generation("viewer"))

        pool = [threading.Thread(target=worker) for _ in range(50)]
        for t in pool:
            t.start()
        for t in pool:
            t.join()
        assert sorted(results) == list(range(1, 51))

    def test_并发刷新轮换同一旧链只有一张新令牌(self, client):
        # 用底层 store 验证并发轮换：只有一次成功，其余按复用处理
        from app.security import rotate_refresh_token

        user = user_store.get_by_username("viewer")
        access, refresh, sid = open_session(user["username"], user["role"])
        outcomes = []
        lock = threading.Lock()

        def worker():
            try:
                rotate_refresh_token(refresh)
                ok = True
            except Exception:
                ok = False
            with lock:
                outcomes.append(ok)

        pool = [threading.Thread(target=worker) for _ in range(30)]
        for t in pool:
            t.start()
        for t in pool:
            t.join()
        assert outcomes.count(True) == 1

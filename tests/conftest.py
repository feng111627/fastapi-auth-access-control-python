import pytest
from fastapi.testclient import TestClient

from app import config
from app.login_guard import login_guard
from app.rate_limit import rate_limiter
from app.store import token_store
from main import app


@pytest.fixture(autouse=True)
def _reset_state():
    """每个用例前清空所有易失状态，避免用例间相互牵连。"""
    rate_limiter.reset()
    token_store.reset()
    login_guard.reset()
    yield
    rate_limiter.reset()
    token_store.reset()
    login_guard.reset()


@pytest.fixture(autouse=True)
def _trust_test_peer(monkeypatch):
    """TestClient 的直连对端固定为 testclient；仅测试环境将其视为可信代理，
    以便用 X-Forwarded-For 模拟不同真实来源（生产配置默认空，不信任任何代理）。
    """
    monkeypatch.setattr(config, "TRUSTED_PROXIES", frozenset({"testclient"}))
    yield


@pytest.fixture
def client():
    return TestClient(app)


def login(client: TestClient, username: str, password: str, source: str) -> dict:
    resp = client.post(
        "/auth/login",
        json={"username": username, "password": password},
        headers={"X-Forwarded-For": source},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


@pytest.fixture
def viewer_tokens(client):
    return login(client, "viewer", "viewer-pass", "10.0.0.1")


@pytest.fixture
def editor_tokens(client):
    return login(client, "editor", "editor-pass", "10.0.0.2")


@pytest.fixture
def admin_tokens(client):
    return login(client, "admin", "admin-pass", "10.0.0.3")


def auth_header(tokens: dict) -> dict:
    return {"Authorization": f"Bearer {tokens['access_token']}"}

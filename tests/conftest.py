import pytest
from fastapi.testclient import TestClient

from app.login_guard import login_guard
from app.rate_limit import rate_limiter
from main import app


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """每个用例前清空限流计数与账号锁定状态，避免用例间相互牵连。"""
    rate_limiter.reset()
    login_guard.reset()
    yield
    rate_limiter.reset()
    login_guard.reset()


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

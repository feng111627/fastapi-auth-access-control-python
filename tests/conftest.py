"""测试公共装置：可定制配置的应用客户端与登录助手。"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


@pytest.fixture
def settings() -> Settings:
    return Settings()


@pytest.fixture
def client(settings: Settings) -> TestClient:
    return TestClient(create_app(settings))


def login(client: TestClient, username: str, password: str) -> dict:
    resp = client.post("/auth/login",
                       json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()


def auth_header(tokens: dict) -> dict:
    return {"Authorization": f"Bearer {tokens['access_token']}"}


@pytest.fixture
def viewer_tokens(client: TestClient) -> dict:
    return login(client, "viewer", "viewer-pass")


@pytest.fixture
def editor_tokens(client: TestClient) -> dict:
    return login(client, "editor", "editor-pass")


@pytest.fixture
def admin_tokens(client: TestClient) -> dict:
    return login(client, "admin", "admin-pass")

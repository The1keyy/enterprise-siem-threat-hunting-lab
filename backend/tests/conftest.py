from collections.abc import Iterator
from pathlib import Path

import bcrypt
import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app

PASSWORD = "correct-password"


def demo_settings(database: Path, **overrides: object) -> Settings:
    password_hash = bcrypt.hashpw(PASSWORD.encode(), bcrypt.gensalt(rounds=4)).decode()
    values: dict[str, object] = {
        "data_mode": "demo",
        "database_url": f"sqlite:///{database}",
        "console_admin_user": "analyst",
        "console_admin_password_hash": password_hash,
        "session_secret": "test-session-secret-for-unit-tests",
        "api_cors_origin": "http://localhost:5173",
    }
    values.update(overrides)
    return Settings(**values)


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    app = create_app(demo_settings(tmp_path / "demo.db"))
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def analyst(client: TestClient) -> TestClient:
    response = client.post(
        "/auth/login",
        json={"username": "analyst", "password": PASSWORD},
    )
    assert response.status_code == 200
    return client

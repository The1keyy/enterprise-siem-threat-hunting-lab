from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from tests.conftest import PASSWORD, demo_settings


def test_live_mode_refuses_to_start_when_wazuh_settings_are_missing(tmp_path: Path) -> None:
    settings = demo_settings(tmp_path / "live-missing.db", data_mode="live")
    with pytest.raises(RuntimeError, match="Demo data will not be used"):
        create_app(settings)


def test_live_mode_returns_503(tmp_path: Path) -> None:
    settings = demo_settings(
        tmp_path / "live.db",
        data_mode="live",
        wazuh_api_url="https://10.10.10.40:55000",
        wazuh_api_user="readonly",
        wazuh_api_password="api-secret",
        wazuh_indexer_url="https://10.10.10.40:9200",
        wazuh_indexer_user="readonly",
        wazuh_indexer_password="indexer-secret",
    )
    app = create_app(settings)
    with TestClient(app) as client:
        health = client.get("/health")
        assert health.status_code == 200
        assert health.json()["mode"] == "live"

        login = client.post(
            "/auth/login",
            json={"username": "analyst", "password": PASSWORD},
        )
        assert login.status_code == 200
        denied = client.get("/api/overview")
        assert denied.status_code == 503
        assert denied.json()["detail"] == "Wazuh integration not implemented yet (Step 8)"
        assert "api-secret" not in denied.text
        assert "indexer-secret" not in denied.text

        client.cookies.clear()
        anonymous = client.get("/api/overview")
        assert anonymous.status_code == 401

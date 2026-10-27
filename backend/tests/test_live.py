from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.integrations.errors import WazuhUnavailable
from app.main import create_app
from tests.conftest import PASSWORD, demo_settings


def test_live_mode_refuses_to_start_when_wazuh_settings_are_missing(tmp_path: Path) -> None:
    settings = demo_settings(tmp_path / "live-missing.db", data_mode="live")
    with pytest.raises(RuntimeError, match="Demo data will not be used"):
        create_app(settings)


class _Down:
    """Stand-in client. Every call reports Wazuh as unreachable."""

    def __getattr__(self, name: str):
        if name == "aclose":

            async def close() -> None:
                return None

            return close

        async def fail(*_args: object, **_kwargs: object) -> None:
            raise WazuhUnavailable("Wazuh indexer unreachable")

        return fail


def _live_settings(database: Path):
    return demo_settings(
        database,
        data_mode="live",
        wazuh_api_url="https://10.10.10.40:55000",
        wazuh_api_user="readonly",
        wazuh_api_password="api-secret",
        wazuh_indexer_url="https://10.10.10.40:9200",
        wazuh_indexer_user="readonly",
        wazuh_indexer_password="indexer-secret",
        wazuh_ca_bundle="",
        correlation_poll_enabled=False,
    )


def test_live_mode_returns_503_when_wazuh_is_down(tmp_path: Path) -> None:
    app = create_app(_live_settings(tmp_path / "live.db"))
    app.state.wazuh_api = _Down()
    app.state.wazuh_indexer = _Down()
    with TestClient(app) as client:
        health = client.get("/health")
        assert health.status_code == 200
        assert health.json()["mode"] == "live"

        login = client.post(
            "/auth/login",
            json={"username": "analyst", "password": PASSWORD},
        )
        assert login.status_code == 200

        incidents = client.get("/api/incidents")
        assert incidents.status_code == 200
        assert incidents.json() == []

        # Metadata exists, so the list asks the indexer for alert counts.
        # Wazuh is down, so this is 503 and not the fixture library.
        detections = client.get("/api/detections")
        assert detections.status_code == 503
        assert "unreachable" in detections.json()["detail"]

        for path in ("/api/overview", "/api/sources", "/api/system/health", "/api/entities/hosts"):
            denied = client.get(path)
            assert denied.status_code == 503, path
            assert "unreachable" in denied.json()["detail"]
            assert "DEMO DATA" not in denied.text
            assert "api-secret" not in denied.text
            assert "indexer-secret" not in denied.text

        too_wide = client.post(
            "/api/hunts/run",
            json={
                "id": "HUNT-002",
                "query": "agent.name:WS01",
                "from": "2026-10-01T00:00:00Z",
                "to": "2026-10-09T00:00:00Z",
            },
        )
        assert too_wide.status_code == 400
        assert "7 days" in too_wide.json()["detail"]

        down = client.post(
            "/api/hunts/run",
            json={
                "id": "HUNT-002",
                "query": "agent.name:WS01",
                "from": "2026-10-01T00:00:00Z",
                "to": "2026-10-02T00:00:00Z",
            },
        )
        assert down.status_code == 503
        assert "unreachable" in down.json()["detail"]

        client.cookies.clear()
        anonymous = client.get("/api/overview")
        assert anonymous.status_code == 401

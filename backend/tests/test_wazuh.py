"""Mocked Wazuh manager API and indexer. Not lab results."""

import json
import logging
from pathlib import Path

import httpx
import pytest

from app.core.config import wazuh_level_severity
from app.integrations.errors import ArchivesNotEnabled, HuntQueryRejected, WazuhUnavailable
from app.integrations.wazuh_api import WazuhApiClient
from app.integrations.wazuh_indexer import WazuhIndexerClient, validate_hunt_query
from app.services.mapping import alert_to_timeline, manager_component_status
from tests.conftest import demo_settings

MOCKS = Path(__file__).parent / "wazuh_mocks"
NOTICE = "SYNTHETIC MOCK of Wazuh 4.14 response shape, not real data, VERIFY in lab\n"
START = "2026-10-01T00:00:00Z"
END = "2026-10-02T00:00:00Z"


def load_mock(name: str) -> dict:
    text = (MOCKS / name).read_text(encoding="utf-8")
    assert text.startswith(NOTICE), name
    return json.loads(text[len(NOTICE) :])


def test_mock_files_are_labeled() -> None:
    files = list(MOCKS.glob("*.json"))
    assert files
    for path in files:
        assert path.read_text(encoding="utf-8").startswith(NOTICE)


def _settings(tmp_path: Path, **overrides: object):
    values: dict[str, object] = {
        "wazuh_api_url": "https://wazuh.example:55000",
        "wazuh_api_user": "readonly",
        "wazuh_api_password": "api-secret",
        "wazuh_indexer_url": "https://wazuh.example:9200",
        "wazuh_indexer_user": "readonly",
        "wazuh_indexer_password": "indexer-secret",
        "wazuh_ca_bundle": "",
        "wazuh_token_ttl_seconds": 900,
        "wazuh_token_refresh_skew_seconds": 60,
    }
    values.update(overrides)
    return demo_settings(tmp_path / "wazuh.db", **values)


def test_severity_mapping_boundaries() -> None:
    assert wazuh_level_severity(0) == "low"
    assert wazuh_level_severity(6) == "low"
    assert wazuh_level_severity(7) == "medium"
    assert wazuh_level_severity(11) == "medium"
    assert wazuh_level_severity(12) == "high"
    assert wazuh_level_severity(14) == "high"
    assert wazuh_level_severity(15) == "critical"
    assert wazuh_level_severity(16) == "critical"


def test_alert_mapping_missing_fields_are_none() -> None:
    event = alert_to_timeline({})
    for key in ("time", "title", "source", "host", "user", "eventId", "ruleId", "severity"):
        assert event[key] is None
    assert event["raw"] == {}

    partial = alert_to_timeline({"rule": {"level": 6}})
    assert partial["severity"] == "low"
    assert partial["host"] is None
    assert partial["user"] is None
    assert partial["title"] is None


def test_manager_status_ignores_non_daemon_fields() -> None:
    assert manager_component_status({"wazuh-analysisd": "running", "note": "stopped"}) == "Healthy"
    assert manager_component_status({"wazuh-analysisd": "stopped"}) == "Degraded"
    assert manager_component_status({}) is None


@pytest.mark.asyncio
async def test_tls_insecure_logs_a_warning(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger="sentinelforge.wazuh")
    settings = _settings(tmp_path, wazuh_tls_insecure=True)
    client = WazuhApiClient(settings)
    await client.aclose()
    assert "LAB ONLY: TLS verification disabled" in caplog.text


@pytest.mark.asyncio
async def test_token_is_cached_and_refreshed_before_expiry(tmp_path: Path) -> None:
    now = {"t": 1_000.0}
    counts = {"auth": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/security/user/authenticate"):
            counts["auth"] += 1
            body = load_mock("authenticate.json")
            body["data"] = {"token": f"synthetic-token-{counts['auth']}"}
            return httpx.Response(200, json=body)
        return httpx.Response(200, json=load_mock("agents.json"))

    client = WazuhApiClient(
        _settings(tmp_path),
        transport=httpx.MockTransport(handler),
        clock=lambda: now["t"],
    )
    try:
        await client.get_agents()
        await client.get_agents()
        assert counts["auth"] == 1
        now["t"] = 1_000.0 + 900 - 60
        await client.get_agents()
        assert counts["auth"] == 2
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_token_refresh_retries_once_on_401(tmp_path: Path) -> None:
    counts = {"auth": 0, "agents": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/security/user/authenticate"):
            counts["auth"] += 1
            return httpx.Response(200, json=load_mock("authenticate.json"))
        counts["agents"] += 1
        if counts["agents"] == 1:
            return httpx.Response(401, json={"title": "Unauthorized", "error": 401})
        assert request.headers["Authorization"] == "Bearer synthetic-token"
        return httpx.Response(200, json=load_mock("agents.json"))

    client = WazuhApiClient(_settings(tmp_path), transport=httpx.MockTransport(handler))
    try:
        agents = await client.get_agents()
    finally:
        await client.aclose()
    assert counts["auth"] == 2
    assert counts["agents"] == 2
    assert agents[0]["name"] == "WS01"


@pytest.mark.asyncio
async def test_custom_rules_keep_sentinelforge_filenames(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/security/user/authenticate"):
            return httpx.Response(200, json=load_mock("authenticate.json"))
        return httpx.Response(200, json=load_mock("rules.json"))

    client = WazuhApiClient(_settings(tmp_path), transport=httpx.MockTransport(handler))
    try:
        rules = await client.get_custom_rules()
    finally:
        await client.aclose()
    assert [rule["filename"] for rule in rules] == ["sentinelforge_auth.xml"]


@pytest.mark.asyncio
async def test_connect_error_is_unavailable(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    client = WazuhApiClient(_settings(tmp_path), transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(WazuhUnavailable, match="Wazuh manager API unreachable"):
            await client.get_agents()
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_alert_search_uses_search_after_not_from(tmp_path: Path) -> None:
    bodies: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        return httpx.Response(200, json=load_mock("alerts_search.json"))

    client = WazuhIndexerClient(_settings(tmp_path), transport=httpx.MockTransport(handler))
    try:
        page = await client.search_alerts(start=START, end=END, size=10, search_after=["cursor"])
    finally:
        await client.aclose()
    assert "from" not in bodies[0]
    assert bodies[0]["search_after"] == ["cursor"]
    assert page["events"][0]["agent"]["name"] == "UBU01"
    mapped = alert_to_timeline(page["events"][0])
    assert mapped["severity"] == "low"
    assert mapped["user"] is None
    assert mapped["srcIp"] == "10.10.10.20"


@pytest.mark.asyncio
async def test_aggregations_and_disk(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/_cluster/health"):
            return httpx.Response(200, json=load_mock("cluster_health.json"))
        if request.url.path.endswith("/_nodes/stats/fs"):
            return httpx.Response(200, json=load_mock("nodes_fs.json"))
        return httpx.Response(200, json=load_mock("aggregations.json"))

    client = WazuhIndexerClient(_settings(tmp_path), transport=httpx.MockTransport(handler))
    try:
        aggs = await client.aggregations(START, END)
        health = await client.health()
    finally:
        await client.aclose()
    assert aggs["by_severity"]["critical"] == 1
    assert aggs["by_severity"]["high"] == 1
    assert aggs["events_total"] == 4
    assert aggs["top_users"][0]["label"] == "sf-test-alice"
    assert health["status"] == "green"
    assert health["nodes"][0]["disk_used_percent"] == 75.0


@pytest.mark.asyncio
async def test_missing_archives_index_has_a_clear_error(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json=load_mock("archives_missing.json"))

    client = WazuhIndexerClient(_settings(tmp_path), transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(ArchivesNotEnabled, match="Archives not enabled on WAZUH01"):
            await client.search_archives("agent.name:UBU01", START, END)
    finally:
        await client.aclose()


def test_hunt_query_rejects_long_windows_and_unknown_fields() -> None:
    validate_hunt_query("agent.name:WS01", START, "2026-10-08T00:00:00Z")
    with pytest.raises(HuntQueryRejected, match="exceeds 7 days"):
        validate_hunt_query("agent.name:WS01", START, "2026-10-08T00:00:01Z")
    with pytest.raises(HuntQueryRejected, match="disallowed fields"):
        validate_hunt_query("event.original:secret", START, END)


@pytest.mark.asyncio
async def test_rejected_hunt_query_is_not_sent(tmp_path: Path) -> None:
    called = {"value": False}

    def handler(request: httpx.Request) -> httpx.Response:
        called["value"] = True
        return httpx.Response(500, json={})

    client = WazuhIndexerClient(_settings(tmp_path), transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(HuntQueryRejected):
            await client.search_archives("event.original:secret", START, END)
    finally:
        await client.aclose()
    assert called["value"] is False

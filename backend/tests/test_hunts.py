"""Hunt definitions from hunting/*.yml, plus a synthetic indexer aggregation.

The mock response is not a lab result.
"""

import json
from types import SimpleNamespace

import httpx
import pytest

from app.integrations.wazuh_indexer import WazuhIndexerClient
from app.services.hunt_catalog import list_hunt_definitions
from app.services.hunt_match import event_matches_query
from app.services.live_read import live_hunt
from tests.test_wazuh import END, START, _settings

NOTICE = "SYNTHETIC MOCK of Wazuh 4.14 response shape, not real data, VERIFY in lab\n"


def test_each_hunt_loads() -> None:
    hunts = list_hunt_definitions()
    assert [hunt["id"] for hunt in hunts] == [f"HUNT-{number:03d}" for number in range(1, 11)]
    assert {hunt["status"] for hunt in hunts} == {"NOT TESTED"}
    assert {hunt["index"] for hunt in hunts} <= {"alerts", "archives"}
    rare = next(hunt for hunt in hunts if hunt["id"] == "HUNT-004")
    assert rare["aggregation"]["type"] == "terms"
    assert rare["aggregation"]["field"] == "data.win.eventdata.targetUserName"


def test_hunt_index_keys_use_config_patterns() -> None:
    from app.core.config import ALERTS_INDEX, ARCHIVES_INDEX
    from app.integrations.errors import HuntQueryRejected
    from app.integrations.wazuh_indexer import resolve_hunt_index

    assert (
        resolve_hunt_index("alerts", alerts=ALERTS_INDEX, archives=ARCHIVES_INDEX) == ALERTS_INDEX
    )
    assert (
        resolve_hunt_index("archives", alerts=ALERTS_INDEX, archives=ARCHIVES_INDEX)
        == ARCHIVES_INDEX
    )
    with pytest.raises(HuntQueryRejected, match="Unknown hunt index"):
        resolve_hunt_index("wazuh-archives-*", alerts=ALERTS_INDEX, archives=ARCHIVES_INDEX)


def test_allowlist_rejects_unknown_fields() -> None:
    from app.integrations.errors import HuntQueryRejected
    from app.integrations.wazuh_indexer import validate_hunt_query

    with pytest.raises(HuntQueryRejected, match="disallowed fields"):
        validate_hunt_query("not.a.real.field:1", START, END)


def test_powershell_hunt_matches_a_fixture_process() -> None:
    from app.fixtures_loader import load_fixture

    hunt = next(item for item in list_hunt_definitions() if item["id"] == "HUNT-001")
    matched = []
    for incident in load_fixture("incidents.json")["incidents"]:
        for event in incident["timeline"]:
            row = dict(event)
            row["incidentId"] = incident["id"]
            if event_matches_query(hunt["query"], row):
                matched.append(row)
    assert any(row["ruleId"] == "SF-005" for row in matched)


@pytest.mark.asyncio
async def test_aggregation_hunt_returns_low_count_buckets(tmp_path) -> None:
    """SYNTHETIC MOCK. Low-count buckets are selected from the mocked agg, not from a lab."""

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["aggs"]["hunt_terms"]["terms"]["field"] == "data.win.eventdata.targetUserName"
        assert request.url.path.startswith("/wazuh-archives-4.x-")
        return httpx.Response(
            200,
            json={
                "hits": {
                    "total": {"value": 13},
                    "hits": [
                        {
                            "_source": _source("sf-test-admin", "2026-10-01T01:00:00Z"),
                            "sort": ["2026-10-01T01:00:00Z", "1"],
                        },
                        {
                            "_source": _source("sf-test-alice", "2026-10-01T02:00:00Z"),
                            "sort": ["2026-10-01T02:00:00Z", "2"],
                        },
                    ],
                },
                "aggregations": {
                    "hunt_terms": {
                        "buckets": [
                            {"key": "sf-test-alice", "doc_count": 10},
                            {"key": "sf-test-admin", "doc_count": 1},
                            {"key": "sf-test-carol", "doc_count": 2},
                        ]
                    }
                },
            },
        )

    client = WazuhIndexerClient(_settings(tmp_path), transport=httpx.MockTransport(handler))
    app = SimpleNamespace(state=SimpleNamespace(wazuh_api=None, wazuh_indexer=client))
    hunt = next(item for item in list_hunt_definitions() if item["id"] == "HUNT-004")
    try:
        result = await live_hunt(
            app,
            hunt_id="HUNT-004",
            query=hunt["query"],
            host="",
            user="",
            source="",
            start=START,
            end=END,
        )
    finally:
        await client.aclose()
    assert result["demo"] is False
    assert [bucket["key"] for bucket in result["buckets"]] == ["sf-test-admin", "sf-test-carol"]
    assert all(bucket["count"] <= 2 for bucket in result["buckets"])
    assert [hit["user"] for hit in result["hits"]] == ["sf-test-admin"]
    assert "SYNTHETIC" not in result["notice"]


def _source(user: str, stamp: str) -> dict:
    return {
        "timestamp": stamp,
        "agent": {"name": "WS01"},
        "rule": {"id": "60106", "level": 3, "description": NOTICE.strip(), "groups": ["windows"]},
        "data": {"win": {"system": {"eventID": "4624"}, "eventdata": {"targetUserName": user}}},
    }

"""SYNTHETIC MOCK. The indexer here is not Wazuh and the alerts are not lab telemetry."""

from __future__ import annotations

import copy
from pathlib import Path

import httpx
import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from app.db import upgrade_database
from app.integrations.errors import WazuhUnavailable
from app.integrations.wazuh_indexer import WazuhIndexerClient
from app.models.tables import AuditLogRow, IncidentRow, IngestedAlertRow
from app.services.checklist import build_checklist, investigation_steps
from app.services.correlation import correlate, load_risk_config
from app.services.correlation_cycle import run_cycle
from app.services.incidents import set_checklist_item
from app.services.spray import SPRAY_BURST, SPRAY_CONFIRMED, classify_spray
from tests.conftest import demo_settings
from tests.test_correlation import _story

LABEL = "SYNTHETIC MOCK"


class FakeIndexer:
    """Pages of synthetic alerts. `fail` simulates Wazuh being down."""

    def __init__(
        self,
        pages: list[list[dict]],
        archives: list[dict] | None = None,
        fail: str | None = None,
    ) -> None:
        self.pages = pages
        self.archives = archives or []
        self.fail = fail
        self.calls: list[object] = []

    async def search_sentinelforge(self, *, search_after: object, size: int) -> dict:
        if self.fail == "alerts":
            raise WazuhUnavailable("Wazuh indexer unreachable")
        self.calls.append(search_after)
        index = len(self.calls) - 1
        if index >= len(self.pages):
            return {"hits": []}
        return {"hits": self.pages[index]}

    async def search_spray_events(self, *, ip: str, start: str, end: str) -> list[dict]:
        if self.fail == "archives":
            raise WazuhUnavailable("Wazuh indexer unreachable")
        return [event for event in self.archives if event.get("ip") == ip]


def _session(tmp_path: Path) -> Session:
    url = f"sqlite:///{tmp_path / 'correlation.db'}"
    upgrade_database(url)
    engine = create_engine(url, connect_args={"check_same_thread": False})
    return Session(engine)


def _settings(tmp_path: Path):
    return demo_settings(
        tmp_path / "unused.db",
        data_mode="live",
        wazuh_api_url="https://10.10.10.40:55000",
        wazuh_api_user="readonly",
        wazuh_api_password="api-secret",
        wazuh_indexer_url="https://10.10.10.40:9200",
        wazuh_indexer_user="readonly",
        wazuh_indexer_password="indexer-secret",
        correlation_poll_enabled=False,
    )


def _pages(alerts: list[dict], size: int) -> list[list[dict]]:
    prepared: list[dict] = []
    for alert in alerts:
        item = copy.deepcopy(alert)
        item["_label"] = LABEL
        rule = dict(item["rule"])
        event_id = ""
        data = item.get("data")
        if isinstance(data, dict) and isinstance(data.get("win"), dict):
            event_id = str(data["win"]["system"]["eventID"])
        groups = ["sentinelforge"]
        groups.append("windows_powershell" if event_id == "4104" else "windows")
        rule["groups"] = groups
        item["rule"] = rule
        item["_sort"] = [item["timestamp"], item["_id"]]
        prepared.append(item)
    return [prepared[index : index + size] for index in range(0, len(prepared), size)]


def _archive(user: str, ip: str = "10.10.10.20") -> dict:
    return {
        "ip": ip,
        "_label": LABEL,
        "timestamp": "2026-10-27T15:00:40.000Z",
        "data": {
            "win": {
                "system": {"eventID": "4625"},
                "eventdata": {"ipAddress": ip, "targetUserName": user},
            }
        },
    }


def test_spray_labels_do_not_change_points() -> None:
    config = load_risk_config()
    confirmed = classify_spray(
        "syn-a",
        "10.10.10.20",
        ["sf-test-alice", r"SENTINELFORGE\sf-test-bob", "sf-test-carol"],
        config,
    )
    burst = classify_spray(
        "syn-b",
        "10.10.10.20",
        ["sf-test-alice", "sf-test-alice", "WS01$", "-"],
        config,
    )
    assert confirmed.status == SPRAY_CONFIRMED
    assert confirmed.users == ("sf-test-alice", "sf-test-bob", "sf-test-carol")
    assert burst.status == SPRAY_BURST
    assert burst.users == ("sf-test-alice",)
    story = correlate(_story(), config=config)
    assert story[0].final == 230


def test_checklist_follows_the_timeline_and_drops_duplicate_text() -> None:
    incident = correlate(_story())[0]
    steps = build_checklist(incident)
    assert steps
    assert steps[0]["sfId"] == "SF-001"
    assert investigation_steps("SF-001")[0] in {item["text"] for item in steps}
    texts = [item["text"] for item in steps]
    assert len(texts) == len(set(texts))
    order = [item["sfId"] for item in steps]
    assert order.index("SF-001") < order.index("SF-004")


@pytest.mark.asyncio
async def test_poll_pages_without_gaps_and_a_second_cycle_does_not_duplicate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("app.services.correlation_cycle._PAGE", 2)
    alerts = _story()
    pages = _pages(alerts, 2)
    archives = [
        _archive("sf-test-alice"),
        _archive("sf-test-bob"),
        _archive("sf-test-carol"),
    ]
    indexer = FakeIndexer(pages, archives)
    settings = _settings(tmp_path)
    with _session(tmp_path) as session:
        first = await run_cycle(session, indexer, settings)
        assert first["error"] is None
        assert first["alertsProcessed"] == 6
        assert first["checkpoint"]["id"] == alerts[-1]["_id"]
        assert indexer.calls[0] is None
        assert indexer.calls[1] == pages[0][-1]["_sort"]
        rows = session.scalars(select(IncidentRow)).all()
        assert len(rows) == 1
        assert rows[0].risk_score == 230
        assert rows[0].severity == "critical"
        assert rows[0].risk["multiplierHosts"] == ["DC01"]
        assert any(item["counted"] is False for item in rows[0].risk["items"])
        assert any(reason.startswith("linked by user") for reason in rows[0].link_reasons)
        assert rows[0].spray_findings[0]["status"] == SPRAY_CONFIRMED
        assert rows[0].checklist
        audits = session.scalars(
            select(AuditLogRow).where(AuditLogRow.action == "generate_checklist")
        ).all()
        assert len(audits) == 1
        assert audits[0].dry_run is False
        assert audits[0].details["response"] == "none"
        stored = session.scalar(select(func.count()).select_from(IngestedAlertRow))
        assert stored == 6

        second = await run_cycle(session, indexer, settings)
        assert second["alertsProcessed"] == 0
        assert second["checkpoint"]["id"] == first["checkpoint"]["id"]
        assert session.scalar(select(func.count()).select_from(IncidentRow)) == 1
        assert session.scalar(select(func.count()).select_from(IngestedAlertRow)) == 6
        again = session.scalars(
            select(AuditLogRow).where(AuditLogRow.action == "generate_checklist")
        ).all()
        assert len(again) == 1
        item_id = str(rows[0].checklist[0]["id"])
        detail = set_checklist_item(session, rows[0].id, item_id, True)
        saved = [item for item in detail["checklist"] if item["id"] == item_id]
        assert saved and saved[0]["checked"] is True


@pytest.mark.asyncio
async def test_spray_below_the_minimum_is_a_burst(tmp_path: Path) -> None:
    alerts = _story()
    indexer = FakeIndexer(_pages(alerts, 50), [_archive("sf-test-alice")])
    with _session(tmp_path) as session:
        await run_cycle(session, indexer, _settings(tmp_path))
        row = session.scalars(select(IncidentRow)).one()
        assert row.risk_score == 230
        assert row.spray_findings[0]["status"] == SPRAY_BURST
        assert row.spray_findings[0]["users"] == ["sf-test-alice"]


@pytest.mark.asyncio
async def test_indexer_down_keeps_the_checkpoint_and_skips_fixtures(tmp_path: Path) -> None:
    indexer = FakeIndexer([], fail="alerts")
    with _session(tmp_path) as session:
        status = await run_cycle(session, indexer, _settings(tmp_path))
        assert status["checkpoint"] is None
        assert status["error"] == "Wazuh indexer unreachable"
        assert status["alertsProcessed"] == 0
        assert session.scalar(select(func.count()).select_from(IncidentRow)) == 0
        assert "DEMO" not in (status["error"] or "")


def test_demo_run_refuses_fixtures(analyst) -> None:
    denied = analyst.post("/api/correlation/run")
    assert denied.status_code == 409
    assert "fixtures" in denied.json()["detail"]
    status = analyst.get("/api/correlation/status")
    assert status.status_code == 200
    body = status.json()
    assert body["enabled"] is False
    assert body["checkpoint"] is None
    assert body["alertsProcessed"] == 0


@pytest.mark.asyncio
async def test_sentinelforge_search_uses_search_after(tmp_path: Path) -> None:
    bodies: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        import json

        bodies.append(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "hits": {
                    "hits": [
                        {
                            "_id": "alert-1",
                            "_source": {
                                "timestamp": "2026-10-27T15:00:00Z",
                                "rule": {"groups": ["sentinelforge"]},
                            },
                            "sort": ["2026-10-27T15:00:00Z", "alert-1"],
                        }
                    ]
                }
            },
        )

    client = WazuhIndexerClient(_settings(tmp_path), transport=httpx.MockTransport(handler))
    try:
        page = await client.search_sentinelforge(search_after=["2026-10-27T15:00:00Z", "alert-0"])
    finally:
        await client.aclose()
    assert "from" not in bodies[0]
    assert bodies[0]["search_after"] == ["2026-10-27T15:00:00Z", "alert-0"]
    assert bodies[0]["query"]["bool"]["filter"] == [{"term": {"rule.groups": "sentinelforge"}}]
    assert page["hits"][0]["_id"] == "alert-1"
    assert page["hits"][0]["_sort"] == ["2026-10-27T15:00:00Z", "alert-1"]

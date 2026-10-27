from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db import SessionLocal
from app.models.tables import AuditLogRow
from app.services.incidents import DRY_RUN_MESSAGE


def test_incident_filters(analyst: TestClient) -> None:
    everyone = analyst.get("/api/incidents")
    assert everyone.status_code == 200
    rows = everyone.json()
    assert rows
    assert all(row["demo"] is True for row in rows)

    critical = [row for row in rows if row["severity"] == "critical"]
    filtered = analyst.get("/api/incidents", params={"severity": "critical"}).json()
    assert [row["id"] for row in filtered] == [row["id"] for row in critical]
    assert critical

    host = rows[0]["hosts"][0]
    by_host = analyst.get("/api/incidents", params={"host": host}).json()
    assert by_host
    assert all(host in row["hosts"] for row in by_host)

    alice = analyst.get("/api/incidents", params={"user": "sf-test-alice"}).json()
    assert alice
    assert all(any("sf-test-alice" in user for user in row["users"]) for row in alice)


def _story_id(analyst: TestClient) -> str:
    rows = analyst.get("/api/incidents").json()
    story = next(row for row in rows if row["riskScore"] == 230)
    return story["id"]


def test_patch_updates_status(analyst: TestClient) -> None:
    incident_id = _story_id(analyst)
    updated = analyst.patch(f"/api/incidents/{incident_id}", json={"status": "Contained"})
    assert updated.status_code == 200
    assert updated.json()["status"] == "Contained"
    again = analyst.get(f"/api/incidents/{incident_id}")
    assert again.json()["status"] == "Contained"
    assert again.json()["riskScore"] == 230


def test_action_requires_confirm_and_stays_a_dry_run(analyst: TestClient) -> None:
    incident_id = _story_id(analyst)
    before = analyst.get(f"/api/incidents/{incident_id}").json()
    denied = analyst.post(
        f"/api/incidents/{incident_id}/actions",
        json={"action": "isolate_endpoint", "target": "WS01", "confirm": False},
    )
    assert denied.status_code == 400

    allowed = analyst.post(
        f"/api/incidents/{incident_id}/actions",
        json={"action": "isolate_endpoint", "target": "WS01", "confirm": True},
    )
    assert allowed.status_code == 200
    assert allowed.json()["message"] == DRY_RUN_MESSAGE

    after = analyst.get(f"/api/incidents/{incident_id}").json()
    assert after["status"] == before["status"]
    assert after["audit"][0]["message"] == DRY_RUN_MESSAGE
    assert after["audit"][0]["target"] == "WS01"

    with SessionLocal() as session:
        rows = session.scalars(
            select(AuditLogRow).where(AuditLogRow.action == "isolate_endpoint")
        ).all()
    assert len(rows) == 1
    assert rows[0].dry_run is True
    assert rows[0].details["executed"] is False

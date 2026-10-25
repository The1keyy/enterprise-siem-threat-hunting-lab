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


def test_patch_updates_status(analyst: TestClient) -> None:
    updated = analyst.patch("/api/incidents/INC-0001", json={"status": "Contained"})
    assert updated.status_code == 200
    assert updated.json()["status"] == "Contained"
    again = analyst.get("/api/incidents/INC-0001")
    assert again.json()["status"] == "Contained"
    assert again.json()["riskScore"] == 125


def test_action_requires_confirm_and_stays_a_dry_run(analyst: TestClient) -> None:
    before = analyst.get("/api/incidents/INC-0001").json()
    denied = analyst.post(
        "/api/incidents/INC-0001/actions",
        json={"action": "isolate_endpoint", "target": "WS01", "confirm": False},
    )
    assert denied.status_code == 400

    allowed = analyst.post(
        "/api/incidents/INC-0001/actions",
        json={"action": "isolate_endpoint", "target": "WS01", "confirm": True},
    )
    assert allowed.status_code == 200
    assert allowed.json()["message"] == DRY_RUN_MESSAGE

    after = analyst.get("/api/incidents/INC-0001").json()
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

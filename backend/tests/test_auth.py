from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db import SessionLocal
from app.models.tables import AuditLogRow
from tests.conftest import PASSWORD


def test_login_succeeds_and_rejects_a_wrong_password(client: TestClient) -> None:
    bad = client.post("/auth/login", json={"username": "analyst", "password": "nope"})
    assert bad.status_code == 401

    good = client.post("/auth/login", json={"username": "analyst", "password": PASSWORD})
    assert good.status_code == 200
    assert good.json()["username"] == "analyst"
    cookie = good.headers["set-cookie"].lower()
    assert "httponly" in cookie
    assert "samesite=lax" in cookie

    me = client.get("/auth/me")
    assert me.status_code == 200
    assert me.json()["username"] == "analyst"

    with SessionLocal() as session:
        rows = session.scalars(select(AuditLogRow).where(AuditLogRow.action == "login")).all()
    assert len(rows) == 2
    assert {row.details["result"] for row in rows} == {"failure", "success"}
    assert all(row.dry_run is False for row in rows)


def test_api_requires_auth(client: TestClient) -> None:
    response = client.get("/api/incidents")
    assert response.status_code == 401
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["mode"] == "demo"

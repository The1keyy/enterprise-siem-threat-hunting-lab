"""Seed demo incidents, notes, risk events, and saved hunts on an empty database."""

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db import SessionLocal
from app.fixtures_loader import load_fixture
from app.models.tables import (
    IncidentEventRow,
    IncidentRow,
    NoteRow,
    RiskEventRow,
    SavedHuntRow,
)


def seed_demo() -> None:
    with SessionLocal() as session:
        count = session.scalar(select(func.count()).select_from(IncidentRow))
        if count:
            return
        incidents = load_fixture("incidents.json")["incidents"]
        for item in incidents:
            _insert_incident(session, item, demo=True)
        for hunt in load_fixture("hunts.json")["hunts"]:
            session.add(
                SavedHuntRow(
                    id=hunt["id"],
                    name=hunt["name"],
                    hypothesis=hunt["hypothesis"],
                    data_source=hunt["dataSource"],
                    query=hunt["query"],
                    expected_behavior=hunt["expectedBehavior"],
                    suspicious_behavior=hunt["suspiciousBehavior"],
                    mitre=hunt["mitre"],
                    investigation_guidance=hunt["investigationGuidance"],
                    status=hunt["status"],
                    demo=True,
                )
            )
        session.commit()


def _insert_incident(session: Session, item: dict[str, Any], demo: bool) -> None:
    session.add(
        IncidentRow(
            id=item["id"],
            title=item["title"],
            severity=item["severity"],
            risk_score=item["riskScore"],
            status=item["status"],
            owner=item["owner"],
            users=item["users"],
            hosts=item["hosts"],
            mitre=item["mitre"],
            first_seen=item["firstSeen"],
            last_seen=item["lastSeen"],
            demo=demo,
            entities=item["entities"],
            risk=item["risk"],
            disposition=item["disposition"],
            summary=item["summary"],
            recommended_containment=item["recommendedContainment"],
            link_reasons=list(item.get("linkReasons") or []),
            multiplier_hosts=list((item.get("risk") or {}).get("multiplierHosts") or []),
            spray_findings=list(item.get("sprayFindings") or []),
            checklist=list(item.get("checklist") or []),
        )
    )
    session.flush()
    for event in item.get("timeline", []):
        session.add(
            IncidentEventRow(
                incident_id=item["id"],
                time=str(event["time"]),
                payload=event,
            )
        )
    for note in item.get("notes", []):
        session.add(
            NoteRow(
                id=note["id"],
                incident_id=item["id"],
                author=note["author"],
                time=note["time"],
                text=note["text"],
            )
        )
    for risk_item in item.get("risk", {}).get("items", []):
        session.add(
            RiskEventRow(
                incident_id=item["id"],
                event=risk_item["event"],
                rule_id=risk_item["ruleId"],
                points=risk_item["points"],
                counted=bool(risk_item.get("counted", True)),
                reason=str(risk_item.get("reason") or "counted"),
            )
        )

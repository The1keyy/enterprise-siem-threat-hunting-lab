"""Incident queue, notes, promotion, and LAB ONLY dry-run actions."""

from datetime import UTC, datetime
from typing import Any

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.fixtures_loader import load_fixture
from app.models.tables import (
    AuditLogRow,
    IncidentEventRow,
    IncidentRow,
    NoteRow,
    RiskEventRow,
)
from app.services.risk import final_score, severity_band

DRY_RUN_MESSAGE = "Dry run: no action executed"
RESPONSE_ACTIONS = {
    "isolate_endpoint": "Isolate lab endpoint",
    "disable_account": "Disable test account",
    "block_ip": "Block test IP",
}


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def write_audit(
    session: Session,
    *,
    actor: str,
    action: str,
    target: str,
    details: dict[str, Any],
    dry_run: bool,
) -> AuditLogRow:
    row = AuditLogRow(
        time=utc_now(),
        actor=actor,
        action=action,
        target=target,
        details=details,
        dry_run=dry_run,
    )
    session.add(row)
    session.flush()
    return row


def _summary(row: IncidentRow) -> dict[str, Any]:
    return {
        "id": row.id,
        "title": row.title,
        "severity": row.severity,
        "riskScore": row.risk_score,
        "status": row.status,
        "owner": row.owner,
        "users": row.users,
        "hosts": row.hosts,
        "mitre": row.mitre,
        "firstSeen": row.first_seen,
        "lastSeen": row.last_seen,
        "demo": True,
    }


def _matches(row: IncidentRow, filters: dict[str, str]) -> bool:
    severities = [item for item in filters.get("severity", "").split(",") if item]
    statuses = [item for item in filters.get("status", "").split(",") if item]
    if severities and row.severity not in severities:
        return False
    if statuses and row.status not in statuses:
        return False
    user_query = filters.get("user", "").strip().lower()
    if user_query and not any(user_query in user.lower() for user in row.users):
        return False
    host = filters.get("host", "")
    if host and host not in row.hosts:
        return False
    technique = filters.get("technique", "")
    if technique and not any(item.get("id") == technique for item in row.mitre):
        return False
    seen = row.last_seen[:10]
    start = filters.get("from", "")
    end = filters.get("to", "")
    if start and seen < start:
        return False
    if end and seen > end:
        return False
    return True


def list_incidents(session: Session, filters: dict[str, str]) -> list[dict[str, Any]]:
    rows = session.scalars(select(IncidentRow).order_by(IncidentRow.id)).all()
    return [_summary(row) for row in rows if _matches(row, filters)]


def _require(session: Session, incident_id: str) -> IncidentRow:
    row = session.get(IncidentRow, incident_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} was not found.")
    return row


def incident_detail(session: Session, incident_id: str) -> dict[str, Any]:
    row = _require(session, incident_id)
    events = session.scalars(
        select(IncidentEventRow)
        .where(IncidentEventRow.incident_id == incident_id)
        .order_by(IncidentEventRow.id)
    ).all()
    notes = session.scalars(
        select(NoteRow).where(NoteRow.incident_id == incident_id).order_by(NoteRow.time)
    ).all()
    risk_items = session.scalars(
        select(RiskEventRow)
        .where(RiskEventRow.incident_id == incident_id)
        .order_by(RiskEventRow.id)
    ).all()
    audits = session.scalars(
        select(AuditLogRow)
        .where(AuditLogRow.action.in_(RESPONSE_ACTIONS))
        .order_by(AuditLogRow.id)
    ).all()
    risk = dict(row.risk)
    risk["items"] = [
        {"event": item.event, "ruleId": item.rule_id, "points": item.points} for item in risk_items
    ]
    detail = _summary(row)
    detail.update(
        {
            "timeline": [event.payload for event in events],
            "entities": row.entities,
            "risk": risk,
            "notes": [
                {"id": note.id, "author": note.author, "time": note.time, "text": note.text}
                for note in notes
            ],
            "disposition": row.disposition,
            "summary": row.summary,
            "recommendedContainment": row.recommended_containment,
            "audit": [
                {
                    "id": f"AUDIT-{entry.id:04d}",
                    "action": entry.details.get("label", entry.action),
                    "target": entry.target,
                    "time": entry.time,
                    "message": DRY_RUN_MESSAGE,
                }
                for entry in audits
                if entry.details.get("incidentId") == incident_id
            ],
        }
    )
    return detail


def update_incident(
    session: Session,
    incident_id: str,
    status: str | None,
    owner: str | None,
) -> dict[str, Any]:
    row = _require(session, incident_id)
    if status is not None:
        row.status = status
    if owner is not None:
        row.owner = owner
    session.commit()
    return incident_detail(session, incident_id)


def update_analyst(
    session: Session,
    incident_id: str,
    disposition: str | None,
    summary: str | None,
) -> dict[str, Any]:
    row = _require(session, incident_id)
    if disposition is not None:
        row.disposition = disposition
    if summary is not None:
        row.summary = summary
    session.commit()
    return incident_detail(session, incident_id)


def add_note(session: Session, incident_id: str, author: str, text: str) -> dict[str, Any]:
    _require(session, incident_id)
    existing = session.scalars(select(NoteRow.id).where(NoteRow.incident_id == incident_id)).all()
    session.add(
        NoteRow(
            id=f"NOTE-{incident_id}-{len(existing) + 1:02d}",
            incident_id=incident_id,
            author=author,
            time=utc_now(),
            text=text,
        )
    )
    session.commit()
    return incident_detail(session, incident_id)


def _asset_for(hosts: list[str], settings: Settings) -> tuple[str, float]:
    multipliers = settings.asset_multipliers()
    if "DC01" in hosts:
        return "domain_controller", multipliers["domain_controller"]
    if any(host in {"UBU01", "WAZUH01"} for host in hosts):
        return "server", multipliers["server"]
    return "workstation", multipliers["workstation"]


def create_incident(
    session: Session,
    settings: Settings,
    title: str,
    severity: str,
    owner: str,
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    if not events:
        raise HTTPException(status_code=400, detail="Select at least one hunt result.")
    ordered = sorted(events, key=lambda item: str(item.get("time", "")))
    numbers = [
        int(str(row).removeprefix("INC-"))
        for row in session.scalars(select(IncidentRow.id)).all()
        if str(row).startswith("INC-") and str(row).removeprefix("INC-").isdigit()
    ]
    incident_id = f"INC-{max(numbers, default=0) + 1:04d}"
    hosts = list(dict.fromkeys(str(event.get("host", "")) for event in ordered))
    users = list(dict.fromkeys(str(event.get("user", "")) for event in ordered))
    asset_type, multiplier = _asset_for(hosts, settings)
    points = settings.promote_event_points
    subtotal = len(ordered) * points
    score = final_score(subtotal, multiplier)
    detections = {
        item["id"]: item for item in load_fixture("detections.json")["detections"]
    }
    mitre: dict[str, dict[str, Any]] = {}
    for event in ordered:
        detection = detections.get(str(event.get("ruleId", "")))
        for technique in (detection or {}).get("mitre", []):
            mitre[technique["id"]] = technique
    first = ordered[0]
    last = ordered[-1]
    payload = {
        "id": incident_id,
        "title": title.strip() or "Promoted hunt",
        "severity": severity,
        "riskScore": score,
        "status": "New",
        "owner": owner,
        "users": users,
        "hosts": hosts,
        "mitre": list(mitre.values()),
        "firstSeen": first["time"],
        "lastSeen": last["time"],
        "timeline": ordered,
        "entities": {
            "users": users,
            "hosts": hosts,
            "srcIps": [],
            "dstIps": [],
            "processes": [],
            "domains": [],
            "hashes": [],
        },
        "risk": {
            "items": [
                {
                    "event": event.get("title", ""),
                    "ruleId": event.get("ruleId", ""),
                    "points": points,
                }
                for event in ordered
            ],
            "subtotal": subtotal,
            "assetType": asset_type,
            "multiplier": multiplier,
            "final": score,
            "severityBand": severity_band(score, settings),
        },
        "notes": [],
        "disposition": "Undetermined",
        "summary": "Promoted from a demo hunt. Not a lab finding.",
        "recommendedContainment": ["Snapshot the lab VM before any change."],
    }
    from app.services.seed import _insert_incident

    _insert_incident(session, payload, demo=True)
    session.commit()
    return incident_detail(session, incident_id)


def record_dry_run(
    session: Session,
    *,
    incident_id: str,
    actor: str,
    action: str,
    target: str,
    confirm: bool,
) -> dict[str, Any]:
    """LAB ONLY. confirm=true writes an audit row and executes nothing."""

    _require(session, incident_id)
    if not confirm:
        raise HTTPException(status_code=400, detail="confirm must be true")
    if action not in RESPONSE_ACTIONS:
        raise HTTPException(status_code=400, detail="Unknown action")
    write_audit(
        session,
        actor=actor,
        action=action,
        target=target,
        details={
            "incidentId": incident_id,
            "label": RESPONSE_ACTIONS[action],
            "executed": False,
            "labOnly": True,
        },
        dry_run=True,
    )
    session.commit()
    return {"demo": True, "message": DRY_RUN_MESSAGE}

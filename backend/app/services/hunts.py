"""Demo hunt runner. It filters fixture timeline events. It does not query Wazuh."""

import json
import re
from datetime import UTC, datetime
from typing import Any

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.tables import IncidentEventRow, SavedHuntRow

HUNT_NOTICE = "Demo results — live hunts query wazuh-archives-* (Step 8)"


def list_hunts(session: Session) -> list[dict[str, Any]]:
    rows = session.scalars(select(SavedHuntRow).order_by(SavedHuntRow.id)).all()
    return [
        {
            "id": row.id,
            "name": row.name,
            "hypothesis": row.hypothesis,
            "dataSource": row.data_source,
            "query": row.query,
            "expectedBehavior": row.expected_behavior,
            "suspiciousBehavior": row.suspicious_behavior,
            "mitre": row.mitre,
            "investigationGuidance": row.investigation_guidance,
            "status": row.status,
            "demo": True,
        }
        for row in rows
    ]


def event_matches_query(query: str, event: dict[str, Any]) -> bool:
    blob = " ".join(
        [
            str(event.get("title", "")),
            str(event.get("ruleId", "")),
            str(event.get("source", "")),
            str(event.get("eventId", "")),
            str(event.get("host", "")),
            str(event.get("user", "")),
            json.dumps(event.get("raw", {}), separators=(",", ":")),
        ]
    ).lower()
    for clause in re.split(r"\s+OR\s+", query, flags=re.IGNORECASE):
        terms: list[str] = []
        for term in re.split(r"\s+AND\s+", clause, flags=re.IGNORECASE):
            value = term[term.rfind(":") + 1 :] if ":" in term else term
            terms.append(re.sub(r'["()]', "", value).strip().lower())
        if terms and all(len(term) > 2 and term in blob for term in terms):
            return True
    return False


def _millis(value: str) -> float | None:
    if not value:
        return None
    text = value.replace("Z", "+00:00")
    if len(text) == 10:
        text = f"{text}T00:00:00+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.timestamp() * 1000


def run_hunt(
    session: Session,
    hunt_id: str,
    query: str,
    host: str,
    user: str,
    source: str,
    start: str,
    end: str,
) -> dict[str, Any]:
    hunt = session.get(SavedHuntRow, hunt_id)
    if hunt is None:
        raise HTTPException(status_code=404, detail=f"Hunt {hunt_id} was not found.")
    start_ms = _millis(start)
    end_ms = _millis(end)
    hits: list[dict[str, Any]] = []
    rows = session.scalars(select(IncidentEventRow).order_by(IncidentEventRow.id)).all()
    for row in rows:
        event = dict(row.payload)
        event["incidentId"] = row.incident_id
        if not event_matches_query(query, event):
            continue
        if host and event.get("host") != host:
            continue
        if user and event.get("user") != user:
            continue
        if source and event.get("source") != source:
            continue
        event_ms = _millis(str(event.get("time", "")))
        if start_ms is not None and event_ms is not None and event_ms < start_ms:
            continue
        if end_ms is not None and event_ms is not None and event_ms > end_ms:
            continue
        hits.append(event)
    return {"demo": True, "notice": HUNT_NOTICE, "huntId": hunt_id, "hits": hits}

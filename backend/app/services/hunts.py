"""Hunt list and demo runner.

Definitions come from hunting/*.yml in both data modes. Demo results match
fixture timeline events. They are not indexer results.
"""

from datetime import UTC, datetime
from typing import Any

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.tables import IncidentEventRow
from app.services.hunt_catalog import get_hunt, list_hunt_definitions
from app.services.hunt_match import demo_buckets, event_matches_query, events_in_buckets

HUNT_NOTICE = (
    "Demo results — matched fixture timeline events. Not an indexer result."
)


def list_hunts() -> list[dict[str, Any]]:
    return list_hunt_definitions()


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
    hunt = get_hunt(hunt_id)
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
    buckets: list[dict[str, Any]] = []
    aggregation = hunt.get("aggregation")
    if isinstance(aggregation, dict):
        buckets = demo_buckets(
            hits,
            str(aggregation["field"]),
            size=int(aggregation["size"]),
            max_doc_count=int(aggregation["maxDocCount"]),
        )
        hits = events_in_buckets(hits, str(aggregation["field"]), buckets)
    return {
        "demo": True,
        "notice": HUNT_NOTICE,
        "huntId": hunt_id,
        "hits": hits,
        "buckets": buckets,
    }


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

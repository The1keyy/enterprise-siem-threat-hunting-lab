"""Persist SID-to-user observations. Correlation itself stays a pure function."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.tables import SidUserRow
from app.services.correlation import RiskConfig, sid_observations


def remember_sids(
    session: Session,
    alerts: list[dict],
    config: RiskConfig | None = None,
) -> None:
    """Insert or replace a mapping when the new observation is at least as new."""

    for observation in sid_observations(alerts, config):
        row = session.get(SidUserRow, observation.sid)
        seen = _iso(observation.last_seen)
        if row is None:
            session.add(
                SidUserRow(sid=observation.sid, user_name=observation.user, last_seen=seen)
            )
            continue
        if seen >= row.last_seen:
            row.user_name = observation.user
            row.last_seen = seen
    session.flush()


def load_sid_map(session: Session) -> dict[str, str]:
    rows = session.scalars(select(SidUserRow)).all()
    return {row.sid: row.user_name for row in rows}


def _iso(value: datetime) -> str:
    return value.isoformat()

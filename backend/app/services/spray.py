"""SF-002 confirmation from distinct archive usernames.

The category points do not change. Archive field paths are VERIFY for 4.14.9:
`data.win.system.eventID`, `data.win.eventdata.ipAddress`, and
`data.win.eventdata.targetUserName` are not confirmed on a lab archive document.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from app.services.correlation import RiskConfig, normalize_user

SPRAY_CONFIRMED = "spray confirmed"
SPRAY_BURST = "same-source failure burst (not confirmed spray)"


@dataclass(frozen=True)
class SprayFinding:
    alert_id: str
    source_ip: str
    status: str
    users: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "alertId": self.alert_id,
            "sourceIp": self.source_ip,
            "status": self.status,
            "users": list(self.users),
        }


def classify_spray(
    alert_id: str,
    source_ip: str,
    usernames: list[object],
    config: RiskConfig,
) -> SprayFinding:
    """Label an SF-002 alert from the distinct normalized account names."""

    found: list[str] = []
    seen: set[str] = set()
    for value in usernames:
        user = normalize_user(value, config)
        if user and user not in seen:
            seen.add(user)
            found.append(user)
    found.sort()
    status = SPRAY_CONFIRMED if len(found) >= config.spray_min_distinct_users else SPRAY_BURST
    return SprayFinding(
        alert_id=alert_id,
        source_ip=source_ip,
        status=status,
        users=tuple(found),
    )


def archive_usernames(events: list[dict[str, Any]]) -> list[str]:
    """Read targetUserName from archive hits. VERIFY the field path on WAZUH01."""

    names: list[str] = []
    for event in events:
        eventdata = _dig(event, "data", "win", "eventdata")
        if not isinstance(eventdata, dict):
            continue
        name = eventdata.get("targetUserName")
        if isinstance(name, str):
            names.append(name)
    return names


def spray_bounds(when: datetime, config: RiskConfig) -> tuple[datetime, datetime]:
    return when - timedelta(seconds=config.spray_timeframe_seconds), when


def _dig(document: object, *path: str) -> object:
    current = document
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current

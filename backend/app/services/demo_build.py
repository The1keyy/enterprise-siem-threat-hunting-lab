"""Build the demo incident fixture from fixtures/alerts.json.

The alerts are synthetic. This does not read the indexer and it does not
invent a lab result. The score is the correlation model.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from app.core.config import REPO_ROOT
from app.schemas.contract import IncidentFile
from app.services.checklist import build_checklist
from app.services.correlation import correlate, load_risk_config
from app.services.incident_record import parse_time, to_document
from app.services.risk_view import correlation_settings
from app.services.spray import archive_usernames, classify_spray, spray_bounds

ALERTS_PATH = REPO_ROOT / "fixtures" / "alerts.json"
INCIDENTS_PATH = REPO_ROOT / "fixtures" / "incidents.json"
RISK_PATH = REPO_ROOT / "fixtures" / "risk_model.json"
NOTICE = "DEMO DATA — SYNTHETIC, not real telemetry. Not a lab result."


def load_alert_fixture(path: Any = None) -> dict[str, Any]:
    document = json.loads((path or ALERTS_PATH).read_text(encoding="utf-8"))
    notice = str(document.get("_notice") or "")
    if not notice.startswith("DEMO DATA"):
        raise ValueError("alerts.json is missing the DEMO DATA notice")
    if document.get("demo") is not True:
        raise ValueError("alerts.json must set demo true")
    return document


def build_incidents(document: dict[str, Any] | None = None) -> dict[str, Any]:
    source = document if document is not None else load_alert_fixture()
    alerts = list(source.get("alerts") or [])
    archives = list(source.get("archives") or [])
    config = load_risk_config()
    incidents = correlate(alerts, config=config)
    grouped = _spray_by_incident(incidents, alerts, archives, config)
    rows = []
    for incident in incidents:
        checklist = build_checklist(incident)
        rows.append(
            to_document(
                incident,
                demo=True,
                config=config,
                spray=grouped.get(incident.id, []),
                checklist=checklist,
            )
        )
    payload = {"_notice": NOTICE, "incidents": rows}
    IncidentFile.model_validate(payload)
    return payload


def build_risk_model() -> dict[str, Any]:
    model = correlation_settings()
    model["_notice"] = (
        "DEMO DATA — copy of backend/app/core/risk_config.yml. Not a lab measurement."
    )
    return model


def _spray_by_incident(
    incidents: list[Any],
    alerts: list[dict[str, Any]],
    archives: list[dict[str, Any]],
    config: Any,
) -> dict[str, list[Any]]:
    owner: dict[str, str] = {}
    for incident in incidents:
        for alert_id in incident.alert_ids:
            owner[alert_id] = incident.id
    grouped: dict[str, list[Any]] = {}
    for alert in alerts:
        rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
        description = str(rule.get("description") or "")
        if not description.startswith("SF-002"):
            continue
        ip = _dig(alert, "data", "win", "eventdata", "ipAddress")
        stamp = alert.get("timestamp")
        alert_id = alert.get("_id")
        if not isinstance(ip, str) or not isinstance(stamp, str) or not isinstance(alert_id, str):
            continue
        when = parse_time(stamp)
        start, end = spray_bounds(when, config)
        names = archive_usernames(_archives_in_window(archives, ip, start, end))
        finding = classify_spray(alert_id, ip, names, config)
        incident_id = owner.get(alert_id)
        if incident_id:
            grouped.setdefault(incident_id, []).append(finding)
    return grouped


def _archives_in_window(
    archives: list[dict[str, Any]],
    ip: str,
    start: datetime,
    end: datetime,
) -> list[dict[str, Any]]:
    matched: list[dict[str, Any]] = []
    for event in archives:
        stamp = event.get("timestamp")
        if not isinstance(stamp, str):
            continue
        when = parse_time(stamp)
        if when < start or when > end:
            continue
        event_ip = _dig(event, "data", "win", "eventdata", "ipAddress")
        event_id = _dig(event, "data", "win", "system", "eventID")
        if str(event_ip) != ip or str(event_id) != "4625":
            continue
        matched.append(event)
    return matched


def _dig(document: object, *path: str) -> object:
    current = document
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current

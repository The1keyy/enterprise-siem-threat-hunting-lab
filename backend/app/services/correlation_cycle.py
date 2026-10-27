"""One live correlation cycle. Demo fixtures are never read here.

A failed indexer call logs the error, stores it on the status row, and leaves
the checkpoint where it was. Alerts already persisted stay persisted.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.db import SessionLocal
from app.integrations.errors import WazuhResponseError, WazuhUnavailable
from app.models.tables import (
    CorrelationStateRow,
    IncidentEventRow,
    IncidentRow,
    IngestedAlertRow,
    NoteRow,
    RiskEventRow,
)
from app.services.correlation import CorrelatedIncident, correlate, load_risk_config
from app.services.incident_record import (
    band_rose,
    dump_engine,
    iso_z,
    load_engine,
    merge_checklist,
    parse_time,
    to_document,
)
from app.services.incidents import write_audit
from app.services.sid_map import load_sid_map, remember_sids
from app.services.spray import SprayFinding, archive_usernames, classify_spray, spray_bounds

logger = logging.getLogger("sentinelforge")

_STATE_ID = 1
_PAGE = 200


async def poll_forever(app: Any, stop: asyncio.Event) -> None:
    """Background poll. Cancelled on shutdown. Failures stay on the status row."""

    settings: Settings = app.state.settings
    interval = settings.correlation_poll_seconds if settings.correlation_poll_seconds > 0 else 60
    while not stop.is_set():
        indexer = getattr(app.state, "wazuh_indexer", None)
        if indexer is not None:
            try:
                async with app.state.correlation_lock:
                    with SessionLocal() as session:
                        await run_cycle(session, indexer, settings)
            except Exception:
                logger.exception("correlation poll failed")
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except TimeoutError:
            continue


def status_view(session: Session, settings: Settings) -> dict[str, Any]:
    row = session.get(CorrelationStateRow, _STATE_ID)
    checkpoint = None
    if row and row.checkpoint_id and row.checkpoint_time:
        checkpoint = {"timestamp": row.checkpoint_time, "id": row.checkpoint_id}
    enabled = (
        settings.data_mode == "live"
        and settings.correlation_poll_enabled
        and settings.correlation_poll_seconds > 0
    )
    return {
        "demo": settings.data_mode == "demo",
        "enabled": enabled,
        "intervalSeconds": settings.correlation_poll_seconds,
        "lastRun": row.last_run_at if row else None,
        "checkpoint": checkpoint,
        "alertsProcessed": row.alerts_processed if row else 0,
        "error": row.last_error if row else None,
    }


async def run_cycle(session: Session, indexer: Any, settings: Settings) -> dict[str, Any]:
    """Fetch new sentinelforge alerts, correlate them, and persist the result."""

    if settings.data_mode != "live":
        raise RuntimeError("Correlation runs only when DATA_MODE=live. Fixtures are not used.")
    state = _state(session)
    try:
        fetched = await _fetch(indexer, state)
    except (WazuhUnavailable, WazuhResponseError) as exc:
        message = str(exc)
        logger.warning("correlation poll failed: %s", message)
        state.last_run_at = iso_z(datetime.now(UTC))
        state.last_error = message
        session.commit()
        return status_view(session, settings)

    known = set(session.scalars(select(IngestedAlertRow.alert_id)).all())
    fresh = [doc for doc in fetched if str(doc.get("_id")) not in known]
    config = load_risk_config()
    remember_sids(session, fresh, config)
    findings = await _spray(indexer, fresh, config, state)
    existing = _load_existing(session)
    produced = correlate(fresh, existing, config=config, sid_map=load_sid_map(session))
    _save(session, produced, fresh, findings)
    if fetched:
        last = fetched[-1]
        sort = last.get("_sort")
        if isinstance(sort, list) and len(sort) >= 2:
            state.checkpoint_time = str(sort[0])
            state.checkpoint_id = str(sort[1])
        else:
            state.checkpoint_time = str(last.get("timestamp") or "")
            state.checkpoint_id = str(last.get("_id") or "")
    state.last_run_at = iso_z(datetime.now(UTC))
    state.alerts_processed = len(fresh)
    if findings is not None:
        state.last_error = None
    session.commit()
    return status_view(session, settings)


async def _fetch(indexer: Any, state: CorrelationStateRow) -> list[dict[str, Any]]:
    cursor: list[Any] | None = None
    if state.checkpoint_time and state.checkpoint_id:
        cursor = [state.checkpoint_time, state.checkpoint_id]
    found: list[dict[str, Any]] = []
    while True:
        page = await indexer.search_sentinelforge(search_after=cursor, size=_PAGE)
        hits = page.get("hits") if isinstance(page, dict) else None
        if not isinstance(hits, list) or not hits:
            break
        docs = [item for item in hits if isinstance(item, dict) and item.get("_id")]
        found.extend(docs)
        last_sort = docs[-1].get("_sort") if docs else None
        if not isinstance(last_sort, list):
            break
        cursor = last_sort
        if len(hits) < _PAGE:
            break
    return found


async def _spray(
    indexer: Any,
    alerts: list[dict[str, Any]],
    config: Any,
    state: CorrelationStateRow,
) -> list[SprayFinding] | None:
    """Return findings, or None when the archive query failed.

    None keeps the previous error text. A successful query clears it.
    Points are not adjusted here.
    """

    findings: list[SprayFinding] = []
    for alert in alerts:
        description = ""
        rule = alert.get("rule")
        if isinstance(rule, dict) and isinstance(rule.get("description"), str):
            description = rule["description"]
        if not description.startswith("SF-002"):
            continue
        ip = _dig(alert, "data", "win", "eventdata", "ipAddress")
        stamp = alert.get("timestamp")
        alert_id = alert.get("_id")
        if not isinstance(ip, str) or not isinstance(stamp, str) or not isinstance(alert_id, str):
            continue
        when = parse_time(stamp)
        start, end = spray_bounds(when, config)
        try:
            events = await indexer.search_spray_events(
                ip=ip,
                start=iso_z(start),
                end=iso_z(end),
            )
        except (WazuhUnavailable, WazuhResponseError) as exc:
            message = str(exc)
            logger.warning("spray archive query failed: %s", message)
            state.last_error = message
            return None
        names = archive_usernames(events if isinstance(events, list) else [])
        findings.append(classify_spray(alert_id, ip, names, config))
    return findings


def _save(
    session: Session,
    produced: list[CorrelatedIncident],
    fresh: list[dict[str, Any]],
    findings: list[SprayFinding] | None,
) -> None:
    previous = {
        row.id: row
        for row in session.scalars(select(IncidentRow).where(IncidentRow.engine.is_not(None)))
    }
    emitted = {item.id for item in produced}
    finding_map = _findings_by_incident(produced, findings or [])
    for old_id, row in list(previous.items()):
        if old_id in emitted:
            continue
        blob = row.engine if isinstance(row.engine, dict) else {}
        old_alerts = {str(item) for item in blob.get("alertIds") or []}
        survivor = next(
            (item for item in produced if old_alerts and old_alerts & set(item.alert_ids)),
            None,
        )
        if survivor is not None:
            for note in session.scalars(select(NoteRow).where(NoteRow.incident_id == old_id)):
                note.incident_id = survivor.id
        session.execute(delete(IncidentEventRow).where(IncidentEventRow.incident_id == old_id))
        session.execute(delete(RiskEventRow).where(RiskEventRow.incident_id == old_id))
        session.delete(row)
    session.flush()

    owners = {str(doc.get("_id")): doc for doc in fresh}
    for incident in produced:
        row = session.get(IncidentRow, incident.id)
        created = row is None
        rose = band_rose(None if row is None else row.severity, incident.band)
        prior_checks = list(row.checklist) if row is not None else []
        checklist, audit_reason = merge_checklist(
            incident,
            prior_checks,
            created=created,
            rose=rose,
        )
        stored_findings = list(row.spray_findings) if row is not None else []
        if findings is not None:
            by_alert = {str(item.get("alertId")): item for item in stored_findings}
            for item in finding_map.get(incident.id, []):
                by_alert[item.alert_id] = item.as_dict()
            stored_findings = list(by_alert.values())
        document = to_document(
            incident,
            demo=False,
            spray=_spray_objects(stored_findings),
            checklist=checklist,
        )
        if row is None:
            row = IncidentRow(
                id=incident.id,
                title=document["title"],
                severity=document["severity"],
                risk_score=document["riskScore"],
                status=document["status"],
                owner=document["owner"],
                users=document["users"],
                hosts=document["hosts"],
                mitre=document["mitre"],
                first_seen=document["firstSeen"],
                last_seen=document["lastSeen"],
                demo=False,
                entities=document["entities"],
                risk=document["risk"],
                disposition=document["disposition"],
                summary=document["summary"],
                recommended_containment=document["recommendedContainment"],
                link_reasons=document["linkReasons"],
                multiplier_hosts=document["risk"]["multiplierHosts"],
                spray_findings=stored_findings,
                checklist=checklist,
                engine=dump_engine(incident),
            )
            session.add(row)
        else:
            row.title = document["title"]
            row.severity = document["severity"]
            row.risk_score = document["riskScore"]
            row.status = incident.status
            row.users = document["users"]
            row.hosts = document["hosts"]
            row.mitre = document["mitre"]
            row.first_seen = document["firstSeen"]
            row.last_seen = document["lastSeen"]
            row.entities = document["entities"]
            row.risk = document["risk"]
            row.link_reasons = document["linkReasons"]
            row.multiplier_hosts = document["risk"]["multiplierHosts"]
            row.spray_findings = stored_findings
            row.checklist = checklist
            row.engine = dump_engine(incident)
        session.flush()
        _replace_children(session, incident.id, document)
        if audit_reason:
            write_audit(
                session,
                actor="correlation",
                action="generate_checklist",
                target=incident.id,
                details={
                    "reason": audit_reason,
                    "itemCount": len(checklist),
                    "sfIds": sorted({str(item["sfId"]) for item in checklist}),
                    "response": "none",
                },
                dry_run=False,
            )
        for alert_id in incident.alert_ids:
            if alert_id not in owners:
                continue
            doc = owners[alert_id]
            if session.get(IngestedAlertRow, alert_id) is None:
                sort = doc.get("_sort")
                sort_time = str(sort[0]) if isinstance(sort, list) and sort else str(
                    doc.get("timestamp") or ""
                )
                session.add(
                    IngestedAlertRow(
                        alert_id=alert_id,
                        incident_id=incident.id,
                        sort_time=sort_time,
                        document=doc,
                    )
                )
            else:
                existing = session.get(IngestedAlertRow, alert_id)
                if existing is not None:
                    existing.incident_id = incident.id


def _replace_children(session: Session, incident_id: str, document: dict[str, Any]) -> None:
    session.execute(delete(IncidentEventRow).where(IncidentEventRow.incident_id == incident_id))
    session.execute(delete(RiskEventRow).where(RiskEventRow.incident_id == incident_id))
    for event in document["timeline"]:
        session.add(
            IncidentEventRow(
                incident_id=incident_id,
                time=str(event["time"]),
                payload=event,
            )
        )
    for item in document["risk"]["items"]:
        session.add(
            RiskEventRow(
                incident_id=incident_id,
                event=str(item["event"]),
                rule_id=str(item["ruleId"]),
                points=int(item["points"]),
                counted=bool(item["counted"]),
                reason=str(item["reason"]),
            )
        )


def _load_existing(session: Session) -> list[CorrelatedIncident]:
    rows = session.scalars(select(IncidentRow).where(IncidentRow.engine.is_not(None))).all()
    loaded: list[CorrelatedIncident] = []
    for row in rows:
        if not isinstance(row.engine, dict):
            continue
        loaded.append(load_engine(row.engine, status=row.status))
    return loaded


def _findings_by_incident(
    incidents: list[CorrelatedIncident],
    findings: list[SprayFinding],
) -> dict[str, list[SprayFinding]]:
    owner: dict[str, str] = {}
    for incident in incidents:
        for alert_id in incident.alert_ids:
            owner[alert_id] = incident.id
    grouped: dict[str, list[SprayFinding]] = {}
    for finding in findings:
        incident_id = owner.get(finding.alert_id)
        if incident_id:
            grouped.setdefault(incident_id, []).append(finding)
    return grouped


def _spray_objects(stored: list[dict[str, Any]]) -> list[SprayFinding]:
    objects: list[SprayFinding] = []
    for item in stored:
        users = item.get("users") if isinstance(item.get("users"), list) else []
        objects.append(
            SprayFinding(
                alert_id=str(item.get("alertId") or ""),
                source_ip=str(item.get("sourceIp") or ""),
                status=str(item.get("status") or ""),
                users=tuple(str(user) for user in users),
            )
        )
    return objects


def _state(session: Session) -> CorrelationStateRow:
    row = session.get(CorrelationStateRow, _STATE_ID)
    if row is None:
        row = CorrelationStateRow(
            id=_STATE_ID,
            checkpoint_time=None,
            checkpoint_id=None,
            last_run_at=None,
            alerts_processed=0,
            last_error=None,
        )
        session.add(row)
        session.flush()
    return row


def _dig(document: object, *path: str) -> object:
    current = document
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current

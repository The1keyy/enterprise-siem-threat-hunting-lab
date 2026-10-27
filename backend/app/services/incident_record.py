"""Turn a correlated incident into the console document, and back into the engine.

The console shape is what the investigation page reads. The engine blob is what
the next live cycle appends to. Promoted hunts have no engine blob.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

from app.core.config import wazuh_level_severity
from app.services.checklist import build_checklist, preserve_checks
from app.services.correlation import (
    CorrelatedIncident,
    Entities,
    RiskConfig,
    ScoreRow,
    TimelineEntry,
    load_risk_config,
)
from app.services.spray import SprayFinding

# Names match frontend/src/lib/techniques.ts. An unknown id keeps the id as the name.
_TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1078": ("Valid Accounts", "Initial Access"),
    "T1059.001": ("PowerShell", "Execution"),
    "T1059.004": ("Unix Shell", "Execution"),
    "T1136.001": ("Local Account", "Persistence"),
    "T1098": ("Account Manipulation", "Persistence"),
    "T1110.001": ("Password Guessing", "Credential Access"),
    "T1110.003": ("Password Spraying", "Credential Access"),
    "T1021.001": ("Remote Desktop Protocol", "Lateral Movement"),
    "T1021.002": ("SMB / Windows Admin Shares", "Lateral Movement"),
    "T1021.006": ("Windows Remote Management", "Lateral Movement"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
}

_BAND_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def iso_z(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


def band_rose(previous: str | None, current: str) -> bool:
    if previous is None:
        return False
    return _BAND_RANK.get(current, 0) > _BAND_RANK.get(previous, 0)


def to_document(
    incident: CorrelatedIncident,
    *,
    demo: bool,
    config: RiskConfig | None = None,
    spray: list[SprayFinding] | None = None,
    checklist: list[dict[str, object]] | None = None,
) -> dict[str, Any]:
    """Console incident. `demo` is true only for the synthetic fixture build."""

    cfg = config or load_risk_config()
    findings = list(spray or [])
    steps = checklist if checklist is not None else build_checklist(incident)
    hosts = list(incident.multiplier_hosts)
    asset = cfg.default_asset_class
    if hosts:
        asset = cfg.hosts.get(hosts[0], cfg.default_asset_class)
    setter = ", ".join(hosts) if hosts else "the default asset class"
    if demo:
        origin = "Synthetic alerts. Not a lab result."
    else:
        origin = "Not LAB VALIDATED until a lab export is compared with this engine."
    summary = (
        f"Subtotal {incident.subtotal} × {incident.multiplier:g} set by {setter} "
        f"= {incident.final} ({incident.band}). {origin}"
    )
    sf_ids: list[str] = []
    for row in incident.breakdown:
        if row.sf_id and row.sf_id not in sf_ids:
            sf_ids.append(row.sf_id)
    host_text = ", ".join(incident.entities.hosts) or "unknown host"
    title = f"{', '.join(sf_ids) or 'Alerts'} on {host_text}"
    by_id = {str(alert.get("_id")): alert for alert in incident.alerts}
    return {
        "id": incident.id,
        "title": title,
        "severity": incident.band,
        "riskScore": incident.final,
        "status": incident.status,
        "owner": "Unassigned",
        "users": list(incident.entities.users),
        "hosts": list(incident.entities.hosts),
        "mitre": [_mitre(item) for item in incident.mitre],
        "firstSeen": iso_z(incident.first_seen),
        "lastSeen": iso_z(incident.last_seen),
        "demo": demo,
        "timeline": [
            _timeline_event(entry, by_id.get(entry.alert_id, {})) for entry in incident.timeline
        ],
        "entities": {
            "users": list(incident.entities.users),
            "hosts": list(incident.entities.hosts),
            "srcIps": list(incident.entities.source_ips),
            "dstIps": [],
            "processes": [],
            "domains": [],
            "hashes": [],
        },
        "risk": {
            "items": [_score_item(row, by_id.get(row.alert_id, {})) for row in incident.breakdown],
            "subtotal": incident.subtotal,
            "assetType": asset,
            "multiplier": incident.multiplier,
            "final": incident.final,
            "severityBand": incident.band,
            "multiplierHosts": hosts,
            "forcedCritical": incident.forced_critical,
        },
        "notes": [],
        "disposition": "Undetermined",
        "summary": summary,
        "recommendedContainment": [],
        "audit": [],
        "linkReasons": list(incident.link_reasons),
        "sprayFindings": [item.as_dict() for item in findings],
        "checklist": steps,
    }


def dump_engine(incident: CorrelatedIncident) -> dict[str, Any]:
    return {
        "id": incident.id,
        "status": incident.status,
        "alerts": list(incident.alerts),
        "alertIds": list(incident.alert_ids),
        "timeline": [
            {
                "alertId": item.alert_id,
                "time": iso_z(item.time),
                "sfId": item.sf_id,
                "host": item.host,
                "level": item.level,
                "ruleId": item.rule_id,
                "description": item.description,
                "linkStrength": item.link_strength,
                "linkReason": item.link_reason,
            }
            for item in incident.timeline
        ],
        "entities": {
            "users": list(incident.entities.users),
            "hosts": list(incident.entities.hosts),
            "sourceIps": list(incident.entities.source_ips),
        },
        "mitre": list(incident.mitre),
        "breakdown": [
            {
                "category": row.category,
                "sfId": row.sf_id,
                "alertId": row.alert_id,
                "time": iso_z(row.time),
                "points": row.points,
                "counted": row.counted,
                "reason": row.reason,
            }
            for row in incident.breakdown
        ],
        "subtotal": incident.subtotal,
        "multiplier": incident.multiplier,
        "multiplierHosts": list(incident.multiplier_hosts),
        "final": incident.final,
        "band": incident.band,
        "forcedCritical": incident.forced_critical,
        "linkReasons": list(incident.link_reasons),
        "firstSeen": iso_z(incident.first_seen),
        "lastSeen": iso_z(incident.last_seen),
    }


def load_engine(raw: dict[str, Any], status: str | None = None) -> CorrelatedIncident:
    """Rebuild the dataclass. `status` is the analyst row when it differs."""

    entities = raw.get("entities") if isinstance(raw.get("entities"), dict) else {}
    incident = CorrelatedIncident(
        id=str(raw["id"]),
        status=str(raw["status"]),
        alerts=tuple(item for item in raw.get("alerts") or [] if isinstance(item, dict)),
        timeline=tuple(_load_timeline(item) for item in raw.get("timeline") or []),
        entities=Entities(
            users=tuple(str(item) for item in entities.get("users") or []),
            hosts=tuple(str(item) for item in entities.get("hosts") or []),
            source_ips=tuple(str(item) for item in entities.get("sourceIps") or []),
        ),
        mitre=tuple(str(item) for item in raw.get("mitre") or []),
        breakdown=tuple(_load_score(item) for item in raw.get("breakdown") or []),
        subtotal=int(raw["subtotal"]),
        multiplier=float(raw["multiplier"]),
        multiplier_hosts=tuple(str(item) for item in raw.get("multiplierHosts") or []),
        final=int(raw["final"]),
        band=str(raw["band"]),
        forced_critical=bool(raw.get("forcedCritical")),
        link_reasons=tuple(str(item) for item in raw.get("linkReasons") or []),
        alert_ids=tuple(str(item) for item in raw.get("alertIds") or []),
        first_seen=parse_time(str(raw["firstSeen"])),
        last_seen=parse_time(str(raw["lastSeen"])),
    )
    if status and status != incident.status:
        return replace(incident, status=status)
    return incident


def merge_checklist(
    incident: CorrelatedIncident,
    previous: list[dict[str, Any]] | None,
    *,
    created: bool,
    rose: bool,
) -> tuple[list[dict[str, object]], str | None]:
    """Return the checklist to store, and why an audit row is needed."""

    if not created and not rose:
        return list(previous or []), None
    fresh = preserve_checks(build_checklist(incident), previous)
    return fresh, "created" if created else "band_rose"


def _mitre(technique_id: str) -> dict[str, str]:
    name, tactic = _TECHNIQUES.get(technique_id, (technique_id, "Unknown"))
    return {"id": technique_id, "name": name, "tactic": tactic}


def _score_item(row: ScoreRow, raw: dict[str, Any]) -> dict[str, Any]:
    rule_id = row.alert_id
    rule = raw.get("rule") if isinstance(raw.get("rule"), dict) else {}
    if rule.get("id") is not None:
        rule_id = str(rule["id"])
    label = row.sf_id or "Alert"
    if row.category:
        label = f"{label} {row.category.replace('_', ' ')}"
    return {
        "event": label,
        "ruleId": rule_id,
        "points": row.points,
        "counted": row.counted,
        "reason": row.reason,
    }


def _timeline_event(entry: TimelineEntry, raw: dict[str, Any]) -> dict[str, Any]:
    rule = raw.get("rule") if isinstance(raw.get("rule"), dict) else {}
    groups = rule.get("groups") if isinstance(rule.get("groups"), list) else []
    return {
        "time": iso_z(entry.time),
        "title": entry.description,
        "source": _source(groups, raw),
        "host": entry.host or "",
        "user": _user(raw),
        "eventId": _event_id(raw),
        "ruleId": entry.rule_id or "",
        "severity": wazuh_level_severity(entry.level),
        "raw": raw,
        "linkStrength": entry.link_strength,
        "linkReason": entry.link_reason,
    }


def _source(groups: list[Any], raw: dict[str, Any]) -> str:
    names = {item for item in groups if isinstance(item, str)}
    if "sysmon" in names:
        return "sysmon"
    if "windows_powershell" in names or "powershell" in names:
        return "powershell"
    if "audit" in names:
        return "auditd"
    if "sshd" in names or "syslog" in names:
        return "linux_auth"
    if "windows" in names:
        return "windows_security"
    if isinstance(raw.get("data"), dict) and "srcip" in raw["data"] and "win" not in raw["data"]:
        return "linux_auth"
    event_id = _event_id(raw)
    if event_id == "4104":
        return "powershell"
    return "windows_security"


def _user(raw: dict[str, Any]) -> str:
    for value in (
        _dig(raw, "data", "win", "eventdata", "targetUserName"),
        _dig(raw, "data", "win", "eventdata", "subjectUserName"),
        _dig(raw, "data", "srcuser"),
        _dig(raw, "data", "dstuser"),
    ):
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _event_id(raw: dict[str, Any]) -> str:
    value = _dig(raw, "data", "win", "system", "eventID")
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(raw.get("data"), dict) and "srcip" in raw["data"]:
        return "sshd"
    return ""


def _load_timeline(raw: object) -> TimelineEntry:
    if not isinstance(raw, dict):
        raise ValueError("timeline entry is not an object")
    return TimelineEntry(
        alert_id=str(raw["alertId"]),
        time=parse_time(str(raw["time"])),
        sf_id=raw.get("sfId") if isinstance(raw.get("sfId"), str) else None,
        host=raw.get("host") if isinstance(raw.get("host"), str) else None,
        level=int(raw.get("level") or 0),
        rule_id=raw.get("ruleId") if isinstance(raw.get("ruleId"), str) else None,
        description=str(raw.get("description") or ""),
        link_strength=raw.get("linkStrength") if isinstance(raw.get("linkStrength"), str) else None,
        link_reason=raw.get("linkReason") if isinstance(raw.get("linkReason"), str) else None,
    )


def _load_score(raw: object) -> ScoreRow:
    if not isinstance(raw, dict):
        raise ValueError("score row is not an object")
    return ScoreRow(
        category=raw.get("category") if isinstance(raw.get("category"), str) else None,
        sf_id=raw.get("sfId") if isinstance(raw.get("sfId"), str) else None,
        alert_id=str(raw["alertId"]),
        time=parse_time(str(raw["time"])),
        points=int(raw.get("points") or 0),
        counted=bool(raw.get("counted")),
        reason=str(raw.get("reason") or ""),
    )


def _dig(document: object, *path: str) -> object:
    current = document
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current

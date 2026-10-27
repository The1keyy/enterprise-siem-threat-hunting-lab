"""Live-mode responses. They call Wazuh and never read /fixtures."""

from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.integrations.errors import HuntQueryRejected, WazuhError
from app.integrations.wazuh_api import WazuhApiClient
from app.integrations.wazuh_indexer import (
    SOURCE_FILTERS,
    WazuhIndexerClient,
    resolve_hunt_index,
    validate_hunt_query,
)
from app.services.hunt_catalog import get_hunt
from app.services.hunt_match import events_in_buckets, low_count_buckets
from app.services.incidents import list_incidents
from app.services.mapping import (
    agent_to_host,
    alert_to_timeline,
    indexer_component_status,
    manager_component_status,
)
from app.services.metadata import detection_api_row, load_detection_metadata

# Lab hostname criticality from the project rules. Unknown names stay None.
_LAB_ASSET = {
    "DC01": ("domain_controller", 1.7),
    "UBU01": ("server", 1.3),
    "WAZUH01": ("server", 1.3),
    "WS01": ("workstation", 1.0),
}

_SOURCE_CARDS = (
    {"id": "windows-security", "name": "Windows Security", "optional": False, "windows": True},
    {"id": "sysmon", "name": "Sysmon", "optional": False, "windows": True},
    {"id": "powershell", "name": "PowerShell Operational", "optional": False, "windows": True},
    {
        "id": "ad-security",
        "name": "Active Directory (DC01 Security)",
        "optional": False,
        "windows": True,
    },
    {"id": "linux-auth", "name": "Linux auth", "optional": False, "windows": False},
    {"id": "auditd", "name": "auditd", "optional": False, "windows": False},
    {"id": "suricata", "name": "Suricata", "optional": True, "windows": False},
)

_CLOSED = {"Resolved", "False Positive"}
_AUTH_FAIL = "authentication_failed"
_AUTH_OK = "authentication_success"


def raise_wazuh(exc: WazuhError) -> None:
    status = 400 if isinstance(exc, HuntQueryRejected) else 503
    raise HTTPException(status_code=status, detail=str(exc)) from exc


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _window(hours: int) -> tuple[str, str]:
    end = datetime.now(UTC)
    return _iso(end - timedelta(hours=hours)), _iso(end)


def _label(stamp: str | None) -> str | None:
    if stamp is None or len(stamp) < 16:
        return None
    return stamp[11:16]


def _clients(app: Any) -> tuple[WazuhApiClient, WazuhIndexerClient]:
    return app.state.wazuh_api, app.state.wazuh_indexer


async def live_overview(app: Any, session: Session) -> dict[str, Any]:
    api, indexer = _clients(app)
    start, end = _window(24)
    try:
        aggs = await indexer.aggregations(start, end)
        recent = await indexer.search_alerts(start=start, end=end, size=8, sort_desc=True)
        agents = await api.get_agents()
        rules = await api.get_custom_rules()
        daemons = await api.get_manager_status()
        cluster = await indexer.health()
    except WazuhError as exc:
        raise_wazuh(exc)
    incidents = list_incidents(session, {})
    active = [row for row in incidents if row["status"] not in _CLOSED]
    enabled_rules = sum(1 for rule in rules if rule.get("status") == "enabled")
    monitored = sum(1 for agent in agents if agent.get("status") == "active")
    severity = aggs["by_severity"]
    return {
        "demo": False,
        "generatedAt": end,
        "kpis": {
            "demo": False,
            "activeIncidents": len(active),
            "criticalAlerts24h": severity["critical"],
            "highAlerts24h": severity["high"],
            "monitoredEndpoints": monitored,
            "detectionRulesEnabled": enabled_rules,
            "eventsIngested24h": aggs["events_total"],
            "meanTimeToInvestigateMinutes": None,
        },
        "alertsOverTime": [
            {
                "demo": False,
                "bucketStart": bucket["bucketStart"],
                "label": _label(bucket["bucketStart"]),
                "critical": bucket["critical"],
                "high": bucket["high"],
                "medium": bucket["medium"],
                "low": bucket["low"],
            }
            for bucket in aggs["alerts_over_time"]
        ],
        "alertsBySeverity": [
            {"demo": False, "severity": name, "count": severity[name]}
            for name in ("critical", "high", "medium", "low")
        ],
        "alertsByTactic": [
            {"demo": False, "tactic": row["label"], "count": row["count"]}
            for row in aggs["by_tactic"]
        ],
        "authFailuresOverTime": [
            {
                "demo": False,
                "bucketStart": bucket["bucketStart"],
                "label": _label(bucket["bucketStart"]),
                "count": bucket["count"],
            }
            for bucket in aggs["auth_failures"]
        ],
        "topSourceIps": [_ranked(row) for row in aggs["top_srcip"]],
        "topTargetedUsers": [_ranked(row) for row in aggs["top_users"]],
        # These lists stay empty. A score is not invented from the indexer.
        "topRiskyHosts": [],
        "topRiskyUsers": [],
        "incidents": [_overview_incident(row) for row in active],
        "recentDetections": [_recent(alert_to_timeline(event)) for event in recent["events"]],
        "activeTechniques": _techniques(recent["events"]),
        "health": [
            {
                "demo": False,
                "name": "Wazuh manager",
                "status": manager_component_status(daemons),
                "lastEvent": None,
            },
            {
                "demo": False,
                "name": "Wazuh indexer",
                "status": indexer_component_status(cluster.get("status")),
                "lastEvent": None,
            },
        ],
    }


def _ranked(row: dict[str, Any]) -> dict[str, Any]:
    return {"demo": False, "label": row["label"], "count": row["count"]}


def _overview_incident(row: dict[str, Any]) -> dict[str, Any]:
    hosts = row.get("hosts") or []
    users = row.get("users") or []
    return {
        "demo": False,
        "id": row.get("id"),
        "title": row.get("title"),
        "severity": row.get("severity"),
        "status": row.get("status"),
        "host": hosts[0] if hosts else None,
        "user": users[0] if users else None,
        "lastSeen": row.get("lastSeen"),
    }


def _recent(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "demo": False,
        "id": event["ruleId"],
        "name": event["title"],
        "severity": event["severity"],
        "host": event["host"],
        "time": event["time"],
    }


def _techniques(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: list[str] = []
    for event in events:
        mapped = alert_to_timeline(event)
        for technique_id in mapped["mitreIds"] or []:
            if technique_id not in seen:
                seen.append(technique_id)
    return [{"demo": False, "id": technique_id, "name": None} for technique_id in seen]


async def live_detections(app: Any, enabled: dict[str, bool]) -> list[dict[str, Any]]:
    metadata = load_detection_metadata()
    if not metadata:
        return []
    _api, indexer = _clients(app)
    rule_ids = [str(rule_id) for row in metadata for rule_id in (row.get("wazuh_rule_ids") or [])]
    start, end = _window(24)
    try:
        stats = await indexer.rule_activity(rule_ids, start, end)
    except WazuhError as exc:
        raise_wazuh(exc)
    rows = []
    for data in metadata:
        detection_id = data.get("id")
        override = enabled.get(detection_id) if isinstance(detection_id, str) else None
        rows.append(detection_api_row(data, stats, enabled=override))
    return rows


async def live_sources(app: Any) -> list[dict[str, Any]]:
    _api, indexer = _clients(app)
    start, end = _window(24)
    try:
        stats = await indexer.source_stats(start, end)
    except WazuhError as exc:
        raise_wazuh(exc)
    cards = []
    for spec in _SOURCE_CARDS:
        stat = stats.get(spec["id"]) or {}
        count = stat.get("count") if isinstance(stat.get("count"), int) else 0
        hosts = stat.get("hosts") if isinstance(stat.get("hosts"), list) else []
        volume = stat.get("volume") if isinstance(stat.get("volume"), list) else []
        cards.append(
            {
                "id": spec["id"],
                "name": spec["name"],
                # Healthy means the 24h aggregation counted at least one event.
                "status": "Healthy" if count > 0 else "Offline",
                "optional": spec["optional"],
                "hosts": hosts,
                "agent": ", ".join(hosts) if hosts else None,
                "lastEvent": stat.get("last"),
                "volume": [
                    {"label": _label(bucket.get("bucketStart")), "count": bucket.get("count")}
                    for bucket in volume
                    if isinstance(bucket, dict)
                ],
                "ingestionErrors": None,
                "windowsValidationRequired": spec["windows"],
                "demo": False,
            }
        )
    return cards


async def live_health(app: Any) -> dict[str, Any]:
    api, indexer = _clients(app)
    try:
        daemons = await api.get_manager_status()
        info = await api.get_manager_info()
        agents = await api.get_agents()
        rules = await api.get_custom_rules()
        cluster = await indexer.health()
    except WazuhError as exc:
        raise_wazuh(exc)
    version = info.get("version") if isinstance(info.get("version"), str) else None
    percents = [
        node["disk_used_percent"]
        for node in cluster.get("nodes") or []
        if isinstance(node, dict) and isinstance(node.get("disk_used_percent"), (int, float))
    ]
    checked = _iso(datetime.now(UTC))
    return {
        "demo": False,
        "components": [
            {
                "id": "manager",
                "name": "Wazuh manager",
                "status": manager_component_status(daemons),
                "version": version,
                "lastCheck": checked,
            },
            {
                "id": "indexer",
                "name": "Wazuh indexer",
                "status": indexer_component_status(cluster.get("status")),
                "version": None,
                "lastCheck": checked,
            },
            {
                "id": "dashboard",
                "name": "Wazuh dashboard",
                "status": None,
                "version": None,
                "lastCheck": None,
            },
            {
                "id": "pipeline",
                "name": "Event pipeline",
                "status": None,
                "version": None,
                "lastCheck": None,
            },
        ],
        "pipeline": ["Agent", "Manager", "Indexer"],
        "agents": [_agent_row(agent_to_host(agent)) for agent in agents],
        "diskPercent": max(percents) if percents else None,
        "failedIngestion": None,
        "activeRules": sum(1 for rule in rules if rule.get("status") == "enabled"),
    }


def _agent_row(host: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": host["name"],
        "ip": host["ip"],
        "os": host["os"],
        "status": host["status"],
        "version": host["version"],
        "lastKeepAlive": host["lastKeepAlive"],
        "lastTelemetry": None,
    }


async def live_entity_users(app: Any, session: Session) -> list[dict[str, Any]]:
    _api, indexer = _clients(app)
    start, end = _window(24 * 7)
    try:
        activity = await indexer.entity_activity(start, end)
    except WazuhError as exc:
        raise_wazuh(exc)
    incidents = list_incidents(session, {})
    return [
        _entity_row(user["name"], user["last"], incidents, "users") for user in activity["users"]
    ]


async def live_entity_hosts(app: Any, session: Session) -> list[dict[str, Any]]:
    api, indexer = _clients(app)
    start, end = _window(24 * 7)
    try:
        agents = await api.get_agents()
        activity = await indexer.entity_activity(start, end)
    except WazuhError as exc:
        raise_wazuh(exc)
    incidents = list_incidents(session, {})
    by_name = {item["name"]: item for item in activity["hosts"]}
    rows = []
    seen: set[str] = set()
    for agent in agents:
        host = agent_to_host(agent)
        name = host["name"]
        if not name:
            continue
        seen.add(name)
        stat = by_name.get(name, {})
        rows.append(_entity_row(name, stat.get("last"), incidents, "hosts"))
    for name, stat in by_name.items():
        if name not in seen:
            rows.append(_entity_row(name, stat.get("last"), incidents, "hosts"))
    return rows


def _entity_row(
    name: str,
    last: str | None,
    incidents: list[dict[str, Any]],
    field: str,
) -> dict[str, Any]:
    return {
        "name": name,
        "riskScore": None,
        "incidentIds": [row["id"] for row in incidents if name in (row.get(field) or [])],
        "lastActivity": last,
        "demo": False,
    }


async def live_user_profile(app: Any, session: Session, name: str) -> dict[str, Any]:
    _api, indexer = _clients(app)
    start, end = _window(24 * 7)
    try:
        page = await indexer.search_alerts(
            start=start, end=end, users=[name], size=100, sort_desc=True
        )
    except WazuhError as exc:
        raise_wazuh(exc)
    if not page["events"]:
        raise HTTPException(status_code=404, detail=f"User {name} was not found.")
    events = [alert_to_timeline(alert) for alert in page["events"]]
    incidents = [row for row in list_incidents(session, {}) if name in (row.get("users") or [])]
    return {
        "demo": False,
        "name": name,
        "riskScore": None,
        "incidentIds": [row["id"] for row in incidents],
        "lastActivity": events[0]["time"],
        "sourceIps": _unique(event["srcIp"] for event in events),
        "endpoints": _unique(event["host"] for event in events),
        "detections": _named(events),
        "incidents": [{"id": row["id"], "name": row["title"]} for row in incidents],
        "mitre": _mitre(events),
        "logins": _logins(events),
        "history": [],
        "lines": [],
    }


async def live_host_profile(app: Any, session: Session, name: str) -> dict[str, Any]:
    api, indexer = _clients(app)
    start, end = _window(24 * 7)
    try:
        agents = await api.get_agents()
        page = await indexer.search_alerts(
            start=start, end=end, hosts=[name], size=100, sort_desc=True
        )
    except WazuhError as exc:
        raise_wazuh(exc)
    agent = next((item for item in agents if item.get("name") == name), None)
    if agent is None and not page["events"]:
        raise HTTPException(status_code=404, detail=f"Host {name} was not found.")
    host = agent_to_host(agent) if agent else {"ip": None, "os": None, "status": None}
    events = [alert_to_timeline(alert) for alert in page["events"]]
    incidents = [row for row in list_incidents(session, {}) if name in (row.get("hosts") or [])]
    asset = _LAB_ASSET.get(name)
    processes: dict[str, int] = {}
    for event in events:
        image = event["image"]
        if image:
            processes[image] = processes.get(image, 0) + 1
    return {
        "demo": False,
        "name": name,
        "riskScore": None,
        "incidentIds": [row["id"] for row in incidents],
        "lastActivity": events[0]["time"] if events else None,
        "ip": host.get("ip"),
        "os": host.get("os"),
        "assetType": asset[0] if asset else None,
        "multiplier": asset[1] if asset else None,
        "agentStatus": host.get("status"),
        "users": _unique(event["user"] for event in events),
        "processes": [{"name": image, "count": count} for image, count in processes.items()],
        "detections": _named(events),
        "incidents": [{"id": row["id"], "name": row["title"]} for row in incidents],
        "connections": [
            {
                "time": event["time"],
                "src": event["srcIp"],
                "dst": host.get("ip"),
                "detail": event["title"],
            }
            for event in events
            if event["srcIp"]
        ],
        "history": [],
        "lines": [],
    }


def _unique(values: Any) -> list[str]:
    found: list[str] = []
    for value in values:
        if isinstance(value, str) and value not in found:
            found.append(value)
    return found


def _named(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for event in events:
        rule_id = event["ruleId"]
        if not rule_id or rule_id in seen:
            continue
        seen.add(rule_id)
        rows.append({"id": rule_id, "name": event["title"]})
    return rows


def _mitre(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for event in events:
        for technique_id in event["mitreIds"] or []:
            if technique_id in seen:
                continue
            seen.add(technique_id)
            tactic = (event["tactics"] or [None])[0]
            rows.append({"id": technique_id, "name": None, "tactic": tactic})
    return rows


def _logins(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for event in events:
        groups = set(event["groups"])
        if _AUTH_FAIL in groups:
            result = "fail"
        elif _AUTH_OK in groups:
            result = "success"
        else:
            continue
        rows.append(
            {
                "time": event["time"],
                "host": event["host"],
                "sourceIp": event["srcIp"],
                "logonType": event["logonType"],
                "result": result,
            }
        )
    return rows


async def live_hunt(
    app: Any,
    *,
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
    _api, indexer = _clients(app)
    aggregation = hunt.get("aggregation") if isinstance(hunt.get("aggregation"), dict) else None
    try:
        validate_hunt_query(query, start, end)
        if source and source not in SOURCE_FILTERS:
            raise HuntQueryRejected(f"Unknown hunt source filter: {source}")
        configured = getattr(app.state, "settings", None) or indexer._settings
        index_name = resolve_hunt_index(
            str(hunt.get("index") or ""),
            alerts=configured.wazuh_alerts_index,
            archives=configured.wazuh_archives_index,
        )
        result = await indexer.search_archives(
            query,
            start,
            end,
            host=host,
            user=user,
            source=source,
            index=index_name,
            aggregation=aggregation,
        )
    except WazuhError as exc:
        raise_wazuh(exc)
    buckets = result.get("buckets") or []
    if aggregation:
        buckets = low_count_buckets(buckets, int(aggregation["maxDocCount"]))
    hits = []
    for event in result["events"]:
        mapped = alert_to_timeline(event)
        mapped["incidentId"] = None
        mapped["raw"] = event
        hits.append(mapped)
    if aggregation:
        hits = events_in_buckets(hits, str(aggregation["field"]), buckets)
    return {
        "demo": False,
        "notice": f"Results from {index_name}. VERIFY (4.14.9) field names. Not a lab result.",
        "huntId": hunt_id,
        "hits": hits,
        "buckets": buckets,
    }


def live_mitre() -> dict[str, Any]:
    grouped: dict[str, list[str]] = {}
    for row in load_detection_metadata():
        status = row.get("status") if isinstance(row.get("status"), str) else "NOT TESTED"
        for technique in row.get("mitre") or []:
            if isinstance(technique, dict) and isinstance(technique.get("id"), str):
                grouped.setdefault(technique["id"], []).append(status)
    rank = {
        "NOT TESTED": 0,
        "NEEDS TUNING": 1,
        "SYNTAX VALID": 2,
        "LOGTEST VALID": 3,
        "LAB VALIDATED": 4,
    }

    def best(statuses: list[str]) -> str:
        chosen = statuses[0]
        for status in statuses[1:]:
            if rank.get(status, 0) > rank.get(chosen, 0):
                chosen = status
        return chosen

    return {
        "demo": False,
        "mapped": len(grouped),
        "labValidated": sum(
            1 for statuses in grouped.values() if best(statuses) == "LAB VALIDATED"
        ),
        "layer": {
            "name": "SentinelForge coverage",
            "versions": {"attack": "VERIFY", "navigator": "VERIFY", "layer": "VERIFY"},
            "domain": "enterprise-attack",
            "description": "Built from detections/metadata. Not fixture telemetry.",
            "techniques": [
                {
                    "techniqueID": technique_id,
                    "comment": best(statuses),
                    "score": rank.get(best(statuses), 0),
                }
                for technique_id, statuses in grouped.items()
            ],
        },
    }


def known_detection_ids() -> set[str]:
    return {row["id"] for row in load_detection_metadata() if isinstance(row.get("id"), str)}

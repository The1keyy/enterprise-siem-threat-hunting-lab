"""Map Wazuh documents onto console records.

Missing fields stay None. This module does not fill in lab hostnames, users, or counts.
"""

from typing import Any

from app.core.config import wazuh_level_severity

# VERIFY (4.14.9): rule.groups values that identify a console telemetry source.
_GROUP_SOURCE = (
    ("sysmon", "sysmon"),
    ("windows_powershell", "powershell"),
    ("powershell", "powershell"),
    ("audit", "auditd"),
    ("sshd", "linux_auth"),
    ("syslog", "linux_auth"),
    ("windows", "windows_security"),
)


def _dig(value: Any, *keys: str) -> Any:
    current = value
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return None


def alert_to_timeline(alert: dict[str, Any]) -> dict[str, Any]:
    """One Wazuh alert or archive document → a timeline event."""

    rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
    agent = alert.get("agent") if isinstance(alert.get("agent"), dict) else {}
    level = rule.get("level")
    severity = wazuh_level_severity(level) if isinstance(level, int) and level >= 0 else None
    groups = rule.get("groups") if isinstance(rule.get("groups"), list) else []
    mitre = rule.get("mitre") if isinstance(rule.get("mitre"), dict) else {}
    mitre_ids = mitre.get("id") if isinstance(mitre.get("id"), list) else None
    tactics = mitre.get("tactic") if isinstance(mitre.get("tactic"), list) else None
    return {
        "time": _text(alert.get("timestamp")),
        "title": _text(rule.get("description")),
        "source": _source(groups),
        "host": _text(agent.get("name")),
        "user": _text(_dig(alert, "data", "win", "eventdata", "targetUserName")),
        "eventId": _text(_dig(alert, "data", "win", "system", "eventID")),
        "ruleId": _text(rule.get("id")),
        "severity": severity,
        "srcIp": _text(_dig(alert, "data", "srcip")),
        "image": _text(_dig(alert, "data", "win", "eventdata", "image")),
        "logonType": _text(_dig(alert, "data", "win", "eventdata", "logonType")),
        "mitreIds": [str(item) for item in mitre_ids] if mitre_ids else None,
        "tactics": [str(item) for item in tactics] if tactics else None,
        "groups": [str(item) for item in groups if isinstance(item, str)],
        "raw": alert,
    }


def _source(groups: list[Any]) -> str | None:
    names = {item for item in groups if isinstance(item, str)}
    for group, source in _GROUP_SOURCE:
        if group in names:
            return source
    return None


def agent_to_host(agent: dict[str, Any]) -> dict[str, Any]:
    """One Wazuh agent record → host fields. Status text is translated, not invented."""

    os_info = agent.get("os") if isinstance(agent.get("os"), dict) else {}
    os_name = _text(os_info.get("name"))
    os_version = _text(os_info.get("version"))
    if os_name and os_version:
        os_text = f"{os_name} {os_version}"
    else:
        os_text = os_name or os_version
    status = agent.get("status")
    # VERIFY (4.14.9): agent status strings include active, disconnected, never_connected.
    translated = {
        "active": "active",
        "disconnected": "disconnected",
        "never_connected": "never connected",
    }
    return {
        "name": _text(agent.get("name")),
        "ip": _text(agent.get("ip")),
        "os": os_text,
        "status": translated.get(status) if isinstance(status, str) else None,
        "version": _text(agent.get("version")),
        "lastKeepAlive": _text(agent.get("lastKeepAlive")),
    }


def manager_component_status(daemons: dict[str, Any]) -> str | None:
    """Healthy only when every reported daemon is running. VERIFY (4.14.9) daemon map."""

    values = [
        value
        for key, value in daemons.items()
        if isinstance(key, str) and key.startswith("wazuh-") and isinstance(value, str)
    ]
    if not values:
        return None
    if all(value == "running" for value in values):
        return "Healthy"
    return "Degraded"


def indexer_component_status(cluster_status: str | None) -> str | None:
    # VERIFY (4.14.9): OpenSearch cluster health status values.
    return {"green": "Healthy", "yellow": "Degraded", "red": "Offline"}.get(cluster_status or "")

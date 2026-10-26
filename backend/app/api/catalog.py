"""Read-only demo catalog: overview, detections, MITRE, entities, sources, health."""

from typing import Any

from fastapi import APIRouter, HTTPException, Request

from app.core.config import WAZUH_VERSION, Settings
from app.fixtures_loader import fixture_copy
from app.schemas.api import DetectionPatch

router = APIRouter()
_detection_enabled: dict[str, bool] = {}

_RANK = {
    "NOT TESTED": 0,
    "NEEDS TUNING": 1,
    "SYNTAX VALID": 2,
    "LOGTEST VALID": 3,
    "LAB VALIDATED": 4,
}


def _with_demo(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for row in rows:
        row["demo"] = True
    return rows


def _detection_rows() -> list[dict[str, Any]]:
    rows = fixture_copy("detections.json")["detections"]
    for row in rows:
        override = _detection_enabled.get(row["id"])
        if override is not None:
            row["enabled"] = override
        row["demo"] = True
    return rows


@router.get("/overview")
def overview() -> dict[str, Any]:
    data = fixture_copy("overview.json")
    data.pop("_notice", None)
    data["demo"] = True
    return data


@router.get("/detections")
def detections() -> list[dict[str, Any]]:
    return _detection_rows()


@router.get("/detections/{detection_id}")
def detection(detection_id: str) -> dict[str, Any]:
    for item in _detection_rows():
        if item["id"] == detection_id:
            return item
    raise HTTPException(status_code=404, detail=f"Detection {detection_id} was not found.")


@router.patch("/detections/{detection_id}")
def patch_detection(detection_id: str, body: DetectionPatch) -> dict[str, Any]:
    for item in fixture_copy("detections.json")["detections"]:
        if item["id"] == detection_id:
            _detection_enabled[detection_id] = body.enabled
            item["enabled"] = body.enabled
            item["demo"] = True
            return item
    raise HTTPException(status_code=404, detail=f"Detection {detection_id} was not found.")


def _best(statuses: list[str]) -> str:
    best = statuses[0]
    for status in statuses[1:]:
        if _RANK[status] > _RANK[best]:
            best = status
    return best


@router.get("/mitre/coverage")
def mitre_coverage() -> dict[str, Any]:
    grouped: dict[str, list[str]] = {}
    for detection_row in fixture_copy("detections.json")["detections"]:
        for technique in detection_row["mitre"]:
            grouped.setdefault(technique["id"], []).append(detection_row["status"])
    lab_validated = sum(1 for statuses in grouped.values() if _best(statuses) == "LAB VALIDATED")
    layer = {
        "name": "SentinelForge demo coverage",
        "versions": {"attack": "VERIFY", "navigator": "VERIFY", "layer": "VERIFY"},
        "domain": "enterprise-attack",
        "description": "DEMO DATA — synthetic fixtures for UI development. Not real telemetry.",
        "techniques": [
            {
                "techniqueID": technique_id,
                "comment": _best(statuses),
                "score": _RANK[_best(statuses)],
            }
            for technique_id, statuses in grouped.items()
        ],
    }
    return {
        "demo": True,
        "mapped": len(grouped),
        "labValidated": lab_validated,
        "layer": layer,
    }


@router.get("/entities/users")
def entity_users() -> list[dict[str, Any]]:
    return _with_demo(fixture_copy("entities.json")["users"])


@router.get("/entities/users/{name}")
def entity_user(name: str) -> dict[str, Any]:
    for profile in fixture_copy("entities.json")["userProfiles"]:
        if profile["name"] == name:
            profile["demo"] = True
            return profile
    raise HTTPException(status_code=404, detail=f"User {name} was not found.")


@router.get("/entities/hosts")
def entity_hosts() -> list[dict[str, Any]]:
    return _with_demo(fixture_copy("entities.json")["hosts"])


@router.get("/entities/hosts/{name}")
def entity_host(name: str) -> dict[str, Any]:
    for profile in fixture_copy("entities.json")["hostProfiles"]:
        if profile["name"] == name:
            profile["demo"] = True
            return profile
    raise HTTPException(status_code=404, detail=f"Host {name} was not found.")


@router.get("/sources")
def sources() -> list[dict[str, Any]]:
    return _with_demo(fixture_copy("sources.json")["sources"])


@router.get("/system/health")
def system_health() -> dict[str, Any]:
    data = fixture_copy("health.json")
    data.pop("_notice", None)
    data["demo"] = True
    return data


@router.get("/automation")
def automation(request: Request) -> list[dict[str, Any]]:
    settings: Settings = request.app.state.settings
    workflows = [
        {
            "id": "enrichment",
            "name": "Alert enrichment",
            "trigger": "New alert",
            "steps": [
                "Alert",
                "Extract IP/domain/hash",
                "Local/free enrichment",
                "Attach to incident",
            ],
            "destructive": "Destructive actions: none (approval required)",
            "status": "Not implemented (Step 14+)",
        },
        {
            "id": "escalation",
            "name": "High-risk escalation",
            "trigger": f"Risk ≥ {settings.severity_high} (high band)",
            "steps": [
                "Risk ≥ threshold",
                "Create incident",
                "Set severity",
                "Generate analyst checklist",
            ],
            "destructive": "Destructive actions: none (approval required)",
            "status": "Not implemented (Step 14+)",
        },
        {
            "id": "context",
            "name": "Investigation context",
            "trigger": "Alert opened for investigation",
            "steps": [
                "Alert",
                "Identify entity",
                "Gather related events",
                "Calculate risk",
                "Display context",
            ],
            "destructive": "Destructive actions: none (approval required)",
            "status": "Not implemented (Step 14+)",
        },
    ]
    return _with_demo(workflows)


@router.get("/settings")
def settings_view(request: Request) -> dict[str, Any]:
    settings: Settings = request.app.state.settings
    critical = settings.severity_critical
    high = settings.severity_high
    medium = settings.severity_medium
    return {
        "demo": settings.data_mode == "demo",
        "dataMode": settings.data_mode,
        "apiUrl": f"http://{settings.api_host}:{settings.api_port}",
        "wazuhVersion": WAZUH_VERSION,
        "weights": [
            {"label": "Failed-auth burst", "points": settings.risk_weight_failed_auth},
            {
                "label": "Successful login after failures",
                "points": settings.risk_weight_success_after_failures,
            },
            {"label": "Encoded PowerShell", "points": settings.risk_weight_encoded_powershell},
            {"label": "Privileged group change", "points": settings.risk_weight_privileged_group},
            {"label": "Remote connection", "points": settings.risk_weight_remote_connection},
            {"label": "New account", "points": settings.risk_weight_new_account},
            {"label": "Suspicious command", "points": settings.risk_weight_suspicious_command},
            {"label": "Scheduled task", "points": settings.risk_weight_scheduled_task},
        ],
        "multipliers": [
            {"assetType": "workstation", "multiplier": settings.asset_multiplier_workstation},
            {"assetType": "server", "multiplier": settings.asset_multiplier_server},
            {
                "assetType": "domain_controller",
                "multiplier": settings.asset_multiplier_domain_controller,
            },
        ],
        "bands": [
            {"severity": "critical", "rule": f"{critical} or higher"},
            {"severity": "high", "rule": f"{high} to {critical - 1}"},
            {"severity": "medium", "rule": f"{medium} to {high - 1}"},
            {"severity": "low", "rule": f"1 to {medium - 1}"},
            {"severity": "info", "rule": "0"},
        ],
    }

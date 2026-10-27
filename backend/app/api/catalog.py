"""Read-only demo catalog: overview, detections, MITRE, entities, sources, health."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.config import WAZUH_VERSION, Settings
from app.db import get_db
from app.fixtures_loader import fixture_copy
from app.schemas.api import DetectionPatch
from app.services.live_read import (
    known_detection_ids,
    live_detections,
    live_entity_hosts,
    live_entity_users,
    live_health,
    live_host_profile,
    live_mitre,
    live_overview,
    live_sources,
    live_user_profile,
)
from app.services.risk_view import correlation_settings

router = APIRouter()
_detection_enabled: dict[str, bool] = {}

_RANK = {
    "NOT TESTED": 0,
    "NEEDS TUNING": 1,
    "SYNTAX VALID": 2,
    "LOGTEST VALID": 3,
    "LAB VALIDATED": 4,
}


def _with_demo(rows: list[dict[str, Any]], *, demo: bool = True) -> list[dict[str, Any]]:
    for row in rows:
        row["demo"] = demo
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
async def overview(request: Request, session: Session = Depends(get_db)) -> dict[str, Any]:
    settings: Settings = request.app.state.settings
    if settings.data_mode == "live":
        return await live_overview(request.app, session)
    data = fixture_copy("overview.json")
    data.pop("_notice", None)
    data["demo"] = True
    return data


@router.get("/detections")
async def detections(request: Request) -> list[dict[str, Any]]:
    settings: Settings = request.app.state.settings
    if settings.data_mode == "live":
        return await live_detections(request.app, _detection_enabled)
    return _detection_rows()


@router.get("/detections/{detection_id}")
async def detection(detection_id: str, request: Request) -> dict[str, Any]:
    settings: Settings = request.app.state.settings
    if settings.data_mode == "live":
        for item in await live_detections(request.app, _detection_enabled):
            if item["id"] == detection_id:
                return item
        raise HTTPException(status_code=404, detail=f"Detection {detection_id} was not found.")
    for item in _detection_rows():
        if item["id"] == detection_id:
            return item
    raise HTTPException(status_code=404, detail=f"Detection {detection_id} was not found.")


@router.patch("/detections/{detection_id}")
async def patch_detection(
    detection_id: str,
    body: DetectionPatch,
    request: Request,
) -> dict[str, Any]:
    settings: Settings = request.app.state.settings
    if settings.data_mode == "live":
        if detection_id not in known_detection_ids():
            raise HTTPException(status_code=404, detail=f"Detection {detection_id} was not found.")
        _detection_enabled[detection_id] = body.enabled
        for item in await live_detections(request.app, _detection_enabled):
            if item["id"] == detection_id:
                return item
        raise HTTPException(status_code=404, detail=f"Detection {detection_id} was not found.")
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
def mitre_coverage(request: Request) -> dict[str, Any]:
    settings: Settings = request.app.state.settings
    if settings.data_mode == "live":
        return live_mitre()
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
async def entity_users(
    request: Request,
    session: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    settings: Settings = request.app.state.settings
    if settings.data_mode == "live":
        return await live_entity_users(request.app, session)
    return _with_demo(fixture_copy("entities.json")["users"])


@router.get("/entities/users/{name}")
async def entity_user(
    name: str,
    request: Request,
    session: Session = Depends(get_db),
) -> dict[str, Any]:
    settings: Settings = request.app.state.settings
    if settings.data_mode == "live":
        return await live_user_profile(request.app, session, name)
    for profile in fixture_copy("entities.json")["userProfiles"]:
        if profile["name"] == name:
            profile["demo"] = True
            return profile
    raise HTTPException(status_code=404, detail=f"User {name} was not found.")


@router.get("/entities/hosts")
async def entity_hosts(
    request: Request,
    session: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    settings: Settings = request.app.state.settings
    if settings.data_mode == "live":
        return await live_entity_hosts(request.app, session)
    return _with_demo(fixture_copy("entities.json")["hosts"])


@router.get("/entities/hosts/{name}")
async def entity_host(
    name: str,
    request: Request,
    session: Session = Depends(get_db),
) -> dict[str, Any]:
    settings: Settings = request.app.state.settings
    if settings.data_mode == "live":
        return await live_host_profile(request.app, session, name)
    for profile in fixture_copy("entities.json")["hostProfiles"]:
        if profile["name"] == name:
            profile["demo"] = True
            return profile
    raise HTTPException(status_code=404, detail=f"Host {name} was not found.")


@router.get("/sources")
async def sources(request: Request) -> list[dict[str, Any]]:
    settings: Settings = request.app.state.settings
    if settings.data_mode == "live":
        return await live_sources(request.app)
    return _with_demo(fixture_copy("sources.json")["sources"])


@router.get("/system/health")
async def system_health(request: Request) -> dict[str, Any]:
    settings: Settings = request.app.state.settings
    if settings.data_mode == "live":
        return await live_health(request.app)
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
            "status": "Stretch",
        },
        {
            "id": "escalation",
            "name": "High-risk escalation",
            "trigger": "Incident created or risk band rises",
            "steps": [
                "Incident opened or band rises",
                "Read the detection investigation steps",
                "Write the checklist on the incident",
                "Record an audit log entry",
            ],
            "destructive": "Destructive actions: none. No response action is executed.",
            "status": "Implemented",
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
            "status": "Stretch",
        },
    ]
    return _with_demo(workflows, demo=settings.data_mode == "demo")


@router.get("/settings")
def settings_view(request: Request) -> dict[str, Any]:
    settings: Settings = request.app.state.settings
    model = correlation_settings()
    return {
        "demo": settings.data_mode == "demo",
        "dataMode": settings.data_mode,
        "apiUrl": f"http://{settings.api_host}:{settings.api_port}",
        "wazuhVersion": WAZUH_VERSION,
        "weights": model["weights"],
        "multipliers": model["multipliers"],
        "bands": model["bands"],
        "correlation": model["correlation"],
    }

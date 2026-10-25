"""Read-only demo catalog: overview, detections, MITRE, entities, sources, health."""

from typing import Any

from fastapi import APIRouter, HTTPException

from app.fixtures_loader import fixture_copy

router = APIRouter()

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


@router.get("/overview")
def overview() -> dict[str, Any]:
    data = fixture_copy("overview.json")
    data.pop("_notice", None)
    data["demo"] = True
    return data


@router.get("/detections")
def detections() -> list[dict[str, Any]]:
    return _with_demo(fixture_copy("detections.json")["detections"])


@router.get("/detections/{detection_id}")
def detection(detection_id: str) -> dict[str, Any]:
    for item in fixture_copy("detections.json")["detections"]:
        if item["id"] == detection_id:
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

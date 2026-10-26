"""Load hunting/*.yml into the API shape. No FastAPI imports.

Hunt definitions are repo files. Fixture JSON is generated from this module
so demo mode shows the same text. Nothing here is a lab result.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

NOTICE = (
    "DEMO DATA — synthetic, not real telemetry. "
    "Hunt definitions are copied from hunting/*.yml. "
    "Queries are not lab results."
)


def load_api_hunts(root: Path) -> list[dict[str, Any]]:
    names = _attack_names(root)
    rows: list[dict[str, Any]] = []
    folder = root / "hunting"
    if not folder.is_dir():
        return rows
    for path in sorted(folder.glob("HUNT-*.yml")):
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            rows.append(to_api(loaded, names))
    return rows


def render_fixture(root: Path) -> dict[str, Any]:
    hunts = load_api_hunts(root)
    for hunt in hunts:
        hunt["demo"] = True
    return {"_notice": NOTICE, "hunts": hunts}


def to_api(data: dict[str, Any], names: dict[str, str]) -> dict[str, Any]:
    source = data.get("data_source") if isinstance(data.get("data_source"), dict) else {}
    index = str(source.get("index") or "")
    channel = str(source.get("channel") or "")
    log = str(source.get("log") or "")
    parts = [part for part in (index, channel, log) if part]
    guidance = data.get("investigation_guidance")
    if isinstance(guidance, list):
        text = "\n".join(
            f"{number}. {str(step).strip()}"
            for number, step in enumerate(guidance, start=1)
            if str(step).strip()
        )
    else:
        text = _text(guidance)
    aggregation = _aggregation(data.get("aggregation"))
    mitre = []
    for item in data.get("mitre") or []:
        if isinstance(item, str):
            technique_id = item
            tactic = ""
        elif isinstance(item, dict):
            technique_id = str(item.get("id") or "")
            tactic = str(item.get("tactic") or "")
        else:
            continue
        mitre.append(
            {
                "id": technique_id,
                "name": names.get(technique_id, technique_id),
                "tactic": tactic,
            }
        )
    return {
        "id": str(data.get("id") or ""),
        "name": str(data.get("name") or ""),
        "hypothesis": _text(data.get("hypothesis")),
        "dataSource": " · ".join(parts),
        "index": index,
        "channel": channel,
        "log": log,
        "query": " ".join(_text(data.get("query")).split()),
        "timeWindowDefault": str(data.get("time_window_default") or ""),
        "expectedBehavior": _text(data.get("expected_behavior")),
        "suspiciousBehavior": _text(data.get("suspicious_behavior")),
        "mitre": mitre,
        "relatedDetections": [str(item) for item in data.get("related_detections") or []],
        "differsFromDetections": _text(data.get("differs_from_detections")),
        "investigationGuidance": text,
        "pivotFields": [str(item) for item in data.get("pivot_fields") or []],
        "aggregation": aggregation,
        "status": str(data.get("status") or ""),
    }


def _text(value: object) -> str:
    return str(value or "").strip()


def _aggregation(value: object) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    return {
        "type": str(value.get("type") or ""),
        "field": str(value.get("field") or ""),
        "size": int(value.get("size") or 0),
        "maxDocCount": int(value.get("max_doc_count") or 0),
    }


def _attack_names(root: Path) -> dict[str, str]:
    path = root / "scripts" / "validation" / "attack_techniques.json"
    if not path.is_file():
        return {}
    document = json.loads(path.read_text(encoding="utf-8"))
    techniques = document.get("techniques") if isinstance(document, dict) else None
    if not isinstance(techniques, dict):
        return {}
    names: dict[str, str] = {}
    for key, value in techniques.items():
        if isinstance(value, dict) and isinstance(value.get("name"), str):
            names[str(key)] = value["name"]
    return names

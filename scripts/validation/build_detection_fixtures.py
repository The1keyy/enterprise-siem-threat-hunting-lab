#!/usr/bin/env python3
"""Rebuild fixtures/detections.json from detection metadata, rule XML, and Sigma.

Rows with no metadata file stay as they are. lastTriggered and alertCount stay
null. The notice still starts with DEMO DATA. Rule text for a written detection
is repo content, not a measured alert.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
FIXTURE = REPO / "fixtures" / "detections.json"
META = REPO / "detections" / "metadata"
RULES = REPO / "detections" / "wazuh" / "rules"
NOTICE = (
    "DEMO DATA — synthetic, not real telemetry. "
    "Detection definitions loaded from detections/ are real repo content. "
    "lastTriggered and alertCount are not lab measurements."
)


def main() -> None:
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    rows = document["detections"]
    by_id = {row["id"]: row for row in rows}
    mitre_names = {
        item["id"]: item
        for row in rows
        for item in row.get("mitre", [])
        if isinstance(item, dict) and "id" in item
    }
    rule_text = _rule_xml()
    for path in sorted(META.glob("SF-*.yml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or "id" not in data:
            continue
        detection_id = str(data["id"])
        current = by_id.get(detection_id)
        if current is None:
            continue
        rule_ids = [str(item) for item in data.get("wazuh_rule_ids") or []]
        sigma_path = REPO / str(data.get("sigma_file") or f"detections/sigma/{detection_id}.yml")
        current.update(
            {
                "name": data.get("name", current["name"]),
                "description": data.get("description", current["description"]),
                "severity": data.get("severity", current["severity"]),
                "mitre": [_mitre(item, mitre_names) for item in data.get("mitre") or []],
                "telemetry": list(data.get("telemetry") or current["telemetry"]),
                "wazuhRuleIds": rule_ids,
                "version": str(data.get("version", current["version"])),
                "enabled": True,
                "status": data.get("status", current["status"]),
                "windowsValidationRequired": bool(data.get("windows_validation_required")),
                "falsePositives": data.get("false_positives", current["falsePositives"]),
                "tuningNotes": data.get("tuning_notes", current["tuningNotes"]),
                "testProcedure": data.get("test_procedure", current["testProcedure"]),
                "expectedEvent": data.get("expected_event", current["expectedEvent"]),
                "expectedAlert": data.get("expected_alert", current["expectedAlert"]),
                "observedResult": data.get("observed_result", "NOT YET VALIDATED"),
                "lastTriggered": None,
                "alertCount": None,
                "wazuhRuleXml": _extract_rules(rule_text, rule_ids),
                "sigmaYaml": sigma_path.read_text(encoding="utf-8") if sigma_path.is_file() else current["sigmaYaml"],
                "tuningHistory": [],
                "demo": True,
            }
        )
    document["_notice"] = NOTICE
    FIXTURE.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {FIXTURE.relative_to(REPO)}")


def _rule_xml() -> str:
    parts = [
        path.read_text(encoding="utf-8")
        for path in sorted(RULES.glob("sentinelforge_*.xml"))
    ]
    return "\n".join(parts)


def _extract_rules(xml: str, rule_ids: list[str]) -> str:
    blocks: list[str] = []
    for rule_id in rule_ids:
        match = re.search(rf'<rule id="{re.escape(rule_id)}".*?</rule>', xml, flags=re.S)
        if match:
            blocks.append(match.group(0).strip())
    return "\n\n".join(blocks)


def _mitre(value: object, known: dict[str, dict[str, str]]) -> dict[str, str]:
    technique_id = value if isinstance(value, str) else str(value)
    found = known.get(technique_id)
    if found:
        return {"id": technique_id, "name": found["name"], "tactic": found["tactic"]}
    return {"id": technique_id, "name": technique_id, "tactic": "Unknown"}


if __name__ == "__main__":
    main()

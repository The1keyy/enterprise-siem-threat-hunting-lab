"""Load detection metadata YAML. An empty directory is a real result, not an error."""

from typing import Any

import yaml

from app.core.config import REPO_ROOT


def load_detection_metadata() -> list[dict[str, Any]]:
    folder = REPO_ROOT / "detections" / "metadata"
    rows: list[dict[str, Any]] = []
    if not folder.is_dir():
        return rows
    for path in sorted(folder.glob("SF-*.yml")):
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            rows.append(loaded)
    return rows


def detection_api_row(
    data: dict[str, Any],
    stats: dict[str, dict[str, Any]],
    *,
    enabled: bool | None = None,
) -> dict[str, Any]:
    rule_ids = [str(item) for item in data.get("wazuh_rule_ids") or []]
    count = 0
    last: str | None = None
    for rule_id in rule_ids:
        stat = stats.get(rule_id)
        if not isinstance(stat, dict):
            continue
        stat_count = stat.get("count")
        if isinstance(stat_count, int):
            count += stat_count
        stamp = stat.get("last")
        if isinstance(stamp, str) and (last is None or stamp > last):
            last = stamp
    mitre = data.get("mitre") if isinstance(data.get("mitre"), list) else []
    telemetry = data.get("telemetry") if isinstance(data.get("telemetry"), list) else []
    chosen_enabled = enabled if enabled is not None else data.get("enabled")
    return {
        "id": data.get("id"),
        "name": data.get("name"),
        "description": data.get("description"),
        "severity": data.get("severity"),
        "mitre": mitre,
        "telemetry": telemetry,
        "wazuhRuleIds": rule_ids,
        "version": data.get("version"),
        "enabled": chosen_enabled if isinstance(chosen_enabled, bool) else None,
        "status": data.get("status"),
        "windowsValidationRequired": data.get("windows_validation_required"),
        "falsePositives": data.get("false_positives"),
        "tuningNotes": data.get("tuning_notes"),
        "testProcedure": data.get("test_procedure"),
        "expectedEvent": data.get("expected_event"),
        "expectedAlert": data.get("expected_alert"),
        "observedResult": data.get("observed_result"),
        "lastTriggered": last,
        "alertCount": count if rule_ids else None,
        "wazuhRuleXml": None,
        "sigmaYaml": None,
        "tuningHistory": [],
        "demo": False,
    }

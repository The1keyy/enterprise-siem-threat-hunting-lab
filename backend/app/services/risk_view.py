"""Read-only view of risk_config.yml. The numbers are the correlation model."""

from typing import Any

from app.services.correlation import RiskConfig, load_risk_config

_LABELS = {
    "auth_burst": "Auth burst",
    "success_after_failures": "Success after failures",
    "suspicious_powershell": "Suspicious PowerShell",
    "privileged_group_change": "Privileged group change",
    "new_account": "New account",
    "remote_access": "Remote access",
    "lateral_movement": "Lateral movement",
}


def correlation_settings(config: RiskConfig | None = None) -> dict[str, Any]:
    cfg = config or load_risk_config()
    critical = cfg.band_critical
    high = cfg.band_high
    medium = cfg.band_medium
    return {
        "weights": [
            {"label": _LABELS.get(name, name), "points": points}
            for name, points in cfg.categories.items()
        ],
        "multipliers": [
            {"assetType": name, "multiplier": value} for name, value in cfg.multipliers.items()
        ],
        "bands": [
            {"severity": "critical", "rule": f"{critical} or higher"},
            {"severity": "high", "rule": f"{high} to {critical - 1}"},
            {"severity": "medium", "rule": f"{medium} to {high - 1}"},
            {"severity": "low", "rule": f"1 to {medium - 1}"},
            {"severity": "info", "rule": "0"},
        ],
        "correlation": {
            "windowMinutes": cfg.window_minutes,
            "hostProximityMinutes": cfg.host_proximity_minutes,
            "halfLifeHours": cfg.half_life_hours,
            "sprayMinDistinctUsers": cfg.spray_min_distinct_users,
            "openLevel": cfg.open_level,
            "criticalLevel": cfg.critical_level,
        },
    }

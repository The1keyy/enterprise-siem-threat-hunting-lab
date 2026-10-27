"""Environment configuration. Values come from the repo-root .env file."""

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[3]
BACKEND_DIR = REPO_ROOT / "backend"
APP_VERSION = "0.1.0"
# Pinned target from docs/VERSIONS.md. This is not a live manager check.
WAZUH_VERSION = "4.14.9"
# VERIFY (4.14.9): pattern names on the all-in-one indexer. One definition.
ALERTS_INDEX = "wazuh-alerts-4.x-*"
ARCHIVES_INDEX = "wazuh-archives-4.x-*"
# Wazuh rule.level bands. ADR 0004.
# VERIFY (4.14.9): built-in levels top out at 15. 15 and above map to critical.
WAZUH_LEVEL_LOW_MAX = 6
WAZUH_LEVEL_MEDIUM_MAX = 11
WAZUH_LEVEL_HIGH_MAX = 14


def wazuh_level_severity(level: int) -> str:
    """Map a Wazuh rule level to a console severity label."""

    if level <= WAZUH_LEVEL_LOW_MAX:
        return "low"
    if level <= WAZUH_LEVEL_MEDIUM_MAX:
        return "medium"
    if level <= WAZUH_LEVEL_HIGH_MAX:
        return "high"
    return "critical"

_LIVE_FIELDS = (
    "wazuh_api_url",
    "wazuh_api_user",
    "wazuh_api_password",
    "wazuh_indexer_url",
    "wazuh_indexer_user",
    "wazuh_indexer_password",
)


class Settings(BaseSettings):
    """Fields match `.env.example`. Risk numbers live here, not in the scorer."""

    model_config = SettingsConfigDict(
        env_file=str(REPO_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    data_mode: str = "demo"
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    api_cors_origin: str = "http://localhost:5173"
    database_url: str = "sqlite:///./backend/data/sentinelforge.db"
    console_admin_user: str = "analyst"
    console_admin_password_hash: str = ""
    session_secret: str = ""
    session_ttl_minutes: int = 60

    wazuh_api_url: str = ""
    wazuh_api_user: str = ""
    wazuh_api_password: str = ""
    wazuh_indexer_url: str = ""
    wazuh_indexer_user: str = ""
    wazuh_indexer_password: str = ""
    wazuh_ca_bundle: str = ""
    wazuh_tls_insecure: bool = False
    wazuh_timeout_seconds: float = 10.0
    wazuh_alerts_index: str = ALERTS_INDEX
    wazuh_archives_index: str = ARCHIVES_INDEX
    # VERIFY (4.14.9): authenticate does not return expires_in. 900s is the usual JWT life.
    wazuh_token_ttl_seconds: int = 900
    wazuh_token_refresh_skew_seconds: int = 60

    # Fixture defaults, same numbers as frontend/src/lib/risk.ts.
    # The correlation engine reads risk_config.yml instead.
    risk_weight_failed_auth: int = 15
    risk_weight_success_after_failures: int = 25
    risk_weight_encoded_powershell: int = 30
    risk_weight_privileged_group: int = 35
    risk_weight_remote_connection: int = 20
    risk_weight_new_account: int = 10
    risk_weight_suspicious_command: int = 20
    risk_weight_scheduled_task: int = 15
    asset_multiplier_workstation: float = 1.0
    asset_multiplier_server: float = 1.3
    asset_multiplier_domain_controller: float = 1.7
    severity_critical: int = 100
    severity_high: int = 60
    severity_medium: int = 30
    promote_event_points: int = Field(default=10)

    def resolved_database_url(self) -> str:
        prefix = "sqlite:///"
        if not self.database_url.startswith(prefix):
            return self.database_url
        location = self.database_url[len(prefix) :]
        if location == ":memory:" or location.startswith("/"):
            return self.database_url
        relative = location[2:] if location.startswith("./") else location
        return f"{prefix}{(REPO_ROOT / relative).resolve()}"

    def risk_weights(self) -> dict[str, int]:
        return {
            "failed_auth": self.risk_weight_failed_auth,
            "success_after_failures": self.risk_weight_success_after_failures,
            "encoded_powershell": self.risk_weight_encoded_powershell,
            "privileged_group": self.risk_weight_privileged_group,
            "remote_connection": self.risk_weight_remote_connection,
            "new_account": self.risk_weight_new_account,
            "suspicious_command": self.risk_weight_suspicious_command,
            "scheduled_task": self.risk_weight_scheduled_task,
        }

    def asset_multipliers(self) -> dict[str, float]:
        return {
            "workstation": self.asset_multiplier_workstation,
            "server": self.asset_multiplier_server,
            "domain_controller": self.asset_multiplier_domain_controller,
        }


def get_settings() -> Settings:
    return Settings()


def ensure_live_settings(settings: Settings) -> None:
    """Live mode must fail closed. It never switches to demo data."""

    if settings.data_mode != "live":
        if settings.data_mode != "demo":
            raise RuntimeError("DATA_MODE must be demo or live. Demo data will not be used.")
        return
    missing: list[str] = []
    for name in _LIVE_FIELDS:
        value = str(getattr(settings, name) or "").strip()
        if not value or "<" in value or ">" in value:
            missing.append(name.upper())
    if missing:
        joined = ", ".join(missing)
        raise RuntimeError(
            f"DATA_MODE=live but Wazuh settings are missing: {joined}. Demo data will not be used."
        )

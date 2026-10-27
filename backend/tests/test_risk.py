from fastapi.testclient import TestClient

from app.core.config import Settings
from app.services.risk import final_score, severity_band


def test_score_uses_config_weights_and_multipliers() -> None:
    settings = Settings(risk_weight_failed_auth=21)
    assert settings.risk_weights()["failed_auth"] == 21
    assert settings.asset_multipliers()["domain_controller"] == 1.7
    assert final_score(125, settings.asset_multipliers()["workstation"]) == 125
    assert final_score(70, settings.asset_multipliers()["domain_controller"]) == 119
    assert severity_band(125, settings) == "critical"
    assert severity_band(119, settings) == "critical"


def test_fixture_incidents_match_the_score(analyst: TestClient) -> None:
    rows = analyst.get("/api/incidents").json()
    story = next(row for row in rows if row["riskScore"] == 230)
    detail = analyst.get(f"/api/incidents/{story['id']}").json()
    assert detail["risk"]["subtotal"] == 135
    assert detail["risk"]["multiplier"] == 1.7
    assert detail["risk"]["assetType"] == "domain_controller"
    assert "DC01" in detail["hosts"]
    assert detail["risk"]["final"] == final_score(detail["risk"]["subtotal"], 1.7)
    assert detail["risk"]["final"] == 230
    assert detail["riskScore"] == detail["risk"]["final"]

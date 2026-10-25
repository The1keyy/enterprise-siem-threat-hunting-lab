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
    first = analyst.get("/api/incidents/INC-0001").json()
    assert first["riskScore"] == 125
    assert first["risk"]["subtotal"] == 125
    assert first["risk"]["multiplier"] == 1
    assert first["risk"]["final"] == 125

    domain = analyst.get("/api/incidents/INC-0002").json()
    assert domain["risk"]["assetType"] == "domain_controller"
    assert domain["risk"]["multiplier"] == 1.7
    assert "DC01" in domain["hosts"]
    assert domain["risk"]["final"] == final_score(domain["risk"]["subtotal"], 1.7)
    assert domain["riskScore"] == domain["risk"]["final"]

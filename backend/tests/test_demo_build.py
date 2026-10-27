"""The committed demo incidents are the correlation engine output."""

import json

from app.services.demo_build import INCIDENTS_PATH, build_incidents


def test_committed_demo_incidents_match_the_engine() -> None:
    built = build_incidents()
    on_disk = json.loads(INCIDENTS_PATH.read_text(encoding="utf-8"))
    assert built == on_disk
    story = next(item for item in built["incidents"] if item["risk"]["final"] == 230)
    assert story["severity"] == "critical"
    assert story["risk"]["subtotal"] == 135
    assert story["risk"]["multiplier"] == 1.7
    assert story["risk"]["multiplierHosts"] == ["DC01"]

#!/usr/bin/env python3
"""Write fixtures/incidents.json by running the correlation engine on fixtures/alerts.json.

The input is labeled SYNTHETIC. The attack-story incident is the model score,
not a lab measurement.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "backend"))

from app.services.demo_build import (  # noqa: E402
    INCIDENTS_PATH,
    RISK_PATH,
    build_incidents,
    build_risk_model,
)


def _write(path: Path, document: dict) -> None:
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    incidents = build_incidents()
    _write(INCIDENTS_PATH, incidents)
    _write(RISK_PATH, build_risk_model())
    story = next(item for item in incidents["incidents"] if item["risk"]["final"] == 230)
    print(
        f"{story['id']} score={story['riskScore']} band={story['severity']} "
        f"subtotal={story['risk']['subtotal']} multiplier={story['risk']['multiplier']}"
    )


if __name__ == "__main__":
    main()

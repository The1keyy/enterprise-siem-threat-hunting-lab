#!/usr/bin/env python3
"""Rebuild fixtures/hunts.json from hunting/*.yml.

The notice still starts with DEMO DATA. Definitions are repo content.
Running a hunt here does not query Wazuh and is not a lab result.
"""

from __future__ import annotations

import json
from pathlib import Path

from hunt_files import render_fixture

REPO = Path(__file__).resolve().parents[2]
FIXTURE = REPO / "fixtures" / "hunts.json"


def main() -> None:
    document = render_fixture(REPO)
    FIXTURE.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {FIXTURE.relative_to(REPO)} ({len(document['hunts'])} hunts)")


if __name__ == "__main__":
    main()

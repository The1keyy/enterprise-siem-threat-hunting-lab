"""Print README figures from the repo. Do not hand-edit those numbers.

Usage: python3 scripts/validation/readme_stats.py
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
META = ROOT / "detections" / "metadata"
HUNTS = ROOT / "hunting"
VERSIONS = ROOT / "docs" / "VERSIONS.md"


def field(text: str, name: str) -> str:
    match = re.search(rf"^{name}:\s*(.+)$", text, re.M)
    if not match:
        raise SystemExit(f"missing {name}")
    return match.group(1).strip().strip('"')


def mitre_ids(text: str) -> str:
    block = re.search(r"^mitre:\n((?:  - .+\n)+)", text, re.M)
    if not block:
        return ""
    ids = re.findall(r"^  - (\S+)\s*$", block.group(1), re.M)
    return ", ".join(ids)


def detections() -> list[dict[str, str]]:
    rows = []
    for path in sorted(META.glob("SF-*.yml")):
        text = path.read_text()
        rows.append(
            {
                "id": field(text, "id"),
                "name": field(text, "name"),
                "mitre": mitre_ids(text),
                "status": field(text, "status"),
            }
        )
    return rows


def hunts() -> list[str]:
    found = []
    for path in sorted(HUNTS.glob("HUNT-*.yml")):
        text = path.read_text()
        match = re.search(r"^# Status:\s*(.+)$", text, re.M)
        found.append(match.group(1).strip() if match else "MISSING")
    return found


def version_cell(label: str) -> str:
    text = VERSIONS.read_text()
    for line in text.splitlines():
        if line.startswith(f"| {label} |"):
            cells = [cell.strip() for cell in line.strip("|").split("|")]
            return cells[1].replace("**", "")
    raise SystemExit(f"version row not found: {label}")


def main() -> None:
    rows = detections()
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    print(f"detections {len(rows)}")
    for status in (
        "NOT TESTED",
        "SYNTAX VALID",
        "LOGTEST VALID",
        "LAB VALIDATED",
        "NEEDS TUNING",
    ):
        print(f"status {status} {counts.get(status, 0)}")
    for number in range(15, 20):
        path = META / f"SF-{number:03d}.yml"
        print(f"metadata SF-{number:03d} {'present' if path.exists() else 'absent'}")
    hunt_status = hunts()
    print(f"hunts {len(hunt_status)}")
    for status in sorted(set(hunt_status)):
        print(f"hunt_status {status} {hunt_status.count(status)}")
    print(f"wazuh {version_cell('Wazuh manager / indexer / dashboard')}")
    print(f"node {version_cell('Node.js')}")
    print(f"python {version_cell('Python')}")
    print(f"fastapi {version_cell('FastAPI')}")
    print(f"sqlalchemy {version_cell('SQLAlchemy')}")
    print(f"react {version_cell('React / React DOM')}")
    print()
    print("| ID | Name | ATT&CK | Status |")
    print("|---|---|---|---|")
    for row in rows:
        print(
            f"| {row['id']} | {row['name']} | {row['mitre']} | `{row['status']}` |"
        )


if __name__ == "__main__":
    main()

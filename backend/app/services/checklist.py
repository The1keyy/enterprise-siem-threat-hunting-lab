"""Analyst checklist from the Investigation section of each SF detection note.

No response action is taken. A checkbox is analyst state.
"""

from __future__ import annotations

import hashlib
import re

from app.core.config import REPO_ROOT
from app.services.correlation import CorrelatedIncident

_STEP = re.compile(r"^\d+\.\s+(.*\S)\s*$")


def investigation_steps(sf_id: str) -> list[str]:
    """Numbered lines under `## Investigation`, in document order."""

    path = REPO_ROOT / "docs" / "detections" / f"{sf_id}.md"
    if not path.is_file():
        return []
    steps: list[str] = []
    collecting = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("## "):
            if collecting:
                break
            collecting = line.strip() == "## Investigation"
            continue
        if not collecting:
            continue
        match = _STEP.match(line.strip())
        if match:
            steps.append(match.group(1).strip())
    return steps


def build_checklist(incident: CorrelatedIncident) -> list[dict[str, object]]:
    """Steps in timeline order. The same sentence is kept once, at its first SF."""

    seen_sf: set[str] = set()
    seen_text: set[str] = set()
    items: list[dict[str, object]] = []
    ordered = sorted(incident.timeline, key=lambda item: (item.time, item.alert_id))
    for entry in ordered:
        sf_id = entry.sf_id
        if not sf_id or sf_id in seen_sf:
            continue
        seen_sf.add(sf_id)
        for step in investigation_steps(sf_id):
            key = _key(step)
            if key in seen_text:
                continue
            seen_text.add(key)
            items.append(
                {
                    "id": _item_id(key),
                    "sfId": sf_id,
                    "text": step,
                    "checked": False,
                }
            )
    return items


def preserve_checks(
    fresh: list[dict[str, object]],
    previous: list[dict[str, object]] | None,
) -> list[dict[str, object]]:
    checked = {
        str(item.get("id"))
        for item in (previous or [])
        if item.get("checked") is True and item.get("id")
    }
    merged: list[dict[str, object]] = []
    for item in fresh:
        copy = dict(item)
        if str(copy.get("id")) in checked:
            copy["checked"] = True
        merged.append(copy)
    return merged


def _key(text: str) -> str:
    return " ".join(text.casefold().split())


def _item_id(key: str) -> str:
    digest = hashlib.sha256(key.encode()).hexdigest()[:10]
    return f"CHK-{digest}"

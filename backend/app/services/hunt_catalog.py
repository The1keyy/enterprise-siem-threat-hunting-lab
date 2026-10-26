"""Saved hunts from hunting/*.yml. Both data modes use these files, not fixtures."""

from __future__ import annotations

import importlib.util
from functools import cache
from typing import Any

from app.core.config import REPO_ROOT


@cache
def _files() -> Any:
    path = REPO_ROOT / "scripts" / "validation" / "hunt_files.py"
    spec = importlib.util.spec_from_file_location("sentinelforge_hunt_files", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def list_hunt_definitions() -> list[dict[str, Any]]:
    return _files().load_api_hunts(REPO_ROOT)


def get_hunt(hunt_id: str) -> dict[str, Any] | None:
    for hunt in list_hunt_definitions():
        if hunt["id"] == hunt_id:
            return hunt
    return None

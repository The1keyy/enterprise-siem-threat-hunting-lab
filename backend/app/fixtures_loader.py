"""Load the shared /fixtures JSON. Every file must carry the demo notice."""

import copy
import json
from functools import lru_cache
from typing import Any

from app.core.config import REPO_ROOT

FIXTURE_NOTICE = "DEMO DATA — synthetic, not real telemetry"


@lru_cache
def load_fixture(name: str) -> dict[str, Any]:
    path = REPO_ROOT / "fixtures" / name
    data = json.loads(path.read_text(encoding="utf-8"))
    notice = data.get("_notice")
    if not isinstance(notice, str) or not notice.startswith("DEMO DATA"):
        raise RuntimeError(f"{name} is missing the DEMO DATA notice")
    return data


def fixture_copy(name: str) -> dict[str, Any]:
    return copy.deepcopy(load_fixture(name))

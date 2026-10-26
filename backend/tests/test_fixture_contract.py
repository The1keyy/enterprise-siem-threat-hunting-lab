"""Shared /fixtures JSON must match the backend schemas and the frontend types."""

import json

from app.core.config import REPO_ROOT
from app.schemas.contract import FIXTURE_MODELS


def test_fixture_files_match_the_api_contract() -> None:
    folder = REPO_ROOT / "fixtures"
    names = sorted(path.name for path in folder.glob("*.json"))
    assert names == sorted(FIXTURE_MODELS)
    for name, model in FIXTURE_MODELS.items():
        payload = json.loads((folder / name).read_text(encoding="utf-8"))
        parsed = model.model_validate(payload)
        assert parsed.notice.startswith("DEMO DATA")

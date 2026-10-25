"""Auth gate for /api. Live mode returns 503 and does not serve fixtures."""

from fastapi import Depends, HTTPException, Request

from app.core.auth import current_username
from app.core.config import Settings


def require_demo_user(request: Request, username: str = Depends(current_username)) -> str:
    settings: Settings = request.app.state.settings
    if settings.data_mode == "live":
        raise HTTPException(
            status_code=503,
            detail="Wazuh integration not implemented yet (Step 8)",
        )
    return username

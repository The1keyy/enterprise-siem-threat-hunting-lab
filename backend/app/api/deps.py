"""Auth gate for /api. Live routes talk to Wazuh themselves and do not serve fixtures."""

from fastapi import Depends

from app.core.auth import current_username


def require_demo_user(username: str = Depends(current_username)) -> str:
    return username

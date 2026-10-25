from fastapi import APIRouter, Request

from app.core.config import APP_VERSION, Settings

router = APIRouter()


@router.get("/health")
def health(request: Request) -> dict[str, str]:
    settings: Settings = request.app.state.settings
    return {"status": "ok", "mode": settings.data_mode, "version": APP_VERSION}

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.api.deps import require_demo_user
from app.core.config import Settings
from app.db import get_db
from app.schemas.api import HuntRunIn
from app.services.hunts import list_hunts, run_hunt
from app.services.live_read import live_hunt

router = APIRouter()


@router.get("/hunts")
def get_hunts(
    session: Session = Depends(get_db),
    _user: str = Depends(require_demo_user),
) -> list[dict]:
    return list_hunts(session)


@router.post("/hunts/run")
async def post_hunt(
    body: HuntRunIn,
    request: Request,
    session: Session = Depends(get_db),
    _user: str = Depends(require_demo_user),
) -> dict:
    settings: Settings = request.app.state.settings
    if settings.data_mode == "live":
        return await live_hunt(
            request.app,
            session,
            hunt_id=body.id,
            query=body.query,
            host=body.host,
            user=body.user,
            source=body.source,
            start=body.start,
            end=body.end,
        )
    return run_hunt(
        session,
        body.id,
        body.query,
        body.host,
        body.user,
        body.source,
        body.start,
        body.end,
    )

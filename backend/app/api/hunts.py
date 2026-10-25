from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import require_demo_user
from app.db import get_db
from app.schemas.api import HuntRunIn
from app.services.hunts import list_hunts, run_hunt

router = APIRouter()


@router.get("/hunts")
def get_hunts(
    session: Session = Depends(get_db),
    _user: str = Depends(require_demo_user),
) -> list[dict]:
    return list_hunts(session)


@router.post("/hunts/run")
def post_hunt(
    body: HuntRunIn,
    session: Session = Depends(get_db),
    _user: str = Depends(require_demo_user),
) -> dict:
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

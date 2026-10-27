"""Live correlation. Demo mode can report status and will not read fixtures."""

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.db import get_db
from app.services.correlation_cycle import run_cycle, status_view

router = APIRouter()


@router.get("/correlation/status")
def correlation_status(
    request: Request,
    session: Session = Depends(get_db),
) -> dict:
    settings: Settings = request.app.state.settings
    return status_view(session, settings)


@router.post("/correlation/run")
async def correlation_run(
    request: Request,
    session: Session = Depends(get_db),
) -> dict:
    settings: Settings = request.app.state.settings
    if settings.data_mode != "live":
        raise HTTPException(
            status_code=409,
            detail="Correlation runs only in live mode. Demo fixtures are not used.",
        )
    indexer = getattr(request.app.state, "wazuh_indexer", None)
    if indexer is None:
        raise HTTPException(status_code=503, detail="Wazuh indexer client is not configured.")
    lock = request.app.state.correlation_lock
    async with lock:
        return await run_cycle(session, indexer, settings)

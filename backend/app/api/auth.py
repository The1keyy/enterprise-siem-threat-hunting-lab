from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from app.core.auth import (
    clear_session_cookie,
    create_token,
    current_username,
    set_session_cookie,
    verify_password,
)
from app.core.config import Settings
from app.db import get_db
from app.schemas.api import LoginIn
from app.services.incidents import write_audit

router = APIRouter(prefix="/auth")


@router.post("/login")
def login(
    body: LoginIn,
    request: Request,
    response: Response,
    session: Session = Depends(get_db),
) -> dict[str, object]:
    settings: Settings = request.app.state.settings
    ok = (
        body.username == settings.console_admin_user
        and verify_password(body.password, settings.console_admin_password_hash)
    )
    write_audit(
        session,
        actor=body.username or "anonymous",
        action="login",
        target=body.username or "anonymous",
        details={"result": "success" if ok else "failure"},
        dry_run=False,
    )
    session.commit()
    if not ok:
        from fastapi import HTTPException

        raise HTTPException(status_code=401, detail="Invalid username or password")
    set_session_cookie(response, settings, create_token(settings, body.username))
    return {"username": body.username, "demo": settings.data_mode == "demo"}


@router.post("/logout")
def logout(response: Response) -> dict[str, bool]:
    clear_session_cookie(response)
    return {"ok": True}


@router.get("/me")
def me(request: Request, username: str = Depends(current_username)) -> dict[str, object]:
    settings: Settings = request.app.state.settings
    return {"username": username, "demo": settings.data_mode == "demo"}

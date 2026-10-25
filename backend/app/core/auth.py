"""Single lab-admin session. The cookie holds a short-lived JWT."""

from datetime import UTC, datetime, timedelta

import bcrypt
import jwt
from fastapi import HTTPException, Request, Response
from jwt import InvalidTokenError

from app.core.config import Settings

COOKIE_NAME = "sentinelforge_session"
_ALGORITHM = "HS256"


def verify_password(password: str, password_hash: str) -> bool:
    if not password_hash:
        return False
    raw = password.encode()
    if len(raw) > 72:
        return False
    try:
        return bcrypt.checkpw(raw, password_hash.encode())
    except ValueError:
        return False


def create_token(settings: Settings, username: str) -> str:
    if not settings.session_secret:
        raise HTTPException(status_code=500, detail="SESSION_SECRET is not set")
    expires = datetime.now(UTC) + timedelta(minutes=settings.session_ttl_minutes)
    return jwt.encode(
        {"sub": username, "exp": expires},
        settings.session_secret,
        algorithm=_ALGORITHM,
    )


def read_username(settings: Settings, token: str) -> str | None:
    if not settings.session_secret:
        return None
    try:
        payload = jwt.decode(token, settings.session_secret, algorithms=[_ALGORITHM])
    except InvalidTokenError:
        return None
    subject = payload.get("sub")
    if not isinstance(subject, str) or not subject:
        return None
    return subject


def set_session_cookie(response: Response, settings: Settings, token: str) -> None:
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=settings.session_ttl_minutes * 60,
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(COOKIE_NAME, path="/")


def current_username(request: Request) -> str:
    settings: Settings = request.app.state.settings
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    username = read_username(settings, token)
    if username is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return username

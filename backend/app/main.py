"""SentinelForge API. Demo mode serves /fixtures. Live mode does not."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.api.auth import router as auth_router
from app.api.health import router as health_router
from app.api.router import router as api_router
from app.core.config import APP_VERSION, Settings, ensure_live_settings, get_settings
from app.core.logging import configure_logging
from app.db import init_database

logger = logging.getLogger("sentinelforge")


class RequestLogMiddleware(BaseHTTPMiddleware):
    """Log the method, path, and status only. Never the body, cookies, or headers."""

    async def dispatch(self, request: Request, call_next) -> Response:  # noqa: ANN001
        response = await call_next(request)
        logger.info(
            "request method=%s path=%s status=%s",
            request.method,
            request.url.path,
            response.status_code,
        )
        return response


@asynccontextmanager
async def _lifespan(app: FastAPI):
    configure_logging()
    settings: Settings = app.state.settings
    logger.info("starting SentinelForge mode=%s", settings.data_mode)
    init_database(settings)
    yield


def create_app(settings: Settings | None = None) -> FastAPI:
    active = settings or get_settings()
    ensure_live_settings(active)
    app = FastAPI(title="SentinelForge", version=APP_VERSION, lifespan=_lifespan)
    app.state.settings = active
    app.add_middleware(RequestLogMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[active.api_cors_origin],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(health_router)
    app.include_router(auth_router)
    app.include_router(api_router)
    return app


app = create_app()

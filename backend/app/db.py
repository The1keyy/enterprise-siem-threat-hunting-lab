"""SQLite engine. Schema changes go through Alembic."""

from collections.abc import Iterator
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import BACKEND_DIR, Settings

SessionLocal = sessionmaker(autoflush=False, autocommit=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def _enable_sqlite_foreign_keys(engine: Engine) -> None:
    @event.listens_for(engine, "connect")
    def _set_pragma(dbapi_connection, _connection_record) -> None:  # noqa: ANN001
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


def upgrade_database(url: str) -> None:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")


def init_database(settings: Settings) -> None:
    url = settings.resolved_database_url()
    if url.startswith("sqlite:///"):
        location = url[len("sqlite:///") :]
        if location != ":memory:":
            Path(location).parent.mkdir(parents=True, exist_ok=True)
    upgrade_database(url)
    engine = create_engine(url, connect_args={"check_same_thread": False})
    _enable_sqlite_foreign_keys(engine)
    SessionLocal.configure(bind=engine)
    if settings.data_mode == "demo":
        from app.services.seed import seed_demo

        seed_demo()


def get_db() -> Iterator[Session]:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()

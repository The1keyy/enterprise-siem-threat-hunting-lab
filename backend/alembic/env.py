"""Alembic environment. The database URL comes from Settings unless overridden."""

import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import create_engine, pool

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from app.core.config import get_settings  # noqa: E402
from app.db import Base  # noqa: E402
from app.models import tables as _tables  # noqa: E402, F401

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def database_url() -> str:
    configured = config.get_main_option("sqlalchemy.url") or ""
    location = configured.removeprefix("sqlite:///")
    if configured.startswith("sqlite:///") and (location.startswith("/") or location == ":memory:"):
        return configured
    return get_settings().resolved_database_url()


def run_migrations_offline() -> None:
    context.configure(url=database_url(), target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    url = database_url()
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    connectable = create_engine(url, poolclass=pool.NullPool, connect_args=connect_args)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

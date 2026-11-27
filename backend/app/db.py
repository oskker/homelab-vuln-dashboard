"""Database engine, session setup and schema migrations."""

from datetime import UTC, datetime
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, event, inspect
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import StaticPool

MIGRATIONS_DIR = Path(__file__).parent / "migrations"
# The schema that version 0.1 created with create_all(), before migrations existed.
LEGACY_REVISION = "0001"


class Base(DeclarativeBase):
    pass


def utcnow() -> datetime:
    """The current time as naive UTC, which is how every time is stored."""
    return datetime.now(UTC).replace(tzinfo=None)


def make_engine(url: str) -> Engine:
    if url.startswith("sqlite"):
        kwargs: dict = {"connect_args": {"check_same_thread": False}}
        if ":memory:" in url:
            # One shared connection so an in-memory database survives across sessions (tests).
            kwargs["poolclass"] = StaticPool
        engine = create_engine(url, **kwargs)

        @event.listens_for(engine, "connect")
        def _enable_foreign_keys(dbapi_connection, _record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        return engine

    return create_engine(url, pool_pre_ping=True)


def migration_config() -> Config:
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    return config


def upgrade_database(engine: Engine) -> None:
    """Bring the schema up to date. Safe to run on every start.

    A database from version 0.1 has the tables but no migration record, so it is marked
    as being at the first revision and then upgraded like any other. Existing scan data
    is kept.
    """
    config = migration_config()
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        tables = set(inspect(connection).get_table_names())
        if "alembic_version" not in tables and "scans" in tables:
            command.stamp(config, LEGACY_REVISION)
        command.upgrade(config, "head")

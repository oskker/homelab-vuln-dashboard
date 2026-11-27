"""Alembic environment. Migrations run from app.db.upgrade_database at startup, which
hands over an open connection; there is no alembic.ini and no offline mode."""

from alembic import context

from app import models  # noqa: F401 - registers every table on Base.metadata
from app.db import Base

connection = context.config.attributes.get("connection")
if connection is None:
    raise RuntimeError("Run migrations through app.db.upgrade_database().")

context.configure(connection=connection, target_metadata=Base.metadata)
with context.begin_transaction():
    context.run_migrations()

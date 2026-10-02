"""Alembic environment configuration.

Uses a synchronous psycopg2 connection for migrations (Alembic's standard
approach — asyncpg is for the application runtime, not migrations).

The database URL is read from intriqo.config.settings.sync_database_url so
the same .env file drives both the app and Alembic.
"""

from __future__ import annotations

import sys
from pathlib import Path
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# ── Make sure src/ is on the path so our package is importable ───────────────
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from intriqo.config import get_settings  # noqa: E402
from intriqo.db.base import Base  # noqa: E402
import intriqo.db.models  # noqa: E402, F401 — registers all models with Base.metadata

# ── Alembic Config object — gives access to alembic.ini ──────────────────────
config = context.config

# ── Override the SQLAlchemy URL from our settings ────────────────────────────
config.set_main_option("sqlalchemy.url", get_settings().sync_database_url)

# ── Set up Python logging from alembic.ini ────────────────────────────────────
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# ── Autogenerate support — point at our declarative Base ─────────────────────
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (emit SQL to stdout, no live DB connection)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode (live DB connection)."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

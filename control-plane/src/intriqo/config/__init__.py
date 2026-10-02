"""Application configuration loaded from environment variables.

Import the module-level ``settings`` singleton wherever settings are needed:

    from intriqo.config import settings
"""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Top-level settings for the Intriqo control plane.

    All values are read from environment variables (case-insensitive).
    Provide a .env file for local development.
    """

    # ── Application ──────────────────────────────────────────────────────────
    app_name: str = "Intriqo Control Plane"
    app_env: str = "development"
    debug: bool = False

    # ── Database ─────────────────────────────────────────────────────────────
    # asyncpg driver for async SQLAlchemy; use psycopg2 URL for Alembic sync migrations
    database_url: str = "postgresql+asyncpg://intriqo:intriqo_dev@localhost:5432/intriqo"

    # Synchronous URL used by Alembic's env.py (psycopg2 / plain psycopg)
    @property
    def sync_database_url(self) -> str:
        """Return a synchronous database URL for Alembic by swapping the driver."""
        return self.database_url.replace(
            "postgresql+asyncpg://", "postgresql+psycopg2://"
        ).replace(
            "postgresql+aiosqlite://", "sqlite:///"
        )

    # ── JWT / Auth ───────────────────────────────────────────────────────────
    jwt_secret_key: str = "CHANGE_ME_IN_PRODUCTION"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30

    # ── Engine client ────────────────────────────────────────────────────────
    engine_event_endpoint: str = "http://localhost:8080/events"

    # ── Agents ───────────────────────────────────────────────────────────────
    agent_service_url: str = "http://localhost:8001"

    # ── CORS ─────────────────────────────────────────────────────────────────
    cors_allow_origins: list[str] = ["http://localhost:5173"]  # Vite dev server

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }


@lru_cache
def get_settings() -> Settings:
    """Return the cached Settings singleton."""
    return Settings()


# Convenience singleton — prefer get_settings() in FastAPI dependencies
# so it remains testable/overridable.
settings = get_settings()

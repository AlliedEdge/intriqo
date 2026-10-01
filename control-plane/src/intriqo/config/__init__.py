"""Application configuration loaded from environment variables."""

from __future__ import annotations

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
    database_url: str = "postgresql+asyncpg://intriqo:intriqo_dev@localhost:5432/intriqo"

    # ── Redis ────────────────────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"

    # ── JWT / Auth ───────────────────────────────────────────────────────────
    jwt_secret_key: str = "CHANGE_ME_IN_PRODUCTION"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30

    # ── Engine client ────────────────────────────────────────────────────────
    engine_grpc_address: str = "localhost:50051"
    engine_event_endpoint: str = "http://localhost:8080/events"

    # ── Agents ───────────────────────────────────────────────────────────────
    agent_service_url: str = "http://localhost:8001"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


# Module-level singleton — import this wherever settings are needed.
settings = Settings()

"""FastAPI application factory."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware


def create_app() -> FastAPI:
    """Create and configure the Intriqo control-plane FastAPI application.

    Architectural constraints:
    - Route handlers are thin: validate input, call a service, return a response.
    - Authentication/authorisation is enforced via FastAPI dependencies, not middleware alone.
    - No business logic or SQL inside route handlers.
    """
    app = FastAPI(
        title="Intriqo Control Plane",
        description="Security Operations Centre API — detection events, incidents, investigations",
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173"],  # Vite dev server
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Register routers ──────────────────────────────────────────────────────
    # Routers are registered here as they are implemented.
    # from intriqo.api.routers import health, events, incidents, investigations
    # app.include_router(health.router, prefix="/health", tags=["health"])
    # app.include_router(events.router, prefix="/api/v1/events", tags=["events"])

    @app.get("/health", tags=["health"])
    async def health_check() -> dict:
        return {"status": "ok", "service": "intriqo-control-plane"}

    return app


app = create_app()

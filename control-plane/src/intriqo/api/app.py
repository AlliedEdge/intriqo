"""FastAPI application factory."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from intriqo.config import get_settings

logger = logging.getLogger("intriqo.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan — startup and shutdown."""
    settings = get_settings()
    logger.info("Intriqo Control Plane starting up (env=%s)", settings.app_env)
    yield
    logger.info("Intriqo Control Plane shutting down")


def create_app() -> FastAPI:
    """Create and configure the Intriqo control-plane FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title="Intriqo Control Plane",
        description=(
            "Security Operations Centre API — "
            "detection events, incidents, investigations, findings"
        ),
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # ── CORS ──────────────────────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allow_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Error handlers ────────────────────────────────────────────────────────

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        """Return HTTPException details inside the standard {"error": {...}} envelope.

        Route handlers raise HTTPException(detail={"error": {"code": ..., "message": ...}}).
        Without this handler FastAPI would wrap that in {"detail": ...}, which doesn't
        match the contract. We unwrap it so callers always see {"error": {...}}.
        """
        detail = exc.detail
        if isinstance(detail, dict) and "error" in detail:
            content = detail  # already {"error": {"code": ..., "message": ...}}
        else:
            content = {"error": {"code": "HTTP_ERROR", "message": str(detail)}}
        headers = getattr(exc, "headers", None) or {}
        return JSONResponse(
            status_code=exc.status_code,
            content=content,
            headers=headers,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """Return Pydantic v2 validation errors in the standard envelope.

        Pydantic v2 includes the original exception object inside error['ctx']['error'].
        That object is not JSON-serialisable, so we sanitise each error dict before
        building the response.
        """
        def _sanitise(err: dict) -> dict:
            """Remove non-serialisable values (e.g. exception instances) from one error dict."""
            safe = {}
            for k, v in err.items():
                if k == "input" and request.url.path.startswith("/api/v1/auth/"):
                    continue
                if k == "ctx" and isinstance(v, dict):
                    safe[k] = {ck: str(cv) if not isinstance(cv, (str, int, float, bool, type(None))) else cv
                                for ck, cv in v.items()}
                elif isinstance(v, (str, int, float, bool, list, dict, type(None))):
                    safe[k] = v
                else:
                    safe[k] = str(v)
            return safe

        errors = [_sanitise(e) for e in exc.errors()]
        first = errors[0] if errors else {}
        field = " → ".join(str(loc) for loc in first.get("loc", []))
        msg = first.get("msg", "Validation error")
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            content={
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": f"{field}: {msg}" if field else msg,
                    "details": errors,
                }
            },
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": "An unexpected error occurred",
                }
            },
        )

    # ── Health check ──────────────────────────────────────────────────────────
    @app.get("/health", tags=["health"])
    async def health_check() -> dict[str, Any]:
        """Basic health check — reports application status and DB connectivity."""
        db_status = "unknown"
        try:
            from sqlalchemy import text

            from intriqo.db.session import get_engine
            engine = get_engine()
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            db_status = "ok"
        except Exception:
            db_status = "error"

        overall = "ok" if db_status == "ok" else "degraded"
        return {
            "status": overall,
            "service": "intriqo-control-plane",
            "version": "0.1.0",
            "checks": {"database": db_status},
        }

    # ── Register v1 routers ───────────────────────────────────────────────────
    from intriqo.api.v1.router import v1_router  # noqa: PLC0415
    app.include_router(v1_router)

    return app


app = create_app()

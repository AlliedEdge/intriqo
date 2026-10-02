"""Master v1 router — aggregates all domain routers."""

from __future__ import annotations

from fastapi import APIRouter

from intriqo.api.v1 import events, incidents, agent_tasks, findings, auth

v1_router = APIRouter(prefix="/api/v1")

v1_router.include_router(auth.router,        tags=["auth"])
v1_router.include_router(events.router,      tags=["events"])
v1_router.include_router(incidents.router,   tags=["incidents"])
v1_router.include_router(agent_tasks.router, tags=["agent-tasks"])
v1_router.include_router(findings.router,    tags=["findings"])

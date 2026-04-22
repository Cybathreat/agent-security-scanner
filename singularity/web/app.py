"""
FastAPI application factory for the Singularity web dashboard.

Provides REST API endpoints and WebSocket for real-time scan progress.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger

from .api import attack_surface, config, findings, modules, quality_gate, replay, scans
from .db import init_db
from .scan_manager import scan_manager
from .ws import scan_progress


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Initialize resources on startup, cleanup on shutdown."""
    import asyncio

    # Initialize database
    await init_db()

    # Set event loop for scan manager
    scan_manager.set_loop(asyncio.get_running_loop())

    logger.info("Web dashboard initialized")

    yield

    logger.info("Web dashboard shutting down")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="Singularity",
        description="Web dashboard API for the Singularity",
        version="0.2.0",
        lifespan=lifespan,
    )

    # CORS — allow frontend dev server (configurable via SINGULARITY_CORS_ORIGINS env var)
    _cors_env = os.environ.get("SINGULARITY_CORS_ORIGINS", "")
    if _cors_env:
        _allowed_origins = [o.strip() for o in _cors_env.split(",") if o.strip()]
    else:
        _allowed_origins = ["http://localhost:3000", "http://127.0.0.1:3000"]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=_allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Health check
    @app.get("/api/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": "0.2.0"}

    # Mount REST API routers
    app.include_router(scans.router, prefix="/api")
    app.include_router(findings.router, prefix="/api")
    app.include_router(modules.router, prefix="/api")
    app.include_router(quality_gate.router, prefix="/api")
    app.include_router(config.router, prefix="/api")
    app.include_router(replay.router, prefix="/api")
    app.include_router(attack_surface.router, prefix="/api")

    # Mount WebSocket router
    app.include_router(scan_progress.router, prefix="/ws")

    return app


# Default app instance
app = create_app()
"""FastAPI application factory and startup for Cyber Sentinel."""

from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from cyber_sentinel.utils.logging import get_logger, setup_logging

logger = get_logger(__name__)

# Global singletons
_pipeline: Optional[object] = None
_repo: Optional[object] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    global _pipeline, _repo
    setup_logging()
    logger.info("Starting Cyber Sentinel API...")

    try:
        from cyber_sentinel.database.database import initialize_database, get_session
        from cyber_sentinel.database.repository import AlertRepository
        from cyber_sentinel.detection.pipeline import SentinelPipeline

        initialize_database()
        _repo = AlertRepository(session_factory=get_session)
        _pipeline = SentinelPipeline(db_repo=_repo)
        logger.info("Pipeline and database initialized")
    except Exception as exc:
        logger.error("Startup error: %s", exc)
        # Still start — /health will show models_loaded = False

    yield

    logger.info("Shutting down Cyber Sentinel API...")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="Cyber Sentinel API",
        description=(
            "Intelligent Cyber Threat and Network Anomaly Detection Sentinel. "
            "Converts raw network telemetry into explainable, auditable, "
            "policy-driven security decisions."
        ),
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # CORS — allow all origins for development
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Global exception handler
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.error("Unhandled exception: %s %s — %s", request.method, request.url, exc)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(exc)},
        )

    # Include routes
    from cyber_sentinel.api.routes import router
    app.include_router(router, prefix="")

    return app


# Module-level app instance
app = create_app()

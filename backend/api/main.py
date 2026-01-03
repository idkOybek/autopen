"""Main FastAPI application."""

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from loguru import logger

from backend.api.routes import health, scans, targets, blacklist, reports
from backend.core.config import settings
from backend.core.logging import setup_logging


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application lifespan events."""
    # Startup
    setup_logging()
    logger.info(f"Starting {settings.APP_NAME} v{settings.VERSION}")
    logger.info(f"Debug mode: {settings.DEBUG}")
    logger.info(f"Database URL: {settings.async_database_url.split('@')[1]}")

    # Auto-recover interrupted scans
    try:
        from backend.core.recovery import recovery_manager
        recovered_scans = await recovery_manager.recover_interrupted_scans()
        if recovered_scans:
            logger.info(f"Recovered {len(recovered_scans)} interrupted scans")
    except Exception as e:
        logger.error(f"Failed to recover interrupted scans: {e}")

    yield

    # Shutdown
    logger.info("Shutting down application")


# Create FastAPI application
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description="Automated Penetration Testing Platform",
    docs_url=f"{settings.API_PREFIX}/docs",
    redoc_url=f"{settings.API_PREFIX}/redoc",
    openapi_url=f"{settings.API_PREFIX}/openapi.json",
    lifespan=lifespan,
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure GZip compression
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Include routers
app.include_router(
    health.router,
    prefix=settings.API_PREFIX,
    tags=["Health"]
)

app.include_router(
    scans.router,
    prefix=f"{settings.API_PREFIX}/scans",
    tags=["Scans"]
)

app.include_router(
    targets.router,
    prefix=f"{settings.API_PREFIX}/targets",
    tags=["Targets"]
)

app.include_router(
    blacklist.router,
    prefix=f"{settings.API_PREFIX}/blacklist",
    tags=["Blacklist"]
)

app.include_router(
    reports.router,
    prefix=f"{settings.API_PREFIX}/reports",
    tags=["Reports"]
)


@app.get("/")
async def root() -> dict:
    """Root endpoint."""
    return {
        "app": settings.APP_NAME,
        "version": settings.VERSION,
        "docs": f"{settings.API_PREFIX}/docs",
    }

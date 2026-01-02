"""Health check endpoints."""

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.deps import get_session
from backend.core.config import settings

router = APIRouter()


@router.get("/health")
async def health_check(db: AsyncSession = Depends(get_session)) -> dict:
    """
    Health check endpoint.

    Checks:
    - API is running
    - Database connection
    """
    try:
        # Check database connection
        await db.execute(text("SELECT 1"))
        db_status = "healthy"
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"

    return {
        "status": "healthy" if db_status == "healthy" else "unhealthy",
        "app_name": settings.APP_NAME,
        "version": settings.VERSION,
        "database": db_status,
    }


@router.get("/ping")
async def ping() -> dict:
    """Simple ping endpoint."""
    return {"message": "pong"}

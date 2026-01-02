#!/usr/bin/env python3
"""Initialize the database."""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from loguru import logger
from sqlalchemy import text

from backend.db.session import async_session_maker, engine
from backend.db.base import Base
from backend.core.config import settings


async def init_db() -> None:
    """Initialize database tables."""
    logger.info("Starting database initialization...")
    logger.info(f"Database URL: {settings.async_database_url.split('@')[1]}")

    try:
        # Test connection
        async with async_session_maker() as session:
            result = await session.execute(text("SELECT 1"))
            logger.info("✓ Database connection successful")

        # Create tables
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            logger.info("✓ Database tables created")

        logger.info("Database initialization completed successfully!")

    except Exception as e:
        logger.error(f"Database initialization failed: {str(e)}")
        raise


if __name__ == "__main__":
    asyncio.run(init_db())

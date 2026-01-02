"""API dependencies."""

from typing import AsyncGenerator

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.session import get_db


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Get database session dependency."""
    async for session in get_db():
        yield session

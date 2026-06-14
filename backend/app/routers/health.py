"""
Health Check Router
Simple endpoint to verify the API is running.
"""

from fastapi import APIRouter

from app.config import get_settings

router = APIRouter(tags=["Health"])
settings = get_settings()


@router.get("/health")
async def health_check():
    """Returns API health status and version info."""
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
    }

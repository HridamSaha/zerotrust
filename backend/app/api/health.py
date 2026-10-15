"""Health check routes."""

from fastapi import APIRouter

from app import __version__
from app.config import get_settings
from app.database import check_database_connection
from app.schemas.health import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
def health_check() -> HealthResponse:
    """Return application and database readiness status."""
    settings = get_settings()
    db_up = check_database_connection()
    return HealthResponse(
        status="ok" if db_up else "degraded",
        app=settings.app_name,
        version=__version__,
        environment=settings.app_env,
        database="up" if db_up else "down",
        detail=None if db_up else "PostgreSQL connection failed",
    )

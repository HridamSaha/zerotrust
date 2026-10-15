"""FastAPI application entrypoint."""

from contextlib import asynccontextmanager
import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.router import api_router
from app.config import get_settings
from app.database import SessionLocal
from app.services.seed import seed_demo_accounts

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    settings = get_settings()
    from app.database import Base, engine
    from app.models import audit, ml_meta, session, user  # noqa: F401
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        seed_demo_accounts(db, settings)
    except Exception:
        logger.exception("Demo account seeding failed")
        db.rollback()
    finally:
        db.close()
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    application = FastAPI(
        title=settings.app_name,
        version=__version__,
        description=(
            "Zero-Trust Access Control Framework using continuous risk assessment. "
            "Academic research prototype — not a production security product."
        ),
        lifespan=lifespan,
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    application.include_router(api_router, prefix=settings.api_prefix)

    @application.get("/", tags=["root"])
    def root():
        return {
            "name": settings.app_name,
            "version": __version__,
            "docs": "/docs",
            "health": f"{settings.api_prefix}/health",
            "dashboard": "/dashboard/",
        }

    frontend_dist = Path(__file__).resolve().parents[2] / "frontend" / "dist"
    if frontend_dist.exists():
        from fastapi.staticfiles import StaticFiles
        application.mount("/dashboard", StaticFiles(directory=str(frontend_dist), html=True), name="frontend")

    return application


app = create_app()

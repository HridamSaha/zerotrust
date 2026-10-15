"""Aggregate API routers."""

from fastapi import APIRouter

from app.api import auth, health, sessions

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(sessions.router)
api_router.include_router(sessions.admin_router)
api_router.include_router(sessions.audit_router)

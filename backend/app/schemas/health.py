"""Health check response schema."""

from typing import Literal, Optional

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    app: str
    version: str
    environment: str
    database: Literal["up", "down"]
    detail: Optional[str] = Field(
        default=None,
        description="Human-readable note when the service is degraded.",
    )

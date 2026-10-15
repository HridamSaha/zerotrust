"""Append-oriented audit log ORM model.

Integrity notes (Phase 2):
- Application code should only INSERT audit rows; no update/delete endpoints will be exposed.
- Database role permissions can further restrict UPDATE/DELETE in production.
- This is NOT claimed as cryptographic tamper-proof storage.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func, JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base

JSON_TYPE = JSON().with_variant(JSONB, "postgresql")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor_user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    session_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("sessions.id", ondelete="SET NULL"), nullable=True, index=True
    )
    action: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    resource: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    outcome: Mapped[str] = mapped_column(String(64), nullable=False)
    detail: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON_TYPE, nullable=True)
    # Optional hash chain field for future integrity experiments; unused in Phase 2.
    prev_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    entry_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )

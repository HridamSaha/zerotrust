"""Session, event, risk assessment, and access-decision ORM models."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
    JSON,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

JSON_TYPE = JSON().with_variant(JSONB, "postgresql")

from app.database import Base

if TYPE_CHECKING:
    from app.models.user import User


class UserSession(Base):
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_uid: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="active", index=True
    )  # active | restricted | step_up_required | revoked | expired
    device_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    device_trusted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    client_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    context_label: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    current_risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    current_risk_level: Mapped[str] = mapped_column(String(32), default="low", nullable=False)
    # Used with JWT claims so revoked sessions cannot keep using old tokens.
    session_token_version: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_activity_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoke_reason: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    user: Mapped["User"] = relationship("User", back_populates="sessions")
    events: Mapped[List["SessionEvent"]] = relationship(
        "SessionEvent",
        back_populates="session",
        cascade="all, delete-orphan",
        order_by="SessionEvent.created_at",
    )
    risk_assessments: Mapped[List["RiskAssessment"]] = relationship(
        "RiskAssessment",
        back_populates="session",
        cascade="all, delete-orphan",
    )
    access_decisions: Mapped[List["AccessDecision"]] = relationship(
        "AccessDecision",
        back_populates="session",
        cascade="all, delete-orphan",
    )


class SessionEvent(Base):
    __tablename__ = "session_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_id: Mapped[int] = mapped_column(
        ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    resource_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    resource_sensitivity: Mapped[int] = mapped_column(Integer, default=1, nullable=False)  # 1–5
    success: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_simulated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    payload: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON_TYPE, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )

    session: Mapped[UserSession] = relationship("UserSession", back_populates="events")
    risk_assessment: Mapped[Optional["RiskAssessment"]] = relationship(
        "RiskAssessment",
        back_populates="trigger_event",
        uselist=False,
    )


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_id: Mapped[int] = mapped_column(
        ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    trigger_event_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("session_events.id", ondelete="SET NULL"), nullable=True
    )
    model_version_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("model_versions.id", ondelete="SET NULL"), nullable=True
    )
    model_name: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_probability: Mapped[float] = mapped_column(Float, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)  # 0–100
    risk_level: Mapped[str] = mapped_column(String(32), nullable=False)
    feature_snapshot: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON_TYPE, nullable=True)
    explanation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    inference_latency_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )

    session: Mapped[UserSession] = relationship("UserSession", back_populates="risk_assessments")
    trigger_event: Mapped[Optional[SessionEvent]] = relationship(
        "SessionEvent", back_populates="risk_assessment"
    )

    @property
    def probability(self) -> float:
        return self.raw_probability
    access_decision: Mapped[Optional["AccessDecision"]] = relationship(
        "AccessDecision",
        back_populates="risk_assessment",
        uselist=False,
    )


class AccessDecision(Base):
    __tablename__ = "access_decisions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_id: Mapped[int] = mapped_column(
        ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    risk_assessment_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("risk_assessments.id", ondelete="SET NULL"), nullable=True
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    resource_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    resource_sensitivity: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    decision: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True
    )  # allow | allow_limited | step_up | deny | revoke
    policy_reason: Mapped[str] = mapped_column(Text, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(32), nullable=False)
    authorized_by_rbac: Mapped[bool] = mapped_column(Boolean, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )

    session: Mapped[UserSession] = relationship("UserSession", back_populates="access_decisions")
    risk_assessment: Mapped[Optional[RiskAssessment]] = relationship(
        "RiskAssessment", back_populates="access_decision"
    )

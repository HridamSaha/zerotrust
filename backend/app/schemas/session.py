"""Extended session and risk-related Pydantic schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import AliasChoices, BaseModel, Field


# ---------------------------------------------------------------------------
# Session schemas (original)
# ---------------------------------------------------------------------------

class SessionCreateRequest(BaseModel):
    device_id: Optional[str] = Field(default=None, max_length=128)
    device_trusted: bool = False
    context_label: Optional[str] = Field(default=None, max_length=128)


class SessionResponse(BaseModel):
    id: int
    session_uid: str
    user_id: int
    status: str
    device_id: Optional[str]
    device_trusted: bool
    client_ip: Optional[str]
    user_agent: Optional[str]
    context_label: Optional[str]
    current_risk_score: float
    current_risk_level: str
    session_token_version: int
    created_at: datetime
    last_activity_at: datetime
    revoked_at: Optional[datetime]
    revoke_reason: Optional[str]

    model_config = {"from_attributes": True}


class SessionCreateResponse(BaseModel):
    session: SessionResponse
    access_token: str
    token_type: str = "bearer"
    expires_in_minutes: int


class SessionListResponse(BaseModel):
    items: List[SessionResponse]
    total: int


class SessionRevokeRequest(BaseModel):
    reason: str = Field(default="user_requested", max_length=255)


# ---------------------------------------------------------------------------
# Session event schemas (Phase 7)
# ---------------------------------------------------------------------------

class SessionEventRequest(BaseModel):
    """Submit a session event to trigger risk assessment."""
    event_type: str = Field(
        default="resource_access",
        max_length=64,
        description="Event type (resource_access, auth_failure, admin_action, …)",
    )
    resource_name: Optional[str] = Field(default=None, max_length=255)
    resource_sensitivity: int = Field(
        default=1, ge=1, le=5,
        description="Resource sensitivity 1 (low) to 5 (critical)",
    )
    success: bool = True
    is_simulated: bool = Field(
        default=False,
        description="Mark as simulated demo event — never treat as real security signal",
    )
    payload: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Additional context (unusual_context, device_trusted, …)",
    )


class RiskAssessmentResponse(BaseModel):
    """Result of a risk assessment."""
    risk_score: float
    risk_level: str
    decision: str
    policy_reason: str
    model_name: str
    probability: float
    inference_latency_ms: float
    explanation: str
    auto_revoked: bool
    session_status: str
    risk_assessment_id: int
    access_decision_id: int


class SessionEventResponse(BaseModel):
    """Response after submitting a session event."""
    event_id: int
    session_uid: str
    event_type: str
    resource_name: Optional[str]
    resource_sensitivity: int
    success: bool
    is_simulated: bool
    created_at: datetime
    risk_assessment: Optional[RiskAssessmentResponse] = None

    model_config = {"from_attributes": True}


class SessionRiskHistoryItem(BaseModel):
    id: int
    risk_score: float
    risk_level: str
    model_name: str
    probability: float = Field(default=0.0, validation_alias=AliasChoices("raw_probability", "probability"))
    explanation: Optional[str] = None
    inference_latency_ms: Optional[float] = None
    created_at: datetime

    model_config = {"from_attributes": True, "populate_by_name": True}


class SessionRiskResponse(BaseModel):
    session_uid: str
    current_risk_score: float
    current_risk_level: str
    session_status: str
    history: List[SessionRiskHistoryItem]
    total_assessments: int


class AccessDecisionItem(BaseModel):
    id: int
    decision: str
    policy_reason: str
    risk_score: float
    risk_level: str
    resource_name: Optional[str]
    resource_sensitivity: int
    authorized_by_rbac: bool
    created_at: datetime

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Audit log schemas (Phase 7)
# ---------------------------------------------------------------------------

class AuditLogItem(BaseModel):
    id: int
    actor_user_id: Optional[int]
    session_id: Optional[int]
    action: str
    resource: Optional[str]
    outcome: str
    detail: Optional[str]
    evidence: Optional[Dict[str, Any]]
    created_at: datetime

    model_config = {"from_attributes": True}


class AuditLogListResponse(BaseModel):
    items: List[AuditLogItem]
    total: int
    page: int
    page_size: int


# ---------------------------------------------------------------------------
# Simulation schemas
# ---------------------------------------------------------------------------

class SimulationRequest(BaseModel):
    session_uid: str
    anomaly_type: str = Field(
        default="burst_traffic",
        description="Type: credential_stuffing | privilege_escalation | burst_traffic | unusual_context | benign",
    )
    event_count: int = Field(default=5, ge=1, le=50)


class SimulationResponse(BaseModel):
    session_uid: str
    events_simulated: int
    anomaly_type: str
    final_risk_score: float
    final_risk_level: str
    final_status: str
    assessments: List[RiskAssessmentResponse]

"""Session management routes — Phase 7 complete implementation.

Endpoints:
  POST /api/sessions                        create session
  GET  /api/sessions                        list user sessions
  GET  /api/sessions/{session_uid}          get session detail
  POST /api/sessions/{session_uid}/events   submit event -> risk assess
  GET  /api/sessions/{session_uid}/risk     risk history
  POST /api/sessions/{session_uid}/revoke   revoke session

  GET  /api/audit-logs                      paginated audit log (admin/analyst)
  GET  /api/admin/sessions/overview         admin overview
"""

from __future__ import annotations

from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.core.deps import get_current_user, require_roles, user_role_names
from app.core.security import create_access_token
from app.database import get_db
from app.models.audit import AuditLog
from app.models.session import (
    AccessDecision,
    RiskAssessment,
    SessionEvent,
    UserSession,
)
from app.models.user import User
from app.schemas.session import (
    AccessDecisionItem,
    AuditLogItem,
    AuditLogListResponse,
    RiskAssessmentResponse,
    SessionCreateRequest,
    SessionCreateResponse,
    SessionEventRequest,
    SessionEventResponse,
    SessionListResponse,
    SessionResponse,
    SessionRiskHistoryItem,
    SessionRiskResponse,
    SessionRevokeRequest,
    SimulationRequest,
    SimulationResponse,
)
from app.services import session_service
from app.services import risk as risk_service

router = APIRouter(prefix="/sessions", tags=["sessions"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _session_response(session: UserSession) -> SessionResponse:
    return SessionResponse.model_validate(session)


def _resolve_session(
    db: Session,
    *,
    current_user: User,
    session_uid: str,
    allow_privileged_read: bool = False,
) -> UserSession:
    session = session_service.get_session_for_user(
        db, user=current_user, session_uid=session_uid
    )
    if session is not None:
        return session

    if allow_privileged_read:
        roles = {r.name.lower() for r in current_user.roles}
        if roles.intersection({"admin", "analyst"}):
            session = (
                db.query(UserSession).filter(UserSession.session_uid == session_uid).first()
            )
            if session is not None:
                return session

    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")


# ---------------------------------------------------------------------------
# Session CRUD
# ---------------------------------------------------------------------------

@router.post("", response_model=SessionCreateResponse, status_code=status.HTTP_201_CREATED)
def create_user_session(
    body: SessionCreateRequest,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> SessionCreateResponse:
    session = session_service.create_session(
        db,
        user=current_user,
        device_id=body.device_id,
        device_trusted=body.device_trusted,
        client_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        context_label=body.context_label,
    )
    token = create_access_token(
        subject=str(current_user.id),
        roles=user_role_names(current_user),
        token_version=current_user.token_version,
        session_uid=session.session_uid,
        session_token_version=session.session_token_version,
        settings=settings,
    )
    return SessionCreateResponse(
        session=_session_response(session),
        access_token=token,
        expires_in_minutes=settings.access_token_expire_minutes,
    )


@router.get("", response_model=SessionListResponse)
def list_sessions(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    include_revoked: bool = Query(default=False),
) -> SessionListResponse:
    items = session_service.list_sessions_for_user(
        db, user=current_user, include_revoked=include_revoked
    )
    return SessionListResponse(items=[_session_response(s) for s in items], total=len(items))


@router.get("/{session_uid}", response_model=SessionResponse)
def get_session(
    session_uid: str,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> SessionResponse:
    session = _resolve_session(
        db,
        current_user=current_user,
        session_uid=session_uid,
        allow_privileged_read=True,
    )
    return _session_response(session)


@router.post("/{session_uid}/revoke", response_model=SessionResponse)
def revoke_session(
    session_uid: str,
    body: SessionRevokeRequest,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> SessionResponse:
    session = session_service.get_session_for_user(
        db, user=current_user, session_uid=session_uid
    )
    if session is None:
        roles = {r.name.lower() for r in current_user.roles}
        if "admin" in roles:
            session = (
                db.query(UserSession).filter(UserSession.session_uid == session_uid).first()
            )
        if session is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")

    revoked = session_service.revoke_session(
        db, session=session, actor=current_user, reason=body.reason
    )
    return _session_response(revoked)


# ---------------------------------------------------------------------------
# Session events + risk assessment  (Phase 7 core)
# ---------------------------------------------------------------------------

@router.post(
    "/{session_uid}/events",
    response_model=SessionEventResponse,
    status_code=status.HTTP_201_CREATED,
)
def submit_session_event(
    session_uid: str,
    body: SessionEventRequest,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> SessionEventResponse:
    """Submit a session event and trigger continuous risk assessment.

    The response includes the full risk assessment result:
    probability, risk_score, risk_level, policy decision, explanation.

    If the session was auto-revoked by policy, auto_revoked=true is set.
    """
    session = _resolve_session(db, current_user=current_user, session_uid=session_uid)

    if session.status == "revoked":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Session has been revoked; no further events accepted",
        )

    # Build payload with context signals.
    payload = body.payload or {}
    payload.setdefault("unusual_context", False)
    payload.setdefault("device_trusted", session.device_trusted)
    if body.is_simulated:
        payload["_simulated"] = True

    # Create event record.
    event = SessionEvent(
        session_id=session.id,
        event_type=body.event_type,
        resource_name=body.resource_name,
        resource_sensitivity=body.resource_sensitivity,
        success=body.success,
        is_simulated=body.is_simulated,
        payload=payload,
    )
    db.add(event)
    db.flush()  # Get event.id.

    # Run risk assessment pipeline.
    try:
        risk_result = risk_service.assess_session_event(
            db,
            session=session,
            event=event,
            user=current_user,
            resource_name=body.resource_name,
            resource_sensitivity=body.resource_sensitivity,
            user_roles=[r.name for r in current_user.roles],
        )
        risk_response = RiskAssessmentResponse(**risk_result)
    except Exception as exc:
        import logging
        logging.getLogger(__name__).error("Risk assessment failed: %s", exc, exc_info=True)
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Risk assessment error: {exc}",
        )

    # Reload event after commit.
    db.refresh(event)

    return SessionEventResponse(
        event_id=event.id,
        session_uid=session_uid,
        event_type=event.event_type,
        resource_name=event.resource_name,
        resource_sensitivity=event.resource_sensitivity,
        success=event.success,
        is_simulated=event.is_simulated,
        created_at=event.created_at,
        risk_assessment=risk_response,
    )


@router.get("/{session_uid}/events")
def list_session_events(
    session_uid: str,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    limit: int = Query(default=100, ge=1, le=500),
) -> dict:
    """Return historical events submitted for this session."""
    session = _resolve_session(
        db,
        current_user=current_user,
        session_uid=session_uid,
        allow_privileged_read=True,
    )
    events = (
        db.query(SessionEvent)
        .filter(SessionEvent.session_id == session.id)
        .order_by(SessionEvent.created_at.desc())
        .limit(limit)
        .all()
    )
    return {
        "session_uid": session_uid,
        "items": [
            {
                "id": ev.id,
                "event_type": ev.event_type,
                "resource_name": ev.resource_name,
                "resource_sensitivity": ev.resource_sensitivity,
                "success": ev.success,
                "is_simulated": ev.is_simulated,
                "payload": ev.payload,
                "created_at": ev.created_at,
            }
            for ev in events
        ],
        "total": len(events),
    }


@router.post("/simulate", response_model=SimulationResponse)
def simulate_session_events(
    body: SimulationRequest,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> SimulationResponse:
    """Inject a burst of simulated events to demonstrate dynamic risk changes and policy reactions."""
    session = _resolve_session(
        db,
        current_user=current_user,
        session_uid=body.session_uid,
        allow_privileged_read=True,
    )

    templates = {
        "credential_stuffing": [
            {"event_type": "auth_failure", "resource_name": "auth_gateway", "resource_sensitivity": 3, "success": False, "payload": {"unusual_context": True, "device_trusted": False}},
            {"event_type": "auth_failure", "resource_name": "auth_gateway", "resource_sensitivity": 3, "success": False, "payload": {"unusual_context": True, "device_trusted": False}},
            {"event_type": "rapid_retry", "resource_name": "auth_gateway", "resource_sensitivity": 4, "success": False, "payload": {"unusual_context": True, "device_trusted": False}},
        ],
        "privilege_escalation": [
            {"event_type": "role_probe", "resource_name": "admin_system_config", "resource_sensitivity": 5, "success": False, "payload": {"unusual_context": True, "device_trusted": False}},
            {"event_type": "unauthorized_export", "resource_name": "security_audit_vault", "resource_sensitivity": 5, "success": False, "payload": {"unusual_context": True, "device_trusted": False}},
        ],
        "burst_traffic": [
            {"event_type": "api_burst", "resource_name": f"resource_{i}", "resource_sensitivity": 2, "success": True, "payload": {"requests_per_minute": 150.0}}
            for i in range(10)
        ],
        "unusual_context": [
            {"event_type": "foreign_ip_access", "resource_name": "portal_dashboard", "resource_sensitivity": 3, "success": True, "payload": {"unusual_context": True, "device_trusted": False}},
        ],
        "benign": [
            {"event_type": "page_view", "resource_name": "dashboard_home", "resource_sensitivity": 1, "success": True, "payload": {"unusual_context": False, "device_trusted": True}},
            {"event_type": "file_read", "resource_name": "public_docs.pdf", "resource_sensitivity": 1, "success": True, "payload": {"unusual_context": False, "device_trusted": True}},
        ],
    }

    event_pool = templates.get(body.anomaly_type, templates["benign"])
    assessments_list = []

    for idx in range(body.event_count):
        tmpl = event_pool[idx % len(event_pool)]
        payload = dict(tmpl.get("payload", {}))
        payload["_simulated"] = True
        payload["anomaly_type"] = body.anomaly_type

        event = SessionEvent(
            session_id=session.id,
            event_type=tmpl["event_type"],
            resource_name=tmpl.get("resource_name"),
            resource_sensitivity=tmpl.get("resource_sensitivity", 1),
            success=tmpl.get("success", True),
            is_simulated=True,
            payload=payload,
        )
        db.add(event)
        db.flush()

        risk_res = risk_service.assess_session_event(
            db,
            session=session,
            event=event,
            user=current_user,
            resource_name=event.resource_name,
            resource_sensitivity=event.resource_sensitivity,
            user_roles=[r.name for r in current_user.roles],
        )
        assessments_list.append(RiskAssessmentResponse(**risk_res))

    db.refresh(session)
    return SimulationResponse(
        session_uid=session.session_uid,
        events_simulated=body.event_count,
        anomaly_type=body.anomaly_type,
        final_risk_score=session.current_risk_score,
        final_risk_level=session.current_risk_level,
        final_status=session.status,
        assessments=assessments_list,
    )


@router.get("/{session_uid}/risk", response_model=SessionRiskResponse)
def get_session_risk(
    session_uid: str,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    limit: int = Query(default=50, ge=1, le=200),
) -> SessionRiskResponse:
    """Return current risk score and assessment history for a session."""
    session = _resolve_session(
        db,
        current_user=current_user,
        session_uid=session_uid,
        allow_privileged_read=True,
    )

    assessments = (
        db.query(RiskAssessment)
        .filter(RiskAssessment.session_id == session.id)
        .order_by(RiskAssessment.created_at.desc())
        .limit(limit)
        .all()
    )

    history = [SessionRiskHistoryItem.model_validate(ra) for ra in assessments]
    return SessionRiskResponse(
        session_uid=session_uid,
        current_risk_score=session.current_risk_score,
        current_risk_level=session.current_risk_level,
        session_status=session.status,
        history=history,
        total_assessments=len(assessments),
    )


@router.get("/{session_uid}/decisions", response_model=list[AccessDecisionItem])
def get_session_decisions(
    session_uid: str,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    limit: int = Query(default=50, ge=1, le=200),
) -> list[AccessDecisionItem]:
    """Return access decision history for a session."""
    session = _resolve_session(
        db,
        current_user=current_user,
        session_uid=session_uid,
        allow_privileged_read=True,
    )
    decisions = (
        db.query(AccessDecision)
        .filter(AccessDecision.session_id == session.id)
        .order_by(AccessDecision.created_at.desc())
        .limit(limit)
        .all()
    )
    return [AccessDecisionItem.model_validate(d) for d in decisions]


# Protected resource demo (verifies revocation enforcement).
@router.get("/{session_uid}/protected-ping")
def protected_ping(
    session_uid: str,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict:
    """Demo protected resource bound to the JWT session claim."""
    claims = getattr(current_user, "_token_claims", {}) or {}
    claim_sid = claims.get("sid")
    if claim_sid != session_uid:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token is not bound to this session",
        )

    session = session_service.get_session_for_user(
        db, user=current_user, session_uid=session_uid
    )
    if session is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")

    claim_stv = claims.get("stv")
    if claim_stv is not None and int(claim_stv) != session.session_token_version:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session token has been revoked",
        )
    if session.status == "revoked":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Session has been revoked",
        )

    return {
        "ok": True,
        "session_uid": session.session_uid,
        "status": session.status,
        "current_risk_score": session.current_risk_score,
        "current_risk_level": session.current_risk_level,
        "user_id": current_user.id,
        "message": "Protected resource accessible",
    }


# ---------------------------------------------------------------------------
# Admin endpoints
# ---------------------------------------------------------------------------

admin_router = APIRouter(prefix="/admin", tags=["admin"])


@admin_router.get("/sessions/overview")
def admin_session_overview(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(require_roles("admin", "analyst"))],
) -> dict:
    total = db.query(UserSession).count()
    active = db.query(UserSession).filter(UserSession.status == "active").count()
    revoked = db.query(UserSession).filter(UserSession.status == "revoked").count()
    restricted = db.query(UserSession).filter(UserSession.status == "restricted").count()
    step_up = db.query(UserSession).filter(UserSession.status == "step_up_required").count()
    high_risk = (
        db.query(UserSession)
        .filter(UserSession.current_risk_level.in_(["high", "critical"]))
        .count()
    )
    return {
        "total": total,
        "active": active,
        "revoked": revoked,
        "restricted": restricted,
        "step_up_required": step_up,
        "high_risk_sessions": high_risk,
    }


# ---------------------------------------------------------------------------
# Audit logs endpoint
# ---------------------------------------------------------------------------

audit_router = APIRouter(prefix="/audit-logs", tags=["audit"])


@audit_router.get("", response_model=AuditLogListResponse)
def list_audit_logs(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(require_roles("admin", "analyst"))],
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    action: Optional[str] = Query(default=None, description="Filter by action type"),
    outcome: Optional[str] = Query(default=None, description="Filter by outcome"),
) -> AuditLogListResponse:
    """Return paginated audit log entries (admin/analyst only)."""
    q = db.query(AuditLog).order_by(AuditLog.created_at.desc())
    if action:
        q = q.filter(AuditLog.action == action)
    if outcome:
        q = q.filter(AuditLog.outcome == outcome)

    total = q.count()
    offset = (page - 1) * page_size
    items = q.offset(offset).limit(page_size).all()

    return AuditLogListResponse(
        items=[AuditLogItem.model_validate(entry) for entry in items],
        total=total,
        page=page,
        page_size=page_size,
    )

"""Risk assessment orchestration service.

Wires together: feature extraction → ML inference → policy evaluation →
DB persistence (risk_assessment + access_decision + audit log).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.session import AccessDecision, RiskAssessment, SessionEvent, UserSession
from app.models.user import User
from app.services import audit as audit_service
from app.services import features as feature_service
from app.services import inference, policy as policy_engine

logger = logging.getLogger(__name__)


def _get_session_events_as_dicts(
    db: Session, session: UserSession
) -> List[Dict[str, Any]]:
    """Load all session events as plain dicts for feature extraction."""
    events = (
        db.query(SessionEvent)
        .filter(SessionEvent.session_id == session.id)
        .order_by(SessionEvent.created_at)
        .all()
    )
    return [
        {
            "event_type": ev.event_type,
            "resource_name": ev.resource_name,
            "resource_sensitivity": ev.resource_sensitivity,
            "success": ev.success,
            "unusual_context": ev.payload.get("unusual_context", False) if ev.payload else False,
            "device_trusted": ev.payload.get("device_trusted", True) if ev.payload else True,
            "created_at": ev.created_at,
        }
        for ev in events
    ]


def assess_session_event(
    db: Session,
    *,
    session: UserSession,
    event: SessionEvent,
    user: User,
    resource_name: Optional[str] = None,
    resource_sensitivity: int = 1,
    required_role: Optional[str] = None,
    user_roles: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Run full risk assessment pipeline for a session event.

    Steps:
    1. Extract features from session event history.
    2. Run ML inference (with GRU feature history).
    3. Compute risk score and level.
    4. Apply policy engine.
    5. Persist RiskAssessment + AccessDecision + audit log.
    6. Update session risk score.
    7. Auto-revoke if policy requires it.

    Returns
    -------
    dict with: risk_score, risk_level, decision, policy_reason,
               model_name, probability, inference_latency_ms, explanation
    """
    settings = get_settings()
    roles = user_roles or [r.name for r in user.roles]

    # 1. Build event history dicts.
    events_dicts = _get_session_events_as_dicts(db, session)

    # Current event dict for feature extraction.
    current_event_dict = {
        "event_type": event.event_type,
        "resource_name": event.resource_name,
        "resource_sensitivity": event.resource_sensitivity,
        "success": event.success,
        "unusual_context": event.payload.get("unusual_context", False) if event.payload else False,
        "device_trusted": event.payload.get("device_trusted", True) if event.payload else True,
        "created_at": event.created_at,
    }

    # 2. Extract tabular features.
    session_start = session.created_at
    if session_start.tzinfo is None:
        session_start = session_start.replace(tzinfo=timezone.utc)

    current_features = feature_service.extract_tabular_features(
        events=events_dicts,
        current_event=current_event_dict,
        session_start=session_start,
    )

    # Build feature history for GRU (one dict per past event).
    feature_history: List[Dict[str, float]] = []
    for past_ev in events_dicts:
        past_feat = feature_service.extract_tabular_features(
            events=[past_ev],
            current_event=past_ev,
            session_start=session_start,
        )
        feature_history.append(past_feat)
    if current_features not in feature_history:
        feature_history.append(current_features)

    # 3. ML inference.
    inference_result = inference.predict(
        current_features,
        feature_history=feature_history,
    )

    probability = inference_result["probability"]
    model_name = inference_result["model_name"]
    latency_ms = inference_result["inference_latency_ms"]
    explanation = inference_result["explanation"]

    # 4. Risk score and level.
    risk_score = inference.probability_to_risk_score(probability)
    risk_level = inference.risk_level_from_score(
        risk_score,
        low_max=settings.risk_low_max,
        medium_max=settings.risk_medium_max,
        high_max=settings.risk_high_max,
    )

    # Hysteresis tracking (count consecutive events at same level).
    prev_level = session.current_risk_level
    if risk_level == prev_level:
        # Increment consecutive count using session payload trick.
        consecutive_count = getattr(session, "_consecutive_risk_count", 0) + 1
    else:
        consecutive_count = 1
    # Attach to session object (transient, not persisted).
    session._consecutive_risk_count = consecutive_count  # type: ignore[attr-defined]

    # Critical escalation counter.
    if risk_level == "critical":
        critical_count = getattr(session, "_consecutive_critical_count", 0) + 1
    else:
        critical_count = 0
    session._consecutive_critical_count = critical_count  # type: ignore[attr-defined]

    # 5. Policy evaluation.
    policy_decision = policy_engine.evaluate(
        risk_score=risk_score,
        risk_level=risk_level,
        resource_sensitivity=resource_sensitivity,
        resource_name=resource_name,
        user_roles=roles,
        required_role=required_role,
        session_status=session.status,
        previous_risk_level=prev_level,
        consecutive_risk_count=consecutive_count,
        settings=settings,
    )

    # 6. Persist RiskAssessment.
    ra = RiskAssessment(
        session_id=session.id,
        trigger_event_id=event.id,
        model_name=model_name,
        raw_probability=probability,
        risk_score=risk_score,
        risk_level=policy_decision.risk_level,
        feature_snapshot=current_features,
        explanation=explanation,
        inference_latency_ms=latency_ms,
    )
    db.add(ra)
    db.flush()  # Get ra.id without full commit.

    # 7. Persist AccessDecision.
    ad = AccessDecision(
        session_id=session.id,
        risk_assessment_id=ra.id,
        user_id=user.id,
        resource_name=resource_name,
        resource_sensitivity=resource_sensitivity,
        decision=policy_decision.decision,
        policy_reason=policy_decision.policy_reason,
        risk_score=risk_score,
        risk_level=policy_decision.risk_level,
        authorized_by_rbac=policy_decision.authorized_by_rbac,
    )
    db.add(ad)

    # 8. Update session risk score.
    session.current_risk_score = risk_score
    session.current_risk_level = policy_decision.risk_level
    session.last_activity_at = datetime.now(timezone.utc)

    # 9. Handle auto-revocation.
    auto_revoked = False
    if policy_engine.should_revoke_session(
        risk_score=risk_score,
        risk_level=policy_decision.risk_level,
        decision=policy_decision.decision,
        resource_sensitivity=resource_sensitivity,
        consecutive_critical_count=critical_count,
    ):
        session.status = "revoked"
        session.revoked_at = datetime.now(timezone.utc)
        session.revoke_reason = f"Auto-revoked by policy: {policy_decision.policy_reason}"
        auto_revoked = True
        logger.warning(
            "Session %s auto-revoked by policy (score=%.1f, level=%s)",
            session.session_uid,
            risk_score,
            policy_decision.risk_level,
        )
    elif policy_decision.decision == "step_up":
        session.status = "step_up_required"
    elif policy_decision.decision == "allow_limited":
        if session.status not in ("revoked", "step_up_required"):
            session.status = "restricted"
    elif policy_decision.decision == "allow" and session.status in ("restricted",):
        session.status = "active"

    db.add(session)
    db.flush()

    # 10. Audit log.
    audit_service.log_event(
        db,
        user_id=user.id,
        session_id=session.id,
        action="risk_assessment",
        resource=resource_name,
        outcome=policy_decision.decision,
        detail={
            "risk_score": round(risk_score, 2),
            "risk_level": policy_decision.risk_level,
            "model": model_name,
            "probability": round(probability, 4),
            "inference_latency_ms": round(latency_ms, 3),
            "policy_reason": policy_decision.policy_reason,
            "auto_revoked": auto_revoked,
            "is_simulated": event.is_simulated,
        },
    )

    db.commit()

    return {
        "risk_score": round(risk_score, 2),
        "risk_level": policy_decision.risk_level,
        "decision": policy_decision.decision,
        "policy_reason": policy_decision.policy_reason,
        "model_name": model_name,
        "probability": round(probability, 4),
        "inference_latency_ms": round(latency_ms, 3),
        "explanation": explanation,
        "auto_revoked": auto_revoked,
        "session_status": session.status,
        "risk_assessment_id": ra.id,
        "access_decision_id": ad.id,
    }

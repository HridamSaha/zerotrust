"""Server-side session lifecycle management."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from sqlalchemy.orm import Session

from app.models.session import UserSession
from app.models.user import User
from app.services.audit import write_audit


def create_session(
    db: Session,
    *,
    user: User,
    device_id: Optional[str] = None,
    device_trusted: bool = False,
    client_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    context_label: Optional[str] = None,
) -> UserSession:
    session = UserSession(
        session_uid=uuid4().hex,
        user_id=user.id,
        status="active",
        device_id=device_id,
        device_trusted=device_trusted,
        client_ip=client_ip,
        user_agent=user_agent,
        context_label=context_label,
        current_risk_score=0.0,
        current_risk_level="low",
        session_token_version=0,
    )
    db.add(session)
    db.flush()
    write_audit(
        db,
        action="session.create",
        outcome="success",
        actor_user_id=user.id,
        session_id=session.id,
        resource=session.session_uid,
        detail="Session established",
        evidence={
            "device_id": device_id,
            "device_trusted": device_trusted,
            "context_label": context_label,
        },
    )
    db.commit()
    db.refresh(session)
    return session


def list_sessions_for_user(
    db: Session,
    *,
    user: User,
    include_revoked: bool = False,
) -> list[UserSession]:
    query = db.query(UserSession).filter(UserSession.user_id == user.id)
    if not include_revoked:
        query = query.filter(UserSession.status != "revoked")
    return query.order_by(UserSession.created_at.desc()).all()


def get_session_for_user(
    db: Session,
    *,
    user: User,
    session_uid: str,
) -> Optional[UserSession]:
    return (
        db.query(UserSession)
        .filter(
            UserSession.session_uid == session_uid,
            UserSession.user_id == user.id,
        )
        .first()
    )


def revoke_session(
    db: Session,
    *,
    session: UserSession,
    actor: User,
    reason: str = "user_requested",
) -> UserSession:
    if session.status == "revoked":
        return session

    session.status = "revoked"
    session.revoked_at = datetime.now(timezone.utc)
    session.revoke_reason = reason
    # Invalidate any JWT that still carries the previous session_token_version.
    session.session_token_version += 1

    write_audit(
        db,
        action="session.revoke",
        outcome="success",
        actor_user_id=actor.id,
        session_id=session.id,
        resource=session.session_uid,
        detail=reason,
        evidence={"session_token_version": session.session_token_version},
    )
    db.commit()
    db.refresh(session)
    return session
